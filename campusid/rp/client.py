"""Authenticating against an upstream OpenID Provider (FR-RP-01).

The sceptical side of the relationship. Downstream we mint tokens and control
the keys; here we consume tokens from a party we do not control, and every check
exists because something upstream might be wrong, compromised, or lying.

The flow is authorization code with PKCE, and the three pieces of per-login
state — `state`, `nonce`, `code_verifier` — live in Redis rather than in a
cookie. That is not preference. The callback arrives as a cross-site
navigation, so a `SameSite=Lax` cookie is not sent on it; the two-cookie
workaround the SAML side needs exists because SAML's binding is a form POST we
must answer, whereas here we control both ends of the redirect and can key the
state off the `state` parameter itself.

**`state` is the lookup key and the CSRF defence at once.** It is a 256-bit
random value, stored server-side with everything the callback needs, and
consumed atomically. A callback carrying a `state` we did not issue is refused
before anything else happens — which is what stops an attacker completing their
own login in a victim's browser and having us link the accounts.

**`nonce` is checked against the stored value, not merely for presence.** An ID
token is replayable until its `exp`; the nonce is what ties one to this login
attempt rather than to any login attempt.

**The ID token's `iss` must equal the configured issuer exactly.** Not
`startswith`, not "ends with the right domain". An issuer that is a prefix of
another is how a multi-tenant provider's tenant A gets accepted as tenant B.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlencode

import httpx
from redis.asyncio import Redis

from campusid.errors import BrokerError, ReasonCode
from campusid.logging import get_logger
from campusid.oidc.jwt import JwtError, decode
from campusid.oidc.pkce import S256, compute_challenge
from campusid.rp.claims import ClaimMapper
from campusid.rp.jwks import JwksCache
from campusid.saml.stores import utcnow

log = get_logger(__name__)

STATE_KEY_PREFIX: Final = "rp:state:"
STATE_TTL: Final = timedelta(minutes=10)
"""How long a login at the upstream provider may take. Long enough for a
password manager and an MFA prompt; short enough that an abandoned attempt stops
being a record of who was trying to sign in where."""

STATE_BYTES: Final = 32
VERIFIER_BYTES: Final = 32
"""Both 256 bits. `state` is the only thing standing between an attacker's login
and a victim's browser, and the verifier is the only thing standing between a
stolen code and a token."""

CLOCK_SKEW: Final = timedelta(seconds=300)
"""FR-RP-01's ceiling. Wider than the SAML gate's 180s because we are the
sceptical party against providers we do not operate, and a five-minute
disagreement between two organisations' clocks is ordinary."""

EXCHANGE_TIMEOUT: Final = 10.0


@dataclass(frozen=True, slots=True)
class UpstreamProvider:
    """A configured upstream OpenID Provider."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    mapper: ClaimMapper = field(default_factory=ClaimMapper)
    """Per provider, because every OP names things differently. A shared default
    instance would be fine — `ClaimMapper` is frozen — but a factory says the
    mapping belongs to the provider rather than to the class."""


@dataclass(frozen=True, slots=True)
class PendingLogin:
    """The per-login state a callback needs, held server-side."""

    nonce: str
    code_verifier: str
    return_to: str | None = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "nonce": self.nonce,
                "code_verifier": self.code_verifier,
                "return_to": self.return_to,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> PendingLogin:
        payload = json.loads(raw)
        return cls(
            nonce=payload["nonce"],
            code_verifier=payload["code_verifier"],
            return_to=payload.get("return_to"),
        )


@dataclass(frozen=True, slots=True)
class UpstreamIdentity:
    """What an upstream login established."""

    issuer: str
    subject: str
    """The provider's `sub`. Stable per person per provider, and the value M3's
    account-linking table will key on."""

    attributes: dict[str, list[str]]
    auth_time: datetime | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()


class UpstreamClient:
    """Drives the authorization-code flow against one provider."""

    def __init__(
        self,
        provider: UpstreamProvider,
        *,
        http: httpx.AsyncClient,
        redis: Redis,
        jwks: JwksCache,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._provider = provider
        self._http = http
        self._redis = redis
        self._jwks = jwks
        self._now = now

    # --- starting a login -------------------------------------------------

    async def begin(self, *, return_to: str | None = None) -> str:
        """Store the login state and return the URL to send the browser to."""
        state = secrets.token_urlsafe(STATE_BYTES)
        pending = PendingLogin(
            nonce=secrets.token_urlsafe(STATE_BYTES),
            code_verifier=secrets.token_urlsafe(VERIFIER_BYTES),
            return_to=return_to,
        )
        await self._redis.set(
            f"{STATE_KEY_PREFIX}{state}",
            pending.to_json(),
            ex=int(STATE_TTL.total_seconds()),
        )

        query = {
            "response_type": "code",
            "client_id": self._provider.client_id,
            "redirect_uri": self._provider.redirect_uri,
            "scope": " ".join(self._provider.scopes),
            "state": state,
            "nonce": pending.nonce,
            "code_challenge": compute_challenge(pending.code_verifier),
            "code_challenge_method": S256,
        }
        return f"{self._provider.authorization_endpoint}?{urlencode(query)}"

    async def consume_state(self, state: str | None) -> PendingLogin:
        """Fetch and delete the pending login, or refuse.

        Atomic, so a captured callback URL cannot be replayed: the second
        attempt finds nothing. A callback whose `state` we did not issue is
        exactly what an attacker sends to complete *their* login in a victim's
        browser, so this is the first check and it is unconditional.
        """
        if not state:
            raise BrokerError(ReasonCode.REQUEST_BINDING_INVALID, "callback carries no state")

        raw = await self._redis.getdel(f"{STATE_KEY_PREFIX}{state}")
        if raw is None:
            raise BrokerError(
                ReasonCode.REQUEST_BINDING_INVALID,
                "the callback does not answer a login this browser started",
            )
        return PendingLogin.from_json(raw)

    # --- finishing one ----------------------------------------------------

    async def exchange(self, code: str, pending: PendingLogin) -> UpstreamIdentity:
        """Redeem the code and validate what comes back."""
        tokens = await self._redeem(code, pending)
        raw_id_token = tokens.get("id_token")
        if not isinstance(raw_id_token, str):
            raise BrokerError(ReasonCode.SIGNATURE_MISSING, "the provider returned no ID token")

        claims = await self._validated_claims(raw_id_token, pending)
        mapper = self._provider.mapper
        return UpstreamIdentity(
            issuer=self._provider.issuer,
            subject=mapper.subject(claims),
            attributes=mapper.attributes(claims),
            auth_time=_instant(claims.get("auth_time")),
            acr=claims.get("acr") if isinstance(claims.get("acr"), str) else None,
            amr=tuple(str(method) for method in claims.get("amr", []) if isinstance(method, str)),
        )

    async def _redeem(self, code: str, pending: PendingLogin) -> dict[str, Any]:
        response = await self._http.post(
            self._provider.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._provider.redirect_uri,
                "code_verifier": pending.code_verifier,
                "client_id": self._provider.client_id,
                "client_secret": self._provider.client_secret,
            },
            timeout=EXCHANGE_TIMEOUT,
        )
        if response.status_code >= 400:
            # The provider's own error text is logged, never surfaced: it is
            # written for us, and a browser showing it would leak how this
            # integration is configured.
            log.warning(
                "rp.token_exchange_failed",
                issuer=self._provider.issuer,
                status=response.status_code,
            )
            raise BrokerError(ReasonCode.GRANT_INVALID, "the provider refused the code")

        payload: dict[str, Any] = response.json()
        return payload

    async def _validated_claims(self, raw: str, pending: PendingLogin) -> dict[str, Any]:
        """Verify the ID token's signature and every claim that binds it here."""
        kid = _kid_of(raw)
        keys = await self._jwks.verification_keys(kid)

        try:
            claims = decode(
                raw,
                keys,
                issuer=self._provider.issuer,
                audience=self._provider.client_id,
                now=self._now(),
                leeway=CLOCK_SKEW,
            )
        except JwtError as exc:
            raise BrokerError(ReasonCode.SIGNATURE_INVALID, str(exc)) from exc

        _check_nonce(claims, pending)
        _check_authorized_party(claims, self._provider.client_id)
        return claims


def _check_nonce(claims: dict[str, Any], pending: PendingLogin) -> None:
    """The token must answer *this* login attempt.

    Compared against the stored value rather than merely required to be
    present. An ID token stays replayable until its `exp`, and a presence check
    would accept one captured from another session at the same provider.
    """
    if not secrets.compare_digest(str(claims.get("nonce", "")), pending.nonce):
        raise BrokerError(
            ReasonCode.REQUEST_BINDING_INVALID, "the ID token answers a different login"
        )


def _check_authorized_party(claims: dict[str, Any], client_id: str) -> None:
    """`azp` names who the token was issued *for* when `aud` has several values.

    OIDC Core §3.1.3.7: when the audience is multi-valued, `azp` must be present
    and must be us. Without the check, a provider that issues one token to
    several audiences hands any of them a token we would accept as our own.
    """
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != client_id:
        raise BrokerError(
            ReasonCode.AUDIENCE_MISMATCH, "the token was authorised for another party"
        )


def _kid_of(token: str) -> str | None:
    """Read `kid` from an unverified header, only to choose a key.

    Reading anything from an unverified token needs a reason, and this is the
    one the design allows: the value selects which key to *try*, and a wrong or
    absent one produces a verification failure rather than a wrong acceptance.
    """
    try:
        header_segment = token.split(".")[0]
        padded = header_segment + "=" * (-len(header_segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, IndexError, UnicodeDecodeError):
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    return kid if isinstance(kid, str) else None


def _instant(value: Any) -> datetime | None:
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, tz=UTC)
    return None
