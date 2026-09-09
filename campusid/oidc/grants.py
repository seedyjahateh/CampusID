"""Authorization codes and refresh token families (FR-OP-04, FR-OP-08).

Both credentials here are bearer tokens with the same lifecycle problem: they
are meant to be used exactly once, they travel through systems we do not
control, and the interesting case is not the honest client but the second
presentation.

Three decisions run through the module.

**Nothing is stored in the form it is presented.** Keys are the SHA-256 of the
credential, so the record is addressable but a dump of Redis — or a key that
lands in a log line, a monitoring exporter, a support ticket — yields nothing
redeemable. Lookup by digest costs nothing because it is an exact-match key, and
a fast hash is right here for the same reason it is right for client secrets:
these are 256-bit values from a CSPRNG, so there is no guessing to slow down.

**Consumption is a `SET NX`, not a delete.** Deleting on use is the obvious
implementation and it destroys the evidence: the second presentation of a code
becomes indistinguishable from an expired one, and reuse — the signal that a
credential leaked — is reported as a routine timeout. Instead the record stays
until it expires and a separate marker records that it was spent, atomically. A
second attempt therefore *finds* the record and knows exactly what it is
looking at.

**Reuse revokes the family, not the token.** When a refresh token is presented
twice, one of the two presentations came from an attacker, and there is no way
to tell which. Revoking only the token that was replayed leaves whichever party
rotated successfully holding a valid one — and if that is the attacker, the
detection accomplished nothing. So the whole lineage descended from one
authorization code dies at once, both parties are logged out, and the legitimate
user re-authenticates. That is the design from RFC 9700 §4.14.2, and the
unpleasant part — the honest user is signed out too — is the point rather than a
side effect.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from redis.asyncio import Redis

from campusid.errors import ReasonCode
from campusid.oidc.errors import INVALID_GRANT, OAuthError
from campusid.saml.stores import utcnow

CODE_KEY_PREFIX: Final = "oidc:code:"
CODE_SPENT_PREFIX: Final = "oidc:code:spent:"
REFRESH_KEY_PREFIX: Final = "oidc:refresh:"
REFRESH_SPENT_PREFIX: Final = "oidc:refresh:spent:"
FAMILY_REVOKED_PREFIX: Final = "oidc:family:revoked:"

CODE_TTL: Final = timedelta(seconds=60)
"""FR-OP-04. A code is redeemed by a server that already has the user's browser
in hand; a minute is generous. Long-lived codes are what make interception worth
attempting."""

REFRESH_TTL: Final = timedelta(days=14)
"""How long a family may keep rotating without the user returning."""

TOKEN_BYTES: Final = 32
"""256 bits. These are the credentials; there is nothing else to guess."""


class GrantReuse(OAuthError):
    """A code or refresh token was presented a second time.

    Its own exception because the caller must do something beyond refusing: the
    family is already revoked by the time this is raised, and the audit layer
    records it as a security event rather than a failed request.
    """


@dataclass(frozen=True, slots=True)
class AuthorizationCode:
    """What was authorised, held between the authorization and token endpoints.

    Every field the token endpoint needs is captured here rather than re-derived
    later. The alternative — trusting parameters repeated on the token request —
    is how a code issued for one `redirect_uri` gets redeemed against another.
    """

    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: tuple[str, ...]
    subject: str
    sid: str
    """The broker session this code came from, so back-channel logout can find
    the tokens it produced."""

    family_id: str
    nonce: str | None = None
    auth_time: datetime | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()

    def to_json(self) -> str:
        payload: dict[str, Any] = asdict(self)
        payload["scopes"] = list(self.scopes)
        payload["amr"] = list(self.amr)
        payload["auth_time"] = self.auth_time.isoformat() if self.auth_time else None
        return json.dumps(payload)

    @classmethod
    def from_json(cls, raw: str) -> AuthorizationCode:
        payload = json.loads(raw)
        payload["scopes"] = tuple(payload["scopes"])
        payload["amr"] = tuple(payload["amr"])
        if payload["auth_time"]:
            payload["auth_time"] = datetime.fromisoformat(payload["auth_time"])
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class RefreshToken:
    """A refresh token's record: what it may be exchanged for, and its lineage."""

    client_id: str
    scopes: tuple[str, ...]
    subject: str
    sid: str
    family_id: str
    generation: int
    """How many rotations deep. Carried for the audit trail — a family revoked at
    generation 40 tells a different story from one revoked at generation 2."""

    issued_at: datetime

    def to_json(self) -> str:
        payload: dict[str, Any] = asdict(self)
        payload["scopes"] = list(self.scopes)
        payload["issued_at"] = self.issued_at.isoformat()
        return json.dumps(payload)

    @classmethod
    def from_json(cls, raw: str) -> RefreshToken:
        payload = json.loads(raw)
        payload["scopes"] = tuple(payload["scopes"])
        payload["issued_at"] = datetime.fromisoformat(payload["issued_at"])
        return cls(**payload)


class GrantStore:
    """Redis-backed storage for codes and refresh tokens."""

    def __init__(
        self,
        redis: Redis,
        *,
        code_ttl: timedelta = CODE_TTL,
        refresh_ttl: timedelta = REFRESH_TTL,
    ) -> None:
        self._redis = redis
        self._code_ttl = code_ttl
        self._refresh_ttl = refresh_ttl

    # --- authorization codes ---------------------------------------------

    async def issue_code(self, grant: AuthorizationCode) -> str:
        """Store a grant and return the code that redeems it."""
        code = _new_token()
        await self._redis.set(
            f"{CODE_KEY_PREFIX}{_digest(code)}",
            grant.to_json(),
            ex=_seconds(self._code_ttl),
        )
        return code

    async def redeem_code(
        self, code: str, *, client_id: str, redirect_uri: str
    ) -> AuthorizationCode:
        """Spend a code, or explain why it cannot be spent.

        The client and redirect URI are checked *here* rather than by the
        caller, against the values recorded when the code was issued. A code is
        bound to the request that produced it; accepting the ones repeated on
        the token request would let a client redeem a code issued to somebody
        else and receive tokens for that user.
        """
        digest = _digest(code)
        raw = await self._redis.get(f"{CODE_KEY_PREFIX}{digest}")
        if raw is None:
            raise OAuthError(INVALID_GRANT, ReasonCode.GRANT_INVALID, "unknown or expired code")

        grant = AuthorizationCode.from_json(raw)

        # SET NX is the whole of single-use. Two concurrent redemptions both
        # read the record above; exactly one wins this write.
        first_use = await self._redis.set(
            f"{CODE_SPENT_PREFIX}{digest}", "1", nx=True, ex=_seconds(self._code_ttl)
        )
        if not first_use:
            await self.revoke_family(grant.family_id)
            raise GrantReuse(
                INVALID_GRANT,
                ReasonCode.GRANT_REUSE_DETECTED,
                f"code replayed for {grant.client_id!r}; family {grant.family_id} revoked",
            )

        if grant.client_id != client_id:
            # Not a mistake anyone makes by accident. The code was intercepted,
            # so the family goes with it.
            await self.revoke_family(grant.family_id)
            raise OAuthError(
                INVALID_GRANT, ReasonCode.GRANT_INVALID, "code was issued to another client"
            )
        if grant.redirect_uri != redirect_uri:
            raise OAuthError(
                INVALID_GRANT, ReasonCode.GRANT_INVALID, "redirect_uri does not match the code"
            )
        return grant

    # --- refresh tokens ---------------------------------------------------

    async def issue_refresh_token(self, record: RefreshToken) -> str:
        """Store a refresh token and return it."""
        token = _new_token()
        await self._redis.set(
            f"{REFRESH_KEY_PREFIX}{_digest(token)}",
            record.to_json(),
            ex=_seconds(self._refresh_ttl),
        )
        return token

    async def rotate_refresh_token(
        self, token: str, *, client_id: str, now: datetime | None = None
    ) -> tuple[str, RefreshToken]:
        """Exchange a refresh token for its successor (FR-OP-08).

        Rotation on every use is what makes reuse detectable at all: if a token
        stayed valid across refreshes there would be no second presentation to
        notice.
        """
        now = now or utcnow()
        digest = _digest(token)
        raw = await self._redis.get(f"{REFRESH_KEY_PREFIX}{digest}")
        if raw is None:
            raise OAuthError(INVALID_GRANT, ReasonCode.GRANT_INVALID, "unknown or expired token")

        record = RefreshToken.from_json(raw)
        if await self.is_family_revoked(record.family_id):
            raise OAuthError(INVALID_GRANT, ReasonCode.GRANT_REVOKED, "the token family is revoked")

        first_use = await self._redis.set(
            f"{REFRESH_SPENT_PREFIX}{digest}", "1", nx=True, ex=_seconds(self._refresh_ttl)
        )
        if not first_use:
            await self.revoke_family(record.family_id)
            raise GrantReuse(
                INVALID_GRANT,
                ReasonCode.GRANT_REUSE_DETECTED,
                f"refresh token replayed at generation {record.generation}; "
                f"family {record.family_id} revoked",
            )

        if record.client_id != client_id:
            await self.revoke_family(record.family_id)
            raise OAuthError(
                INVALID_GRANT, ReasonCode.GRANT_INVALID, "token was issued to another client"
            )

        successor = RefreshToken(
            client_id=record.client_id,
            scopes=record.scopes,
            subject=record.subject,
            sid=record.sid,
            family_id=record.family_id,
            generation=record.generation + 1,
            issued_at=now,
        )
        return await self.issue_refresh_token(successor), successor

    async def describe_refresh_token(self, token: str) -> RefreshToken | None:
        """Look a refresh token up without spending it.

        For revocation, which must not consume the credential it is destroying:
        marking it spent would make a second revocation call look like reuse and
        revoke a family that a legitimate client had already asked us to revoke.
        """
        raw = await self._redis.get(f"{REFRESH_KEY_PREFIX}{_digest(token)}")
        return RefreshToken.from_json(raw) if raw is not None else None

    # --- families ----------------------------------------------------------

    async def revoke_family(self, family_id: str) -> None:
        """Kill every token descended from one authorization code.

        A marker rather than a sweep of the individual tokens: the successors
        are addressable only by digests we do not keep a list of, and a marker
        is one atomic write instead of an enumeration that can be interrupted
        half-done.
        """
        await self._redis.set(
            f"{FAMILY_REVOKED_PREFIX}{family_id}", "1", ex=_seconds(self._refresh_ttl)
        )

    async def is_family_revoked(self, family_id: str) -> bool:
        """Consulted on refresh, and by introspection, so a revoked family's
        access tokens stop being reported active before they expire."""
        return bool(await self._redis.exists(f"{FAMILY_REVOKED_PREFIX}{family_id}"))


def new_family_id() -> str:
    """Names the lineage descending from one authorization code."""
    return secrets.token_urlsafe(16)


def _new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def _digest(token: str) -> str:
    """What is stored in place of the credential."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _seconds(ttl: timedelta) -> int:
    return max(int(ttl.total_seconds()), 1)
