"""Minting ID tokens and access tokens (FR-OP-10).

The ID token answers "who signed in, when, and how strongly". The access token
answers "what may the bearer do". They are separate credentials because they
have separate audiences — the ID token is for the client, the access token is
for whatever the client calls with it — and conflating them is how an ID token
ends up being sent to an API that then treats it as authorisation.

**The ID token carries no identity attributes unless a scope asked for them.**
With `openid` alone the claim set is exactly the ten claims FR-OP-10 lists and
nothing else, and there is a test that pins that set exactly, because "one extra
claim slipped in" is how a token that was safe to log stops being.

**Access tokens are JWTs, which cannot be revoked, so the design has to say what
happens instead.** Two things: they live fifteen minutes, and they carry the
`fid` of the refresh family they descend from. Introspection consults that
family's revocation marker, so a family killed by reuse detection stops being
reported active immediately even though the signature on its access tokens is
still perfectly good. The residual window — a resource server that validates
locally and never introspects will honour a revoked token until it expires — is
real, and fifteen minutes is the size of it.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final

from campusid.oidc.jwt import TYPE_AT_JWT, TYPE_JWT, SigningKey, encode

ID_TOKEN_TTL: Final = timedelta(minutes=5)
"""FR-OP-10. An ID token is consumed the moment it arrives; a long-lived one is
a replayable assertion of identity sitting in a log."""

ACCESS_TOKEN_TTL: Final = timedelta(minutes=15)
"""The revocation window. See the module docstring — this number *is* the
security property, not a performance setting."""

ID_TOKEN_BASE_CLAIMS: Final[frozenset[str]] = frozenset(
    {"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid"}
)
"""Exactly FR-OP-10's list. Pinned here so the test asserting it does not
restate the requirement in its own words."""


@dataclass(frozen=True, slots=True)
class TokenContext:
    """Everything a token is minted from.

    Assembled once at the token endpoint and passed to both minters, so an ID
    token and the access token issued beside it cannot disagree about who
    authenticated, when, or at what assurance.
    """

    issuer: str
    client_id: str
    subject: str
    """The pairwise or shared identifier this client sees. Never the internal
    person key — that is what pairwise identifiers exist to keep out of here."""

    sid: str
    family_id: str
    scopes: frozenset[str]
    auth_time: datetime
    nonce: str | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()
    claims: dict[str, Any] = field(default_factory=dict)
    """Identity claims already filtered by scope and by the release policy."""


def id_token(
    context: TokenContext,
    key: SigningKey,
    *,
    now: datetime,
    ttl: timedelta = ID_TOKEN_TTL,
) -> str:
    """Mint the ID token for one authentication.

    `aud` is the client and nothing else: an ID token addressed to several
    parties is one the others can present as evidence of a login that was not
    theirs.
    """
    claims: dict[str, Any] = {
        "iss": context.issuer,
        "sub": context.subject,
        "aud": context.client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "auth_time": int(context.auth_time.timestamp()),
        "sid": context.sid,
    }
    # Emitted only when they exist rather than as nulls. A client checking
    # `nonce` against its stored value must fail on absence, and a JSON null
    # compares equal to nothing while still looking like an answer.
    if context.nonce is not None:
        claims["nonce"] = context.nonce
    if context.acr is not None:
        claims["acr"] = context.acr
    if context.amr:
        claims["amr"] = list(context.amr)

    # Identity claims are additive and gated upstream: `context.claims` is
    # already the intersection of what the scopes asked for and what policy
    # released. Nothing is widened here.
    claims.update(context.claims)
    return encode(claims, key, typ=TYPE_JWT)


def access_token(
    context: TokenContext,
    key: SigningKey,
    *,
    now: datetime,
    ttl: timedelta = ACCESS_TOKEN_TTL,
) -> tuple[str, str]:
    """Mint an access token (RFC 9068), returning it with its `jti`.

    Audience is the issuer, because the only resource this broker protects is
    its own `/userinfo`. Saying so explicitly matters: an access token with no
    audience is one any resource server that trusts our JWKS will accept, which
    turns every client's token into a universal key.

    `typ` is `at+jwt`, so a resource server can refuse an ID token presented as
    a bearer credential by reading the header rather than by inspecting claims.
    """
    jti = secrets.token_urlsafe(16)
    claims: dict[str, Any] = {
        "iss": context.issuer,
        "sub": context.subject,
        "aud": context.issuer,
        "client_id": context.client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": jti,
        "scope": " ".join(sorted(context.scopes)),
        "sid": context.sid,
        # The refresh family. Introspection reads it to report a revoked
        # family's tokens as inactive before they expire.
        "fid": context.family_id,
    }
    if context.acr is not None:
        claims["acr"] = context.acr
    if context.amr:
        claims["amr"] = list(context.amr)
    return encode(claims, key, typ=TYPE_AT_JWT), jti


def logout_token(
    context: TokenContext,
    key: SigningKey,
    *,
    now: datetime,
    ttl: timedelta = timedelta(minutes=2),
) -> str:
    """The back-channel logout token (FR-OP-12).

    `events` is what distinguishes it from an ID token, and the absence of
    `nonce` is required rather than incidental: OpenID Connect Back-Channel
    Logout 1.0 §2.4 forbids it, precisely so a logout token can never be
    replayed into a client's login handler as proof that somebody signed in.
    """
    claims: dict[str, Any] = {
        "iss": context.issuer,
        "aud": context.client_id,
        "sub": context.subject,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": secrets.token_urlsafe(16),
        "sid": context.sid,
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    return encode(claims, key, typ="logout+jwt")
