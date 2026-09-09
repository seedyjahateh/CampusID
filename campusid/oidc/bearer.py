"""Accepting an access token (FR-OP-09, FR-OP-11).

The other half of `tokens.py`: that module mints them, this one decides whether
one presented back to us is still good. Both `/userinfo` and introspection go
through here, so there is one answer to "is this token active" rather than two
that can drift.

Four checks, and the last is the one that makes a JWT revocable at all:

1. **The header names `at+jwt`.** RFC 9068. An ID token presented as a bearer
   credential is refused by its type rather than by noticing it lacks a `scope`
   claim — a client that confuses the two should be told so, not accommodated.
2. **The signature verifies against a key we publish**, with the algorithm
   supplied by us and merely compared against the header.
3. **`aud` is our own issuer.** We are the resource server for `/userinfo`, and
   a token minted for something else is not ours to honour.
4. **The refresh family is not revoked.** A signature stays valid for the
   token's whole lifetime, so this is the only thing standing between reuse
   detection and a fifteen-minute window in which a compromised session's access
   tokens still work. It costs one Redis lookup on a request that is about to do
   a policy evaluation anyway.

A resource server that validates locally and never introspects still honours a
revoked token until it expires. That residual window is real and is exactly
`ACCESS_TOKEN_TTL`; it is not hidden behind an implementation that pretends
otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from campusid.errors import ReasonCode
from campusid.oidc.errors import OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.jwt import TYPE_AT_JWT, JwtError, decode
from campusid.oidc.keys import KeySet

# RFC 6750's error code, not a credential. Flagged by the bandit rule for the
# word "token"; the string has to be exactly this.
INVALID_TOKEN: Final = "invalid_token"  # noqa: S105
"""RFC 6750 §3.1. Distinct from OAuth's `invalid_grant`: this is a resource
server's vocabulary, and it is what belongs in a `WWW-Authenticate` header."""


@dataclass(frozen=True, slots=True)
class BearerToken:
    """A verified, unrevoked access token."""

    claims: dict[str, Any]

    @property
    def subject(self) -> str:
        return str(self.claims["sub"])

    @property
    def client_id(self) -> str:
        return str(self.claims["client_id"])

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset(str(self.claims.get("scope", "")).split())

    @property
    def sid(self) -> str:
        return str(self.claims["sid"])

    @property
    def family_id(self) -> str:
        return str(self.claims["fid"])


def credentials(header: str | None) -> str | None:
    """Extract a bearer credential from an `Authorization` header.

    RFC 6750 allows the token in a query parameter too, and this deliberately
    does not: a token in a URL reaches browser history, referrer headers, and
    every access log between here and the client.
    """
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def verify(
    token: str | None,
    *,
    keys: KeySet,
    grants: GrantStore,
    issuer: str,
    now: datetime,
) -> BearerToken:
    """Verify an access token, or raise.

    Raises rather than returning None so callers cannot forget the failure
    branch — the one place a resource server must never fall through.
    """
    if not token:
        raise OAuthError(INVALID_TOKEN, ReasonCode.GRANT_INVALID, "no bearer token presented")

    try:
        claims = decode(
            token,
            keys.verification_keys,
            issuer=issuer,
            audience=issuer,
            now=now,
            expected_typ=TYPE_AT_JWT,
        )
    except JwtError as exc:
        raise OAuthError(INVALID_TOKEN, ReasonCode.GRANT_INVALID, str(exc)) from exc

    family = claims.get("fid")
    if not isinstance(family, str):
        # Every token this broker mints carries one. A token without it was
        # signed by a key of ours under an older format, and honouring it would
        # mean honouring something that cannot be revoked.
        raise OAuthError(INVALID_TOKEN, ReasonCode.GRANT_INVALID, "token carries no family")
    if await grants.is_family_revoked(family):
        raise OAuthError(INVALID_TOKEN, ReasonCode.GRANT_REVOKED, "the token family is revoked")

    return BearerToken(claims=claims)


def challenge(exc: OAuthError) -> dict[str, str]:
    """The `WWW-Authenticate` header for a refused bearer token.

    Carries the error code and nothing else. RFC 6750 permits a description;
    ours would name which of four checks failed, which is the reconnaissance the
    uniform error page exists to withhold.
    """
    return {"WWW-Authenticate": f'Bearer error="{exc.error}"'}
