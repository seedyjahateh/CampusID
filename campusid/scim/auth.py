"""Authenticating the SCIM API (FR-SCIM-13).

An OAuth bearer token from this broker's own token endpoint, carrying
`scim:read` for reads and `scim:write` for mutations. The same verification the
`/userinfo` endpoint uses, so a revoked family stops provisioning as immediately
as it stops a login — a compromised SIS credential is exactly the case where
that matters.

Two scopes rather than one, because the reads and the writes have genuinely
different blast radii. A reporting job that lists users needs `scim:read` and
would be a catastrophe with `scim:write`; giving both to everything because it
is simpler is how a read-only integration ends up able to deprovision the
campus.

The token is a client credential, not a person's. Nothing here consults a
session: an SIS runs at three in the morning and there is nobody logged in.
"""

from __future__ import annotations

from typing import Final

from fastapi import Request

from campusid.oidc import bearer
from campusid.oidc.errors import OAuthError
from campusid.saml.stores import utcnow
from campusid.scim.errors import ScimError, forbidden, unauthorized

SCOPE_READ: Final = "scim:read"
SCOPE_WRITE: Final = "scim:write"
"""FR-SCIM-13. `scim:write` does not imply `scim:read` — a client that only
pushes changes has no business enumerating the directory, and the check below
requires whichever one the operation actually needs."""


async def require_scope(request: Request, scope: str) -> bearer.BearerToken:
    """Verify the caller's token and check it carries `scope`.

    Raises `ScimError`, so the SCIM error envelope is what a client sees rather
    than the OAuth one — two error formats on one endpoint is a conformance
    failure that a client discovers by failing to parse a response.
    """
    state = request.app.state
    try:
        token = await bearer.verify(
            bearer.credentials(request.headers.get("authorization")),
            keys=state.oidc_keys,
            grants=state.grants,
            issuer=state.settings.oidc_issuer,
            now=utcnow(),
        )
    except OAuthError as exc:
        # Deliberately loses the detail. This is the one SCIM response whose
        # caller may not be a legitimate client, so it behaves like the SAML
        # gate rather than like a helpful API.
        raise unauthorized() from exc

    if scope not in token.scopes:
        # Named, unlike the 401 above: an authenticated client holding the
        # wrong scope has a fixable configuration problem and deserves to know
        # which one it is missing.
        raise forbidden(scope)

    return token


def challenge(error: ScimError) -> dict[str, str]:
    """The `WWW-Authenticate` header a 401 carries (RFC 6750 §3)."""
    return {"WWW-Authenticate": 'Bearer realm="scim"'} if error.status == 401 else {}
