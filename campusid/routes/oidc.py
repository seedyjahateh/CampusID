"""The OpenID Provider's public metadata endpoints (FR-OP-01, FR-OP-02).

Two documents, both cacheable, both served to anyone. They are the only OIDC
endpoints that need no authentication and reveal nothing sensitive: the JWKS
carries public parameters by construction, and the discovery document describes
what the broker will do rather than who has done it.

Both carry a short `Cache-Control`. Long-lived caching of the JWKS is the classic
way a key rotation breaks a federation — a client that cached the old document
for a day refuses tokens signed by the new key for a day — while no caching at
all makes every relying party's token verification depend on our availability.
Five minutes is short enough that a rotation propagates within the overlap
window and long enough that the endpoint is not on anybody's hot path.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from campusid.logging import get_logger
from campusid.oidc import bearer
from campusid.oidc.discovery import discovery_document
from campusid.oidc.errors import OAuthError
from campusid.oidc.identity import release_to
from campusid.saml.stores import utcnow

log = get_logger(__name__)

router = APIRouter(tags=["oidc"])

METADATA_CACHE_CONTROL: Final = "public, max-age=300"
NO_STORE: Final = {"Cache-Control": "no-store"}


@router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request) -> JSONResponse:
    """Describe this provider to a client that wants to configure itself."""
    return JSONResponse(
        discovery_document(request.app.state.settings.oidc_issuer),
        headers={"Cache-Control": METADATA_CACHE_CONTROL},
    )


@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    """Publish the keys that verify our tokens.

    Read from application state rather than rebuilt per request, so every
    response describes the same key set — a client fetching this twice during a
    rotation must not see the new key appear and vanish.
    """
    return JSONResponse(
        request.app.state.oidc_keys.as_jwks(),
        headers={"Cache-Control": METADATA_CACHE_CONTROL},
    )


@router.get("/userinfo")
async def userinfo(request: Request) -> JSONResponse:
    """Claims about the bearer of an access token (FR-OP-11).

    Evaluated fresh on every call, through the same release engine and the same
    policy the SAML side uses. That is what makes the requirement — "OIDC and
    SAML release identical sets for the same policy" — a consequence of there
    being one implementation rather than an agreement between two, and it means
    a policy change or a FERPA suppression takes effect on the next call rather
    than on the next login.

    The `sub` is re-derived rather than copied from the token, so a response
    that somehow disagreed with the token about who this is would be impossible
    rather than merely unlikely. It is compared, and a mismatch is a refusal.
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
        log.info("oidc.userinfo.rejected", error=exc.error, reason=exc.reason.value)
        return JSONResponse(
            {"error": exc.error},
            status_code=401,
            headers={**NO_STORE, **bearer.challenge(exc)},
        )

    session = await state.sessions.load(token.sid)
    if session is None:
        # The session behind the token is gone: signed out, expired, or killed
        # by an administrator. The token's signature says nothing about that,
        # which is the whole reason this endpoint consults the session.
        return JSONResponse(
            {"error": bearer.INVALID_TOKEN},
            status_code=401,
            headers={**NO_STORE, "WWW-Authenticate": f'Bearer error="{bearer.INVALID_TOKEN}"'},
        )

    settings = state.settings
    identity = release_to(
        session,
        state.policies.get(token.client_id),
        token.scopes,
        pairwise_salt=settings.pairwise_salt_bytes,
        scope=settings.scope,
    )
    if identity.subject != token.subject:
        # Only reachable if the pairwise salt or the SP's policy identity
        # changed under a live token. Refusing is the honest answer: we can no
        # longer say the bearer is who the token says they are.
        log.warning("oidc.userinfo.subject_drift", client_id=token.client_id)
        return JSONResponse({"error": bearer.INVALID_TOKEN}, status_code=401, headers=NO_STORE)

    body: dict[str, Any] = {"sub": identity.subject, **identity.claims}
    return JSONResponse(body, headers=NO_STORE)
