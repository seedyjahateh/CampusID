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

from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from campusid.oidc.discovery import discovery_document

router = APIRouter(tags=["oidc"])

METADATA_CACHE_CONTROL: Final = "public, max-age=300"


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
