"""The SCIM discovery endpoints (FR-SCIM-01).

Three documents describing what this server does, served before a client has
sent anything it could get wrong. They are the SCIM equivalent of the OIDC
discovery document and carry the same obligation: every flag is a promise a
conformance client will hold us to.

Unauthenticated, deliberately. RFC 7644 §2 permits either, and these documents
describe the *server* rather than anybody in it — requiring a token to learn
which features exist would mean an integrator cannot check compatibility before
asking for credentials. Nothing here names a person.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from campusid.scim.errors import not_found
from campusid.scim.schemas import (
    LIST_RESPONSE,
    resource_types,
    schemas,
    service_provider_config,
)

router = APIRouter(tags=["scim"])

SCIM_CONTENT_TYPE: Final = "application/scim+json"
"""RFC 7644 §8.1. A conformance client checks it, and `application/json` is a
documented interoperability failure rather than a harmless difference."""

DISCOVERY_CACHE_CONTROL: Final = "public, max-age=300"
"""These change only when the server does. Cacheable for the same reason the
OIDC metadata is, and for the same short window."""


def _scim(body: object, status: int = 200) -> JSONResponse:
    return JSONResponse(
        body,
        status_code=status,
        media_type=SCIM_CONTENT_TYPE,
        headers={"Cache-Control": DISCOVERY_CACHE_CONTROL},
    )


def _listing(resources: list[dict[str, object]]) -> dict[str, object]:
    """Wrap a discovery collection as a `ListResponse`.

    RFC 7644 §4 requires it even for the fixed collections here, and a client
    written against the specification reads `Resources` rather than a bare
    array. Returning the array would work with a hand-written client and fail
    with a conformant one — the wrong way round.
    """
    return {
        "schemas": [LIST_RESPONSE],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/scim/v2/ServiceProviderConfig")
async def provider_config(request: Request) -> JSONResponse:
    """What this server supports."""
    return _scim(service_provider_config(request.app.state.settings.oidc_issuer))


@router.get("/scim/v2/ResourceTypes")
async def list_resource_types(request: Request) -> JSONResponse:
    """Which resources exist, and which extensions each carries."""
    return _scim(_listing(resource_types(request.app.state.settings.oidc_issuer)))


@router.get("/scim/v2/ResourceTypes/{resource_id}")
async def get_resource_type(request: Request, resource_id: str) -> JSONResponse:
    issuer = request.app.state.settings.oidc_issuer
    for resource in resource_types(issuer):
        if resource["id"] == resource_id:
            return _scim(resource)

    error = not_found("ResourceType", resource_id)
    return JSONResponse(error.to_dict(), status_code=error.status, media_type=SCIM_CONTENT_TYPE)


@router.get("/scim/v2/Schemas")
async def list_schemas(request: Request) -> JSONResponse:
    """Every schema, including the campus extension.

    Declaring the extension here is what makes it discoverable rather than a
    private arrangement: an SIS integrator can read what the broker expects
    without asking anybody, and a conformance client can find it.
    """
    return _scim(_listing(schemas(request.app.state.settings.oidc_issuer)))


@router.get("/scim/v2/Schemas/{schema_id:path}")
async def get_schema(request: Request, schema_id: str) -> JSONResponse:
    """One schema by its URN.

    The path converter matters: a schema id is a URN full of colons and dots,
    and the default converter stops at the first slash — which these do not
    contain, but a future `urn:.../v2/User` would.
    """
    issuer = request.app.state.settings.oidc_issuer
    for schema in schemas(issuer):
        if schema["id"] == schema_id:
            return _scim(schema)

    error = not_found("Schema", schema_id)
    return JSONResponse(error.to_dict(), status_code=error.status, media_type=SCIM_CONTENT_TYPE)
