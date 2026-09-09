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

from typing import Any, Final

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from campusid.scim.auth import SCOPE_READ, SCOPE_WRITE, challenge, require_scope
from campusid.scim.errors import ScimError, ScimType, invalid_filter, not_found
from campusid.scim.filters import ScimFilterError, parse_filter
from campusid.scim.patch import PatchError, apply_patch, parse_operations
from campusid.scim.resources import from_scim
from campusid.scim.schemas import (
    LIST_RESPONSE,
    resource_types,
    schemas,
    service_provider_config,
)
from campusid.scim.store import DEFAULT_COUNT

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


# --- /Users -----------------------------------------------------------------


def _error(exc: ScimError) -> JSONResponse:
    """The one way this API reports a failure (FR-SCIM-12)."""
    return JSONResponse(
        exc.to_dict(),
        status_code=exc.status,
        media_type=SCIM_CONTENT_TYPE,
        headers={"Cache-Control": "no-store", **challenge(exc)},
    )


def _resource(body: dict[str, Any], status: int = 200) -> JSONResponse:
    """A single resource, with the ETag a client's `If-Match` needs.

    `no-store` rather than the discovery documents' cache header: this is one
    person's record, and an intermediary holding it is a disclosure nobody
    intended.
    """
    headers = {"Cache-Control": "no-store"}
    meta = body.get("meta")
    if isinstance(meta, dict):
        headers["ETag"] = meta["version"]
        headers["Location"] = meta["location"]
    return JSONResponse(body, status_code=status, media_type=SCIM_CONTENT_TYPE, headers=headers)


@router.post("/scim/v2/Users")
async def create_user(request: Request) -> JSONResponse:
    """Create a person (FR-SCIM-02), idempotently on `externalId` (FR-SCIM-14)."""
    try:
        await require_scope(request, SCOPE_WRITE)
        raw = await _body(request)
        resource, created = await request.app.state.scim_users.create(from_scim(raw), raw)
    except ScimError as exc:
        return _error(exc)

    # 201 for a new person, 200 for a replay. The status is the only thing
    # telling a retrying client whether its first attempt landed.
    return _resource(resource, 201 if created else 200)


@router.get("/scim/v2/Users")
async def list_users(
    request: Request,
    filter: str | None = None,
    startIndex: int = 1,
    count: int = DEFAULT_COUNT,
    sortBy: str | None = None,
    sortOrder: str = "ascending",
) -> JSONResponse:
    """List people (FR-SCIM-07, FR-SCIM-08).

    The parameter names are the specification's, capitalisation and all. A
    client sends `startIndex` and nothing else will do, so the linter is
    silenced rather than the API renamed.
    """
    try:
        await require_scope(request, SCOPE_READ)
        predicate = parse_filter(filter) if filter else None
        page = await request.app.state.scim_users.search(
            predicate=predicate,
            start_index=startIndex,
            count=count,
            sort_by=sortBy,
            descending=sortOrder.lower() == "descending",
        )
    except ScimFilterError as exc:
        return _error(invalid_filter(str(exc)))
    except ScimError as exc:
        return _error(exc)

    return JSONResponse(
        page.to_list_response(),
        media_type=SCIM_CONTENT_TYPE,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/scim/v2/Users/{resource_id}")
async def get_user(request: Request, resource_id: str) -> Response:
    """Read one person (FR-SCIM-03)."""
    try:
        await require_scope(request, SCOPE_READ)
        resource = await request.app.state.scim_users.get(resource_id)
    except ScimError as exc:
        return _error(exc)

    version = resource["meta"]["version"]
    if _matches_none(request, version):
        # FR-SCIM-09. The client already holds this version, so 304 saves it
        # parsing a document it has.
        return Response(status_code=304, headers={"ETag": version, "Cache-Control": "no-store"})

    return _resource(_project(request, resource))


@router.put("/scim/v2/Users/{resource_id}")
async def replace_user(request: Request, resource_id: str) -> JSONResponse:
    """Replace a person (FR-SCIM-04)."""
    try:
        await require_scope(request, SCOPE_WRITE)
        raw = await _body(request)
        resource = await request.app.state.scim_users.replace(
            resource_id, from_scim(raw), raw, if_match=request.headers.get("if-match")
        )
    except ScimError as exc:
        return _error(exc)

    return _resource(resource)


@router.patch("/scim/v2/Users/{resource_id}")
async def patch_user(request: Request, resource_id: str) -> JSONResponse:
    """Modify parts of a person (FR-SCIM-05).

    The patch is applied to the *projected document* rather than to rows. That
    is what lets `emails[type eq "work"].value` mean what it says: the path
    addresses the SCIM representation, and translating a value filter into a
    query over three tables would be reimplementing the specification in SQL.
    The result is written back through the ordinary replace path.
    """
    store = request.app.state.scim_users
    try:
        await require_scope(request, SCOPE_WRITE)
        current = await store.get(resource_id)
        patched = apply_patch(current, parse_operations(await _body(request)))
        resource = await store.apply_patched(
            resource_id, from_scim(patched), patched, if_match=request.headers.get("if-match")
        )
    except PatchError as exc:
        return _error(ScimError(400, str(exc), exc.scim_type))
    except ScimError as exc:
        return _error(exc)

    return _resource(resource)


@router.delete("/scim/v2/Users/{resource_id}")
async def delete_user(request: Request, resource_id: str) -> Response:
    """Deprovision a person (FR-SCIM-06).

    A soft delete: the person is deactivated and their identifiers tombstoned,
    so the audit trail keeps naming them and their ePPN is never handed to
    anybody else.
    """
    try:
        await require_scope(request, SCOPE_WRITE)
        await request.app.state.scim_users.soft_delete(
            resource_id, if_match=request.headers.get("if-match")
        )
    except ScimError as exc:
        return _error(exc)

    return Response(status_code=204, headers={"Cache-Control": "no-store"})


# --- /Groups ----------------------------------------------------------------


def _wants_members(request: Request) -> bool:
    """Whether this request asked for the membership.

    `members` is `returned: "request"` in the Group schema, so it is served only
    when the client names it in `attributes`. That is not a shortcut: a group
    here may have tens of thousands of members, and returning them by default
    would make `GET /Groups` cost the whole membership table.
    """
    requested = _csv(request.query_params.get("attributes"))
    excluded = _csv(request.query_params.get("excludedAttributes"))
    return "members" in requested and "members" not in excluded


@router.post("/scim/v2/Groups")
async def create_group(request: Request) -> JSONResponse:
    """Create a group (FR-SCIM-11)."""
    try:
        await require_scope(request, SCOPE_WRITE)
        resource, created = await request.app.state.scim_groups.create(await _body(request))
    except ScimError as exc:
        return _error(exc)

    return _resource(resource, 201 if created else 200)


@router.get("/scim/v2/Groups")
async def list_groups(
    request: Request,
    filter: str | None = None,
    startIndex: int = 1,
    count: int = DEFAULT_COUNT,
    sortBy: str | None = None,
    sortOrder: str = "ascending",
) -> JSONResponse:
    """List groups.

    A filter here addresses the group's own attributes. "Who is in this group"
    is asked from the other side — `GET /Users?filter=groups.value eq "<id>"` —
    which pages, where a members filter would have to load every membership row
    to answer.
    """
    try:
        await require_scope(request, SCOPE_READ)
        predicate = parse_filter(filter) if filter else None
        page = await request.app.state.scim_groups.search(
            predicate=predicate,
            start_index=startIndex,
            count=count,
            sort_by=sortBy,
            descending=sortOrder.lower() == "descending",
            with_members=_wants_members(request),
        )
    except ScimFilterError as exc:
        return _error(invalid_filter(str(exc)))
    except ScimError as exc:
        return _error(exc)

    return JSONResponse(
        page.to_list_response(),
        media_type=SCIM_CONTENT_TYPE,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/scim/v2/Groups/{group_id}")
async def get_group(request: Request, group_id: str) -> Response:
    """Read one group."""
    try:
        await require_scope(request, SCOPE_READ)
        resource = await request.app.state.scim_groups.get(
            group_id, with_members=_wants_members(request)
        )
    except ScimError as exc:
        return _error(exc)

    version = resource["meta"]["version"]
    if _matches_none(request, version):
        return Response(status_code=304, headers={"ETag": version, "Cache-Control": "no-store"})

    return _resource(_project(request, resource))


@router.put("/scim/v2/Groups/{group_id}")
async def replace_group(request: Request, group_id: str) -> JSONResponse:
    """Replace a group.

    A body with no `members` at all leaves the membership alone — see the store
    for why. An explicit empty array still clears it.
    """
    try:
        await require_scope(request, SCOPE_WRITE)
        resource = await request.app.state.scim_groups.replace(
            group_id, await _body(request), if_match=request.headers.get("if-match")
        )
    except ScimError as exc:
        return _error(exc)

    return _resource(resource)


@router.patch("/scim/v2/Groups/{group_id}")
async def patch_group(request: Request, group_id: str) -> JSONResponse:
    """Modify a group (FR-SCIM-11's performance requirement).

    Unlike `/Users`, this does not patch a projected document. A group's
    document is its membership, and projecting it to change one member is the
    full-collection read the requirement exists to avoid — so membership
    operations become row-level writes and the rest is a short attribute
    mapping.
    """
    try:
        await require_scope(request, SCOPE_WRITE)
        operations = parse_operations(await _body(request))
        resource = await request.app.state.scim_groups.patch(
            group_id, operations, if_match=request.headers.get("if-match")
        )
    except PatchError as exc:
        return _error(ScimError(400, str(exc), exc.scim_type))
    except ScimError as exc:
        return _error(exc)

    return _resource(resource)


@router.delete("/scim/v2/Groups/{group_id}")
async def delete_group(request: Request, group_id: str) -> Response:
    """Delete a group, and its membership with it.

    A real delete, unlike a person's. A group is an access-control grouping
    rather than somebody's identity, and a tombstone would only make its name
    unusable for whatever replaces it.
    """
    try:
        await require_scope(request, SCOPE_WRITE)
        await request.app.state.scim_groups.delete(
            group_id, if_match=request.headers.get("if-match")
        )
    except ScimError as exc:
        return _error(exc)

    return Response(status_code=204, headers={"Cache-Control": "no-store"})


# --- request helpers --------------------------------------------------------


async def _body(request: Request) -> dict[str, Any]:
    try:
        document = await request.json()
    except ValueError as exc:
        raise ScimError(400, "the request body is not valid JSON", ScimType.INVALID_SYNTAX) from exc
    if not isinstance(document, dict):
        raise ScimError(400, "the request body must be an object", ScimType.INVALID_SYNTAX)
    return document


def _matches_none(request: Request, version: str) -> bool:
    header = request.headers.get("if-none-match")
    if not header:
        return False
    if header.strip() == "*":
        return True
    tags = {tag.strip() for tag in header.split(",")}
    return bool(tags & {version, version.removeprefix("W/")})


def _project(request: Request, resource: dict[str, Any]) -> dict[str, Any]:
    """Apply `attributes` / `excludedAttributes` (FR-SCIM-03).

    `id`, `meta` and `schemas` survive both, because a resource without them is
    not addressable and a client that excluded them by accident would get a
    document it cannot do anything with.
    """
    always = {"id", "meta", "schemas"}
    requested = _csv(request.query_params.get("attributes"))
    excluded = _csv(request.query_params.get("excludedAttributes"))

    if requested:
        keep = always | requested
        return {key: value for key, value in resource.items() if key in keep}
    if excluded:
        return {
            key: value for key, value in resource.items() if key in always or key not in excluded
        }
    return resource


def _csv(value: str | None) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()} if value else set()
