"""The SCIM HTTP surface (FR-SCIM-03, 09, 12, 13).

The stores are substituted here, deliberately. What these tests are about is the
layer between HTTP and the store — the status a create returns, the ETag a
client's `If-Match` will quote back, the envelope every failure arrives in, and
the scope each verb requires. All of that is decided before any row is touched,
and testing it against Postgres would prove the same thing more slowly and less
exhaustively.

The tokens are real. They come from the broker's own token endpoint through the
client-credentials grant, because FR-SCIM-13's claim is precisely that the SCIM
API is authenticated by a token this broker issued — a forged one would test the
verifier against itself.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.oidc.clients import ClientType, OidcClient, hash_secret
from campusid.oidc.errors import INVALID_CLIENT, OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.keys import KeySet
from campusid.scim.errors import ScimError, ScimType, duplicate, not_found, version_mismatch
from campusid.scim.schemas import CORE_GROUP, CORE_USER
from campusid.scim.store import Page

BASE = "https://broker.test"
CLIENT_ID = "campus-sis"
SECRET = "s" * 43
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

USER = {
    "schemas": [CORE_USER],
    "id": "8f14e45f-ceea-467a-9b2e-2b5ea3e2a9c1",
    "userName": "sam.obrien@campus.test",
    "active": True,
    "emails": [{"value": "sam.obrien@campus.test", "primary": True}],
    "meta": {
        "resourceType": "User",
        "location": f"{BASE}/scim/v2/Users/8f14e45f-ceea-467a-9b2e-2b5ea3e2a9c1",
        "version": 'W/"deadbeef"',
    },
}

GROUP = {
    "schemas": [CORE_GROUP],
    "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    "displayName": "lms-students",
    "meta": {
        "resourceType": "Group",
        "location": f"{BASE}/scim/v2/Groups/1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "version": 'W/"3"',
    },
}


class _Clients:
    """Just the provisioning client, which is all the SCIM surface needs."""

    def __init__(self, client: OidcClient) -> None:
        self._client = client

    async def get(self, client_id: str) -> OidcClient | None:
        return self._client if client_id == self._client.client_id else None

    async def require(self, client_id: str | None) -> OidcClient:
        from campusid.errors import ReasonCode

        if client_id != self._client.client_id:
            raise OAuthError(INVALID_CLIENT, ReasonCode.UNKNOWN_CLIENT, "no such client")
        return self._client


class _Recorder:
    """A store that remembers how it was called and answers with a fixture.

    Faithful about shape rather than behaviour: every method takes what the real
    one takes, so a route passing `if_match` to the wrong parameter fails here.
    """

    def __init__(self, resource: dict[str, Any]) -> None:
        self.resource = resource
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.raises: ScimError | None = None

    def _record(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((name, args, kwargs))
        if self.raises is not None:
            raise self.raises


class _Users(_Recorder):
    async def create(self, parsed: Any, raw: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        self._record("create", parsed, raw)
        return self.resource, True

    async def get(self, resource_id: str) -> dict[str, Any]:
        self._record("get", resource_id)
        return self.resource

    async def search(self, **kwargs: Any) -> Page:
        self._record("search", **kwargs)
        return Page([self.resource], 1, kwargs.get("start_index", 1))

    async def replace(self, resource_id: str, parsed: Any, raw: Any, **kwargs: Any) -> Any:
        self._record("replace", resource_id, **kwargs)
        return self.resource

    async def apply_patched(self, resource_id: str, parsed: Any, raw: Any, **kwargs: Any) -> Any:
        self._record("apply_patched", resource_id, **kwargs)
        return self.resource

    async def soft_delete(self, resource_id: str, **kwargs: Any) -> None:
        self._record("soft_delete", resource_id, **kwargs)


class _Groups(_Recorder):
    async def create(self, document: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        self._record("create", document)
        return self.resource, True

    async def get(self, group_id: str, **kwargs: Any) -> dict[str, Any]:
        self._record("get", group_id, **kwargs)
        return self.resource

    async def search(self, **kwargs: Any) -> Page:
        self._record("search", **kwargs)
        return Page([self.resource], 1, kwargs.get("start_index", 1))

    async def replace(self, group_id: str, document: Any, **kwargs: Any) -> Any:
        self._record("replace", group_id, **kwargs)
        return self.resource

    async def patch(self, group_id: str, operations: Any, **kwargs: Any) -> Any:
        self._record("patch", group_id, operations=operations, **kwargs)
        return self.resource

    async def delete(self, group_id: str, **kwargs: Any) -> None:
        self._record("delete", group_id, **kwargs)


@pytest.fixture
def users() -> _Users:
    return _Users(dict(USER))


@pytest.fixture
def groups() -> _Groups:
    return _Groups(dict(GROUP))


@pytest.fixture
def wired(app: FastAPI, oidc_key_set: KeySet, users: _Users, groups: _Groups) -> FastAPI:
    redis = aioredis.FakeRedis(decode_responses=True)
    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.oidc_keys = oidc_key_set
    app.state.scim_users = users
    app.state.scim_groups = groups
    app.state.clients = _Clients(
        OidcClient(
            client_id=CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=("https://sis.campus.test/unused",),
            allowed_scopes=frozenset({"openid", "scim:read", "scim:write"}),
            secret_hash=hash_secret(SECRET),
        )
    )
    return app


@pytest.fixture
async def http(wired: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE) as client:
        yield client


async def _headers(http: AsyncClient, scope: str = "scim:read scim:write") -> dict[str, str]:
    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": scope,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --- authentication and authorisation (FR-SCIM-13) --------------------------


async def test_a_missing_token_is_a_401_with_a_challenge(http: AsyncClient) -> None:
    response = await http.get("/scim/v2/Users")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="scim"'
    assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


async def test_the_401_carries_no_scim_type(http: AsyncClient) -> None:
    """The one SCIM response whose caller may not be a legitimate client. It
    behaves like the SAML gate rather than like a helpful API."""
    response = await http.get("/scim/v2/Users", headers={"Authorization": "Bearer nonsense"})

    assert response.status_code == 401
    assert "scimType" not in response.json()


async def test_a_read_token_cannot_write(http: AsyncClient) -> None:
    response = await http.post(
        "/scim/v2/Users",
        json={"userName": "x@campus.test"},
        headers=await _headers(http, "scim:read"),
    )

    assert response.status_code == 403
    assert "scim:write" in response.json()["detail"]


async def test_a_write_token_cannot_read(http: AsyncClient) -> None:
    """`scim:write` does not imply `scim:read`. A client that only pushes changes
    has no business enumerating the directory."""
    response = await http.get("/scim/v2/Users", headers=await _headers(http, "scim:write"))

    assert response.status_code == 403
    assert "scim:read" in response.json()["detail"]


# --- /Users -----------------------------------------------------------------


async def test_a_create_returns_201_and_the_location(http: AsyncClient) -> None:
    response = await http.post(
        "/scim/v2/Users",
        json={"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
        headers=await _headers(http),
    )

    assert response.status_code == 201
    assert response.headers["location"] == USER["meta"]["location"]  # type: ignore[index]
    assert response.headers["etag"] == 'W/"deadbeef"'
    assert response.headers["cache-control"] == "no-store"


async def test_a_resource_is_never_cached(http: AsyncClient) -> None:
    """One person's record. An intermediary holding it is a disclosure nobody
    intended, which is why this differs from the discovery documents."""
    response = await http.get(f"/scim/v2/Users/{USER['id']}", headers=await _headers(http))

    assert response.headers["cache-control"] == "no-store"


async def test_a_body_that_is_not_json_is_a_400(http: AsyncClient) -> None:
    response = await http.post(
        "/scim/v2/Users",
        content=b"not json",
        headers={**await _headers(http), "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == ScimType.INVALID_SYNTAX


async def test_a_body_that_is_not_an_object_is_a_400(http: AsyncClient) -> None:
    response = await http.post("/scim/v2/Users", json=[1, 2, 3], headers=await _headers(http))

    assert response.status_code == 400
    assert response.json()["scimType"] == ScimType.INVALID_SYNTAX


async def test_a_known_version_gets_a_304(http: AsyncClient) -> None:
    """FR-SCIM-09. The client already holds this version, so it is spared
    parsing a document it has."""
    response = await http.get(
        f"/scim/v2/Users/{USER['id']}",
        headers={**await _headers(http), "If-None-Match": 'W/"deadbeef"'},
    )

    assert response.status_code == 304
    assert response.content == b""


async def test_a_star_if_none_match_gets_a_304(http: AsyncClient) -> None:
    response = await http.get(
        f"/scim/v2/Users/{USER['id']}", headers={**await _headers(http), "If-None-Match": "*"}
    )

    assert response.status_code == 304


async def test_if_match_reaches_the_store(http: AsyncClient, users: _Users) -> None:
    await http.put(
        f"/scim/v2/Users/{USER['id']}",
        json={"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
        headers={**await _headers(http), "If-Match": 'W/"deadbeef"'},
    )

    name, _, kwargs = users.calls[-1]
    assert name == "replace"
    assert kwargs["if_match"] == 'W/"deadbeef"'


async def test_a_stale_if_match_becomes_a_412(http: AsyncClient, users: _Users) -> None:
    users.raises = version_mismatch('W/"newer"')

    response = await http.put(
        f"/scim/v2/Users/{USER['id']}",
        json={"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
        headers={**await _headers(http), "If-Match": 'W/"stale"'},
    )

    assert response.status_code == 412


async def test_a_duplicate_username_becomes_a_409(http: AsyncClient, users: _Users) -> None:
    users.raises = duplicate("userName", "sam.obrien@campus.test")

    response = await http.post(
        "/scim/v2/Users",
        json={"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
        headers=await _headers(http),
    )

    assert response.status_code == 409
    assert response.json()["scimType"] == ScimType.UNIQUENESS


async def test_an_unknown_person_is_a_404(http: AsyncClient, users: _Users) -> None:
    users.raises = not_found("User", "missing")

    response = await http.get("/scim/v2/Users/missing", headers=await _headers(http))

    assert response.status_code == 404
    assert response.json()["status"] == "404"


async def test_a_patch_is_parsed_before_the_store_is_touched(
    http: AsyncClient, users: _Users
) -> None:
    """A malformed PATCH must not have reached the store at all — that is what
    makes the atomicity claim mean something."""
    response = await http.patch(
        f"/scim/v2/Users/{USER['id']}",
        json={"schemas": [PATCH_OP], "Operations": [{"op": "invent", "path": "displayName"}]},
        headers=await _headers(http),
    )

    assert response.status_code == 400
    assert [call[0] for call in users.calls] == ["get"]


async def test_a_delete_is_204_with_no_body(http: AsyncClient, users: _Users) -> None:
    response = await http.delete(f"/scim/v2/Users/{USER['id']}", headers=await _headers(http))

    assert response.status_code == 204
    assert response.content == b""
    assert users.calls[-1][0] == "soft_delete"


async def test_a_listing_is_a_list_response(http: AsyncClient) -> None:
    response = await http.get("/scim/v2/Users?count=5&startIndex=1", headers=await _headers(http))

    body = response.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert body["totalResults"] == 1
    assert body["itemsPerPage"] == 1


async def test_a_malformed_filter_is_an_invalid_filter(http: AsyncClient) -> None:
    response = await http.get(
        "/scim/v2/Users?filter=userName eq", headers=await _headers(http, "scim:read")
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == ScimType.INVALID_FILTER


async def test_sort_order_reaches_the_store(http: AsyncClient, users: _Users) -> None:
    await http.get(
        "/scim/v2/Users?sortBy=userName&sortOrder=descending", headers=await _headers(http)
    )

    _, _, kwargs = users.calls[-1]
    assert kwargs["sort_by"] == "userName"
    assert kwargs["descending"] is True


# --- attribute projection (FR-SCIM-03) --------------------------------------


async def test_requested_attributes_narrow_the_document(http: AsyncClient) -> None:
    response = await http.get(
        f"/scim/v2/Users/{USER['id']}?attributes=userName", headers=await _headers(http)
    )

    body = response.json()
    assert set(body) == {"id", "meta", "schemas", "userName"}


async def test_excluded_attributes_are_dropped(http: AsyncClient) -> None:
    response = await http.get(
        f"/scim/v2/Users/{USER['id']}?excludedAttributes=emails", headers=await _headers(http)
    )

    assert "emails" not in response.json()
    assert "userName" in response.json()


async def test_the_addressable_attributes_survive_exclusion(http: AsyncClient) -> None:
    """A resource without `id`, `meta` or `schemas` is not addressable, and a
    client that excluded them by accident would get a document it cannot use."""
    response = await http.get(
        f"/scim/v2/Users/{USER['id']}?excludedAttributes=id,meta,schemas",
        headers=await _headers(http),
    )

    assert set(response.json()) >= {"id", "meta", "schemas"}


# --- /Groups ----------------------------------------------------------------


async def test_a_group_create_returns_201(http: AsyncClient, groups: _Groups) -> None:
    response = await http.post(
        "/scim/v2/Groups",
        json={"schemas": [CORE_GROUP], "displayName": "lms-students"},
        headers=await _headers(http),
    )

    assert response.status_code == 201
    assert response.headers["etag"] == 'W/"3"'
    assert groups.calls[-1][0] == "create"


async def test_members_are_asked_for_only_when_named(http: AsyncClient, groups: _Groups) -> None:
    await http.get(f"/scim/v2/Groups/{GROUP['id']}", headers=await _headers(http))
    plain = groups.calls[-1][2]["with_members"]

    await http.get(
        f"/scim/v2/Groups/{GROUP['id']}?attributes=displayName,members",
        headers=await _headers(http),
    )
    asked = groups.calls[-1][2]["with_members"]

    assert (plain, asked) == (False, True)


async def test_excluding_members_beats_requesting_them(http: AsyncClient, groups: _Groups) -> None:
    """A client that names `members` in both lists is contradicting itself, and
    the safe reading of a contradiction is the one that returns less."""
    await http.get(
        f"/scim/v2/Groups/{GROUP['id']}?attributes=members&excludedAttributes=members",
        headers=await _headers(http),
    )

    assert groups.calls[-1][2]["with_members"] is False


async def test_group_patch_operations_reach_the_store_parsed(
    http: AsyncClient, groups: _Groups
) -> None:
    """Parsed, not raw. The route validates the PatchOp envelope so the store
    never sees an operation it would have to re-check."""
    response = await http.patch(
        f"/scim/v2/Groups/{GROUP['id']}",
        json={
            "schemas": [PATCH_OP],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": "x"}]}],
        },
        headers=await _headers(http),
    )

    assert response.status_code == 200
    name, _, kwargs = groups.calls[-1]
    assert name == "patch"
    assert kwargs["operations"][0].op == "add"


async def test_a_group_patch_without_the_schema_is_refused(http: AsyncClient) -> None:
    response = await http.patch(
        f"/scim/v2/Groups/{GROUP['id']}",
        json={"Operations": [{"op": "add", "path": "members", "value": []}]},
        headers=await _headers(http),
    )

    assert response.status_code == 400


async def test_a_group_delete_is_204(http: AsyncClient, groups: _Groups) -> None:
    response = await http.delete(f"/scim/v2/Groups/{GROUP['id']}", headers=await _headers(http))

    assert response.status_code == 204
    assert groups.calls[-1][0] == "delete"


async def test_a_group_listing_is_a_list_response(http: AsyncClient) -> None:
    response = await http.get("/scim/v2/Groups", headers=await _headers(http, "scim:read"))

    assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]


async def test_a_malformed_group_filter_is_an_invalid_filter(http: AsyncClient) -> None:
    response = await http.get(
        '/scim/v2/Groups?filter=displayName eq "x" and', headers=await _headers(http)
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == ScimType.INVALID_FILTER


async def test_a_group_too_large_to_scan_surfaces_as_too_many(
    http: AsyncClient, groups: _Groups
) -> None:
    groups.raises = ScimError(400, "narrow the filter", ScimType.TOO_MANY)

    response = await http.get("/scim/v2/Groups", headers=await _headers(http))

    assert response.status_code == 400
    assert response.json()["scimType"] == ScimType.TOO_MANY
