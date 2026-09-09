"""SCIM `/Groups` end to end (FR-SCIM-11).

The requirement has a number in it — a single-member PATCH on a ten-thousand
member group under 500 ms — so the file ends with a test that builds such a
group and measures. Everything before it establishes that the endpoint is
correct; that one establishes that it is correct for the size a university
actually has.

The cases worth reading are the ones where a naive implementation is correct and
slow: a member removal expressed as a value filter, and a `PUT` that omits
`members` entirely.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from scripts.federation_init import SIS_CLIENT_ID, SIS_SECRET
from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.lifecycle.models import EntitlementGrant, LifecycleEvent
from campusid.scim.models import ScimGroup, ScimGroupMember, ScimSourceRecord
from campusid.scim.schemas import CORE_GROUP, CORE_USER

pytestmark = pytest.mark.integration

BROKER = "http://broker:8000"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

LARGE_GROUP = 10_000
"""FR-SCIM-11's number. Built once, by bulk insert, because the point of the
test is the PATCH and not the fixture."""

PATCH_BUDGET_SECONDS = 0.5


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Clean up whatever the test made, and nothing that was here before it."""
    factory = create_session_factory(engine)

    async with factory() as session:
        people = set(await session.scalars(select(Person.person_uuid)))
        groups = set(await session.scalars(select(ScimGroup.group_uuid)))

    yield factory

    async with factory() as session, session.begin():
        keep_groups = groups or {uuid.UUID(int=0)}
        await session.execute(delete(ScimGroup).where(ScimGroup.group_uuid.not_in(keep_groups)))

        keep_people = people or {uuid.UUID(int=0)}
        for table in (
            LifecycleEvent,
            EntitlementGrant,
            ScimSourceRecord,
            Account,
            Identifier,
            Affiliation,
        ):
            await session.execute(delete(table).where(table.person_uuid.not_in(keep_people)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep_people)))


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BROKER, timeout=60.0) as client:
        yield client


async def _headers(
    http: httpx.AsyncClient, scopes: str = "scim:read scim:write", **extra: str
) -> dict[str, str]:
    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": scopes,
            "client_id": SIS_CLIENT_ID,
            "client_secret": SIS_SECRET,
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}", **extra}


async def _person(http: httpx.AsyncClient) -> dict[str, Any]:
    response = await http.post(
        "/scim/v2/Users",
        json={
            "schemas": [CORE_USER],
            "userName": f"member.{uuid.uuid4().hex[:8]}@campus.test",
            "name": {"givenName": "Dana", "familyName": "Wu"},
            "active": True,
        },
        headers=await _headers(http),
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def _group(http: httpx.AsyncClient, **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schemas": [CORE_GROUP],
        "displayName": f"lms-students-{uuid.uuid4().hex[:8]}",
    }
    document.update(overrides)
    response = await http.post("/scim/v2/Groups", json=document, headers=await _headers(http))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def _patch(
    http: httpx.AsyncClient, group_id: str, *operations: dict[str, Any], **extra: str
) -> httpx.Response:
    return await http.patch(
        f"/scim/v2/Groups/{group_id}",
        json={"schemas": [PATCH_OP], "Operations": list(operations)},
        headers=await _headers(http, **extra),
    )


async def _members(http: httpx.AsyncClient, group_id: str) -> list[str]:
    response = await http.get(
        f"/scim/v2/Groups/{group_id}?attributes=displayName,members",
        headers=await _headers(http, "scim:read"),
    )
    assert response.status_code == 200, response.text
    return [member["value"] for member in response.json().get("members", [])]


# --- the basics -------------------------------------------------------------


async def test_a_group_is_created_with_its_members(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(http)

    group = await _group(http, members=[{"value": person["id"]}])

    assert group["schemas"] == [CORE_GROUP]
    assert [member["value"] for member in group["members"]] == [person["id"]]


async def test_a_duplicate_display_name_is_a_409(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Two groups called `lms-students` are indistinguishable to whoever is
    deciding who gets access."""
    first = await _group(http)

    response = await http.post(
        "/scim/v2/Groups",
        json={"schemas": [CORE_GROUP], "displayName": first["displayName"]},
        headers=await _headers(http),
    )

    assert response.status_code == 409
    assert response.json()["scimType"] == "uniqueness"


async def test_a_replayed_create_returns_the_same_group(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-SCIM-14 for groups. Two groups with the same members are two answers
    to "who has access", which is worse than no group at all."""
    external_id = f"sis-{uuid.uuid4().hex[:8]}"
    first = await _group(http, externalId=external_id)

    replay = await http.post(
        "/scim/v2/Groups",
        json={
            "schemas": [CORE_GROUP],
            "displayName": f"different-name-{uuid.uuid4().hex[:8]}",
            "externalId": external_id,
        },
        headers=await _headers(http),
    )

    assert replay.status_code == 200
    assert replay.json()["id"] == first["id"]


async def test_a_member_who_does_not_exist_is_a_400(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The foreign key would refuse this too, as a 500. A member who is not here
    is the client's mistake and deserves an error that names them."""
    absent = str(uuid.uuid4())

    response = await http.post(
        "/scim/v2/Groups",
        json={
            "schemas": [CORE_GROUP],
            "displayName": f"ghosts-{uuid.uuid4().hex[:8]}",
            "members": [{"value": absent}],
        },
        headers=await _headers(http),
    )

    assert response.status_code == 400
    assert absent in response.json()["detail"]


async def test_a_group_is_deleted_outright(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Unlike a person. A group is an access-control grouping rather than
    somebody's identity, and a tombstone would only make its name unusable for
    whatever replaces it."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    deleted = await http.delete(
        f"/scim/v2/Groups/{group['id']}", headers=await _headers(http, "scim:write")
    )

    assert deleted.status_code == 204
    gone = await http.get(f"/scim/v2/Groups/{group['id']}", headers=await _headers(http))
    assert gone.status_code == 404

    async with sessions() as session:
        remaining = await session.scalars(
            select(ScimGroupMember.person_uuid).where(
                ScimGroupMember.group_uuid == uuid.UUID(group["id"])
            )
        )
    assert list(remaining) == [], "membership should have gone with the group"

    still_here = await http.get(f"/scim/v2/Users/{person['id']}", headers=await _headers(http))
    assert still_here.status_code == 200, "deleting a group must not touch its members"


# --- members are returned only on request -----------------------------------


async def test_members_are_not_returned_unless_asked_for(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`returned: "request"`. A group here may have tens of thousands of members
    and serving them by default would make listing groups cost the whole
    membership table."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    plain = await http.get(f"/scim/v2/Groups/{group['id']}", headers=await _headers(http))

    assert plain.status_code == 200
    assert "members" not in plain.json()
    assert plain.json()["displayName"] == group["displayName"]


async def test_members_are_returned_when_asked_for(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    assert await _members(http, group["id"]) == [person["id"]]


async def test_a_person_sees_the_groups_they_are_in(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The other direction, and the one a client uses to enumerate a large
    group's membership. Read-only on the User: membership is changed through
    /Groups so there is one audited path to a grant, not two."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    response = await http.get(f"/scim/v2/Users/{person['id']}", headers=await _headers(http))

    assert response.status_code == 200
    assert [entry["value"] for entry in response.json()["groups"]] == [group["id"]]


# --- PATCH ------------------------------------------------------------------


async def test_patch_adds_a_member(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    group = await _group(http)
    person = await _person(http)

    response = await _patch(
        http, group["id"], {"op": "add", "path": "members", "value": [{"value": person["id"]}]}
    )

    assert response.status_code == 200, response.text
    assert await _members(http, group["id"]) == [person["id"]]


async def test_adding_an_existing_member_twice_changes_nothing(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The composite primary key resolves it, so a client retrying a lost
    response does not produce a member listed twice."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    again = await _patch(
        http, group["id"], {"op": "add", "path": "members", "value": [{"value": person["id"]}]}
    )

    assert again.status_code == 200, again.text
    assert await _members(http, group["id"]) == [person["id"]]


async def test_patch_removes_one_member_by_value_filter(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The shape every client sends, and the one that has to stay cheap."""
    keep, drop = await _person(http), await _person(http)
    group = await _group(http, members=[{"value": keep["id"]}, {"value": drop["id"]}])

    response = await _patch(
        http, group["id"], {"op": "remove", "path": f'members[value eq "{drop["id"]}"]'}
    )

    assert response.status_code == 200, response.text
    assert await _members(http, group["id"]) == [keep["id"]]


async def test_patch_without_a_filter_empties_the_group(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`remove` on the whole collection means the whole collection. It is the
    filtered form that must not do this."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    response = await _patch(http, group["id"], {"op": "remove", "path": "members"})

    assert response.status_code == 200, response.text
    assert await _members(http, group["id"]) == []


async def test_patch_renames_a_group(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    group = await _group(http)
    renamed = f"renamed-{uuid.uuid4().hex[:8]}"

    response = await _patch(
        http, group["id"], {"op": "replace", "path": "displayName", "value": renamed}
    )

    assert response.status_code == 200, response.text
    assert response.json()["displayName"] == renamed


async def test_a_patch_is_atomic_across_its_operations(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A rename and a membership change in one request either both happen or
    neither does. Here the second operation names somebody who does not exist."""
    group = await _group(http)
    original = group["displayName"]

    response = await _patch(
        http,
        group["id"],
        {"op": "replace", "path": "displayName", "value": f"never-{uuid.uuid4().hex[:8]}"},
        {"op": "add", "path": "members", "value": [{"value": str(uuid.uuid4())}]},
    )

    assert response.status_code == 400
    current = await http.get(f"/scim/v2/Groups/{group['id']}", headers=await _headers(http))
    assert current.json()["displayName"] == original


async def test_patching_an_unknown_attribute_is_refused(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    group = await _group(http)

    response = await _patch(
        http, group["id"], {"op": "replace", "path": "description", "value": "anything"}
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidPath"


# --- concurrency (FR-SCIM-09) -----------------------------------------------


async def test_a_stale_if_match_is_a_412(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    group = await _group(http)
    stale = group["meta"]["version"]
    await _patch(http, group["id"], {"op": "replace", "path": "displayName", "value": "moved-on"})

    response = await _patch(
        http,
        group["id"],
        {"op": "replace", "path": "displayName", "value": "too-late"},
        **{"If-Match": stale},
    )

    assert response.status_code == 412


async def test_the_version_changes_when_membership_does(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The counter has to move for a membership change, not only for a rename —
    otherwise a client's If-Match would accept a group whose members are not the
    ones it read."""
    person = await _person(http)
    group = await _group(http)
    before = group["meta"]["version"]

    after = await _patch(
        http, group["id"], {"op": "add", "path": "members", "value": [{"value": person["id"]}]}
    )

    assert after.json()["meta"]["version"] != before


# --- PUT --------------------------------------------------------------------


async def test_put_without_members_leaves_them_alone(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`members` is returned on request, so an ordinary read-modify-write never
    had them to send back. Treating the omission as "remove everybody" would
    empty a group on a rename."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])
    renamed = f"renamed-{uuid.uuid4().hex[:8]}"

    response = await http.put(
        f"/scim/v2/Groups/{group['id']}",
        json={"schemas": [CORE_GROUP], "displayName": renamed},
        headers=await _headers(http),
    )

    assert response.status_code == 200, response.text
    assert response.json()["displayName"] == renamed
    assert await _members(http, group["id"]) == [person["id"]]


async def test_put_with_an_empty_members_array_clears_them(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The client saying so, rather than the client not mentioning it."""
    person = await _person(http)
    group = await _group(http, members=[{"value": person["id"]}])

    response = await http.put(
        f"/scim/v2/Groups/{group['id']}",
        json={"schemas": [CORE_GROUP], "displayName": group["displayName"], "members": []},
        headers=await _headers(http),
    )

    assert response.status_code == 200, response.text
    assert await _members(http, group["id"]) == []


# --- listing and filtering --------------------------------------------------


async def test_groups_are_listed_and_filtered(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    group = await _group(http)

    response = await http.get(
        f'/scim/v2/Groups?filter=displayName eq "{group["displayName"]}"',
        headers=await _headers(http, "scim:read"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["id"] == group["id"]


async def test_a_listing_carries_no_membership(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(http)
    await _group(http, members=[{"value": person["id"]}])

    response = await http.get("/scim/v2/Groups", headers=await _headers(http, "scim:read"))

    assert response.status_code == 200
    assert all("members" not in resource for resource in response.json()["Resources"])


# --- authorisation (FR-SCIM-13) ---------------------------------------------


async def test_a_read_scope_token_cannot_create_a_group(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    response = await http.post(
        "/scim/v2/Groups",
        json={"schemas": [CORE_GROUP], "displayName": f"nope-{uuid.uuid4().hex[:8]}"},
        headers=await _headers(http, "scim:read"),
    )

    assert response.status_code == 403
    assert "scim:write" in response.json()["detail"]


# --- the number in the requirement ------------------------------------------


@pytest.mark.slow
async def test_one_member_patch_on_a_ten_thousand_member_group_is_fast(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-SCIM-11's performance requirement, measured rather than asserted.

    The group is built by bulk insert because the fixture is not what is under
    test; the two PATCHes that follow go through the endpoint like any other
    request. If membership were a list on the group, both would be a read and a
    write of ten thousand entries and neither would come close to the budget.
    """
    newcomer = await _person(http)
    group = await _group(http)
    group_uuid = uuid.UUID(group["id"])

    async with sessions() as session, session.begin():
        people = [
            {
                "person_uuid": uuid.uuid4(),
                "edu_person_unique_id": f"{uuid.uuid4().hex}@campus.test",
                "status": "active",
                "provisioning_source": "sis",
            }
            for _ in range(LARGE_GROUP)
        ]
        await session.execute(insert(Person), people)
        await session.execute(
            insert(ScimGroupMember),
            [{"group_uuid": group_uuid, "person_uuid": person["person_uuid"]} for person in people],
        )

    started = time.perf_counter()
    added = await _patch(
        http, group["id"], {"op": "add", "path": "members", "value": [{"value": newcomer["id"]}]}
    )
    add_seconds = time.perf_counter() - started
    assert added.status_code == 200, added.text

    started = time.perf_counter()
    removed = await _patch(
        http, group["id"], {"op": "remove", "path": f'members[value eq "{newcomer["id"]}"]'}
    )
    remove_seconds = time.perf_counter() - started
    assert removed.status_code == 200, removed.text

    assert add_seconds < PATCH_BUDGET_SECONDS, f"add took {add_seconds:.3f}s"
    assert remove_seconds < PATCH_BUDGET_SECONDS, f"remove took {remove_seconds:.3f}s"


@pytest.mark.slow
async def test_a_very_large_group_is_answered_without_its_membership(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Rather than with the first thousand of them, which the client would have
    no way to tell from the whole membership."""
    group = await _group(http)
    group_uuid = uuid.UUID(group["id"])

    async with sessions() as session, session.begin():
        people = [
            {
                "person_uuid": uuid.uuid4(),
                "edu_person_unique_id": f"{uuid.uuid4().hex}@campus.test",
                "status": "active",
                "provisioning_source": "sis",
            }
            for _ in range(1_500)
        ]
        await session.execute(insert(Person), people)
        await session.execute(
            insert(ScimGroupMember),
            [{"group_uuid": group_uuid, "person_uuid": person["person_uuid"]} for person in people],
        )

    response = await http.get(
        f"/scim/v2/Groups/{group['id']}?attributes=displayName,members",
        headers=await _headers(http, "scim:read"),
    )

    assert response.status_code == 200
    assert "members" not in response.json()
