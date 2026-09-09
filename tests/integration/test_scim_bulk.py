"""`POST /scim/v2/Bulk` end to end (FR-SCIM-10).

The unit tests establish that the parser and the runner are right. This
establishes that the endpoint is wired to them and that a `bulkId` reference
survives all the way to a row: the person created by operation one really is the
member of the group created by operation two.

That is the whole justification for the endpoint. Without working references it
is a loop the client could have written itself.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from scripts.federation_init import SIS_CLIENT_ID, SIS_SECRET
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.lifecycle.models import EntitlementGrant, LifecycleEvent
from campusid.scim.bulk import BULK_REQUEST, BULK_RESPONSE
from campusid.scim.models import ScimGroup, ScimSourceRecord
from campusid.scim.schemas import CORE_GROUP, CORE_USER, MAX_BULK_PAYLOAD

pytestmark = pytest.mark.integration

BROKER = "http://broker:8000"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)

    async with factory() as session:
        people = set(await session.scalars(select(Person.person_uuid)))
        groups = set(await session.scalars(select(ScimGroup.group_uuid)))

    yield factory

    async with factory() as session, session.begin():
        await session.execute(
            delete(ScimGroup).where(ScimGroup.group_uuid.not_in(groups or {uuid.UUID(int=0)}))
        )
        keep = people or {uuid.UUID(int=0)}
        for table in (
            LifecycleEvent,
            EntitlementGrant,
            ScimSourceRecord,
            Account,
            Identifier,
            Affiliation,
        ):
            await session.execute(delete(table).where(table.person_uuid.not_in(keep)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep)))


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BROKER, timeout=60.0) as client:
        yield client


async def _headers(http: httpx.AsyncClient, scopes: str = "scim:read scim:write") -> dict[str, str]:
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
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _user(bulk_id: str) -> dict[str, Any]:
    return {
        "method": "POST",
        "path": "/Users",
        "bulkId": bulk_id,
        "data": {
            "schemas": [CORE_USER],
            "userName": f"joiner.{uuid.uuid4().hex[:8]}@campus.test",
            "name": {"givenName": "Marcus", "familyName": "Reed"},
            "active": True,
        },
    }


async def _bulk(http: httpx.AsyncClient, *operations: Any, **extra: Any) -> httpx.Response:
    return await http.post(
        "/scim/v2/Bulk",
        json={"schemas": [BULK_REQUEST], "Operations": list(operations), **extra},
        headers=await _headers(http),
    )


async def test_a_night_of_joiners_arrives_in_one_request(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    response = await _bulk(http, *[_user(f"p{index}") for index in range(5)])

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schemas"] == [BULK_RESPONSE]
    assert [entry["status"] for entry in body["Operations"]] == ["201"] * 5


async def test_a_bulk_id_reference_reaches_the_membership(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The person created by the first operation really is a member of the group
    created by the second, which the client could not have expressed any other
    way — it did not know the id."""
    name = f"lms-{uuid.uuid4().hex[:8]}"

    response = await _bulk(
        http,
        _user("joiner"),
        {
            "method": "POST",
            "path": "/Groups",
            "bulkId": "cohort",
            "data": {
                "schemas": [CORE_GROUP],
                "displayName": name,
                "members": [{"value": "bulkId:joiner"}],
            },
        },
    )

    assert response.status_code == 200, response.text
    entries = {entry["bulkId"]: entry for entry in response.json()["Operations"]}
    person_id = entries["joiner"]["location"].rsplit("/", 1)[-1]
    group_id = entries["cohort"]["location"].rsplit("/", 1)[-1]

    members = await http.get(
        f"/scim/v2/Groups/{group_id}?attributes=displayName,members", headers=await _headers(http)
    )
    assert [member["value"] for member in members.json()["members"]] == [person_id]


async def test_a_group_sent_before_its_members_still_works(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Execution order is not request order. A client writing the group first is
    not making a mistake: it cannot know the person's id either way."""
    name = f"lms-{uuid.uuid4().hex[:8]}"

    response = await _bulk(
        http,
        {
            "method": "POST",
            "path": "/Groups",
            "bulkId": "cohort",
            "data": {
                "schemas": [CORE_GROUP],
                "displayName": name,
                "members": [{"value": "bulkId:joiner"}],
            },
        },
        _user("joiner"),
    )

    assert response.status_code == 200, response.text
    assert [entry["bulkId"] for entry in response.json()["Operations"]] == ["joiner", "cohort"]


async def test_one_bad_operation_does_not_undo_the_others(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A bulk request is not a transaction, and the response says exactly which
    operation failed."""
    response = await _bulk(
        http,
        _user("good"),
        {"method": "DELETE", "path": f"/Users/{uuid.uuid4()}"},
    )

    assert response.status_code == 200
    assert [entry["status"] for entry in response.json()["Operations"]] == ["201", "404"]


async def test_fail_on_errors_stops_the_run(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    response = await _bulk(
        http,
        {"method": "DELETE", "path": f"/Users/{uuid.uuid4()}"},
        _user("never"),
        failOnErrors=1,
    )

    assert response.status_code == 200
    assert len(response.json()["Operations"]) == 1


async def test_a_circular_reference_is_refused_outright(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Nothing runs. The request describes something that cannot happen, so a
    partial result would leave the client to work out which half it got."""
    response = await _bulk(
        http,
        {
            "method": "POST",
            "path": "/Groups",
            "bulkId": "a",
            "data": {
                "displayName": f"a-{uuid.uuid4().hex[:6]}",
                "members": [{"value": "bulkId:b"}],
            },
        },
        {
            "method": "POST",
            "path": "/Groups",
            "bulkId": "b",
            "data": {
                "displayName": f"b-{uuid.uuid4().hex[:6]}",
                "members": [{"value": "bulkId:a"}],
            },
        },
    )

    assert response.status_code == 409


async def test_an_oversized_request_is_refused_before_it_is_parsed(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The limit ServiceProviderConfig advertises, enforced. A client sizes its
    batches by what discovery said, so a promise the server does not keep is
    worse than a smaller promise."""
    response = await http.post(
        "/scim/v2/Bulk",
        content=b'{"padding": "' + b"x" * (MAX_BULK_PAYLOAD + 1) + b'"}',
        headers={**await _headers(http), "Content-Type": "application/scim+json"},
    )

    assert response.status_code == 413


async def test_bulk_needs_the_write_scope(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Regardless of what the operations turn out to be: a scope that depended
    on the contents would need parsing before it could be authorised."""
    response = await http.post(
        "/scim/v2/Bulk",
        json={"schemas": [BULK_REQUEST], "Operations": [_user("p")]},
        headers=await _headers(http, "scim:read"),
    )

    assert response.status_code == 403
