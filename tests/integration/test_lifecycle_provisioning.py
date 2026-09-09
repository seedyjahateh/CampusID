"""Provisioning drives the lifecycle (FR-LC-01, FR-LC-02, FR-LC-03).

The unit tests establish that the orchestrator does the right things in the right
order. This establishes that a SCIM write reaches it at all — that creating
somebody with an affiliation really grants the entitlements that affiliation
justifies, and that deleting them really takes the access away.

Both are things a reviewer checks by looking at rows, not by reading code, which
is why they are here rather than mocked.
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
from campusid.scim.models import ScimSourceRecord
from campusid.scim.schemas import CAMPUS_USER, CORE_USER

pytestmark = pytest.mark.integration

BROKER = "http://broker:8000"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

LMS = "urn:mace:campus.edu:entitlement:lms:access"
MAIL = "urn:mace:campus.edu:entitlement:mail:alias"
LIBRARY = "urn:mace:campus.edu:entitlement:library:eresources"
HR = "urn:mace:campus.edu:entitlement:hr:selfservice"
ALUMNI = "urn:mace:campus.edu:entitlement:alumni:portal"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(Person.person_uuid)))

    yield factory

    async with factory() as session, session.begin():
        keep = pre_existing or {uuid.UUID(int=0)}
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


async def _headers(http: httpx.AsyncClient) -> dict[str, str]:
    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "scim:read scim:write",
            "client_id": SIS_CLIENT_ID,
            "client_secret": SIS_SECRET,
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _document(*affiliations: str, **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schemas": [CORE_USER, CAMPUS_USER],
        "userName": f"joiner.{uuid.uuid4().hex[:8]}@campus.test",
        "name": {"givenName": "Sam", "familyName": "O'Brien"},
        "active": True,
        CAMPUS_USER: {
            "affiliations": [
                {"value": affiliation, "primary": index == 0}
                for index, affiliation in enumerate(affiliations)
            ]
        },
    }
    document.update(overrides)
    return document


async def _create(http: httpx.AsyncClient, *affiliations: str) -> dict[str, Any]:
    response = await http.post(
        "/scim/v2/Users", json=_document(*affiliations), headers=await _headers(http)
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def _entitlements(sessions: async_sessionmaker[AsyncSession], person_id: str) -> set[str]:
    async with sessions() as session:
        rows = await session.scalars(
            select(EntitlementGrant).where(
                EntitlementGrant.person_uuid == uuid.UUID(person_id),
                EntitlementGrant.revoked_at.is_(None),
            )
        )
        return {grant.entitlement_urn for grant in rows}


async def _events(sessions: async_sessionmaker[AsyncSession], person_id: str) -> list[str]:
    async with sessions() as session:
        rows = await session.scalars(
            select(LifecycleEvent)
            .where(LifecycleEvent.person_uuid == uuid.UUID(person_id))
            .order_by(LifecycleEvent.occurred_at)
        )
        return [event.event_type for event in rows]


# --- joiner -----------------------------------------------------------------


async def test_a_create_with_an_affiliation_grants_its_entitlements(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-LC-01. The SIS says "student" and the LMS access follows from that,
    rather than from somebody remembering to ask for it."""
    person = await _create(http, "student")

    assert await _entitlements(sessions, person["id"]) == {LMS, MAIL, LIBRARY}
    assert await _events(sessions, person["id"]) == ["joiner"]


async def test_a_create_without_an_affiliation_grants_nothing(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """And writes no event: nothing about this person's relationship to the
    institution changed, because they have none yet."""
    person = await _create(http)

    assert await _entitlements(sessions, person["id"]) == set()
    assert await _events(sessions, person["id"]) == []


# --- mover ------------------------------------------------------------------


async def test_taking_a_job_adds_the_entitlements_it_justifies(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-LC-02, the ordinary half."""
    person = await _create(http, "student")

    document = _document("student", "staff")
    document["userName"] = person["userName"]
    response = await http.put(
        f"/scim/v2/Users/{person['id']}", json=document, headers=await _headers(http)
    )
    assert response.status_code == 200, response.text

    assert HR in await _entitlements(sessions, person["id"])
    assert LMS in await _entitlements(sessions, person["id"])
    assert await _events(sessions, person["id"]) == ["joiner", "mover"]


async def test_graduating_removes_what_is_no_longer_justified(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The half that gets skipped. An entitlement no longer justified is removed,
    not merely superseded — which is the difference between an access review that
    ends and one that runs forever."""
    person = await _create(http, "student")

    document = _document("alum")
    document["userName"] = person["userName"]
    response = await http.put(
        f"/scim/v2/Users/{person['id']}", json=document, headers=await _headers(http)
    )
    assert response.status_code == 200, response.text

    held = await _entitlements(sessions, person["id"])
    assert LIBRARY not in held, "a licensed resource ends with the affiliation"
    assert ALUMNI in held
    assert MAIL in held, "alumni keep the alias, because a rule still justifies it"


# --- leaver -----------------------------------------------------------------


async def test_a_delete_deprovisions(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-LC-03 reached from a SCIM DELETE."""
    person = await _create(http, "staff")
    assert await _entitlements(sessions, person["id"])

    response = await http.delete(f"/scim/v2/Users/{person['id']}", headers=await _headers(http))

    assert response.status_code == 204
    assert await _events(sessions, person["id"]) == ["joiner", "leaver"]
    # HR self-service has a week's grace so somebody leaving can retrieve their
    # own payslips; the immediate ones are gone now.
    assert LIBRARY not in await _entitlements(sessions, person["id"])


async def test_setting_active_false_deprovisions_too(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The other route into FR-LC-03. Which field the SIS happened to change must
    not decide whether somebody's access ends."""
    person = await _create(http, "student")

    response = await http.patch(
        f"/scim/v2/Users/{person['id']}",
        json={
            "schemas": [PATCH_OP],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=await _headers(http),
    )

    assert response.status_code == 200, response.text
    assert await _events(sessions, person["id"]) == ["joiner", "leaver"]
    assert LIBRARY not in await _entitlements(sessions, person["id"])


async def test_a_deleted_person_keeps_their_grant_history(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "This person had library access until June" is a question an auditor asks,
    and a deleted row cannot answer it."""
    person = await _create(http, "student")

    await http.delete(f"/scim/v2/Users/{person['id']}", headers=await _headers(http))

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(EntitlementGrant).where(
                    EntitlementGrant.person_uuid == uuid.UUID(person["id"])
                )
            )
        )
    assert {grant.entitlement_urn for grant in rows} == {LMS, MAIL, LIBRARY}
    assert any(grant.revoked_at is not None for grant in rows)
