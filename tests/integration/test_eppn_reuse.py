"""ePPN reuse protection (FR-LC-08).

The incident this design exists to prevent is specific and has happened at real
institutions: a student graduates, their `jsmith@campus.edu` is freed, a new
J. Smith arrives and is given it, and the learning management system — which
keys on ePPN because that is what SAML hands it — shows the new student the
previous one's coursework and grades.

The fix is that an identifier is an *attribute of* a person rather than the
person's key, and that released values are tombstoned rather than deleted. The
enforcement is a unique constraint covering released rows, so reissue is a write
the database refuses rather than a rule the application remembers.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.identity.registry import (
    Assertion,
    IdentityRegistry,
    new_unique_id,
)

pytestmark = pytest.mark.integration

SCOPE = "campus.test"
CAMPUS_IDP = "https://idp.campus.test/saml"


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
        for table in (Account, Identifier, Affiliation):
            await session.execute(delete(table).where(table.person_uuid.not_in(keep)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep)))


@pytest.fixture
def registry(sessions: async_sessionmaker[AsyncSession]) -> IdentityRegistry:
    return IdentityRegistry(sessions, scope=SCOPE)


async def _person(sessions: async_sessionmaker[AsyncSession]) -> str:
    async with sessions() as session, session.begin():
        person = Person(edu_person_unique_id=new_unique_id(SCOPE))
        session.add(person)
        await session.flush()
        return str(person.person_uuid)


# --- allocation -------------------------------------------------------------


async def test_the_first_holder_gets_the_plain_name(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person_uuid = await _person(sessions)

    assert await registry.allocate_eppn(person_uuid, "jsmith") == f"jsmith@{SCOPE}"


async def test_a_second_holder_is_suffixed(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Two people genuinely named J. Smith. Nobody's identifier is taken away to
    make room."""
    first = await _person(sessions)
    second = await _person(sessions)
    await registry.allocate_eppn(first, "jsmith")

    assert await registry.allocate_eppn(second, "jsmith") == f"jsmith2@{SCOPE}"


async def test_a_released_name_is_never_reissued(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The requirement, as one assertion. The graduate's ePPN stays taken
    forever, so the new arrival gets a different one and no LMS keyed on ePPN
    hands them somebody else's coursework."""
    graduate = await _person(sessions)
    newcomer = await _person(sessions)
    issued = await registry.allocate_eppn(graduate, "jsmith")
    await registry.release_identifier(graduate, "eppn", issued)

    reallocated = await registry.allocate_eppn(newcomer, "jsmith")

    assert reallocated != issued
    assert reallocated == f"jsmith2@{SCOPE}"


async def test_the_new_person_is_a_different_person(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-LC-08's other half: a different `eduPersonUniqueId` as well as a
    different ePPN. The unique id is the one an SP can safely key on."""
    graduate = await _person(sessions)
    newcomer = await _person(sessions)

    first = await registry.get(graduate)
    second = await registry.get(newcomer)

    assert first is not None and second is not None
    assert first.edu_person_unique_id != second.edu_person_unique_id


async def test_suffixes_keep_climbing_past_a_tombstone(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A released `jsmith2` does not free `jsmith2` either. Every generation is
    tombstoned, not just the first."""
    people = [await _person(sessions) for _ in range(3)]
    await registry.allocate_eppn(people[0], "jsmith")
    second = await registry.allocate_eppn(people[1], "jsmith")
    await registry.release_identifier(people[1], "eppn", second)

    assert await registry.allocate_eppn(people[2], "jsmith") == f"jsmith3@{SCOPE}"


async def test_an_empty_local_part_is_refused(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person_uuid = await _person(sessions)

    with pytest.raises(ValueError, match="local part"):
        await registry.allocate_eppn(person_uuid, "   ")


# --- the tombstone ----------------------------------------------------------


async def test_a_released_identifier_keeps_its_row(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The row *is* the protection. Deleting it would free the value, which is
    why there is deliberately no method that removes one."""
    person_uuid = await _person(sessions)
    issued = await registry.allocate_eppn(person_uuid, "jsmith")

    await registry.release_identifier(person_uuid, "eppn", issued)

    live = await registry.identifiers(person_uuid)
    everything = await registry.identifiers(person_uuid, include_released=True)
    assert [i.value for i in live] == []
    assert [i.value for i in everything] == [issued]


async def test_a_released_identifier_stops_being_primary(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Otherwise a tombstoned value would still be the one released to SPs."""
    person_uuid = await _person(sessions)
    issued = await registry.allocate_eppn(person_uuid, "jsmith")

    await registry.release_identifier(person_uuid, "eppn", issued)

    everything = await registry.identifiers(person_uuid, include_released=True)
    assert everything[0].is_primary is False


async def test_releasing_twice_is_harmless(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A runbook step run twice should not fail the second time and send
    somebody looking for a problem that is not there."""
    person_uuid = await _person(sessions)
    issued = await registry.allocate_eppn(person_uuid, "jsmith")

    await registry.release_identifier(person_uuid, "eppn", issued)
    await registry.release_identifier(person_uuid, "eppn", issued)

    assert len(await registry.identifiers(person_uuid, include_released=True)) == 1


# --- what the database refuses on its own ----------------------------------


async def test_the_schema_refuses_a_duplicate_identifier(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    """The second barrier. A row written by hand during an incident, by a
    script, or by a future migration must not be able to reissue a value."""
    first = await _person(sessions)
    second = await _person(sessions)

    async with sessions() as session, session.begin():
        session.add(
            Identifier(person_uuid=first, id_type="eppn", value=f"clash@{SCOPE}", scope=SCOPE)
        )

    with pytest.raises(IntegrityError):
        async with sessions() as session, session.begin():
            session.add(
                Identifier(person_uuid=second, id_type="eppn", value=f"clash@{SCOPE}", scope=SCOPE)
            )


async def test_the_schema_refuses_a_duplicate_even_when_the_first_is_released(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    """The constraint covers released rows deliberately. This is FR-LC-08
    enforced by the database rather than by the application remembering."""
    first = await _person(sessions)
    second = await _person(sessions)

    async with sessions() as session, session.begin():
        session.add(
            Identifier(
                person_uuid=first,
                id_type="eppn",
                value=f"released@{SCOPE}",
                scope=SCOPE,
                released_at=datetime.now(UTC),
            )
        )

    with pytest.raises(IntegrityError):
        async with sessions() as session, session.begin():
            session.add(
                Identifier(
                    person_uuid=second,
                    id_type="eppn",
                    value=f"released@{SCOPE}",
                    scope=SCOPE,
                )
            )


async def test_the_schema_refuses_two_accounts_for_one_subject(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    """A subject is meaningful only within its issuer, and one subject at one
    issuer is one person. Two rows would make which person depend on row
    order."""
    first = await _person(sessions)
    second = await _person(sessions)

    async with sessions() as session, session.begin():
        session.add(
            Account(
                person_uuid=first,
                idp_entity_id=CAMPUS_IDP,
                protocol="saml",
                subject_at_idp="name-id",
            )
        )

    with pytest.raises(IntegrityError):
        async with sessions() as session, session.begin():
            session.add(
                Account(
                    person_uuid=second,
                    idp_entity_id=CAMPUS_IDP,
                    protocol="saml",
                    subject_at_idp="name-id",
                )
            )


async def test_the_schema_refuses_an_unknown_status(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    with pytest.raises(IntegrityError):
        async with sessions() as session, session.begin():
            session.add(Person(edu_person_unique_id=new_unique_id(SCOPE), status="probably-fine"))


async def test_a_person_is_suspended_rather_than_deleted(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A person who authenticated has to stay nameable in the audit trail for as
    long as the trail does, so there is no delete path here at all."""
    person_uuid = await _person(sessions)

    await registry.set_status(person_uuid, "suspended")

    person = await registry.get(person_uuid)
    assert person is not None
    assert person.status == "suspended"


async def test_a_suspended_person_cannot_be_linked_to_by_eppn(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The leaver path and the linking rules meeting: suspending somebody has to
    actually stop a new IdP asserting their name and being believed."""
    person_uuid = await _person(sessions)
    issued = await registry.allocate_eppn(person_uuid, "leaver")
    await registry.set_status(person_uuid, "suspended")

    resolved = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "new-sub", eppn=issued))

    assert resolved.person_uuid != person_uuid
