"""Role assignments, their origins and their windows (FR-AZ-01, 06, 07).

The test the requirement names is the two-source case: somebody holding one role
for two reasons keeps it when one reason goes away. A table keyed on person and
role would silently take it away, which is why the rows are keyed on the origin
instead — and why this runs against a real database, where that index either
exists or does not.

Time bounds are checked when the question is asked rather than only when the
assignment is made. An assignment that expired last night is still in the table
this morning, and a system that only checked on the way in would honour it
forever.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.authz.models import RoleAssignment
from campusid.authz.roles import Assignment, Origin, RoleError, RoleStore
from campusid.authz.store import RoleAssignmentStore
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Person

pytestmark = pytest.mark.integration

ROLES = Path("/app/config/roles.yaml")
TODAY = date(2026, 6, 30)
ADMIN = "iam-admin@campus.test"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(engine)


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> RoleAssignmentStore:
    return RoleAssignmentStore(sessions, catalogue=RoleStore(ROLES))


@pytest.fixture
async def person(sessions: async_sessionmaker[AsyncSession]) -> AsyncIterator[str]:
    async with sessions() as session, session.begin():
        row = Person(
            edu_person_unique_id=f"{uuid.uuid4().hex}@campus.test",
            status="active",
            provisioning_source="sis",
        )
        session.add(row)
        await session.flush()
        created = str(row.person_uuid)

    yield created

    async with sessions() as session, session.begin():
        key = uuid.UUID(created)
        await session.execute(delete(RoleAssignment).where(RoleAssignment.person_uuid == key))
        await session.execute(delete(Person).where(Person.person_uuid == key))


def _derived(*pairs: tuple[str, str, str]) -> tuple[Assignment, ...]:
    return tuple(
        Assignment(role=role, origin=Origin(origin), reference=reference)
        for role, origin, reference in pairs
    )


# --- the case the requirement names -----------------------------------------


async def test_a_role_from_two_sources_survives_losing_one(
    store: RoleAssignmentStore, person: str
) -> None:
    """FR-AZ-01. Somebody who is an employee because they are staff *and*
    because they are faculty stays an employee when one of those ends."""
    await store.reconcile_derived(
        person,
        _derived(
            ("employee", "affiliation", "staff"),
            ("employee", "affiliation", "faculty"),
        ),
        on=TODAY,
    )

    await store.reconcile_derived(
        person, _derived(("employee", "affiliation", "faculty")), on=TODAY
    )

    assert "employee" in await store.roles_for(person, on=TODAY)


async def test_losing_every_source_loses_the_role(store: RoleAssignmentStore, person: str) -> None:
    await store.reconcile_derived(person, _derived(("employee", "affiliation", "staff")), on=TODAY)

    await store.reconcile_derived(person, (), on=TODAY)

    assert "employee" not in await store.roles_for(person, on=TODAY)


async def test_a_direct_grant_survives_a_derivation_run(
    store: RoleAssignmentStore, person: str
) -> None:
    """A derivation that quietly removed somebody's granted role would be the
    system overruling a human without telling them."""
    await store.grant(person, "course-admin", granted_by=ADMIN, valid_from=TODAY)

    await store.reconcile_derived(person, (), on=TODAY)

    assert "course-admin" in await store.roles_for(person, on=TODAY)


# --- origins are recorded ---------------------------------------------------


async def test_every_assignment_records_why_it_exists(
    store: RoleAssignmentStore, person: str
) -> None:
    await store.reconcile_derived(person, _derived(("student", "affiliation", "student")), on=TODAY)
    await store.grant(person, "course-admin", granted_by=ADMIN, valid_from=TODAY)

    assignments = await store.assignments_for(person)

    origins = {(row.role, row.origin_kind, row.origin_ref) for row in assignments}
    assert ("student", "affiliation", "student") in origins
    assert ("course-admin", "direct", ADMIN) in origins


async def test_a_direct_grant_records_who_made_it(store: RoleAssignmentStore, person: str) -> None:
    """A derived role is a fact about the person; a direct one is a decision
    somebody made and should be able to be asked about."""
    await store.grant(person, "course-admin", granted_by=ADMIN, valid_from=TODAY)

    granted = [row for row in await store.assignments_for(person) if row.origin_kind == "direct"]

    assert granted[0].granted_by == ADMIN


async def test_a_repeated_derivation_does_not_grow_the_table(
    store: RoleAssignmentStore, person: str
) -> None:
    """The derivation runs on every login. A second identical row is a replay
    rather than a second reason."""
    facts = _derived(("student", "affiliation", "student"))

    await store.reconcile_derived(person, facts, on=TODAY)
    added, _ = await store.reconcile_derived(person, facts, on=TODAY)

    assert added == 0
    assert len(await store.assignments_for(person)) == 1


async def test_an_ended_assignment_is_kept_rather_than_deleted(
    store: RoleAssignmentStore, person: str
) -> None:
    """So "they were an instructor until June" stays answerable."""
    await store.reconcile_derived(
        person, _derived(("instructor", "affiliation", "faculty")), on=TODAY
    )
    await store.reconcile_derived(person, (), on=TODAY)

    rows = await store.assignments_for(person)

    assert len(rows) == 1
    assert rows[0].valid_until == TODAY


async def test_a_fact_that_becomes_true_again_reopens_the_assignment(
    store: RoleAssignmentStore, person: str
) -> None:
    """Somebody re-enrols. The unique index is on the origin, so a second row
    would be refused anyway — reopening is both correct and the only option."""
    facts = _derived(("student", "affiliation", "student"))
    await store.reconcile_derived(person, facts, on=TODAY - timedelta(days=30))
    await store.reconcile_derived(person, (), on=TODAY - timedelta(days=10))

    await store.reconcile_derived(person, facts, on=TODAY)

    assert "student" in await store.roles_for(person, on=TODAY)


# --- time bounds (FR-AZ-06) -------------------------------------------------


async def test_a_role_is_not_held_before_it_starts(store: RoleAssignmentStore, person: str) -> None:
    await store.grant(
        person, "course-admin", granted_by=ADMIN, valid_from=TODAY + timedelta(days=7)
    )

    assert "course-admin" not in await store.roles_for(person, on=TODAY)


async def test_a_role_is_not_held_after_it_ends(store: RoleAssignmentStore, person: str) -> None:
    """Checked when the question is asked. An assignment that expired last night
    is still in the table this morning."""
    await store.grant(
        person,
        "course-admin",
        granted_by=ADMIN,
        valid_from=TODAY,
        valid_until=TODAY + timedelta(days=1),
    )

    assert "course-admin" not in await store.roles_for(person, on=TODAY + timedelta(days=2))


async def test_the_window_is_half_open(store: RoleAssignmentStore, person: str) -> None:
    """`valid_from` counts and `valid_until` does not — the same convention the
    affiliation table already uses.

    It is what makes an immediate revocation immediate: revoking today sets the
    bound to today, and with an inclusive bound the role would survive until
    midnight. It also lets one assignment end on the day the next begins with
    neither a gap nor an overlap.
    """
    await store.grant(
        person,
        "course-admin",
        granted_by=ADMIN,
        valid_from=TODAY,
        valid_until=TODAY + timedelta(days=1),
    )

    assert "course-admin" in await store.roles_for(person, on=TODAY)
    assert "course-admin" not in await store.roles_for(person, on=TODAY + timedelta(days=1))


async def test_the_past_is_still_answerable(store: RoleAssignmentStore, person: str) -> None:
    """ "Was this person an approver in March?" is the same query as "are they one
    today", which is what makes an access review possible at all."""
    march = TODAY - timedelta(days=120)
    await store.grant(
        person,
        "course-admin",
        granted_by=ADMIN,
        valid_from=march,
        valid_until=march + timedelta(days=5),
    )

    assert "course-admin" in await store.roles_for(person, on=march + timedelta(days=1))
    assert "course-admin" not in await store.roles_for(person, on=TODAY)


async def test_a_role_granted_and_revoked_the_same_day_was_never_held(
    store: RoleAssignmentStore, person: str
) -> None:
    """A zero-length window, which is what an immediate revocation produces and
    what it should mean."""
    await store.grant(person, "course-admin", granted_by=ADMIN, valid_from=TODAY)

    await store.revoke(person, "course-admin", on=TODAY)

    assert "course-admin" not in await store.roles_for(person, on=TODAY)


# --- separation of duties (FR-AZ-07) ----------------------------------------


async def test_an_incompatible_grant_is_refused(store: RoleAssignmentStore, person: str) -> None:
    """Refused before the write, with the conflict named. Recording it and
    alerting afterwards would mean the control exists only in a report."""
    await store.grant(person, "finance-requester", granted_by=ADMIN, valid_from=TODAY)

    with pytest.raises(RoleError, match="expenditure"):
        await store.grant(person, "finance-approver", granted_by=ADMIN, valid_from=TODAY)


async def test_the_refused_role_was_not_written(store: RoleAssignmentStore, person: str) -> None:
    await store.grant(person, "finance-requester", granted_by=ADMIN, valid_from=TODAY)
    with pytest.raises(RoleError):
        await store.grant(person, "finance-approver", granted_by=ADMIN, valid_from=TODAY)

    assert "finance-approver" not in await store.roles_for(person, on=TODAY)


async def test_the_conflicting_role_is_grantable_once_the_first_has_ended(
    store: RoleAssignmentStore, person: str
) -> None:
    """Separation of duties is about what somebody holds at once, not about what
    they have ever held."""
    await store.grant(
        person,
        "finance-requester",
        granted_by=ADMIN,
        valid_from=TODAY - timedelta(days=10),
        valid_until=TODAY - timedelta(days=1),
    )

    await store.grant(person, "finance-approver", granted_by=ADMIN, valid_from=TODAY)

    assert "finance-approver" in await store.roles_for(person, on=TODAY)


async def test_an_unknown_role_cannot_be_granted(store: RoleAssignmentStore, person: str) -> None:
    with pytest.raises(RoleError, match="no such role"):
        await store.grant(person, "invented-role", granted_by=ADMIN, valid_from=TODAY)


# --- revoking ---------------------------------------------------------------


async def test_revoking_ends_every_reason_at_once(store: RoleAssignmentStore, person: str) -> None:
    """Revoking a role from somebody who holds it twice and leaving one reason
    standing is the revocation that does not revoke."""
    await store.reconcile_derived(
        person,
        _derived(
            ("employee", "affiliation", "staff"),
            ("employee", "affiliation", "faculty"),
        ),
        on=TODAY,
    )

    ended = await store.revoke(person, "employee", on=TODAY)

    assert ended == 2
    assert "employee" not in await store.roles_for(person, on=TODAY)


async def test_revoking_something_not_held_is_harmless(
    store: RoleAssignmentStore, person: str
) -> None:
    assert await store.revoke(person, "course-admin", on=TODAY) == 0
