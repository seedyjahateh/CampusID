"""Entitlement grants, grace periods and the timeline (FR-LC-05, FR-LC-06).

Against live Postgres, because what this store does *is* the persistence: the
unique constraint that makes a replayed grant a no-op, and the deadline column
that makes a grace period survive a restart.

The case worth reading is the restart. A grace period expressed as a timer ends
when the process does; expressed as a date in a row, it ends on the day it said
it would, and the sweep that notices is the same sweep whether the broker has
been up for a month or a minute.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import date, timedelta

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.lifecycle.models import EntitlementGrant, LifecycleEvent
from campusid.lifecycle.rules import LifecycleRules, load_rules
from campusid.lifecycle.store import GRACE_EXPIRY, LifecycleStore
from campusid.scim.models import ScimSourceRecord

pytestmark = pytest.mark.integration

LMS = "urn:mace:campus.edu:entitlement:lms:access"
MAIL = "urn:mace:campus.edu:entitlement:mail:alias"
LIBRARY = "urn:mace:campus.edu:entitlement:library:eresources"
HR = "urn:mace:campus.edu:entitlement:hr:selfservice"

TODAY = date(2026, 6, 30)


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
def rules() -> LifecycleRules:
    from pathlib import Path

    return load_rules(Path("/app/config/lifecycle_rules.yaml"))


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> LifecycleStore:
    return LifecycleStore(sessions)


async def _person(sessions: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    async with sessions() as session, session.begin():
        person = Person(
            edu_person_unique_id=f"{uuid.uuid4().hex}@campus.test",
            status="active",
            provisioning_source="sis",
        )
        session.add(person)
        await session.flush()
        return person.person_uuid


async def _grants(
    sessions: async_sessionmaker[AsyncSession], person_uuid: uuid.UUID
) -> list[EntitlementGrant]:
    async with sessions() as session:
        return list(
            await session.scalars(
                select(EntitlementGrant).where(EntitlementGrant.person_uuid == person_uuid)
            )
        )


# --- joining ----------------------------------------------------------------


async def test_a_joiner_gets_their_entitlements_with_reasons(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The justification is the point: an entitlement without one cannot be
    reviewed and cannot be removed for a reason."""
    person = await _person(sessions)
    delta = rules.transition(set(), {"student"}, on=TODAY)

    await store.apply(person, delta, before=set(), after={"student"})

    grants = await _grants(sessions, person)
    assert {grant.entitlement_urn for grant in grants} == {LMS, MAIL, LIBRARY}
    assert all(grant.justification_kind == "affiliation" for grant in grants)
    lms = next(grant for grant in grants if grant.entitlement_urn == LMS)
    assert lms.justification_ref == "students-get-the-lms:student"


async def test_a_replayed_transition_does_not_double_grant(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A provisioning client that retries is the ordinary case, not an edge one."""
    person = await _person(sessions)
    delta = rules.transition(set(), {"student"}, on=TODAY)

    await store.apply(person, delta, before=set(), after={"student"})
    await store.apply(person, delta, before=set(), after={"student"})

    assert len(await _grants(sessions, person)) == 3


# --- moving -----------------------------------------------------------------


async def test_an_entitlement_survives_losing_one_of_two_justifications(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Somebody who is both student and faculty holds the LMS twice. Stopping
    being a student must leave the faculty grant standing."""
    person = await _person(sessions)
    await store.apply(
        person,
        rules.transition(set(), {"student", "faculty"}, on=TODAY),
        before=set(),
        after={"student", "faculty"},
    )

    await store.apply(
        person,
        rules.transition({"student", "faculty"}, {"faculty"}, on=TODAY),
        before={"student", "faculty"},
        after={"faculty"},
    )

    assert LMS in await store.held(person, on=TODAY)


# --- grace periods ----------------------------------------------------------


async def test_a_graduating_student_keeps_the_lms_through_its_grace_period(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )

    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    held = await store.held(person, on=TODAY + timedelta(days=29))
    assert LMS in held, "the grace period has not ended yet"
    assert LIBRARY not in held, "a licensed resource ends with the affiliation"


async def test_the_grace_period_ends_whether_or_not_anybody_was_watching(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-LC-05's durable half, and the reason the deadline is a column rather
    than a timer. The sweep is the same sweep whether the broker has been up for
    a month or a minute."""
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    # A year later: nothing has been running, and the revocation is still due.
    expired = await store.expire_due(on=TODAY + timedelta(days=365))

    assert str(person) in expired
    assert LMS not in await store.held(person, on=TODAY + timedelta(days=365))


async def test_two_sweeps_at_once_expire_a_grant_once(
    rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The multi-node case, and the reason the selection takes a row lock.

    The sweep starts in the application lifespan, so a three-node deployment runs
    three sweeps. Without `FOR UPDATE SKIP LOCKED` both transactions select the
    same grant, both set `revoked_at`, and both write a `grace.expiry` event.

    The revocation is idempotent — the same state either way — so this is not a
    correctness problem for access. **The timeline is not idempotent**, and a
    duplicate expiry there is wrong in the one place an access review reads it.

    The contention is forced rather than raced. An earlier version ran two sweeps
    through `asyncio.gather` and passed with the lock removed — the two
    transactions happened to serialise, so it proved nothing while looking like
    proof. Here one transaction holds the row locks while the sweep runs in
    another, which is the situation the lock exists for and is deterministic.
    """
    person = await _person(sessions)
    store = LifecycleStore(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )
    later = TODAY + timedelta(days=365)

    async with sessions() as holder, holder.begin():
        # Stand in for the other node: hold every due row locked.
        locked = list(
            await holder.scalars(
                select(EntitlementGrant)
                .where(
                    EntitlementGrant.person_uuid == person,
                    EntitlementGrant.revoked_at.is_(None),
                    EntitlementGrant.revoke_at.is_not(None),
                    EntitlementGrant.revoke_at <= later,
                )
                .with_for_update()
            )
        )
        assert locked, "the fixture produced no grant inside a grace period"

        # Bounded, because the regression does not fail — it *blocks*. Without
        # `SKIP LOCKED` the sweep selects the row anyway and then waits on the
        # holder's lock to update it, which never clears because the holder is
        # this transaction. An unbounded await would hang CI rather than report.
        try:
            swept = await asyncio.wait_for(store.expire_due(on=later), timeout=10)
        except TimeoutError:
            pytest.fail(
                "the sweep blocked on a row another node holds: it is selecting "
                "locked rows instead of skipping them"
            )

    assert swept == [], "the sweep claimed a grant another node was already handling"

    # And with nothing holding them, the same sweep does the work exactly once.
    assert str(person) in await store.expire_due(on=later)
    async with sessions() as session:
        events = list(
            await session.scalars(
                select(LifecycleEvent).where(
                    LifecycleEvent.person_uuid == person,
                    LifecycleEvent.event_type == GRACE_EXPIRY,
                )
            )
        )
    assert len(events) == len(locked), "one expiry produced more than one timeline event"


async def test_a_sweep_before_the_deadline_revokes_nothing(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    assert await store.expire_due(on=TODAY + timedelta(days=1)) == []
    assert LMS in await store.held(person, on=TODAY + timedelta(days=1))


async def test_a_second_transition_does_not_extend_a_countdown(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """An access already counting down must not be given more time by an
    unrelated change, or a person who moves twice never loses anything."""
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )
    later = TODAY + timedelta(days=10)

    await store.apply(
        person,
        rules.transition({"alum"}, {"alum"}, on=later),
        before={"alum"},
        after={"alum"},
    )

    lms = next(grant for grant in await _grants(sessions, person) if grant.entitlement_urn == LMS)
    assert lms.revoke_at == TODAY + timedelta(days=30)


async def test_a_revoked_grant_is_kept_rather_than_deleted(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "This person had HR self-service until August" is a question an auditor
    asks, and a deleted row cannot answer it."""
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"staff"}, on=TODAY), before=set(), after={"staff"}
    )

    await store.apply(
        person, rules.transition({"staff"}, set(), on=TODAY), before={"staff"}, after=set()
    )
    await store.expire_due(on=TODAY + timedelta(days=30))

    grants = await _grants(sessions, person)
    hr = next(grant for grant in grants if grant.entitlement_urn == HR)
    assert hr.revoked_at is not None
    assert hr.granted_at is not None


# --- the timeline -----------------------------------------------------------


async def test_every_transition_writes_a_timeline_event(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    events = await store.timeline(person)

    assert [event.event_type for event in events] == ["joiner", "mover"]
    assert all(event.source == "scim" for event in events)


async def test_a_timeline_event_records_both_sides(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A diff is derivable from the states; the states are not derivable from a
    diff, and what an auditor asks a year later is what the record said."""
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    graduation = (await store.timeline(person))[1]

    assert graduation.before_state["affiliations"] == ["student"]
    assert graduation.after_state["affiliations"] == ["alum"]
    assert LMS in graduation.before_state["entitlements"]
    assert LMS not in graduation.after_state["entitlements"]


async def test_a_timeline_event_carries_a_correlation_id(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """So a deprovisioning can be followed from the message that triggered it to
    the session that was terminated."""
    person = await _person(sessions)

    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )

    assert (await store.timeline(person))[0].correlation_id


async def test_a_grace_expiry_is_its_own_event(
    store: LifecycleStore, rules: LifecycleRules, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Attributed to the scheduler rather than to whoever last touched the
    person, because "the SIS did it" and "the deadline arrived" are different
    answers."""
    person = await _person(sessions)
    await store.apply(
        person, rules.transition(set(), {"student"}, on=TODAY), before=set(), after={"student"}
    )
    await store.apply(
        person,
        rules.transition({"student"}, {"alum"}, on=TODAY),
        before={"student"},
        after={"alum"},
    )

    await store.expire_due(on=TODAY + timedelta(days=31))

    expiry = (await store.timeline(person))[-1]
    assert expiry.event_type == "grace_expiry"
    assert expiry.source == "scheduler"
    assert expiry.before_state["entitlement"] == LMS
