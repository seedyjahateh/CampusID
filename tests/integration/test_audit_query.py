"""Reading the audit trail (FR-AUD-03).

Against live Postgres, because what is being tested is largely the query: the
filters, the half-open time range, and the keyset paging that stays correct while
events are still being written.

That last one is the case worth reading. Offset paging re-reads every skipped row
and, worse, shifts under a concurrent insert — so an investigator paging through
a busy trail quietly loses an event they never knew was there. Keyset paging on
the sequence cannot.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.audit.events import EventType, Outcome
from campusid.audit.log import AuditLog, set_correlation_id
from campusid.audit.models import AuditEventRecord
from campusid.audit.query import MAX_LIMIT, AuditQueryStore, Query, as_json
from campusid.config import get_settings
from campusid.db import create_owner_engine, create_session_factory

pytestmark = pytest.mark.integration

ALICE = "alice@campus.test"
BOB = "bob@campus.test"
PORTAL = "https://portal.campus.test/sp"
ANALYTICS = "https://analytics.campus.test/sp"

DAY = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """The owner engine: these tests clear the trail, which the application's
    own role cannot do (FR-AUD-04)."""
    engine = create_owner_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)
    async with factory() as session, session.begin():
        await session.execute(delete(AuditEventRecord))
    yield factory
    async with factory() as session, session.begin():
        await session.execute(delete(AuditEventRecord))


@pytest.fixture
def audit(sessions: async_sessionmaker[AsyncSession]) -> AuditLog:
    return AuditLog(sessions)


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> AuditQueryStore:
    return AuditQueryStore(sessions)


@pytest.fixture
async def trail(audit: AuditLog) -> None:
    """A small trail with something for each filter to find."""
    set_correlation_id("login-one")
    await audit.record(
        EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject=ALICE, target=PORTAL, now=DAY
    )
    await audit.record(
        EventType.ATTRIBUTE_RELEASE,
        Outcome.SUCCESS,
        subject=ALICE,
        target=PORTAL,
        now=DAY + timedelta(seconds=1),
    )
    set_correlation_id("login-two")
    await audit.record(
        EventType.AUTH_FAILURE,
        Outcome.FAILURE,
        subject=BOB,
        target=ANALYTICS,
        now=DAY + timedelta(days=1),
    )
    set_correlation_id("admin-one")
    await audit.record(
        EventType.ADMIN_ACTION,
        Outcome.SUCCESS,
        actor=ALICE,
        target=PORTAL,
        reason="onboarding",
        now=DAY + timedelta(days=2),
    )


# --- the four questions -----------------------------------------------------


async def test_events_about_one_person(store: AuditQueryStore, trail: None) -> None:
    """US-02: what happened to this person."""
    page = await store.search(Query(subject=ALICE))

    assert {event.subject for event in page.events} == {ALICE}
    assert len(page.events) == 2


async def test_events_one_relying_party_received(store: AuditQueryStore, trail: None) -> None:
    """The disclosure record under FERPA §99.32."""
    page = await store.search(Query(target=ANALYTICS))

    assert [event.subject for event in page.events] == [BOB]


async def test_failures_in_a_window(store: AuditQueryStore, trail: None) -> None:
    """US-11: every authentication failure for a subject across a date range."""
    page = await store.search(
        Query(outcome=Outcome.FAILURE.value, since=DAY, until=DAY + timedelta(days=2))
    )

    assert [event.subject for event in page.events] == [BOB]


async def test_everything_around_one_event(store: AuditQueryStore, trail: None) -> None:
    """FR-AUD-02, and the single most useful filter: the question is never "did
    this happen" but "what else happened around it"."""
    page = await store.search(Query(correlation_id="login-one"))

    assert len(page.events) == 2
    assert {event.correlation_id for event in page.events} == {"login-one"}


# --- the other filters ------------------------------------------------------


async def test_filtering_by_actor_is_not_filtering_by_subject(
    store: AuditQueryStore, trail: None
) -> None:
    """An administrator acting on somebody else is the case worth being able to
    ask about separately, and the one a single "who" field would lose."""
    as_actor = await store.search(Query(actor=ALICE))
    as_subject = await store.search(Query(subject=ALICE))

    assert [e.event_type for e in as_actor.events] == [EventType.ADMIN_ACTION.value]
    assert EventType.ADMIN_ACTION.value not in [e.event_type for e in as_subject.events]


async def test_filtering_by_type(store: AuditQueryStore, trail: None) -> None:
    page = await store.search(Query(event_type=EventType.ATTRIBUTE_RELEASE.value))

    assert len(page.events) == 1


async def test_filters_compose(store: AuditQueryStore, trail: None) -> None:
    page = await store.search(Query(subject=ALICE, target=PORTAL, outcome=Outcome.SUCCESS.value))

    assert len(page.events) == 2


async def test_a_filter_matching_nothing_returns_nothing(
    store: AuditQueryStore, trail: None
) -> None:
    page = await store.search(Query(subject="nobody@campus.test"))

    assert page.events == []
    assert page.next_cursor is None


async def test_an_unfiltered_query_is_answered(store: AuditQueryStore, trail: None) -> None:
    """A legitimate thing to ask of an audit trail, so it is answered — bounded
    by the page size like any other rather than refused."""
    page = await store.search(Query())

    assert len(page.events) == 4


# --- the time range ---------------------------------------------------------


async def test_the_range_is_half_open(store: AuditQueryStore, trail: None) -> None:
    """`since` counts and `until` does not, so "events on the 3rd" is one
    expression rather than a question about midnight."""
    page = await store.search(Query(since=DAY, until=DAY + timedelta(days=1)))

    assert {event.subject for event in page.events} == {ALICE}


async def test_the_lower_bound_includes_its_own_instant(
    store: AuditQueryStore, trail: None
) -> None:
    page = await store.search(Query(since=DAY, until=DAY + timedelta(seconds=1)))

    assert len(page.events) == 1


async def test_a_range_with_no_upper_bound_runs_to_now(store: AuditQueryStore, trail: None) -> None:
    page = await store.search(Query(since=DAY + timedelta(days=1)))

    assert len(page.events) == 2


# --- ordering and paging ----------------------------------------------------


async def test_results_are_newest_first(store: AuditQueryStore, trail: None) -> None:
    """ "What happened to this person" means recently, almost always."""
    page = await store.search(Query())

    assert [event.seq for event in page.events] == sorted(
        (event.seq for event in page.events), reverse=True
    )


async def test_a_page_reports_a_cursor_when_there_is_more(
    store: AuditQueryStore, trail: None
) -> None:
    page = await store.search(Query(limit=2))

    assert len(page.events) == 2
    assert page.next_cursor is not None


async def test_the_last_page_reports_no_cursor(store: AuditQueryStore, trail: None) -> None:
    """Derived from what came back rather than from a second count query:
    counting the whole match to decide whether to show a Next button is how an
    audit view becomes the slowest page in the console."""
    page = await store.search(Query(limit=100))

    assert page.next_cursor is None


async def test_paging_reaches_every_event_exactly_once(store: AuditQueryStore, trail: None) -> None:
    seen: list[int] = []
    cursor: int | None = None
    while True:
        page = await store.search(Query(limit=2, before_seq=cursor))
        seen.extend(event.seq for event in page.events)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert sorted(seen) == sorted(set(seen))
    assert len(seen) == 4


async def test_a_write_between_pages_does_not_hide_an_event(
    store: AuditQueryStore, audit: AuditLog, trail: None
) -> None:
    """The reason for keyset paging. Under offset paging a row inserted between
    two requests shifts every subsequent offset by one, and an investigator
    quietly loses an event they never knew was there."""
    first = await store.search(Query(limit=2))
    await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject="latecomer")

    second = await store.search(Query(limit=2, before_seq=first.next_cursor))

    assert not {e.seq for e in first.events} & {e.seq for e in second.events}
    assert len(second.events) == 2


async def test_an_absurd_limit_is_capped(store: AuditQueryStore, trail: None) -> None:
    """A caller asking for a million rows gets five hundred, because the
    alternative is one request that reads the whole table."""
    page = await store.search(Query(limit=10_000_000))

    assert len(page.events) <= MAX_LIMIT


async def test_a_limit_of_zero_still_returns_something(store: AuditQueryStore, trail: None) -> None:
    """Clamped up rather than honoured: a page of nothing with a cursor is a loop
    that never terminates."""
    page = await store.search(Query(limit=0))

    assert len(page.events) == 1


# --- the timeline -----------------------------------------------------------


async def test_a_timeline_reads_oldest_first(store: AuditQueryStore, trail: None) -> None:
    events = await store.timeline(ALICE)

    assert [event.seq for event in events] == sorted(event.seq for event in events)


async def test_a_timeline_covers_only_that_person(store: AuditQueryStore, trail: None) -> None:
    assert {event.subject for event in await store.timeline(BOB)} == {BOB}


async def test_a_timeline_shows_the_most_recent_page(
    store: AuditQueryStore, audit: AuditLog
) -> None:
    """Reversed after querying newest-first rather than queried ascending, so a
    busy account's timeline does not open on a first login from three years ago
    and show nothing since."""
    for n in range(6):
        await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject=ALICE, detail={"n": n})

    events = await store.timeline(ALICE, limit=2)

    assert [event.detail["n"] for event in events] == [4, 5]


# --- what a record looks like -----------------------------------------------


async def test_a_record_carries_its_chain_columns(store: AuditQueryStore, trail: None) -> None:
    """An auditor handed a page of events should be able to verify the links
    themselves rather than take the console's word for it — and the console is
    the thing whose word is in question if the trail is."""
    page = await store.search(Query(limit=1))

    rendered = as_json(page.events[0])
    assert len(rendered["hash"]) == 64
    assert len(rendered["prev_hash"]) == 64


async def test_a_record_renders_its_time_as_text(store: AuditQueryStore, trail: None) -> None:
    page = await store.search(Query(limit=1))

    assert as_json(page.events[0])["occurred_at"].startswith("20")
