"""Exporting and pruning the audit trail (FR-AUD-08).

Two halves of one requirement, and they meet at an awkward place: retention and a
hash chain pull against each other, because deleting old events breaks the chain
by construction and a verifier cannot tell a retention pass apart from somebody
removing a row to hide something.

The anchor is what resolves that, and most of these tests are about it. A pass
records where it cut and what the last removed event hashed to; the verifier
resumes from there. Tampering is still caught, because the anchor is a row and
the application role cannot write one.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.audit.chain import GENESIS, UNLINKED
from campusid.audit.events import EventType, Outcome
from campusid.audit.export import filename, ndjson
from campusid.audit.log import AuditLog, set_correlation_id
from campusid.audit.models import AuditEventRecord, AuditRetentionAnchor
from campusid.audit.query import AuditQueryStore, Query
from campusid.audit.retention import DEFAULT_RETENTION, RetentionStore
from campusid.config import get_settings
from campusid.db import create_engine, create_owner_engine, create_session_factory

pytestmark = pytest.mark.integration

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_owner_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)
    await _clear(factory)
    yield factory
    await _clear(factory)


async def _clear(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session, session.begin():
        await session.execute(delete(AuditRetentionAnchor))
        await session.execute(delete(AuditEventRecord))


@pytest.fixture
def audit(sessions: async_sessionmaker[AsyncSession]) -> AuditLog:
    return AuditLog(sessions)


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> AuditQueryStore:
    return AuditQueryStore(sessions)


@pytest.fixture
def retention(sessions: async_sessionmaker[AsyncSession]) -> RetentionStore:
    return RetentionStore(sessions)


async def _emit(audit: AuditLog, count: int, *, at: datetime) -> None:
    for n in range(count):
        set_correlation_id(f"chain-{n}")
        await audit.record(
            EventType.AUTH_SUCCESS,
            Outcome.SUCCESS,
            subject=f"person-{n}",
            now=at + timedelta(seconds=n),
        )


async def _collect(store: AuditQueryStore, query: Query) -> list[dict[str, object]]:
    lines = [line async for line in ndjson(store, query)]
    return [json.loads(line) for line in lines]


# --- the export format ------------------------------------------------------


async def test_every_event_is_one_line(store: AuditQueryStore, audit: AuditLog) -> None:
    """One object per line, no enclosing array, no trailing comma to get wrong —
    which is what every SIEM ingests without being told anything."""
    await _emit(audit, 4, at=NOW)

    lines = [line async for line in ndjson(store, Query())]

    assert len(lines) == 4
    assert all(line.endswith(b"\n") for line in lines)
    assert all(json.loads(line) for line in lines)


async def test_an_export_is_oldest_first(store: AuditQueryStore, audit: AuditLog) -> None:
    """Unlike the console. An export is read forward and appended to, and a SIEM
    ingesting newest-first would have to reverse the file before it could stitch
    two exports together."""
    await _emit(audit, 5, at=NOW)

    events = await _collect(store, Query())

    assert [event["seq"] for event in events] == sorted(event["seq"] for event in events)  # type: ignore[type-var]


async def test_every_line_carries_its_chain(store: AuditQueryStore, audit: AuditLog) -> None:
    """An export that dropped them would be a copy nobody can check against the
    original, which is most of the point of exporting an audit trail."""
    await _emit(audit, 2, at=NOW)

    events = await _collect(store, Query())

    assert all(len(str(event["hash"])) == 64 for event in events)
    assert [event["prev_hash"] for event in events[1:]] == [event["hash"] for event in events[:-1]]


async def test_an_export_honours_its_filters(store: AuditQueryStore, audit: AuditLog) -> None:
    await _emit(audit, 4, at=NOW)

    events = await _collect(store, Query(subject="person-2"))

    assert [event["subject"] for event in events] == ["person-2"]


async def test_an_export_of_nothing_is_empty(store: AuditQueryStore) -> None:
    assert [line async for line in ndjson(store, Query())] == []


async def test_an_export_larger_than_one_page_is_complete(
    store: AuditQueryStore, audit: AuditLog
) -> None:
    """Streamed in pages, so the boundary between them has to be seamless — the
    case a single-page test would never reach."""
    await _emit(audit, 12, at=NOW)

    events = await _collect(store, Query(limit=3))

    assert len(events) == 12
    assert len({event["seq"] for event in events}) == 12


def test_the_filename_says_what_is_in_it() -> None:
    """Because an export lands in a downloads folder next to four others, and
    `export.json` is how the wrong window gets ingested."""
    name = filename(Query(since=NOW, until=NOW + timedelta(days=1)))

    assert "2026-09-11" in name
    assert name.endswith(".ndjson")


# --- pruning ----------------------------------------------------------------


async def test_nothing_old_enough_is_a_no_op(retention: RetentionStore, audit: AuditLog) -> None:
    await _emit(audit, 3, at=NOW)

    pruned = await retention.prune(
        sink=_nowhere, performed_by="operator", reason="routine", now=NOW
    )

    assert pruned.removed == 0
    assert pruned.through_seq is None


async def _nowhere(rows: list[AuditEventRecord]) -> None:
    return None


async def test_old_events_are_removed(
    retention: RetentionStore, audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 3, at=NOW - timedelta(days=500))
    await _emit(audit, 2, at=NOW)

    pruned = await retention.prune(
        sink=_nowhere, performed_by="operator", reason="routine", now=NOW
    )

    assert pruned.removed == 3
    async with sessions() as session:
        remaining = list(await session.scalars(select(AuditEventRecord)))
    assert len(remaining) == 2


async def test_everything_removed_is_exported_first(
    retention: RetentionStore, audit: AuditLog
) -> None:
    """Nothing is deleted that has not reached the sink. An export that fails
    half way leaves the trail intact, which is the direction this failure has to
    fall."""
    await _emit(audit, 4, at=NOW - timedelta(days=500))
    seen: list[str] = []

    async def sink(rows: list[AuditEventRecord]) -> None:
        seen.extend(row.event_id for row in rows)

    await retention.prune(sink=sink, performed_by="operator", reason="routine", now=NOW)

    assert len(seen) == 4


async def test_a_failing_export_leaves_the_trail_alone(
    retention: RetentionStore, audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 3, at=NOW - timedelta(days=500))

    async def broken(rows: list[AuditEventRecord]) -> None:
        raise OSError("the disk is full")

    with pytest.raises(OSError, match="disk is full"):
        await retention.prune(sink=broken, performed_by="operator", reason="routine", now=NOW)

    async with sessions() as session:
        assert len(list(await session.scalars(select(AuditEventRecord)))) == 3


async def test_the_window_is_configurable(retention: RetentionStore, audit: AuditLog) -> None:
    await _emit(audit, 3, at=NOW - timedelta(days=10))

    pruned = await retention.prune(
        older_than=timedelta(days=5),
        sink=_nowhere,
        performed_by="operator",
        reason="short window",
        now=NOW,
    )

    assert pruned.removed == 3


def test_the_default_window_is_the_requirements() -> None:
    """Four hundred days rather than a year, so the trail always covers the same
    month last year — which is what an annual access review compares against."""
    assert timedelta(days=400) == DEFAULT_RETENTION


async def test_what_a_pass_would_remove_can_be_asked_first(
    retention: RetentionStore, audit: AuditLog
) -> None:
    """Because anybody meeting a command that deletes audit records should be
    able to see what it would do."""
    await _emit(audit, 3, at=NOW - timedelta(days=500))
    await _emit(audit, 2, at=NOW)

    assert await retention.due(now=NOW) == 3


# --- the anchor -------------------------------------------------------------


async def test_a_pruned_trail_still_verifies(retention: RetentionStore, audit: AuditLog) -> None:
    """The point of the anchor. Without it a retention policy and a verifiable
    trail are mutually exclusive."""
    await _emit(audit, 4, at=NOW - timedelta(days=500))
    await _emit(audit, 3, at=NOW)

    await retention.prune(sink=_nowhere, performed_by="operator", reason="routine", now=NOW)

    assert await audit.verify_chain() is None


async def test_the_anchor_records_what_was_cut(
    retention: RetentionStore, audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "The trail starts in March because we prune at 400 days" and "the trail
    starts in March because somebody deleted February" have to look different."""
    await _emit(audit, 4, at=NOW - timedelta(days=500))
    await _emit(audit, 1, at=NOW)

    await retention.prune(
        sink=_nowhere, performed_by="marcus.reed", reason="quarterly pass", now=NOW
    )

    async with sessions() as session:
        anchor = await session.scalar(select(AuditRetentionAnchor))
    assert anchor is not None
    assert anchor.removed_count == 4
    assert anchor.performed_by == "marcus.reed"
    assert anchor.reason == "quarterly pass"


async def test_deleting_beyond_the_anchor_is_still_caught(
    retention: RetentionStore, audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The anchor vouches for exactly what the pass removed and nothing more.
    A row taken out afterwards breaks the link like any other."""
    await _emit(audit, 3, at=NOW - timedelta(days=500))
    await _emit(audit, 3, at=NOW)
    await retention.prune(sink=_nowhere, performed_by="operator", reason="routine", now=NOW)

    async with sessions() as session, session.begin():
        oldest = await session.scalar(
            select(AuditEventRecord).order_by(AuditEventRecord.seq).limit(1)
        )
        assert oldest is not None
        await session.execute(delete(AuditEventRecord).where(AuditEventRecord.seq == oldest.seq))

    broken = await audit.verify_chain()

    assert broken is not None
    assert broken.problem == UNLINKED


async def test_editing_a_surviving_row_is_still_caught(
    retention: RetentionStore, audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 2, at=NOW - timedelta(days=500))
    await _emit(audit, 3, at=NOW)
    await retention.prune(sink=_nowhere, performed_by="operator", reason="routine", now=NOW)

    async with sessions() as session, session.begin():
        await session.execute(text("UPDATE audit_event SET subject = 'tampered'"))

    assert await audit.verify_chain() is not None


async def test_two_passes_chain_their_anchors(retention: RetentionStore, audit: AuditLog) -> None:
    """The verifier starts from the newest anchor, so a second pass has to leave
    a trail that still verifies against it rather than against the first."""
    await _emit(audit, 3, at=NOW - timedelta(days=800))
    await _emit(audit, 3, at=NOW - timedelta(days=500))
    await _emit(audit, 2, at=NOW)

    await retention.prune(
        older_than=timedelta(days=700), sink=_nowhere, performed_by="op", reason="first", now=NOW
    )
    await retention.prune(
        older_than=timedelta(days=400), sink=_nowhere, performed_by="op", reason="second", now=NOW
    )

    assert await audit.verify_chain() is None


async def test_a_trail_pruned_to_nothing_reports_the_anchor_as_its_head(
    retention: RetentionStore, audit: AuditLog
) -> None:
    """Otherwise a published head would appear to reset, which is also what a
    trail somebody had emptied would look like."""
    await _emit(audit, 3, at=NOW - timedelta(days=500))

    await retention.prune(sink=_nowhere, performed_by="operator", reason="routine", now=NOW)

    assert await audit.chain_head() != GENESIS


async def test_events_written_after_a_pass_continue_the_chain(
    retention: RetentionStore, audit: AuditLog
) -> None:
    await _emit(audit, 2, at=NOW - timedelta(days=500))
    await retention.prune(sink=_nowhere, performed_by="operator", reason="routine", now=NOW)

    await _emit(audit, 2, at=NOW)

    assert await audit.verify_chain() is None


# --- who may write an anchor ------------------------------------------------


async def test_the_application_role_cannot_forge_an_anchor() -> None:
    """An anchor is a claim about what was legitimately removed, so it has to be
    as hard to forge as the trail it vouches for. The broker has no reason to
    write one while serving a request, and cannot."""
    if not get_settings().app_database_url:
        pytest.skip("no separate application role is configured")

    app_engine = create_engine(get_settings())
    try:
        with pytest.raises(Exception, match="permission denied"):
            async with app_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO audit_retention_anchor "
                        "(removed_through_seq, removed_through_hash, removed_count, cutoff, "
                        " performed_by, reason) "
                        "VALUES (1, 'x', 1, now(), 'nobody', 'forged')"
                    )
                )
    finally:
        await app_engine.dispose()


async def test_the_application_role_can_read_anchors() -> None:
    """It has to: the verifier runs with the application's connection in the
    broker's own health checks."""
    if not get_settings().app_database_url:
        pytest.skip("no separate application role is configured")

    app_engine = create_engine(get_settings())
    try:
        async with app_engine.connect() as connection:
            await connection.execute(text("SELECT count(*) FROM audit_retention_anchor"))
    finally:
        await app_engine.dispose()
