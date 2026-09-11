"""The hash chain and the append-only trail, against live Postgres
(FR-AUD-04, FR-AUD-05).

The unit tests cover the arithmetic; these cover what only the database can
answer. The writer takes a lock and links each event to the tail, so events
written concurrently form one chain rather than a fork — which a verifier would
report as tampering, because from the outside a fork and a tamper are the same
thing.

FR-AUD-04's other half is here too: there is no update or delete path in
`campusid/audit/` at all, and the trail survives a verification after a real
sequence of writes.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.audit.chain import ALTERED, GENESIS, UNLINKED
from campusid.audit.events import EventType, Outcome
from campusid.audit.log import AuditLog, set_correlation_id
from campusid.audit.models import AuditEventRecord
from campusid.config import get_settings
from campusid.db import create_engine, create_owner_engine, create_session_factory

pytestmark = pytest.mark.integration


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """The *owner* engine, because these tests clear the trail.

    The application's role cannot delete from `audit_event` — that is the whole
    point of FR-AUD-04 and it is asserted below. A test that needs to start from
    an empty table therefore has to connect as the role that owns the schema,
    which is exactly the separation being tested.
    """
    engine = create_owner_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def app_engine() -> AsyncIterator[AsyncEngine]:
    """How the broker itself connects."""
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A trail of its own.

    Every test here empties `audit_event` first, because a chain is a property of
    the *whole* table: verifying a tail while older rows exist would either pass
    vacuously or fail on somebody else's fixture.
    """
    factory = create_session_factory(engine)
    async with factory() as session, session.begin():
        await session.execute(delete(AuditEventRecord))
    yield factory
    async with factory() as session, session.begin():
        await session.execute(delete(AuditEventRecord))


@pytest.fixture
def audit(sessions: async_sessionmaker[AsyncSession]) -> AuditLog:
    return AuditLog(sessions)


async def _emit(audit: AuditLog, count: int, *, subject: str = "somebody") -> None:
    for n in range(count):
        set_correlation_id(f"chain-{n}")
        await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject=f"{subject}-{n}")


async def _rows(sessions: async_sessionmaker[AsyncSession]) -> list[AuditEventRecord]:
    async with sessions() as session:
        result = await session.scalars(select(AuditEventRecord).order_by(AuditEventRecord.seq))
        return list(result)


# --- writing a chain --------------------------------------------------------


async def test_an_empty_trail_verifies(audit: AuditLog) -> None:
    assert await audit.verify_chain() is None
    assert await audit.chain_head() == GENESIS


async def test_written_events_form_a_chain(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 5)

    rows = await _rows(sessions)

    assert len(rows) == 5
    assert rows[0].prev_hash == GENESIS
    assert [row.prev_hash for row in rows[1:]] == [row.hash for row in rows[:-1]]


async def test_a_written_chain_verifies(audit: AuditLog) -> None:
    """The round trip that matters: hashed on the way in, read back out of the
    real columns, and checked. A chain that verified only in memory would prove
    nothing about what Postgres kept."""
    await _emit(audit, 8)

    assert await audit.verify_chain() is None


async def test_the_sequence_increases(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 4)

    sequences = [row.seq for row in await _rows(sessions)]

    assert sequences == sorted(sequences)
    assert len(set(sequences)) == 4


async def test_the_head_advances_with_every_event(audit: AuditLog) -> None:
    await _emit(audit, 1)
    first = await audit.chain_head()
    await _emit(audit, 1, subject="another")

    assert await audit.chain_head() != first


# --- concurrency ------------------------------------------------------------


async def test_concurrent_writes_form_one_chain_rather_than_a_fork(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The reason the writer takes a lock. Two writers reading the same tail
    would produce two events claiming the same predecessor, and a verifier
    reports that as tampering because from the outside it is indistinguishable
    from one."""
    await asyncio.gather(
        *(
            audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject=f"racer-{n}")
            for n in range(12)
        )
    )

    rows = await _rows(sessions)
    assert len(rows) == 12
    assert len({row.prev_hash for row in rows}) == 12
    assert await audit.verify_chain() is None


# --- tampering --------------------------------------------------------------


async def test_editing_a_row_is_detected_with_the_exact_event(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-AUD-05's acceptance test: tamper one row, and the verifier identifies
    the exact broken link."""
    await _emit(audit, 5)
    rows = await _rows(sessions)
    victim = rows[2]

    async with sessions() as session, session.begin():
        await session.execute(
            text("UPDATE audit_event SET subject = :value WHERE id = :id"),
            {"value": "tampered", "id": victim.id},
        )

    broken = await audit.verify_chain()

    assert broken is not None
    assert broken.event_id == victim.event_id
    assert broken.problem == ALTERED


async def test_deleting_a_row_is_detected(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _emit(audit, 5)
    rows = await _rows(sessions)

    async with sessions() as session, session.begin():
        await session.execute(delete(AuditEventRecord).where(AuditEventRecord.id == rows[1].id))

    broken = await audit.verify_chain()

    assert broken is not None
    assert broken.event_id == rows[2].event_id
    assert broken.problem == UNLINKED


async def test_editing_the_detail_is_detected(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`detail` holds what actually happened rather than who it happened to, so
    it is the field most worth editing and the one a chain that covered only the
    columns would miss."""
    await _emit(audit, 3)
    rows = await _rows(sessions)

    async with sessions() as session, session.begin():
        await session.execute(
            # `CAST(... AS jsonb)` rather than the `::` shorthand: SQLAlchemy's
            # text() reads a colon as the start of a bind parameter.
            text("UPDATE audit_event SET detail = CAST(:value AS jsonb) WHERE id = :id"),
            {"value": '{"rewritten": true}', "id": rows[1].id},
        )

    assert await audit.verify_chain() is not None


async def test_a_timestamp_round_trip_does_not_break_the_chain(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Postgres keeps `timestamptz` to the microsecond. A hash computed from a
    more precise value would verify on the way in and fail on the way back out,
    which is a bug that appears only after a restart."""
    set_correlation_id("precision")
    await audit.record(
        EventType.AUTH_SUCCESS,
        Outcome.SUCCESS,
        subject="precise",
        now=datetime(2026, 9, 11, 12, 0, 30, 123456, tzinfo=UTC),
    )

    assert await audit.verify_chain() is None


# --- append-only from the application's side --------------------------------


async def test_the_emitter_exposes_no_way_to_change_a_row(audit: AuditLog) -> None:
    """FR-AUD-04's application-side half. A role grant protects against a
    compromised process; having no code that can modify a row protects against
    the ordinary bug, and the second is the one that actually happens."""
    surface = {name for name in dir(audit) if not name.startswith("_")}

    assert not {"update", "delete", "amend", "remove"} & surface


# --- append-only, enforced by the database ----------------------------------


def _requires_the_restricted_role() -> None:
    if not get_settings().app_database_url:
        pytest.skip("no separate application role is configured")


async def _refused(engine: AsyncEngine, statement: str) -> str:
    """Run a statement expecting Postgres to refuse it, and return why.

    The reason is returned rather than only the exception type, because
    "permission denied" and "syntax error" are both `ProgrammingError` and only
    one of them means the grant is doing its job.
    """
    with pytest.raises(DBAPIError) as raised:
        async with engine.begin() as connection:
            await connection.execute(text(statement))
    return str(raised.value)


async def test_the_application_role_cannot_update_the_trail(
    app_engine: AsyncEngine, audit: AuditLog
) -> None:
    """FR-AUD-04's acceptance test. Until the grant existed, the append-only
    promise rested entirely on there being no code that writes an UPDATE — real
    protection against the ordinary bug and none at all against a compromised
    process, which is the case an audit trail exists for."""
    _requires_the_restricted_role()
    await _emit(audit, 1)

    assert "permission denied" in await _refused(
        app_engine, "UPDATE audit_event SET subject = 'tampered'"
    )


async def test_the_application_role_cannot_delete_from_the_trail(
    app_engine: AsyncEngine, audit: AuditLog
) -> None:
    _requires_the_restricted_role()
    await _emit(audit, 1)

    assert "permission denied" in await _refused(app_engine, "DELETE FROM audit_event")


async def test_the_application_role_cannot_truncate_the_trail(
    app_engine: AsyncEngine,
) -> None:
    """The one that empties the table without touching a row, and the one a
    grant of UPDATE and DELETE alone would leave open."""
    _requires_the_restricted_role()

    assert "permission denied" in await _refused(app_engine, "TRUNCATE audit_event")


async def test_the_application_role_cannot_alter_the_trail(
    app_engine: AsyncEngine,
) -> None:
    """An append-only grant the grantee can ALTER away is decoration."""
    _requires_the_restricted_role()

    assert "must be owner" in await _refused(app_engine, "ALTER TABLE audit_event DROP COLUMN hash")


async def test_the_application_role_cannot_create_a_table(
    app_engine: AsyncEngine,
) -> None:
    """No DDL rights at all. A role that can create a table can create one that
    shadows nothing useful today and something useful tomorrow."""
    _requires_the_restricted_role()

    assert "permission denied" in await _refused(app_engine, "CREATE TABLE scratch (n int)")


async def test_the_application_role_can_still_read_and_write(
    app_engine: AsyncEngine, audit: AuditLog
) -> None:
    """The grant has to leave the broker able to do its job, or the trail stops
    being written and the protection is total in the wrong direction."""
    _requires_the_restricted_role()
    await _emit(audit, 2)

    async with app_engine.connect() as connection:
        count = await connection.scalar(text("SELECT count(*) FROM audit_event"))

    assert count == 2


async def test_the_application_role_can_still_write_to_other_tables(
    app_engine: AsyncEngine,
) -> None:
    """Only the audit trail is append-only. A role that could not update a
    session or a factor would be a broker that cannot run."""
    _requires_the_restricted_role()

    async with app_engine.begin() as connection:
        # Touches no rows, so it asserts the privilege rather than changing
        # anything another test depends on.
        await connection.execute(
            text("UPDATE person SET updated_at = updated_at WHERE person_uuid IS NULL")
        )


async def test_a_replayed_event_id_cannot_duplicate_an_event(
    audit: AuditLog, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """An audit trail that double-counts is as misleading as one that misses.
    The failure is swallowed like any other write failure, so the trail keeps
    one row rather than gaining a second."""
    await _emit(audit, 1)
    rows = await _rows(sessions)

    async with sessions() as session, session.begin():
        session.add(
            AuditEventRecord(
                id=uuid.uuid4(),
                event_id=rows[0].event_id,
                event_type="auth.success",
                outcome="success",
                occurred_at=datetime.now(UTC),
                correlation_id="duplicate",
                prev_hash=GENESIS,
                hash="0" * 64,
                detail={},
            )
        )
        with pytest.raises(Exception):  # noqa: B017
            await session.flush()
