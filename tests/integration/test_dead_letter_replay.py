"""The dead-letter queue and replaying it (FR-LC-09).

Against live Postgres, because the queue's whole value is durability: an account
that could not be disabled is a security finding, and a finding that lives in a
process is one that ends when the process does.

The behaviour worth reading is what happens when a replay fails again. It
extends the history on the item that is already there rather than filing a
second one — otherwise the queue grows with every attempt to drain it, which is
the failure mode that makes people stop draining it.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Person
from campusid.lifecycle.deadletter import DeadLetterQueue, Item
from campusid.lifecycle.models import DeadLetter
from campusid.lifecycle.retry import Attempt, RetriesExhausted

pytestmark = pytest.mark.integration

LOGIN = "sam.obrien@campus.test"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(engine)


@pytest.fixture
def queue(sessions: async_sessionmaker[AsyncSession]) -> DeadLetterQueue:
    return DeadLetterQueue(sessions)


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
        await session.execute(delete(DeadLetter).where(DeadLetter.person_uuid == key))
        await session.execute(delete(Person).where(Person.person_uuid == key))


def _attempts(count: int) -> list[Attempt]:
    return [Attempt(number=index, error="directory unreachable") for index in range(1, count + 1)]


async def _file(queue: DeadLetterQueue, person: str, *, attempts: int = 5) -> str:
    return await queue.record(
        person_uuid=person,
        target="ldap",
        operation="disable",
        payload={"login": LOGIN},
        attempts=_attempts(attempts),
    )


# --- filing -----------------------------------------------------------------


async def test_an_exhausted_write_becomes_a_durable_row(
    queue: DeadLetterQueue, person: str
) -> None:
    await _file(queue, person)

    outstanding = await queue.outstanding()

    mine = [item for item in outstanding if item.person_uuid == person]
    assert mine[0].target == "ldap"
    assert mine[0].payload == {"login": LOGIN}
    assert len(mine[0].attempts) == 5


async def test_the_login_is_carried_so_a_replay_can_still_address_it(
    queue: DeadLetterQueue, person: str
) -> None:
    """By the time somebody replays this, the person's identifiers may have been
    released and the registry would no longer volunteer one."""
    await _file(queue, person)

    item = next(row for row in await queue.outstanding() if row.person_uuid == person)

    assert item.payload["login"] == LOGIN


async def test_filing_the_same_failure_twice_extends_one_item(
    queue: DeadLetterQueue, person: str
) -> None:
    """A stuck account retried nightly would otherwise produce a queue that
    grows with every attempt to drain it."""
    first = await _file(queue, person)
    second = await _file(queue, person, attempts=3)

    assert first == second
    item = next(row for row in await queue.outstanding() if row.person_uuid == person)
    assert len(item.attempts) == 8


# --- replaying --------------------------------------------------------------


async def test_a_successful_replay_clears_the_item(queue: DeadLetterQueue, person: str) -> None:
    item_id = await _file(queue, person)
    dispatched: list[Item] = []

    async def _dispatch(item: Item) -> None:
        dispatched.append(item)

    assert await queue.replay(item_id, _dispatch)

    assert dispatched[0].payload["login"] == LOGIN
    assert not [row for row in await queue.outstanding() if row.person_uuid == person]


async def test_a_replayed_item_is_marked_rather_than_deleted(
    queue: DeadLetterQueue, person: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "This account was still enabled for three days" is a question an auditor
    asks after somebody fixes it."""
    item_id = await _file(queue, person)

    async def _dispatch(item: Item) -> None:
        return None

    await queue.replay(item_id, _dispatch)

    async with sessions() as session:
        row = await session.get(DeadLetter, uuid.UUID(item_id))
    assert row is not None
    assert row.replayed_at is not None


async def test_a_failed_replay_leaves_the_item_outstanding(
    queue: DeadLetterQueue, person: str
) -> None:
    item_id = await _file(queue, person)

    async def _dispatch(item: Item) -> None:
        raise RetriesExhausted(_attempts(5))

    assert not await queue.replay(item_id, _dispatch)

    still = [row for row in await queue.outstanding() if row.person_uuid == person]
    assert still and still[0].id == item_id


async def test_a_failed_replay_does_not_file_a_second_item(
    queue: DeadLetterQueue, person: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The failure mode that makes people stop draining a queue."""
    item_id = await _file(queue, person)

    async def _dispatch(item: Item) -> None:
        raise RetriesExhausted(_attempts(5))

    await queue.replay(item_id, _dispatch)
    await queue.replay(item_id, _dispatch)

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(DeadLetter).where(DeadLetter.person_uuid == uuid.UUID(person))
            )
        )
    assert len(rows) == 1
    assert len(rows[0].attempts) == 15


async def test_an_unexpected_failure_is_recorded_too(queue: DeadLetterQueue, person: str) -> None:
    """A replay that raises something other than exhausted retries is still a
    replay that did not work, and the item must not quietly clear."""
    item_id = await _file(queue, person)

    async def _dispatch(item: Item) -> None:
        raise RuntimeError("the replay code itself is broken")

    assert not await queue.replay(item_id, _dispatch)
    assert [row for row in await queue.outstanding() if row.person_uuid == person]


async def test_replaying_something_already_replayed_does_nothing(
    queue: DeadLetterQueue, person: str
) -> None:
    """Two operators draining the same queue must not dispatch the same write
    twice — which for a disable is harmless and for a create is not."""
    item_id = await _file(queue, person)
    calls: list[Item] = []

    async def _dispatch(item: Item) -> None:
        calls.append(item)

    await queue.replay(item_id, _dispatch)
    assert not await queue.replay(item_id, _dispatch)

    assert len(calls) == 1


async def test_replaying_an_unknown_item_is_not_an_error(queue: DeadLetterQueue) -> None:
    async def _dispatch(item: Item) -> None:
        raise AssertionError("should not be dispatched")

    assert not await queue.replay(str(uuid.uuid4()), _dispatch)
