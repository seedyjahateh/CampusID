"""Holding and replaying failed downstream writes (FR-LC-09).

The store behind the dead letter, and the thing that makes an exhausted retry
different from a lost one: an item here is visible, countable, and replayable.

**Replay is the same operation, not a different one.** The item carries the
target, the operation and the payload, and replaying dispatches exactly what
failed. A separate "fix it" path would be a second implementation of
provisioning that nobody exercises until the day it matters.

**An item is marked replayed, never deleted.** "This account was still enabled
for three days" is a question an auditor asks after somebody fixes it, and a
deleted row cannot answer it.

**A replay that fails again is not a new item.** It updates the attempts on the
one that is already there, because two rows for one stuck account make the queue
grow with every attempt to drain it.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.log import correlation_id
from campusid.lifecycle.models import DeadLetter
from campusid.lifecycle.retry import Attempt, RetriesExhausted
from campusid.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Item:
    """One dead letter, in a shape a caller can act on."""

    id: str
    person_uuid: str
    target: str
    operation: str
    payload: dict[str, Any]
    attempts: list[dict[str, Any]]
    created_at: datetime


class DeadLetterQueue:
    """Reads and writes the dead-letter table."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def record(
        self,
        *,
        person_uuid: str,
        target: str,
        operation: str,
        payload: dict[str, Any],
        attempts: list[Attempt],
    ) -> str:
        """File a failed write, or add to the one already filed.

        Keyed on the person, target and operation rather than given a fresh row
        each time: a stuck account retried nightly would otherwise produce a
        queue that grows with every attempt to drain it, and the thing an
        operator wants to see is one entry with a history.
        """
        history = [{"attempt": item.number, "error": item.error} for item in attempts]

        async with self._sessions() as session, session.begin():
            existing = await session.scalar(
                select(DeadLetter).where(
                    DeadLetter.person_uuid == uuid.UUID(person_uuid),
                    DeadLetter.target == target,
                    DeadLetter.operation == operation,
                    DeadLetter.replayed_at.is_(None),
                )
            )
            if existing is not None:
                existing.attempts = [*existing.attempts, *history]
                existing.payload = payload
                log.warning(
                    "provisioning.dead_letter.updated",
                    person_uuid=person_uuid,
                    target=target,
                    operation=operation,
                    total_attempts=len(existing.attempts),
                )
                return str(existing.id)

            item = DeadLetter(
                person_uuid=uuid.UUID(person_uuid),
                target=target,
                operation=operation,
                payload=payload,
                attempts=history,
                correlation_id=correlation_id(),
            )
            session.add(item)
            await session.flush()
            log.error(
                "provisioning.dead_letter.recorded",
                person_uuid=person_uuid,
                target=target,
                operation=operation,
            )
            return str(item.id)

    async def outstanding(self, *, limit: int = 100) -> list[Item]:
        """Everything still stuck, oldest first.

        Oldest first because the oldest is the one that has been wrong longest,
        which is the ordering an operator draining a queue wants and the
        opposite of what a log gives them.
        """
        async with self._sessions() as session:
            rows = await session.scalars(
                select(DeadLetter)
                .where(DeadLetter.replayed_at.is_(None))
                .order_by(DeadLetter.created_at)
                .limit(limit)
            )
            return [_to_item(row) for row in rows]

    async def replay(self, item_id: str, dispatch: Callable[[Item], Awaitable[None]]) -> bool:
        """Run a stuck item again through whatever dispatches it.

        Returns whether it succeeded. A failure leaves the item outstanding with
        its history extended rather than filing a second one, because two rows
        for one stuck account make the queue grow as it is drained.
        """
        async with self._sessions() as session:
            row = await session.get(DeadLetter, uuid.UUID(item_id))
            if row is None or row.replayed_at is not None:
                return False
            item = _to_item(row)

        try:
            await dispatch(item)
        except RetriesExhausted as exc:
            await self.record(
                person_uuid=item.person_uuid,
                target=item.target,
                operation=item.operation,
                payload=item.payload,
                attempts=exc.attempts,
            )
            return False
        except Exception as exc:
            await self.record(
                person_uuid=item.person_uuid,
                target=item.target,
                operation=item.operation,
                payload=item.payload,
                attempts=[Attempt(number=1, error=str(exc))],
            )
            return False

        async with self._sessions() as session, session.begin():
            replayed = await session.get(DeadLetter, uuid.UUID(item_id))
            if replayed is not None:
                # Marked rather than deleted: "this was stuck for three days" is
                # a question somebody asks after it is fixed.
                replayed.replayed_at = datetime.now(UTC)
        log.info("provisioning.dead_letter.replayed", item=item_id, target=item.target)
        return True


def _to_item(row: DeadLetter) -> Item:
    return Item(
        id=str(row.id),
        person_uuid=str(row.person_uuid),
        target=row.target,
        operation=row.operation,
        payload=dict(row.payload),
        attempts=list(row.attempts),
        created_at=row.created_at,
    )
