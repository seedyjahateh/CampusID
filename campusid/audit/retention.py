"""Pruning the audit trail without making it unverifiable (FR-AUD-08).

Retention and a hash chain pull against each other. Deleting old events breaks
the chain by construction — the oldest surviving row links to a predecessor that
is gone, and a verifier cannot tell that apart from somebody having removed it to
hide something. Refusing to prune is not an answer either: a trail nobody may
delete from is one that eventually fills a disk, and the requirement asks for a
configurable retention in any case.

The answer is an anchor. A pass records where it cut and what the last removed
event hashed to, and the verifier resumes from that value instead of from the
genesis constant. Forging one means writing a row, and the application role
cannot — pruning is an owner operation run deliberately rather than something the
broker does while answering a request.

**Nothing is deleted that has not been exported first.** The caller supplies a
sink, the rows go to it, and only then does the delete run. An export that fails
half way leaves the trail intact, which is the direction this failure has to fall.

**The cut is on the sequence, not on the timestamp.** Once the boundary row is
chosen by time, the delete is `seq <= n` — so an event written with an old
`occurred_at` after the pass started cannot fall inside the window and be removed
without an anchor covering it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.chain import GENESIS
from campusid.audit.models import AuditEventRecord, AuditRetentionAnchor
from campusid.logging import get_logger

log = get_logger(__name__)

DEFAULT_RETENTION: Final = timedelta(days=400)
"""FR-AUD-08's default.

Four hundred days rather than a year, so a trail always covers the same month
last year — which is what somebody comparing an annual access review against the
previous one actually needs.
"""

Sink = Callable[[list[AuditEventRecord]], Awaitable[None]]
"""Where the events go before they are deleted. Supplied by the caller so this
module has no opinion about whether that is a file, a bucket or a SIEM."""


@dataclass(frozen=True, slots=True)
class Pruned:
    """What one pass did."""

    removed: int
    through_seq: int | None
    through_hash: str

    @property
    def anchored(self) -> bool:
        return self.removed > 0


class RetentionStore:
    """Prunes the trail and records the anchors that keep it verifiable."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def anchor_before(self, seq: int) -> tuple[int, str] | None:
        """The most recent anchor at or before a position, if there is one.

        Read by the verifier to decide where the surviving chain legitimately
        begins. Returns the sequence and hash of the last removed event, so the
        caller can check that the first surviving row links to it.
        """
        async with self._sessions() as session:
            row = await session.scalar(
                select(AuditRetentionAnchor)
                .where(AuditRetentionAnchor.removed_through_seq < seq)
                .order_by(AuditRetentionAnchor.removed_through_seq.desc())
                .limit(1)
            )
        if row is None:
            return None
        return row.removed_through_seq, row.removed_through_hash

    async def starting_hash(self) -> str:
        """What the oldest surviving event should link back to.

        The genesis constant when nothing has ever been pruned, and the last
        anchor's hash when something has. A verifier that assumed genesis after a
        prune would report the whole trail as broken, and one that skipped the
        check entirely would let a deletion pass unnoticed — the anchor is what
        makes the third option possible.
        """
        async with self._sessions() as session:
            row = await session.scalar(
                select(AuditRetentionAnchor)
                .order_by(AuditRetentionAnchor.removed_through_seq.desc())
                .limit(1)
            )
        return row.removed_through_hash if row is not None else GENESIS

    async def prune(
        self,
        *,
        older_than: timedelta = DEFAULT_RETENTION,
        sink: Sink,
        performed_by: str,
        reason: str,
        now: datetime | None = None,
        batch: int = 1000,
    ) -> Pruned:
        """Export and then remove everything older than the window.

        The boundary row is chosen first and the delete is keyed on its sequence,
        so an event written afterwards with an old timestamp cannot slip inside
        the window and be removed without an anchor covering it.
        """
        moment = now or datetime.now(UTC)
        cutoff = moment - older_than

        boundary = await self._boundary(cutoff)
        if boundary is None:
            log.info("audit.retention.nothing_to_prune", cutoff=cutoff.isoformat())
            return Pruned(removed=0, through_seq=None, through_hash=await self.starting_hash())

        through_seq, through_hash = boundary
        exported = await self._export(through_seq, sink, batch)

        async with self._sessions() as session, session.begin():
            removed = await session.execute(
                delete(AuditEventRecord).where(AuditEventRecord.seq <= through_seq)
            )
            session.add(
                AuditRetentionAnchor(
                    removed_through_seq=through_seq,
                    removed_through_hash=through_hash,
                    removed_count=exported,
                    cutoff=cutoff,
                    performed_at=moment,
                    performed_by=performed_by,
                    reason=reason,
                )
            )

        log.info(
            "audit.retention.pruned",
            removed=removed.rowcount,
            through_seq=through_seq,
            cutoff=cutoff.isoformat(),
            performed_by=performed_by,
        )
        return Pruned(removed=exported, through_seq=through_seq, through_hash=through_hash)

    async def _boundary(self, cutoff: datetime) -> tuple[int, str] | None:
        """The newest event older than the cutoff, or None if there is none."""
        async with self._sessions() as session:
            row = await session.scalar(
                select(AuditEventRecord)
                .where(AuditEventRecord.occurred_at < cutoff)
                .order_by(AuditEventRecord.seq.desc())
                .limit(1)
            )
        return (row.seq, row.hash) if row is not None else None

    async def _export(self, through_seq: int, sink: Sink, batch: int) -> int:
        """Hand every doomed event to the sink, oldest first, before anything is
        deleted. A failure here leaves the trail intact, which is the direction
        this failure has to fall."""
        exported = 0
        last = 0
        while True:
            async with self._sessions() as session:
                rows = list(
                    await session.scalars(
                        select(AuditEventRecord)
                        .where(
                            AuditEventRecord.seq > last,
                            AuditEventRecord.seq <= through_seq,
                        )
                        .order_by(AuditEventRecord.seq)
                        .limit(batch)
                    )
                )
            if not rows:
                return exported
            await sink(rows)
            exported += len(rows)
            last = rows[-1].seq

    async def due(
        self, *, older_than: timedelta = DEFAULT_RETENTION, now: datetime | None = None
    ) -> int:
        """How many events a pass would remove. For an operator deciding whether
        to run one, and for a dashboard that shows the trail's span."""
        cutoff = (now or datetime.now(UTC)) - older_than
        async with self._sessions() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(AuditEventRecord)
                .where(AuditEventRecord.occurred_at < cutoff)
            )
        return int(count or 0)
