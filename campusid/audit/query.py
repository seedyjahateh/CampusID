"""Reading the audit trail (FR-AUD-03).

A trail nobody can query is a trail nobody uses, and the questions it has to
answer are specific: what happened to this person, what did this relying party
receive, what failed in this window, and what else happened around this event.
Those four shapes are what the filters and the indexes are for — not a generic
search over a large table.

**Paged on the sequence, not on an offset.** `OFFSET 10000` re-reads ten thousand
rows to skip them, and an audit trail is exactly the table where somebody pages
to the end. Keyset paging reads only the page. It also stays correct while events
are being written, which offset paging does not: a row inserted between two
requests shifts every subsequent offset by one, and an investigator quietly loses
an event they never knew was there.

**Newest first, because that is how the question is asked.** "What happened to
this person" means recently, almost always. The timeline view reverses it for
display, which is a presentation decision and belongs there rather than here.

**The cursor is the sequence number, not an opaque token.** It reveals how many
events exist, which is information somebody entitled to read the trail already
has, and in exchange the page boundary is legible in a log and reproducible by
hand — which matters when the thing being investigated is the investigation tool.

**Filters compose and none of them is required.** An unfiltered query is a
legitimate thing to ask of an audit trail, so it is answered — bounded by the
page size like any other, rather than refused on the theory that nobody means it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.models import AuditEventRecord

DEFAULT_LIMIT: Final = 50
MAX_LIMIT: Final = 500
"""A page an operator can read and a response the browser can hold.

Capped rather than trusted: a caller asking for a million rows gets five hundred,
because the alternative is one request that reads the whole table and a database
that stops answering anything else.
"""


@dataclass(frozen=True, slots=True)
class Query:
    """What to look for. Every field is optional and they compose."""

    subject: str | None = None
    """Who the event was about. The person-centric view (US-02)."""

    actor: str | None = None
    """Who did it, when that differs from who it was about — an administrator
    acting on somebody else, which is the case worth being able to ask about
    separately."""

    target: str | None = None
    """What it was done to: the relying party that received attributes, the
    entity that was registered. The disclosure record under FERPA §99.32."""

    event_type: str | None = None
    outcome: str | None = None
    correlation_id: str | None = None
    """Everything that happened around one event (FR-AUD-02). The single most
    useful filter, and the reason the id exists."""

    since: datetime | None = None
    until: datetime | None = None
    """Half-open: `since` counts, `until` does not. The same convention the
    affiliation and role tables use, so "events on the 3rd" is one expression
    rather than a question about midnight."""

    limit: int = DEFAULT_LIMIT
    before_seq: int | None = None
    """The cursor: return events strictly older than this position."""


@dataclass(frozen=True, slots=True)
class Page:
    """One page of results, and how to ask for the next."""

    events: list[AuditEventRecord] = field(default_factory=list)
    next_cursor: int | None = None
    """None when this is the last page.

    Derived from whether a full page came back rather than from a second count
    query: counting the whole match to decide whether to show a Next button is
    the classic way an audit view becomes the slowest page in the console.
    """


class AuditQueryStore:
    """Answers questions about the trail."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def search(self, query: Query) -> Page:
        """One page of matching events, newest first."""
        limit = max(1, min(query.limit, MAX_LIMIT))
        async with self._sessions() as session:
            rows = list(
                await session.scalars(
                    _filtered(select(AuditEventRecord), query)
                    .order_by(AuditEventRecord.seq.desc())
                    # One more than asked for, so "is there another page" is
                    # answered by what came back rather than by counting the
                    # whole match.
                    .limit(limit + 1)
                )
            )

        if len(rows) > limit:
            return Page(events=rows[:limit], next_cursor=rows[limit - 1].seq)
        return Page(events=rows, next_cursor=None)

    async def timeline(self, subject: str, *, limit: int = DEFAULT_LIMIT) -> list[AuditEventRecord]:
        """One person's history, oldest first (US-02, FR-ADM-05).

        Reversed here rather than queried ascending, so the *most recent* page is
        the one returned — a timeline that started at the beginning of a busy
        account's history would show a first login from three years ago and
        nothing since.
        """
        page = await self.search(Query(subject=subject, limit=limit))
        return list(reversed(page.events))


def _filtered(statement: Select[Any], query: Query) -> Select[Any]:
    """Apply whichever filters were given.

    Equality on the indexed columns and a half-open range on time. Nothing here
    does a pattern match: `LIKE '%…%'` on a subject cannot use the index, and an
    audit view that degrades to a sequential scan is one an operator stops
    reaching for.
    """
    if query.subject is not None:
        statement = statement.where(AuditEventRecord.subject == query.subject)
    if query.actor is not None:
        statement = statement.where(AuditEventRecord.actor == query.actor)
    if query.target is not None:
        statement = statement.where(AuditEventRecord.target == query.target)
    if query.event_type is not None:
        statement = statement.where(AuditEventRecord.event_type == query.event_type)
    if query.outcome is not None:
        statement = statement.where(AuditEventRecord.outcome == query.outcome)
    if query.correlation_id is not None:
        statement = statement.where(AuditEventRecord.correlation_id == query.correlation_id)
    if query.since is not None:
        statement = statement.where(AuditEventRecord.occurred_at >= query.since)
    if query.until is not None:
        statement = statement.where(AuditEventRecord.occurred_at < query.until)
    if query.before_seq is not None:
        statement = statement.where(AuditEventRecord.seq < query.before_seq)
    return statement


def as_json(record: AuditEventRecord) -> dict[str, Any]:
    """One event, in the shape the API and the export both use.

    Shared so a record read through the console and the same record in an export
    cannot disagree — which is the first thing anybody checks when they suspect
    one of them.

    The chain columns are included. An auditor handed a page of events should be
    able to verify the links themselves rather than take the console's word for
    it, and the console is the thing whose word is in question if the trail is.
    """
    return {
        "seq": record.seq,
        "event_id": record.event_id,
        "event_type": record.event_type,
        "outcome": record.outcome,
        "occurred_at": record.occurred_at.isoformat(),
        "correlation_id": record.correlation_id,
        "actor": record.actor,
        "subject": record.subject,
        "target": record.target,
        "reason": record.reason,
        "source_ip": record.source_ip,
        "user_agent": record.user_agent,
        "session_id": record.session_id,
        "detail": record.detail,
        "prev_hash": record.prev_hash,
        "hash": record.hash,
    }
