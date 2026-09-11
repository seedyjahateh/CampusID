"""The export format, without a database (FR-AUD-08).

The streaming and the ordering, against a substituted store. What the format has
to be is not a database question: one JSON object per line, oldest first, every
line carrying the hashes, and a file that a SIEM can split and resume at a line
boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from campusid.audit.export import CONTENT_TYPE, PAGE, filename, ndjson
from campusid.audit.models import AuditEventRecord
from campusid.audit.query import AuditQueryStore, Page, Query

WHEN = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


@dataclass
class _Record:
    seq: int
    event_id: str = "event"
    event_type: str = "auth.success"
    outcome: str = "success"
    occurred_at: datetime = WHEN
    correlation_id: str = "chain"
    actor: str | None = None
    subject: str | None = "somebody"
    target: str | None = None
    reason: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    hash: str = "a" * 64


class _Store:
    """The query store, reduced to the one call the exporter makes.

    Pages are served newest-first with a keyset cursor, exactly as the real one
    does — so the exporter's reversal is exercised rather than assumed.
    """

    def __init__(self, total: int, page: int = 3) -> None:
        self.rows = [_Record(seq=n) for n in range(1, total + 1)]
        self.page = page
        self.asked: list[Query] = []

    async def search(self, query: Query) -> Page:
        self.asked.append(query)
        newest_first = sorted(self.rows, key=lambda r: r.seq, reverse=True)
        if query.before_seq is not None:
            newest_first = [r for r in newest_first if r.seq < query.before_seq]
        window = newest_first[: self.page]
        cursor = window[-1].seq if len(newest_first) > self.page else None
        return Page(events=cast("list[AuditEventRecord]", window), next_cursor=cursor)


def _store(total: int, page: int = 3) -> AuditQueryStore:
    return cast("AuditQueryStore", _Store(total, page))


async def _lines(store: AuditQueryStore, query: Query | None = None) -> list[dict[str, Any]]:
    return [json.loads(line) async for line in ndjson(store, query or Query())]


# --- the format -------------------------------------------------------------


async def test_one_object_per_line() -> None:
    """No enclosing array and no trailing comma to get wrong, which is what a
    SIEM ingests without being told anything."""
    raw = [line async for line in ndjson(_store(4), Query())]

    assert len(raw) == 4
    assert all(line.endswith(b"\n") for line in raw)
    assert all(line.count(b"\n") == 1 for line in raw)


async def test_lines_are_json_objects() -> None:
    assert all(isinstance(event, dict) for event in await _lines(_store(3)))


async def test_keys_are_ordered_within_a_line() -> None:
    """So two exports of one event are byte-identical, and a diff between them
    means something changed rather than that a dict iterated differently."""
    raw = [line async for line in ndjson(_store(1), Query())]

    decoded = json.loads(raw[0])
    assert list(decoded) == sorted(decoded)


def test_the_media_type_promises_a_stream() -> None:
    """Not `application/json`, which would promise a single document and deliver
    a sequence of them."""
    assert CONTENT_TYPE == "application/x-ndjson"


# --- ordering ---------------------------------------------------------------


async def test_an_export_is_oldest_first() -> None:
    """An export is read forward and appended to. A SIEM ingesting newest-first
    would have to reverse the file before it could stitch two together."""
    events = await _lines(_store(7))

    assert [event["seq"] for event in events] == sorted(event["seq"] for event in events)


async def test_every_event_appears_exactly_once() -> None:
    events = await _lines(_store(10))

    assert sorted(event["seq"] for event in events) == list(range(1, 11))


async def test_a_trail_smaller_than_one_page_still_works() -> None:
    assert len(await _lines(_store(2, page=10))) == 2


async def test_an_empty_trail_exports_nothing() -> None:
    assert await _lines(_store(0)) == []


async def test_pages_are_asked_for_at_the_stores_own_ceiling() -> None:
    """So the exporter cannot request a page the store would silently clamp,
    which would make the cursor arithmetic disagree with what came back."""
    store = _Store(5)

    await _lines(cast("AuditQueryStore", store), Query(limit=1))

    assert all(asked.limit == PAGE for asked in store.asked)


async def test_filters_are_carried_into_every_page() -> None:
    store = _Store(9)

    await _lines(cast("AuditQueryStore", store), Query(subject="somebody"))

    assert all(asked.subject == "somebody" for asked in store.asked)


async def test_a_starting_cursor_is_honoured() -> None:
    """An export resumed from a known position, which is how a scheduled one
    picks up where the last left off."""
    events = await _lines(_store(8), Query(before_seq=4))

    assert [event["seq"] for event in events] == [1, 2, 3]


# --- what a line carries ----------------------------------------------------


async def test_every_line_carries_its_chain() -> None:
    """An export that dropped them would be a copy nobody can check against the
    original, which is most of the point of exporting an audit trail."""
    events = await _lines(_store(3))

    assert all(len(event["hash"]) == 64 for event in events)
    assert all(len(event["prev_hash"]) == 64 for event in events)


async def test_a_line_carries_the_whole_event() -> None:
    events = await _lines(_store(1))

    assert set(events[0]) >= {
        "seq",
        "event_id",
        "event_type",
        "outcome",
        "occurred_at",
        "correlation_id",
        "subject",
        "detail",
    }


# --- the filename -----------------------------------------------------------


def test_the_filename_names_the_window() -> None:
    """An export lands in a downloads folder next to four others, and
    `export.json` is how the wrong window gets ingested."""
    name = filename(Query(since=WHEN, until=WHEN + timedelta(days=2)))

    assert name == "campusid-audit-2026-09-11-to-2026-09-13.ndjson"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (Query(), "campusid-audit-start-to-now.ndjson"),
        (Query(since=WHEN), "campusid-audit-2026-09-11-to-now.ndjson"),
        (Query(until=WHEN), "campusid-audit-start-to-2026-09-11.ndjson"),
    ],
)
def test_an_open_window_says_so(query: Query, expected: str) -> None:
    """Rather than leaving the bound out, which would make an unbounded export
    look like a narrow one in a directory listing."""
    assert filename(query) == expected


def test_replacing_a_query_does_not_change_the_original() -> None:
    """The exporter rewrites the limit and cursor on every page. A mutable query
    would leave the caller's filters altered after an export, which is the kind
    of bug that only shows up on the second call."""
    original = Query(subject="somebody", limit=5)

    replace(original, limit=PAGE)

    assert original.limit == 5
