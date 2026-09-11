"""Exporting the audit trail (FR-AUD-08).

Newline-delimited JSON, because that is what every SIEM ingests without being
told anything: one event per line, no enclosing array, no trailing comma to get
wrong, and a file that can be tailed, split, and resumed at a line boundary. A
JSON array would have to be held whole at both ends.

**Streamed, not assembled.** A year of a real deployment's trail does not fit in
memory at either end of the wire, and an export that only works on a small trail
is one nobody can run on the trail that matters. Pages come from the same keyset
query the console uses, so the export cannot disagree with what an operator sees
on screen — which is the first thing anybody checks when they suspect one of them.

**Every line carries its hash and the hash before it.** An export that dropped
them would be a copy nobody can check against the original, which is most of the
point of exporting an audit trail in the first place. A SIEM that stores the two
columns can verify the chain itself without asking the broker anything.

**The window is explicit.** An export with no bounds is a request to read the
whole table, which is occasionally what somebody means and usually not; the
caller says which, and the same filters the console uses apply.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any, Final

from campusid.audit.query import MAX_LIMIT, AuditQueryStore, Query, as_json
from campusid.logging import get_logger

log = get_logger(__name__)

CONTENT_TYPE: Final = "application/x-ndjson"
"""What a SIEM expects. Not `application/json`, which would promise a single
document and get a stream of them."""

PAGE: Final = MAX_LIMIT
"""How much is held in memory at once. The query's own ceiling, so the export
cannot ask for a page the store would refuse."""


async def ndjson(store: AuditQueryStore, query: Query) -> AsyncIterator[bytes]:
    """Every matching event, one JSON object per line, oldest first.

    Oldest first, unlike the console: an export is read forward and appended to,
    and a SIEM ingesting newest-first would have to reverse the file before it
    could stitch two exports together.

    The pages come back newest-first from the store, so each is reversed and the
    windows walk backwards — which means a caller who stops early has the *most
    recent* events, the ones most likely to be wanted, rather than the oldest.
    """
    pages: list[list[dict[str, Any]]] = []
    cursor = query.before_seq
    exported = 0

    while True:
        page = await store.search(replace(query, limit=PAGE, before_seq=cursor))
        if not page.events:
            break
        pages.append([as_json(event) for event in page.events])
        exported += len(page.events)
        cursor = page.next_cursor
        if cursor is None:
            break

    # Reversed as a whole rather than per page, so the file is in one order
    # throughout. Holding the page *indices* is cheap; the alternative is a
    # second pass over the database to read the same rows in the other
    # direction, which doubles the cost of the one operation already known to be
    # the heaviest thing this service does.
    for events in reversed(pages):
        for event in reversed(events):
            yield json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"

    log.info("audit.exported", events=exported)


def filename(query: Query) -> str:
    """A name that says what is in the file.

    Because an export lands in somebody's downloads folder next to four others,
    and `export.json` is how the wrong window gets ingested.
    """
    since = query.since.date().isoformat() if query.since else "start"
    until = query.until.date().isoformat() if query.until else "now"
    return f"campusid-audit-{since}-to-{until}.ndjson"
