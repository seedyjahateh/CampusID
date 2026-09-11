"""The audit hash chain (FR-AUD-05).

Every event carries the hash of the one before it, so the trail is a chain rather
than a pile. Changing a row, removing one, or inserting one between two others
breaks the link at that point and every link after it — which turns "was this
trail tampered with" from a question nobody can answer into an arithmetic one.

**What this does and does not prove.** A chain detects tampering by anybody who
cannot recompute it. Somebody with write access to the whole table can rewrite
every row from the tamper point forward and produce a chain that verifies — the
defence against that is publishing the head hash somewhere they do not control,
which is an operational practice rather than code. What the chain does buy is
that *partial* tampering is impossible to hide: a deleted row, an edited field,
an inserted event. That covers the realistic case, which is somebody with SQL
access and a few minutes rather than somebody who has taken the database.

**Canonical serialisation is the whole security of it.** Two encodings of one
event that hash differently make the verifier report tampering that did not
happen; two *different* events that hash the same make tampering invisible. So
the encoding is pinned here, in one function, with sorted keys, no insignificant
whitespace, and every value rendered as text — and the field list is explicit
rather than derived from the row, so adding a column is a decision about whether
it is covered rather than a silent change to what the hash means.

**Times are rendered at microsecond precision in UTC.** Postgres stores
`timestamptz` to the microsecond; a chain computed from a value with more
precision than the column keeps would verify on the way in and fail on the way
back out, which is the worst kind of bug to debug — it appears only after a
restart.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

GENESIS: Final = "0" * 64
"""What the first event links to.

A fixed value rather than an empty string, so the first row is chained like every
other one and the verifier has no special case for it — a special case at the
head is where somebody hides a row.
"""

FIELDS: Final = (
    "event_id",
    "event_type",
    "outcome",
    "occurred_at",
    "correlation_id",
    "actor",
    "subject",
    "target",
    "reason",
    "source_ip",
    "user_agent",
    "session_id",
    "detail",
)
"""Exactly what the hash covers.

Written out rather than derived from the model, so a new column is a decision
about whether it belongs in the chain. Deriving it would mean a column added for
an unrelated reason silently changes every future hash while leaving every past
one unverifiable against the new rule.

`seq`, `prev_hash` and `hash` are deliberately absent: the first is assigned by
the database after the hash is computed, and the other two are the chain itself.
"""


@dataclass(frozen=True, slots=True)
class Broken:
    """Where a chain stopped verifying, and how."""

    seq: int
    event_id: str
    problem: str

    def __str__(self) -> str:
        return f"event {self.event_id} at sequence {self.seq}: {self.problem}"


ALTERED: Final = "content does not match its recorded hash"
UNLINKED: Final = "does not link to the previous event"
OUT_OF_ORDER: Final = "sequence numbers are not increasing"


def canonical(event: dict[str, Any]) -> str:
    """The one encoding of an event that the hash is taken over.

    Sorted keys and no insignificant whitespace, because two encodings of one
    event that hash differently make the verifier cry tamper at an honest trail.
    Unknown keys are ignored rather than included, so a caller passing a row with
    extra columns hashes the same thing the writer did.
    """
    payload = {name: _render(event.get(name)) for name in FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link(previous: str, event: dict[str, Any]) -> str:
    """The hash of one event, given the hash of the one before it."""
    material = f"{previous}{canonical(event)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify(events: list[dict[str, Any]]) -> Broken | None:
    """Walk a whole chain in order, returning the first break or None.

    The *first* break, because every link after a tamper is broken as a
    consequence — reporting all of them would bury the one row an investigator
    needs under a list of rows that are fine.

    An empty trail verifies. A deployment that has recorded nothing has nothing
    to have tampered with, and treating that as a failure would make the verifier
    cry wolf on every fresh install.
    """
    return verify_from(GENESIS, events)


def verify_from(expected: str, events: list[dict[str, Any]]) -> Broken | None:
    """Verify a slice of a chain that is expected to follow `expected`.

    Exists so a trail too large to hold in memory can be walked in batches with
    the boundary between two batches checked exactly like any other link. A
    verifier that could only run on a small trail is one nobody runs on a large
    one, which is the trail that matters.
    """
    last_seq: int | None = None

    for event in events:
        seq = int(event.get("seq") or 0)
        event_id = str(event.get("event_id") or "")

        if last_seq is not None and seq <= last_seq:
            # The caller handed these back out of order, or a sequence was
            # reused. Either way the chain cannot be checked against an ordering
            # that is not one.
            return Broken(seq=seq, event_id=event_id, problem=OUT_OF_ORDER)

        if str(event.get("prev_hash") or "") != expected:
            # A row removed or inserted. Reported before the content check
            # because it is the more specific failure: the row itself may be
            # perfectly intact and simply not belong here.
            return Broken(seq=seq, event_id=event_id, problem=UNLINKED)

        computed = link(expected, event)
        if computed != str(event.get("hash") or ""):
            return Broken(seq=seq, event_id=event_id, problem=ALTERED)

        expected = computed
        last_seq = seq

    return None


def head(events: list[dict[str, Any]]) -> str:
    """The hash the chain currently ends on.

    Worth publishing somewhere the database's owner does not control — that is
    what turns "partial tampering is detectable" into "tampering is detectable",
    and it is the one part of this that cannot live in code.
    """
    return str(events[-1]["hash"]) if events else GENESIS


def _render(value: Any) -> Any:
    """One value, in the form the hash is taken over.

    Datetimes become microsecond-precision UTC text, matching what Postgres keeps
    — a chain computed from a value more precise than the column would verify on
    the way in and fail on the way back out, which is a bug that only appears
    after a restart.
    """
    if isinstance(value, datetime):
        moment = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    if isinstance(value, dict):
        # Sorted here as well as at the top level: `detail` is arbitrary JSON,
        # and JSONB does not preserve key order, so anything relying on it would
        # verify differently after a round trip through the database.
        return {str(key): _render(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_render(item) for item in value]
    if value is None:
        return None
    if isinstance(value, bool | int | float):
        return value
    return str(value)
