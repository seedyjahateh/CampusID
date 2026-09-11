"""The audit hash chain, without a database (FR-AUD-05).

The arithmetic and the verifier. What a chain buys is that *partial* tampering is
impossible to hide — an edited field, a deleted row, an inserted event — so the
tests are mostly three ways of doing each of those and checking the verifier
names the right link.

What it does not buy is tested too, by absence: somebody who can rewrite every
row from the tamper point forward produces a chain that verifies. The defence
against that is publishing the head hash somewhere they do not control, which is
an operational practice rather than code, and `head` exists to make it possible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from campusid.audit.chain import (
    ALTERED,
    FIELDS,
    GENESIS,
    OUT_OF_ORDER,
    UNLINKED,
    canonical,
    head,
    link,
    verify,
    verify_from,
)

WHEN = datetime(2026, 9, 11, 12, 0, 30, 123456, tzinfo=UTC)


def _event(n: int, **overrides: Any) -> dict[str, Any]:
    return {
        "event_id": f"event-{n}",
        "event_type": "auth.success",
        "outcome": "success",
        "occurred_at": WHEN,
        "correlation_id": f"chain-{n}",
        "actor": None,
        "subject": "somebody",
        "target": None,
        "reason": None,
        "source_ip": None,
        "user_agent": None,
        "session_id": None,
        "detail": {"idp": "campus"},
        **overrides,
    }


def _chain(count: int, **overrides: Any) -> list[dict[str, Any]]:
    """A well-formed trail of `count` events, sealed the way the writer seals."""
    events: list[dict[str, Any]] = []
    previous = GENESIS
    for n in range(1, count + 1):
        event = _event(n, **overrides)
        current = link(previous, event)
        events.append({**event, "seq": n, "prev_hash": previous, "hash": current})
        previous = current
    return events


# --- the encoding -----------------------------------------------------------


def test_the_same_event_encodes_the_same_way_twice() -> None:
    """Two encodings of one event that hashed differently would make the verifier
    cry tamper at an honest trail."""
    assert canonical(_event(1)) == canonical(_event(1))


def test_key_order_does_not_change_the_encoding() -> None:
    """JSONB does not preserve key order, so anything relying on it would verify
    differently after a round trip through the database."""
    forward = _event(1, detail={"a": 1, "b": 2})
    backward = _event(1, detail={"b": 2, "a": 1})

    assert canonical(forward) == canonical(backward)


def test_an_unknown_column_does_not_change_the_encoding() -> None:
    """So a caller handing over a whole row hashes what the writer hashed."""
    assert canonical(_event(1)) == canonical({**_event(1), "id": "a primary key"})


def test_a_naive_timestamp_is_read_as_utc() -> None:
    """The database hands back aware datetimes and a test may not. Reading a
    naive one as local time would make the hash depend on the container's
    timezone."""
    naive = _event(1, occurred_at=WHEN.replace(tzinfo=None))

    assert canonical(naive) == canonical(_event(1))


def test_the_covered_fields_are_stated_rather_than_derived() -> None:
    """A new column should be a decision about whether it belongs in the chain.
    Deriving the list would let a column added for an unrelated reason silently
    change every future hash."""
    assert "detail" in FIELDS
    # The chain's own columns are never part of what it covers, or the hash would
    # have to contain itself.
    assert not {"seq", "prev_hash", "hash"} & set(FIELDS)


# --- an honest trail --------------------------------------------------------


def test_a_well_formed_chain_verifies() -> None:
    assert verify(_chain(5)) is None


def test_an_empty_trail_verifies() -> None:
    """A deployment that has recorded nothing has nothing to have tampered with,
    and failing here would cry wolf on every fresh install."""
    assert verify([]) is None


def test_the_first_event_links_to_the_genesis_value() -> None:
    """A fixed value rather than an empty string, so the head is chained like
    every other row and the verifier has no special case there — a special case
    at the head is where somebody hides a row."""
    assert _chain(1)[0]["prev_hash"] == GENESIS


# --- editing a row ----------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["subject", "outcome", "event_type", "correlation_id", "actor", "reason"]
)
def test_editing_any_covered_field_is_caught(field: str) -> None:
    events = _chain(4)
    events[2][field] = "tampered"

    broken = verify(events)

    assert broken is not None
    assert broken.event_id == "event-3"
    assert broken.problem == ALTERED


def test_editing_the_detail_is_caught() -> None:
    """The field most likely to be edited, because it holds what actually
    happened rather than who it happened to."""
    events = _chain(3)
    events[1]["detail"] = {"idp": "somewhere else"}

    broken = verify(events)

    assert broken is not None
    assert broken.event_id == "event-2"


def test_editing_the_timestamp_is_caught() -> None:
    """Moving an event in time is how somebody makes an action look like it
    happened during a window they were authorised for."""
    events = _chain(3)
    events[1]["occurred_at"] = WHEN.replace(hour=3)

    assert verify(events) is not None


def test_rehashing_an_edited_row_is_still_caught() -> None:
    """The row now hashes to what it claims, but the row after it still links to
    the old value. The chain catches at the next link rather than at this one,
    which is the property that makes a partial rewrite impossible."""
    events = _chain(4)
    events[1]["subject"] = "tampered"
    events[1]["hash"] = link(events[1]["prev_hash"], events[1])

    broken = verify(events)

    assert broken is not None
    assert broken.event_id == "event-3"
    assert broken.problem == UNLINKED


# --- removing and inserting -------------------------------------------------


def test_deleting_a_row_is_caught() -> None:
    events = _chain(5)
    del events[2]

    broken = verify(events)

    assert broken is not None
    assert broken.event_id == "event-4"
    assert broken.problem == UNLINKED


def test_deleting_the_last_row_is_not_visible_from_the_chain_alone() -> None:
    """Honest about a real limit: truncating the tail leaves a chain that
    verifies. Detecting it needs the published head, which is what `head` is
    for."""
    events = _chain(5)
    truncated = events[:-1]

    assert verify(truncated) is None
    assert head(truncated) != head(events)


def test_inserting_a_row_is_caught() -> None:
    events = _chain(4)
    forged = {**_event(99), "seq": 3, "prev_hash": events[1]["hash"]}
    forged["hash"] = link(forged["prev_hash"], forged)
    events.insert(2, forged)

    broken = verify(events)

    assert broken is not None
    assert broken.problem in (UNLINKED, OUT_OF_ORDER)


def test_reordering_two_rows_is_caught() -> None:
    events = _chain(4)
    events[1], events[2] = events[2], events[1]

    assert verify(events) is not None


def test_a_reused_sequence_number_is_caught() -> None:
    """Two events sharing a position make the order the verifier walks
    ambiguous, which is precisely where a row could be hidden."""
    events = _chain(3)
    events[2]["seq"] = events[1]["seq"]

    broken = verify(events)

    assert broken is not None
    assert broken.problem == OUT_OF_ORDER


# --- what the verifier says -------------------------------------------------


def test_only_the_first_break_is_reported() -> None:
    """Every link after a tamper is broken as a consequence. Reporting them all
    would bury the one row an investigator needs."""
    events = _chain(6)
    events[1]["subject"] = "tampered"
    events[4]["subject"] = "also tampered"

    broken = verify(events)

    assert broken is not None
    assert broken.event_id == "event-2"


def test_the_break_reads_as_a_sentence() -> None:
    """An operator sees this in a cron mail at three in the morning."""
    events = _chain(2)
    events[1]["subject"] = "tampered"

    assert "event-2" in str(verify(events))


# --- verifying in batches ---------------------------------------------------


def test_a_chain_split_in_two_verifies_across_the_seam() -> None:
    """A verifier that only worked on a trail small enough to hold in memory is
    one nobody runs on the trail that matters."""
    events = _chain(6)

    assert verify_from(GENESIS, events[:3]) is None
    assert verify_from(events[2]["hash"], events[3:]) is None


def test_a_tamper_at_the_seam_is_caught() -> None:
    events = _chain(6)
    events[3]["subject"] = "tampered"

    assert verify_from(events[2]["hash"], events[3:]) is not None


def test_a_batch_that_does_not_follow_is_caught() -> None:
    """Which is what stops somebody removing a whole batch between two reads."""
    events = _chain(6)

    assert verify_from(GENESIS, events[3:]) is not None


# --- the head ---------------------------------------------------------------


def test_the_head_of_an_empty_trail_is_the_genesis_value() -> None:
    assert head([]) == GENESIS


def test_the_head_changes_with_every_event() -> None:
    """So a published head pins the whole trail, including its length."""
    assert head(_chain(3)) != head(_chain(4))
