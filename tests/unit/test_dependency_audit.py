"""The dependency vulnerability gate (NFR-SEC-08).

The requirement allows a known vulnerability through CI only with "a documented,
dated exception", and the whole value of that clause is in the word *dated*. An
undated suppression is a permanent one, and a list of permanent suppressions is
how a dependency audit turns into a file nobody reads.

So the expiry is enforced rather than recorded, and these tests are mostly about
the expiry and about refusing entries that could not be reviewed later.

The `pip-audit` invocation itself is not tested here. Asserting the argument list
would be asserting that the code says what the code says; what makes it correct
is that it runs in CI against the committed locks, where a real advisory produces
a real failure.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from scripts.audit_dependencies import EXCEPTIONS, Exception_, expired, parse

TODAY = date(2026, 9, 11)


def _entry(**overrides: Any) -> dict[str, Any]:
    return {
        "id": "GHSA-xxxx-xxxx-xxxx",
        "package": "some-library",
        "opened": date(2026, 6, 1),
        "review_by": date(2026, 9, 1),
        "reason": "the advisory is in a code path this project never calls",
        **overrides,
    }


# --- expiry -----------------------------------------------------------------


def test_an_exception_past_its_review_date_has_expired() -> None:
    """The failure this mechanism exists to produce.

    A suppression that outlives the reason for it is worse than no suppression,
    because it looks like a decision somebody is still standing behind.
    """
    exceptions = parse({"exceptions": [_entry(review_by=date(2026, 9, 1))]})

    assert expired(exceptions, TODAY) == exceptions


def test_an_exception_is_live_on_its_review_date() -> None:
    """Inclusive, so a ninety-day exception gets ninety days rather than
    eighty-nine and a build failure at breakfast."""
    exceptions = parse({"exceptions": [_entry(review_by=TODAY)]})

    assert expired(exceptions, TODAY) == []


def test_a_live_exception_is_not_expired() -> None:
    exceptions = parse({"exceptions": [_entry(review_by=date(2026, 12, 10))]})

    assert expired(exceptions, TODAY) == []


def test_expiry_is_per_entry() -> None:
    """One stale entry must not take the others down with it, and must not be
    hidden by them either."""
    exceptions = parse(
        {
            "exceptions": [
                _entry(id="GHSA-live", review_by=date(2026, 12, 10)),
                _entry(id="GHSA-stale", review_by=date(2026, 1, 1)),
            ]
        }
    )

    assert [exception.id for exception in expired(exceptions, TODAY)] == ["GHSA-stale"]


# --- what an entry has to carry ---------------------------------------------


@pytest.mark.parametrize("field", ["id", "package", "opened", "review_by", "reason"])
def test_an_incomplete_exception_is_refused(field: str) -> None:
    """Every field is what makes the entry reviewable a year later, so a missing
    one is an error rather than a default — the default would be exactly the
    thing the reviewer needed."""
    entry = _entry()
    del entry[field]

    with pytest.raises(ValueError, match="missing"):
        parse({"exceptions": [entry]})


def test_an_empty_reason_is_refused() -> None:
    """A suppression with no argument attached is the shape this file exists to
    prevent."""
    with pytest.raises(ValueError, match="missing"):
        parse({"exceptions": [_entry(reason="")]})


def test_a_quoted_date_is_refused() -> None:
    """PyYAML reads an unquoted YYYY-MM-DD as a date and a quoted one as a
    string, which would compare as text and be wrong exactly once a year."""
    with pytest.raises(ValueError, match="must be a YYYY-MM-DD date"):
        parse({"exceptions": [_entry(review_by="2026-12-10")]})


def test_a_file_with_no_exceptions_parses_to_none() -> None:
    """The correct state, and the one to return to."""
    assert parse({"exceptions": []}) == []
    assert parse({}) == []


def test_exceptions_must_be_a_list() -> None:
    with pytest.raises(ValueError, match="must be a list"):
        parse({"exceptions": {"id": "GHSA-xxxx"}})


# --- the committed file -----------------------------------------------------


def test_the_committed_exception_file_is_valid() -> None:
    """Parsed here rather than only in CI.

    A malformed exception file fails the audit step, which is late and looks like
    a vulnerability finding. Failing in the unit suite says what it actually is.
    """
    document = yaml.safe_load(Path(EXCEPTIONS).read_text(encoding="utf-8")) or {}

    parse(document)


def test_no_exception_in_the_repository_has_already_expired() -> None:
    """Runs on today's date, deliberately.

    Every other test here injects a clock. This one must not: the point is that
    the repository's own exceptions are live *now*, and a test that pinned the
    date would keep passing forever after they stopped being.
    """
    document = yaml.safe_load(Path(EXCEPTIONS).read_text(encoding="utf-8")) or {}

    stale = expired(parse(document), date.today())

    assert stale == [], f"expired dependency exceptions: {[entry.id for entry in stale]}"


def test_an_exception_keeps_the_dates_it_was_given() -> None:
    """A round trip, so a refactor of the parser cannot quietly swap two fields
    that are both dates and would both still parse."""
    (exception,) = parse({"exceptions": [_entry(opened=date(2026, 6, 1))]})

    assert exception == Exception_(
        id="GHSA-xxxx-xxxx-xxxx",
        package="some-library",
        opened=date(2026, 6, 1),
        review_by=date(2026, 9, 1),
        reason="the advisory is in a code path this project never calls",
    )
