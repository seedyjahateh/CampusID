"""Every reason code must be exercised by at least one test.

Without this, the negative suite falls behind the code silently: someone adds a
rejection path, no test covers it, and coverage stays green because the *line*
is executed by some unrelated case that never asserts the code.

This is a source scan, so it proves a code is *named* in an assertion, not that
the assertion is meaningful. That is a deliberate trade: the alternative —
instrumenting `SamlRejected` and checking the tally at session end — is
sensitive to test selection, so it would fail whenever anyone ran a subset.
A named code with a bad test is a review problem; a code with no test at all is
the failure this catches.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from campusid.errors import NOT_YET_REACHABLE, ReasonCode

pytestmark = pytest.mark.security

TESTS_ROOT = Path(__file__).resolve().parent.parent
REFERENCE = re.compile(r"ReasonCode\.([A-Z0-9_]+)")


def _codes_referenced_in_tests() -> set[str]:
    referenced: set[str] = set()
    for path in TESTS_ROOT.rglob("test_*.py"):
        if path.name == Path(__file__).name:
            continue  # this file names them all, which would prove nothing
        referenced.update(REFERENCE.findall(path.read_text(encoding="utf-8")))
    return referenced


def test_every_reason_code_is_exercised() -> None:
    expected = {code.name for code in ReasonCode} - {code.name for code in NOT_YET_REACHABLE}

    missing = sorted(expected - _codes_referenced_in_tests())

    assert not missing, (
        "reason codes with no negative test: "
        + ", ".join(missing)
        + ". Add a test asserting each, or move it to NOT_YET_REACHABLE with a "
        "note saying which milestone implements it."
    )


def test_deferred_codes_are_declared_deliberately() -> None:
    """`NOT_YET_REACHABLE` is an escape hatch, so it must stay small and named.

    Enumerating it here means growing the set is a deliberate edit to a test
    rather than a quiet way to silence the check above. Every entry names the
    milestone that removes it.
    """
    assert {code.name for code in NOT_YET_REACHABLE} == {
        # M2, with assertion decryption
        "DECRYPTION_FAILED",
        "UNSUPPORTED_ENCRYPTION_ALGORITHM",
        # later in M1, with the request-binding cookie
        "REQUEST_BINDING_INVALID",
    }
