"""Pairwise subject identifiers (FR-ARP-04).

The property under test is unlinkability: two service providers comparing notes
must not be able to tell they are talking about the same person. That is the
difference between "analytics knows a user came back" and "analytics can join
its records to the health centre's".
"""

from __future__ import annotations

import pytest

from campusid.policy.pairwise import SEPARATOR, pairwise_id, subject_id

pytestmark = pytest.mark.security

SALT = b"a-test-salt-not-used-anywhere-real"
SCOPE = "campus.edu"

LMS = "https://lms.campus.test/shibboleth"
ANALYTICS = "https://analytics.campus.test/shibboleth"


def test_the_same_person_looks_different_to_different_sps() -> None:
    """The whole point. Two SPs holding these values learn nothing by
    comparing them."""
    at_lms = pairwise_id(SALT, "person-1", LMS, SCOPE)
    at_analytics = pairwise_id(SALT, "person-1", ANALYTICS, SCOPE)

    assert at_lms != at_analytics


def test_the_same_person_looks_the_same_to_one_sp() -> None:
    """Equally essential: an identifier that changed per login would make every
    returning user look like a new account."""
    first = pairwise_id(SALT, "person-1", LMS, SCOPE)
    second = pairwise_id(SALT, "person-1", LMS, SCOPE)

    assert first == second


def test_different_people_look_different_at_one_sp() -> None:
    assert pairwise_id(SALT, "person-1", LMS, SCOPE) != pairwise_id(SALT, "person-2", LMS, SCOPE)


def test_the_identifier_reveals_nothing_about_the_person() -> None:
    """Derived, not encoded. A value that contained the person key would be an
    identifier in name only."""
    value = pairwise_id(SALT, "sam.obrien@campus.edu", LMS, SCOPE)

    assert "sam.obrien" not in value
    assert "sam" not in value.split("@")[0].lower()


def test_the_identifier_carries_the_scope() -> None:
    """The REFEDS `pairwise-id` form is `opaque@scope`, which is what makes it
    recognisable to a federation partner as an identifier rather than a name."""
    value = pairwise_id(SALT, "person-1", LMS, SCOPE)

    assert value.endswith(f"@{SCOPE}")
    assert len(value.split("@")[0]) >= 20


def test_the_concatenation_is_unambiguous() -> None:
    """Without a separator, ("ab", "cd") and ("a", "bcd") hash identically —
    so one SP could predict another's identifier for a chosen user.

    Constructed to collide under naive concatenation, and asserted not to.
    """
    first = pairwise_id(SALT, "ab", "cd", SCOPE)
    second = pairwise_id(SALT, "a", "bcd", SCOPE)

    assert first != second
    assert SEPARATOR not in b"abcd"  # the separator cannot occur in either input


def test_a_different_salt_produces_different_identifiers() -> None:
    """Which is exactly why the salt cannot be rotated in place: every SP would
    see its entire user base replaced by strangers at once."""
    assert pairwise_id(SALT, "person-1", LMS, SCOPE) != pairwise_id(
        b"a-different-salt", "person-1", LMS, SCOPE
    )


def test_an_empty_salt_is_refused() -> None:
    """Deriving from nothing produces a value anyone can recompute."""
    with pytest.raises(ValueError, match="salt"):
        pairwise_id(b"", "person-1", LMS, SCOPE)


def test_the_shared_subject_id_is_the_same_everywhere() -> None:
    """`subject-id` is correlatable by design, which is why `pairwise` is the
    default and this is opt-in per SP."""
    assert subject_id("person-1", SCOPE) == subject_id("person-1", SCOPE)
    assert subject_id("person-1", SCOPE).endswith(f"@{SCOPE}")
