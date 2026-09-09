"""Attribute normalisation (FR-ARP-08).

Everything downstream compares these values as strings — a release rule's value
filter, an authorisation check, a pairwise identifier's stability — so
normalising once at the boundary is the difference between a policy that works
and one that works on Tuesdays.
"""

from __future__ import annotations

import pytest

from campusid.policy.attributes import (
    AFFILIATION,
    DISPLAY_NAME,
    EPPN,
    MAIL,
    PRIMARY_AFFILIATION,
    SCOPED_AFFILIATION,
)
from campusid.policy.normalize import AFFILIATION_VOCABULARY, normalize

SCOPE = "campus.test"


def _normalized(attributes: dict[str, list[str]]) -> dict[str, list[str]]:
    return normalize(attributes, scope=SCOPE).attributes


def test_the_principal_name_is_lowercased() -> None:
    """The PRD's own example. A pairwise identifier derived from a person key
    that changes case between logins is not stable, which is the whole property
    it exists to have."""
    assert _normalized({EPPN: ["Sam.OBrien@CAMPUS.TEST"]}) == {EPPN: ["sam.obrien@campus.test"]}


def test_a_principal_name_scoped_elsewhere_is_dropped() -> None:
    """Our campus IdP asserting `attacker@elsewhere.test` is claiming authority
    over a namespace it does not have. Dropped rather than corrected: rewriting
    the scope would manufacture an identity nobody asserted."""
    result = normalize({EPPN: ["attacker@elsewhere.test"]}, scope=SCOPE)

    assert result.attributes == {}
    assert result.dropped[0].reason.startswith("scoped to")


def test_an_unscoped_principal_name_is_dropped() -> None:
    result = normalize({EPPN: ["sam.obrien"]}, scope=SCOPE)

    assert result.attributes == {}
    assert result.dropped[0].reason == "not scoped"


def test_the_scope_is_taken_from_the_last_at_sign() -> None:
    """An `eduPersonPrincipalName` local part may legally contain an `@`.
    Splitting on the first would read `a@b@campus.test` as scoped to
    `b@campus.test` — exactly the confusion an unusual username would aim for.
    """
    assert _normalized({EPPN: ["a@b@campus.test"]}) == {EPPN: ["a@b@campus.test"]}


# --- the controlled vocabulary ---------------------------------------------


@pytest.mark.parametrize("affiliation", sorted(AFFILIATION_VOCABULARY))
def test_every_vocabulary_term_survives(affiliation: str) -> None:
    assert _normalized({AFFILIATION: [affiliation]}) == {AFFILIATION: [affiliation]}


def test_an_affiliation_is_lowercased() -> None:
    assert _normalized({AFFILIATION: ["Student"]}) == {AFFILIATION: ["student"]}


def test_an_invented_affiliation_is_dropped() -> None:
    """An SP's authorisation rules are written against the exact eduPerson
    terms, so a local invention either does nothing or falls into somebody's
    default branch."""
    result = normalize({AFFILIATION: ["adjunct-faculty"]}, scope=SCOPE)

    assert result.attributes == {}
    assert "controlled vocabulary" in result.dropped[0].reason


def test_a_scoped_affiliation_is_checked_on_both_halves() -> None:
    assert _normalized({SCOPED_AFFILIATION: ["Student@Campus.Test"]}) == {
        SCOPED_AFFILIATION: ["student@campus.test"]
    }


@pytest.mark.parametrize(
    "value",
    ["adjunct@campus.test", "student@elsewhere.test", "student", ""],
)
def test_a_bad_scoped_affiliation_is_dropped(value: str) -> None:
    assert _normalized({SCOPED_AFFILIATION: [value]}) == {}


def test_the_primary_affiliation_uses_the_same_vocabulary() -> None:
    assert _normalized({PRIMARY_AFFILIATION: ["FACULTY"]}) == {PRIMARY_AFFILIATION: ["faculty"]}


# --- partial survival ------------------------------------------------------


def test_one_bad_value_does_not_take_the_others_with_it() -> None:
    """A person with three affiliations, one misspelled, keeps the two that are
    valid. Refusing the whole attribute turns one bad directory entry into a
    login that silently loses its group memberships, and the operator sees an
    authorisation failure rather than a data problem.
    """
    result = normalize({AFFILIATION: ["student", "wizard", "member"]}, scope=SCOPE)

    assert result.attributes == {AFFILIATION: ["student", "member"]}
    assert [dropped.value for dropped in result.dropped] == ["wizard"]


def test_everything_dropped_is_recorded() -> None:
    """An attribute that quietly shrank between the assertion and the release
    log is a support ticket nobody can answer."""
    result = normalize(
        {EPPN: ["x@elsewhere.test"], AFFILIATION: ["wizard"]},
        scope=SCOPE,
    )

    assert {dropped.attribute for dropped in result.dropped} == {EPPN, AFFILIATION}


def test_an_attribute_losing_every_value_disappears() -> None:
    """Rather than becoming an empty list, which downstream reads as "released
    with no values" instead of "not released"."""
    assert _normalized({AFFILIATION: ["wizard"]}) == {}


def test_values_are_deduplicated_after_normalisation() -> None:
    """`Student` and `student` are one value once the case is settled, and a
    duplicate in a released attribute reads as a data error."""
    assert _normalized({AFFILIATION: ["Student", "student", "STUDENT"]}) == {
        AFFILIATION: ["student"]
    }


def test_surrounding_whitespace_is_stripped() -> None:
    assert _normalized({AFFILIATION: ["  student  "]}) == {AFFILIATION: ["student"]}


def test_an_empty_value_is_dropped() -> None:
    result = normalize({AFFILIATION: ["   "]}, scope=SCOPE)

    assert result.dropped[0].reason == "empty"


# --- mail ------------------------------------------------------------------


def test_only_the_domain_of_an_address_is_lowercased() -> None:
    """RFC 5321 makes the local part case-sensitive and the domain not. In
    practice almost every provider folds case, but "almost every" is not a
    property to build an identifier on, and being correct costs one line."""
    assert _normalized({MAIL: ["Sam.OBrien@CAMPUS.TEST"]}) == {MAIL: ["Sam.OBrien@campus.test"]}


def test_something_that_is_not_an_address_is_dropped() -> None:
    assert _normalized({MAIL: ["not-an-address"]}) == {}


def test_mail_is_not_restricted_to_our_own_scope() -> None:
    """Unlike a principal name. A person's contact address at another
    institution is a fact about them, not a claim of authority over that
    domain."""
    assert _normalized({MAIL: ["sam@elsewhere.test"]}) == {MAIL: ["sam@elsewhere.test"]}


# --- everything else -------------------------------------------------------


def test_an_attribute_with_no_rule_passes_through_unchanged() -> None:
    """Normalisation is a fixed list of known cases, not a guess. A display name
    is whatever the directory says it is; case-folding it would be wrong."""
    assert _normalized({DISPLAY_NAME: ["Sam O'Brien"]}) == {DISPLAY_NAME: ["Sam O'Brien"]}


def test_nothing_in_produces_nothing_out() -> None:
    assert normalize({}, scope=SCOPE).attributes == {}
