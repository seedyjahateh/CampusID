"""The SCIM filter grammar (FR-SCIM-07, RFC 7644 §3.4.2.2).

Thirty expressions, six of them malformed, per the PRD. The parser and the
evaluator are tested together because a filter that parses into the wrong tree
and a filter that evaluates the wrong way are the same bug to whoever sent it.
"""

from __future__ import annotations

from typing import Any

import pytest

from campusid.scim.filters import (
    MAX_DEPTH,
    And,
    Comparison,
    Not,
    Operator,
    Or,
    Present,
    ScimFilterError,
    ValuePath,
    matches,
    parse_attr_path,
    parse_filter,
)

SAM: dict[str, Any] = {
    "id": "2819c223-7f76-453a-919d-413861904646",
    "userName": "sam.obrien",
    "active": True,
    "name": {"givenName": "Samira", "familyName": "O'Brien"},
    "emails": [
        {"type": "work", "value": "sam.obrien@campus.test", "primary": True},
        {"type": "home", "value": "sam@example.test"},
    ],
    "meta": {"created": "2026-01-15T09:00:00Z"},
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        "department": "Computer Science",
        "employeeNumber": "E00184213",
    },
}

DANA: dict[str, Any] = {
    "id": "ff8c1c1a-0000-4000-8000-000000000001",
    "userName": "dana.wu",
    "active": False,
    "name": {"givenName": "Dana"},
    "emails": [{"type": "work", "value": "dana.wu@campus.test"}],
}


def _match(expression: str, resource: dict[str, Any] = SAM) -> bool:
    return matches(parse_filter(expression), resource)


# --- the operators, one each -----------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('userName eq "sam.obrien"', True),
        ('userName eq "dana.wu"', False),
        ('userName ne "dana.wu"', True),
        ('userName co "obrien"', True),
        ('userName co "nothere"', False),
        ('userName sw "sam"', True),
        ('userName sw "obrien"', False),
        ('userName ew "obrien"', True),
        ('userName ew "sam"', False),
        ("userName pr", True),
        ("nickName pr", False),
        ('meta.created gt "2026-01-01T00:00:00Z"', True),
        ('meta.created lt "2026-01-01T00:00:00Z"', False),
        ('meta.created ge "2026-01-15T09:00:00Z"', True),
        ('meta.created le "2026-01-15T09:00:00Z"', True),
        ("active eq true", True),
        ("active eq false", False),
    ],
)
def test_an_operator_evaluates(expression: str, expected: bool) -> None:
    assert _match(expression) is expected


def test_string_equality_is_case_insensitive() -> None:
    """RFC 7643 §2.2 makes `caseExact` false by default. Getting this backwards
    means a provisioning client's idempotency check silently fails and it
    creates a second person."""
    assert _match('userName eq "SAM.OBRIEN"')
    assert _match('userName co "OBRIEN"')


def test_an_attribute_name_is_case_insensitive() -> None:
    """§2.1. A client sending `USERNAME` is addressing `userName`."""
    assert _match('USERNAME eq "sam.obrien"')


# --- logical structure -----------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('userName eq "sam.obrien" and active eq true', True),
        ('userName eq "sam.obrien" and active eq false', False),
        ('userName eq "dana.wu" or active eq true', True),
        ('userName eq "dana.wu" or active eq false', False),
        ('not (userName eq "dana.wu")', True),
        ('not (userName eq "sam.obrien")', False),
        ('(userName eq "dana.wu" or userName eq "sam.obrien") and active eq true', True),
    ],
)
def test_logical_composition(expression: str, expected: bool) -> None:
    assert _match(expression) is expected


def test_and_binds_tighter_than_or() -> None:
    """`a or b and c` is `a or (b and c)`. Parsed wrongly, a client asking for
    "these two departments, active only" gets every inactive person in one of
    them."""
    tree = parse_filter('userName eq "x" or userName eq "sam.obrien" and active eq true')

    assert isinstance(tree, Or)
    assert isinstance(tree.right, And)


def test_parentheses_override_precedence() -> None:
    tree = parse_filter('(userName eq "x" or userName eq "y") and active eq true')

    assert isinstance(tree, And)
    assert isinstance(tree.left, Or)


def test_not_binds_tightest() -> None:
    tree = parse_filter("not (active eq true) and userName pr")

    assert isinstance(tree, And)
    assert isinstance(tree.left, Not)


# --- value paths -----------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('emails[type eq "work"]', True),
        ('emails[type eq "other"]', False),
        ('emails[type eq "work" and value ew "campus.test"]', True),
        ('emails[type eq "home" and value ew "campus.test"]', False),
        ("emails[primary eq true]", True),
    ],
)
def test_a_value_path_matches_any_member(expression: str, expected: bool) -> None:
    assert _match(expression) is expected


def test_a_value_path_does_not_match_across_members() -> None:
    """The predicate applies to *one* member at a time. Evaluating it against
    the flattened collection would make "the work email at example.test" match a
    person with a work email and, separately, an example.test address."""
    assert not _match('emails[type eq "home" and primary eq true]')


def test_a_comparison_on_a_multivalued_attribute_matches_any_value() -> None:
    """`emails.value eq "..."` asks about the collection, unlike a value path
    which asks about a member."""
    assert _match('emails.value eq "sam@example.test"')


def test_a_value_path_on_a_single_valued_attribute_is_a_non_match() -> None:
    """Rather than an error. A filter is client input, and `name[x eq "y"]` is a
    question about a shape the resource does not have."""
    assert not _match('name[givenName eq "Samira"]')


# --- sub-attributes and extensions -----------------------------------------


def test_a_sub_attribute_is_read() -> None:
    assert _match('name.givenName eq "Samira"')


def test_an_extension_attribute_is_read_by_its_urn() -> None:
    """The URN is kept rather than discarded so an extension attribute sharing a
    short name with a core one can still be addressed unambiguously."""
    expression = (
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department "
        'eq "Computer Science"'
    )

    assert _match(expression)


def test_the_urn_splits_at_the_last_colon() -> None:
    """A schema URI *is* colon-separated. Splitting on the first would make the
    attribute `ietf`."""
    path = parse_attr_path("urn:ietf:params:scim:schemas:core:2.0:User:userName")

    assert path.urn == "urn:ietf:params:scim:schemas:core:2.0:User"
    assert path.attribute == "userName"


def test_an_unknown_extension_is_a_non_match() -> None:
    assert not _match('urn:example:2.0:User:whatever eq "x"')


# --- what a missing or mistyped attribute does -----------------------------


def test_a_missing_attribute_never_matches() -> None:
    """Except under `ne`. A client filtering a mixed collection cannot be
    expected to know which attributes every resource carries before it can ask
    a question about any of them."""
    for operator in ("eq", "co", "sw", "ew", "gt", "ge", "lt", "le"):
        assert not _match(f'nickName {operator} "anything"')


def test_a_missing_attribute_satisfies_ne() -> None:
    """An attribute that is not there is not equal to anything."""
    assert _match('nickName ne "anything"')


def test_a_substring_operator_declines_a_non_string() -> None:
    """`co` against a boolean is a question with no meaning, and coercing would
    invent an answer."""
    assert not _match('active co "tru"')


def test_an_ordering_operator_declines_mismatched_types() -> None:
    """No match rather than a `TypeError`. A 500 is the wrong answer to a
    question that simply does not apply."""
    assert not _match("userName gt 5")
    assert not _match("active gt false")


# --- malformed filters (the PRD's six) -------------------------------------


@pytest.mark.parametrize(
    ("expression", "why"),
    [
        ("userName eq", "a comparison with no value"),
        ('userName "sam"', "a value with no operator"),
        ('userName xx "sam"', "an operator that does not exist"),
        ('(userName eq "sam"', "an unclosed group"),
        ('emails[type eq "work"', "an unclosed value filter"),
        ('userName eq "sam" and', "a dangling conjunction"),
        ("", "an empty filter"),
        ('userName eq "sam" extra', "trailing rubbish"),
        ("üserName eq 1", "a character outside the grammar"),
    ],
)
def test_a_malformed_filter_is_refused(expression: str, why: str) -> None:
    """`invalidFilter` with a position, not a 500. Unlike a protocol rejection
    this is a client *integration* error: whoever sent it is trying to get it
    right and needs to know where it went wrong."""
    with pytest.raises(ScimFilterError):
        parse_filter(expression)


def test_a_filter_that_nests_too_deep_is_refused() -> None:
    """Recursive descent on unbounded nesting is a stack overflow with a polite
    name, and Python's own limit produces a 500 rather than the `invalidFilter`
    the specification asks for."""
    expression = "not (" * (MAX_DEPTH + 2) + "userName pr" + ")" * (MAX_DEPTH + 2)

    with pytest.raises(ScimFilterError, match="nests deeper"):
        parse_filter(expression)


def test_an_over_long_filter_is_refused() -> None:
    """A cap is cheaper than a parser that has to stay linear under adversarial
    input."""
    with pytest.raises(ScimFilterError, match="exceeds"):
        parse_filter('userName eq "' + "a" * 5000 + '"')


def test_a_three_level_path_is_refused() -> None:
    """SCIM has exactly two levels. A third addresses something the data model
    cannot express, and accepting it silently would make the operation a no-op
    the client believes succeeded."""
    with pytest.raises(ScimFilterError, match="nests deeper"):
        parse_filter('name.given.first eq "Samira"')


# --- the tree the parser builds --------------------------------------------


def test_a_comparison_parses_to_its_parts() -> None:
    tree = parse_filter('userName eq "sam.obrien"')

    assert isinstance(tree, Comparison)
    assert tree.path.attribute == "userName"
    assert tree.operator is Operator.EQ
    assert tree.value == "sam.obrien"


def test_presence_parses_without_a_value() -> None:
    assert isinstance(parse_filter("userName pr"), Present)


def test_a_value_path_parses_to_a_predicate() -> None:
    tree = parse_filter('emails[type eq "work"]')

    assert isinstance(tree, ValuePath)
    assert tree.path.attribute == "emails"
    assert isinstance(tree.predicate, Comparison)


@pytest.mark.parametrize(
    ("literal", "expected"),
    [("true", True), ("false", False), ("null", None), ("42", 42), ("4.5", 4.5), ("-7", -7)],
)
def test_literals_parse_to_python_values(literal: str, expected: Any) -> None:
    tree = parse_filter(f"answer eq {literal}")

    assert isinstance(tree, Comparison)
    assert tree.value == expected


def test_an_escaped_quote_survives_the_string_literal() -> None:
    """A quote inside a value is escaped JSON-style, and the parser has to give
    the value back unescaped — otherwise a display name containing a quotation
    mark never matches itself."""
    tree = parse_filter(r'displayName eq "Sam \"The Cat\" Jones"')

    assert isinstance(tree, Comparison)
    assert tree.value == 'Sam "The Cat" Jones'


def test_an_apostrophe_needs_no_escaping() -> None:
    """SCIM strings are double-quoted, so an apostrophe is an ordinary
    character — and Irish surnames are not an edge case at a university."""
    tree = parse_filter('name.familyName eq "O\'Brien"')

    assert isinstance(tree, Comparison)
    assert tree.value == "O'Brien"
    assert matches(tree, SAM)


# --- filtering a collection ------------------------------------------------


def test_a_filter_selects_from_a_collection() -> None:
    """What the list endpoint actually does with the tree."""
    tree = parse_filter("active eq true")

    selected = [person["userName"] for person in (SAM, DANA) if matches(tree, person)]

    assert selected == ["sam.obrien"]


def test_a_filter_can_select_nobody() -> None:
    tree = parse_filter('userName eq "nobody"')

    assert [p for p in (SAM, DANA) if matches(tree, p)] == []
