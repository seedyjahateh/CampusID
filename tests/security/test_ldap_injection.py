"""LDAP filter and DN injection (FR-DIR-07).

The requirement asks for twelve payloads, and the ones that matter are the ones
that change the *shape* of the filter rather than its content. `*)(uid=*` inside
a `(uid=%s)` template becomes `(uid=*)(uid=*)`: against a bind-then-search login
that is an authentication bypass, and against a group lookup it is a privilege
escalation.

The subtler half is the escaper undoing its own work. Escape the backslash last
and every `\\5c` you just wrote turns back into a literal backslash followed by
digits, which is a filter that parses, means something else, and looks correct
in a diff.
"""

from __future__ import annotations

import pytest

from campusid.directory.escaping import (
    all_of,
    any_of,
    equality,
    escape_dn,
    escape_filter,
)
from campusid.directory.profiles import ACTIVE_DIRECTORY, OPENLDAP, DirectoryProfile

pytestmark = pytest.mark.security

PAYLOADS = [
    "*",
    "*)(uid=*",
    "*)(|(uid=*",
    "admin)(&(objectClass=*",
    "\\",
    "\\2a",
    "sam)(cn=*",
    "(",
    ")",
    "\x00",
    "sam\x00)(uid=*",
    "*))%00",
]
"""Twelve, as the requirement asks. The last three carry a NUL: a filter
assembled in a language that terminates strings on one would be truncated by the
server rather than by us, so the escaper has to see it as a character."""


@pytest.mark.parametrize("payload", PAYLOADS)
def test_no_payload_survives_as_filter_syntax(payload: str) -> None:
    """The property that matters, stated once. Whatever the payload was, what
    comes out cannot open or close a clause, cannot introduce a wildcard, and
    cannot terminate the string."""
    escaped = escape_filter(payload)

    assert "(" not in escaped
    assert ")" not in escaped
    assert "*" not in escaped
    assert "\x00" not in escaped


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_payload_cannot_change_the_shape_of_a_filter(payload: str) -> None:
    """One balanced pair of parentheses, whatever went in. A payload that
    changed the count changed the meaning."""
    built = equality("uid", payload)

    assert built.count("(") == 1
    assert built.count(")") == 1
    assert built.startswith("(uid=")


def test_the_classic_bypass_is_neutralised() -> None:
    """`*)(uid=*` is the payload every LDAP injection article opens with,
    because against `(uid=%s)` it matches every entry in the tree."""
    assert equality("uid", "*)(uid=*") == r"(uid=\2a\29\28uid=\2a)"


def test_a_backslash_is_escaped_before_everything_else() -> None:
    """The escaper undoing its own work is the failure that gets shipped: escape
    the backslash last and `\\2a` becomes a literal backslash followed by `2a`,
    which the server reads as an escaped asterisk."""
    assert escape_filter("\\2a") == r"\5c2a"
    assert escape_filter("\\*") == r"\5c\2a"


def test_an_ordinary_value_is_left_readable() -> None:
    """Escaping everything would be safe and would also make every log line and
    every debugging session harder for no gain."""
    assert escape_filter("sam.obrien@campus.test") == "sam.obrien@campus.test"


# --- distinguished names ----------------------------------------------------


def test_a_comma_in_a_dn_value_is_escaped() -> None:
    """The DN failure that is not a security bug until it is: an unescaped comma
    splits one component into two, so `cn=O'Brien, Sam,ou=people` names an entry
    nobody meant."""
    assert escape_dn("O'Brien, Sam") == "O'Brien\\, Sam"


def test_dn_and_filter_escaping_are_not_interchangeable() -> None:
    """They share a backslash and nothing else. A DN escaped as a filter value
    keeps its commas; a filter escaped as a DN keeps its parentheses."""
    value = "Sam, (admin)"

    assert "," in escape_filter(value)
    assert "(" in escape_dn(value)


def test_a_leading_hash_is_escaped() -> None:
    """RFC 4514 §2.4: a leading `#` introduces a hex-encoded value, so an
    unescaped one turns a name into a different kind of thing entirely."""
    assert escape_dn("#1").startswith("\\#")


def test_leading_and_trailing_spaces_are_escaped() -> None:
    """They are not preserved otherwise, and a DN that loses a space does not
    match the entry it names."""
    assert escape_dn(" Sam ") == "\\ Sam\\ "


def test_a_backslash_in_a_dn_is_escaped_first() -> None:
    assert escape_dn("a\\,b") == "a\\\\\\,b"


# --- building filters -------------------------------------------------------


def test_a_multi_attribute_filter_is_a_disjunction() -> None:
    built = any_of(("uid", "mail"), "sam")

    assert built == "(|(uid=sam)(mail=sam))"


def test_a_single_attribute_needs_no_disjunction() -> None:
    """`(|(uid=sam))` is valid and every server accepts it; it is also noise in
    every log line that carries it."""
    assert any_of(("uid",), "sam") == "(uid=sam)"


def test_a_disjunction_escapes_every_branch() -> None:
    built = any_of(("uid", "mail"), "*)(uid=*")

    assert built.count("(") == 3
    assert built.count(")") == 3


def test_an_empty_attribute_list_is_refused() -> None:
    """`(|)` is a filter that matches nothing, and a caller that produced one
    has a bug it should hear about here rather than as an empty result set."""
    with pytest.raises(ValueError, match="at least one"):
        any_of((), "sam")


def test_a_conjunction_drops_nothing_it_was_given() -> None:
    assert all_of("(a=1)", "(b=2)") == "(&(a=1)(b=2))"


def test_a_conjunction_of_one_is_that_one() -> None:
    assert all_of("(a=1)") == "(a=1)"


def test_an_empty_conjunction_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        all_of()


# --- profiles build escaped filters -----------------------------------------


@pytest.mark.parametrize("directory", [ACTIVE_DIRECTORY, OPENLDAP])
@pytest.mark.parametrize("payload", ["*)(uid=*", "\\", "*"])
def test_every_profile_filter_escapes_its_input(directory: DirectoryProfile, payload: str) -> None:
    """The escaping has to be in the filter builders, not in the callers. A
    template somebody can fill in without going through an escaper is a filter
    assembled by hand, which is what FR-DIR-07 exists to prevent.

    Compared against a benign value rather than against a fixed count, so the
    property is "this payload changed nothing structural" rather than a number
    that has to be updated whenever a profile gains a login attribute.
    """
    benign = directory.user_filter("sam")
    built = directory.user_filter(payload)

    assert "*" not in built
    assert built.count("(") == benign.count("(")
    assert built.count(")") == benign.count(")")


def test_a_user_filter_is_constrained_by_object_class() -> None:
    """Without it a search for `uid=admin` can be answered by a group, a computer
    account, or anything else somebody put in the tree."""
    assert "objectClass=inetOrgPerson" in OPENLDAP.user_filter("sam")
    assert "objectClass=user" in ACTIVE_DIRECTORY.user_filter("sam")


def test_a_reverse_membership_filter_escapes_the_dn() -> None:
    """The DN reaching this filter came from the directory, and a value from the
    directory is still a value: an entry named to contain filter syntax is a way
    in for whoever can create entries."""
    built = OPENLDAP.group_members_filter("cn=evil*)(cn=*,ou=groups,dc=campus,dc=test")

    assert "*" not in built
