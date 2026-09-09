"""Escaping values that go into LDAP filters and DNs (FR-DIR-07).

The injection that matters here is not a database one. An LDAP filter is a
parenthesised expression, and a value that contains `)` or `(` closes and opens
clauses — so `*)(uid=*` inside a `(uid=%s)` template becomes `(uid=*)(uid=*)`,
which matches everybody. Against a bind-then-search authentication flow that is
an authentication bypass; against a group lookup it is a privilege escalation.

Two encodings, and they are not the same one. RFC 4515 §3 escapes *assertion
values* inside a filter, and RFC 4514 §2.4 escapes *attribute values* inside a
distinguished name. They share a backslash-escape mechanism and share almost
nothing else: a filter escapes five characters as two-digit hex, while a DN
escapes a different set with a bare backslash and has positional rules a filter
has none of. Using one where the other belongs produces a value that looks
escaped and is not.

**Everything is escaped, always.** There is no "this value came from our own
configuration so it is safe" path, because the value that is safe today is the
one somebody makes configurable next year. The cost is a function call.
"""

from __future__ import annotations

from typing import Final

FILTER_ESCAPES: Final[dict[str, str]] = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\x00": r"\00",
}
"""RFC 4515 §3's five, hex-encoded.

The backslash is first in the table and, more importantly, is handled first in
the substitution below: escaping it after the others would turn each `\\5c` back
into a literal backslash followed by digits, which is the classic way an escaper
undoes its own work.

`*` is here because it is the wildcard. A search for a user whose surname really
is `*` must not match everybody, and an attacker supplying one must not either.
"""

DN_ESCAPES: Final[dict[str, str]] = {
    "\\": "\\\\",
    ",": "\\,",
    "+": "\\+",
    '"': '\\"',
    "<": "\\<",
    ">": "\\>",
    ";": "\\;",
    "=": "\\=",
}
"""RFC 4514 §2.4's set, minus the two that are positional.

`#` is escaped only at the start of a value and a space only at the start or the
end, which is why those two are handled separately below rather than by table
lookup. Escaping them everywhere would produce a DN that is technically valid and
does not match the entry it names.
"""


def escape_filter(value: str) -> str:
    """Escape an assertion value for use inside an LDAP filter (RFC 4515 §3).

    The whole of FR-DIR-07. Every value interpolated into a filter goes through
    here, including ones that came from our own configuration.
    """
    escaped = value.replace("\\", FILTER_ESCAPES["\\"])
    for character, replacement in FILTER_ESCAPES.items():
        if character == "\\":
            continue
        escaped = escaped.replace(character, replacement)
    return escaped


def escape_dn(value: str) -> str:
    """Escape an attribute value for use inside a DN (RFC 4514 §2.4).

    Distinct from the filter escaping and not interchangeable with it: a DN
    escaped as a filter value keeps its commas, and a comma in a DN component
    silently splits it into two.
    """
    escaped = value.replace("\\", DN_ESCAPES["\\"])
    for character, replacement in DN_ESCAPES.items():
        if character == "\\":
            continue
        escaped = escaped.replace(character, replacement)

    # Positional, per §2.4: a leading `#` would be read as the start of a
    # hex-encoded value, and leading or trailing space is not preserved unless
    # escaped. Applied after the table so the backslash they introduce is not
    # itself escaped again.
    if escaped.startswith("#"):
        escaped = "\\" + escaped
    if escaped.startswith(" "):
        escaped = "\\" + escaped
    if escaped.endswith(" ") and not escaped.endswith("\\ "):
        escaped = escaped[:-1] + "\\ "
    return escaped


def equality(attribute: str, value: str) -> str:
    """`(attribute=value)`, with the value escaped.

    A function rather than a format string at each call site. The point of
    FR-DIR-07 is that no filter is assembled by hand, and a template somebody
    can fill in without going through an escaper is a filter assembled by hand.
    """
    return f"({attribute}={escape_filter(value)})"


def any_of(attributes: tuple[str, ...], value: str) -> str:
    """`(|(a=value)(b=value))` — one value against several attribute names.

    The shape a directory profile needs: "find this person by whichever of these
    three names this directory happens to use for a login."
    """
    if not attributes:
        raise ValueError("a filter needs at least one attribute")
    if len(attributes) == 1:
        return equality(attributes[0], value)
    clauses = "".join(equality(attribute, value) for attribute in attributes)
    return f"(|{clauses})"


def all_of(*clauses: str) -> str:
    """`(&(a)(b))`. Clauses are already-built filters, not values."""
    present = [clause for clause in clauses if clause]
    if not present:
        raise ValueError("a conjunction needs at least one clause")
    if len(present) == 1:
        return present[0]
    return f"(&{''.join(present)})"
