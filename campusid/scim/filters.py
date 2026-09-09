"""The SCIM filter and path grammar (RFC 7644 §3.4.2.2 and §3.5.2).

One grammar, two uses. A query filter selects resources; a PATCH path selects
*parts* of one resource. They share operators, precedence and the value-filter
syntax, so they share a parser — the alternative is two half-implementations
that disagree about `emails[type eq "work"]` in ways nobody notices until a
provisioning client corrupts a record.

The grammar, from the RFC:

    FILTER    = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"
    valuePath = attrPath "[" valFilter "]"
    attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
    logExp    = FILTER SP ("and" / "or") SP FILTER
    attrPath  = [URI ":"] ATTRNAME *1subAttr

Precedence is `not` over `and` over `or`, and parentheses override both.

Three things here are decisions rather than transcription:

**A missing attribute makes a comparison false, never an error.** `userName sw
"a"` against a resource with no `userName` is a resource that does not match. A
client filtering a mixed collection would otherwise have to know which
attributes every resource carries before it could ask a question about any of
them.

**String comparison is case-insensitive by default.** RFC 7643 §2.2 makes
`caseExact` false unless an attribute says otherwise, so `userName eq
"SAM.OBRIEN"` finds `sam.obrien`. Getting this backwards means a provisioning
client's idempotency check silently fails and it creates a duplicate person.

**Depth and length are capped.** A filter arrives from a client over the
network, and recursive descent on unbounded nesting is a stack overflow with a
polite name. The caps are generous enough that no real filter reaches them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

MAX_FILTER_LENGTH: Final = 4096
"""Longer than any filter a client legitimately sends. A cap here is cheaper
than a parser that has to stay linear under adversarial input."""

MAX_DEPTH: Final = 20
"""Nesting depth. Recursive descent on unbounded nesting is a stack overflow,
and Python's own recursion limit produces a 500 rather than the `invalidFilter`
the specification asks for."""


class ScimFilterError(ValueError):
    """A filter or path could not be parsed.

    Surfaces to the client as `scimType: invalidFilter` with a 400. The message
    names the position, because unlike a protocol rejection this is a *client
    integration* error: whoever sent it is trying to get it right and needs to
    know where it went wrong.
    """


class Operator(StrEnum):
    """The comparison operators, exactly the RFC's set."""

    EQ = "eq"
    NE = "ne"
    CO = "co"
    SW = "sw"
    EW = "ew"
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"


ORDERED: Final[frozenset[Operator]] = frozenset(
    {Operator.GT, Operator.GE, Operator.LT, Operator.LE}
)
"""Operators that need an ordering. Applied to values of different types they
are meaningless rather than false, and the parser cannot know the types — so the
evaluator returns no match rather than inventing one."""

SUBSTRING: Final[frozenset[Operator]] = frozenset({Operator.CO, Operator.SW, Operator.EW})
"""Operators defined only for strings (RFC 7644 §3.4.2.2). `co` against a
boolean is not false — it is a question with no meaning — and the evaluator
declines rather than coercing."""


# --- the syntax tree --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AttrPath:
    """`[urn:]attribute[.sub]`."""

    attribute: str
    sub_attribute: str | None = None
    urn: str | None = None
    """The schema URI, when the client qualified the name. Kept rather than
    discarded so a resource carrying an extension attribute of the same short
    name as a core one can still be addressed unambiguously."""

    def __str__(self) -> str:
        name = f"{self.attribute}.{self.sub_attribute}" if self.sub_attribute else self.attribute
        return f"{self.urn}:{name}" if self.urn else name


@dataclass(frozen=True, slots=True)
class Comparison:
    """`attrPath op value`."""

    path: AttrPath
    operator: Operator
    value: Any


@dataclass(frozen=True, slots=True)
class Present:
    """`attrPath pr` — the attribute exists and is neither null nor empty."""

    path: AttrPath


@dataclass(frozen=True, slots=True)
class ValuePath:
    """`attrPath[valFilter]` — the members of a multi-valued attribute that match."""

    path: AttrPath
    predicate: Node


@dataclass(frozen=True, slots=True)
class And:
    left: Node
    right: Node


@dataclass(frozen=True, slots=True)
class Or:
    left: Node
    right: Node


@dataclass(frozen=True, slots=True)
class Not:
    inner: Node


Node = Comparison | Present | ValuePath | And | Or | Not


@dataclass(frozen=True, slots=True)
class PatchPath:
    """A PATCH target: an attribute, optionally filtered, optionally a sub-attribute.

    `emails[type eq "work"].value` parses to path=`emails`,
    predicate=`type eq "work"`, sub_attribute=`value`. The trailing
    sub-attribute is what distinguishes "replace the work email's value" from
    "replace the whole work email object", and conflating them loses a `type`
    the client never asked to change.
    """

    path: AttrPath
    predicate: Node | None = None
    sub_attribute: str | None = None


# --- tokenizer --------------------------------------------------------------

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<lbracket>\[)
  | (?P<rbracket>\])
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<number>-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)
  | (?P<word>[A-Za-z][A-Za-z0-9_:.$-]*)
  # Only ever reached for the `.sub` that follows a value filter:
  # `emails[type eq "work"].value`. Inside a word the dot is part of the word,
  # so this alternative is last and matches only what the others could not.
  | (?P<dot>\.)
    """,
    re.VERBOSE,
)

_LOGICAL: Final = frozenset({"and", "or", "not"})
_LITERALS: Final[dict[str, Any]] = {"true": True, "false": False, "null": None}


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    text: str
    position: int


def _tokenize(source: str) -> list[_Token]:
    if len(source) > MAX_FILTER_LENGTH:
        raise ScimFilterError(f"filter exceeds {MAX_FILTER_LENGTH} characters")

    tokens: list[_Token] = []
    position = 0
    while position < len(source):
        match = _TOKEN.match(source, position)
        if match is None:
            raise ScimFilterError(f"unexpected character {source[position]!r} at {position}")
        kind = match.lastgroup or ""
        if kind != "space":
            tokens.append(_Token(kind, match.group(), position))
        position = match.end()
    return tokens


# --- parser -----------------------------------------------------------------


class _Parser:
    """Recursive descent over the token stream.

    Depth is threaded explicitly rather than inferred from the Python stack,
    so the limit is a documented number rather than whatever
    `sys.getrecursionlimit()` happens to be minus the frames already in use.
    """

    def __init__(self, tokens: list[_Token], source: str) -> None:
        self._tokens = tokens
        self._source = source
        self._index = 0

    # --- token helpers -------------------------------------------------

    def _peek(self) -> _Token | None:
        return self._tokens[self._index] if self._index < len(self._tokens) else None

    def _next(self) -> _Token:
        token = self._peek()
        if token is None:
            raise ScimFilterError(f"unexpected end of filter: {self._source!r}")
        self._index += 1
        return token

    def _accept_word(self, word: str) -> bool:
        token = self._peek()
        if token is not None and token.kind == "word" and token.text.lower() == word:
            self._index += 1
            return True
        return False

    def _expect(self, kind: str) -> _Token:
        token = self._next()
        if token.kind != kind:
            raise ScimFilterError(f"expected {kind} at {token.position}, found {token.text!r}")
        return token

    # --- grammar --------------------------------------------------------

    def parse_filter(self, depth: int = 0) -> Node:
        """`logExp` at the `or` level — the loosest binding."""
        if depth > MAX_DEPTH:
            raise ScimFilterError(f"filter nests deeper than {MAX_DEPTH}")

        node = self._parse_and(depth)
        while self._accept_word("or"):
            node = Or(node, self._parse_and(depth))
        return node

    def _parse_and(self, depth: int) -> Node:
        node = self._parse_unary(depth)
        while self._accept_word("and"):
            node = And(node, self._parse_unary(depth))
        return node

    def _parse_unary(self, depth: int) -> Node:
        if self._accept_word("not"):
            self._expect("lparen")
            inner = self.parse_filter(depth + 1)
            self._expect("rparen")
            return Not(inner)

        token = self._peek()
        if token is not None and token.kind == "lparen":
            self._next()
            inner = self.parse_filter(depth + 1)
            self._expect("rparen")
            return inner

        return self._parse_attribute_expression(depth)

    def _parse_attribute_expression(self, depth: int) -> Node:
        path = self._parse_attr_path()

        token = self._peek()
        if token is not None and token.kind == "lbracket":
            self._next()
            predicate = self.parse_filter(depth + 1)
            self._expect("rbracket")
            return ValuePath(path, predicate)

        operator_token = self._next()
        if operator_token.kind != "word":
            raise ScimFilterError(
                f"expected an operator at {operator_token.position}, "
                f"found {operator_token.text!r}"
            )

        word = operator_token.text.lower()
        if word == "pr":
            return Present(path)

        try:
            operator = Operator(word)
        except ValueError as exc:
            raise ScimFilterError(
                f"{operator_token.text!r} is not a SCIM operator (at {operator_token.position})"
            ) from exc

        return Comparison(path, operator, self._parse_value())

    def _parse_attr_path(self) -> AttrPath:
        token = self._next()
        if token.kind != "word":
            raise ScimFilterError(
                f"expected an attribute name at {token.position}, found {token.text!r}"
            )
        return parse_attr_path(token.text, token.position)

    def _parse_value(self) -> Any:
        token = self._next()
        if token.kind == "string":
            return _unquote(token.text)
        if token.kind == "number":
            return float(token.text) if _is_decimal(token.text) else int(token.text)
        if token.kind == "word" and token.text.lower() in _LITERALS:
            return _LITERALS[token.text.lower()]
        raise ScimFilterError(f"expected a value at {token.position}, found {token.text!r}")

    def at_end(self) -> bool:
        return self._peek() is None

    def remaining(self) -> _Token | None:
        return self._peek()


def parse_attr_path(text: str, position: int = 0) -> AttrPath:
    """Split `[urn:]attribute[.sub]`.

    The URN is everything up to the last colon, because a schema URI *is*
    colon-separated — `urn:ietf:params:scim:schemas:core:2.0:User:userName`
    qualifies `userName`, and splitting on the first colon would produce the
    attribute `ietf`.
    """
    urn: str | None = None
    name = text
    if ":" in text:
        urn, _, name = text.rpartition(":")
        if not name:
            raise ScimFilterError(f"attribute name missing after schema URI at {position}")

    attribute, _, sub_attribute = name.partition(".")
    if not attribute:
        raise ScimFilterError(f"empty attribute name at {position}")
    if "." in sub_attribute:
        # SCIM has exactly two levels. A third would be addressing something
        # the data model cannot express, and accepting it silently would make
        # the PATCH a no-op the client believes succeeded.
        raise ScimFilterError(f"{text!r} nests deeper than attribute.sub at {position}")

    return AttrPath(attribute, sub_attribute or None, urn)


def parse_filter(source: str) -> Node:
    """Parse a query filter (§3.4.2.2)."""
    parser = _Parser(_tokenize(source), source)
    node = parser.parse_filter()
    if not parser.at_end():
        trailing = parser.remaining()
        assert trailing is not None
        raise ScimFilterError(f"unexpected {trailing.text!r} at {trailing.position}")
    return node


def parse_patch_path(source: str) -> PatchPath:
    """Parse a PATCH `path` (§3.5.2).

    Narrower than a filter: exactly one attribute, an optional value filter, and
    an optional sub-attribute *after* the filter. `emails[type eq "work"].value`
    is the shape that matters and the one clients get wrong.
    """
    tokens = _tokenize(source)
    if not tokens:
        raise ScimFilterError("a PATCH path cannot be empty")

    parser = _Parser(tokens, source)
    path = parser._parse_attr_path()

    predicate: Node | None = None
    sub_attribute = path.sub_attribute

    token = parser.remaining()
    if token is not None and token.kind == "lbracket":
        if sub_attribute is not None:
            # `emails.value[type eq "work"]` addresses a filter *inside* a
            # sub-attribute, which the data model has no meaning for.
            raise ScimFilterError(f"{source!r} filters a sub-attribute")
        parser._next()
        predicate = parser.parse_filter(depth=1)
        parser._expect("rbracket")

        trailing = parser.remaining()
        if trailing is not None:
            if trailing.kind != "dot":
                raise ScimFilterError(
                    f"expected a sub-attribute after the filter at {trailing.position}"
                )
            parser._next()
            name = parser._expect("word")
            if "." in name.text or ":" in name.text:
                raise ScimFilterError(f"invalid sub-attribute at {name.position}")
            sub_attribute = name.text
        path = AttrPath(path.attribute, None, path.urn)

    if not parser.at_end():
        trailing = parser.remaining()
        assert trailing is not None
        raise ScimFilterError(f"unexpected {trailing.text!r} at {trailing.position}")

    return PatchPath(path, predicate, sub_attribute)


# --- evaluation -------------------------------------------------------------


def matches(node: Node, resource: dict[str, Any]) -> bool:
    """Whether a resource satisfies a filter."""
    if isinstance(node, And):
        return matches(node.left, resource) and matches(node.right, resource)
    if isinstance(node, Or):
        return matches(node.left, resource) or matches(node.right, resource)
    if isinstance(node, Not):
        return not matches(node.inner, resource)
    if isinstance(node, Present):
        return _present(_read(resource, node.path))
    if isinstance(node, ValuePath):
        members = _read(resource, node.path)
        if not isinstance(members, list):
            return False
        # A value path matches the *resource* when any member matches, which is
        # what `emails[type eq "work"]` means as a query. PATCH uses the same
        # predicate to select which members to change; see `select_members`.
        return any(
            isinstance(member, dict) and matches(node.predicate, member) for member in members
        )
    return _compare(node, resource)


def select_members(predicate: Node, members: list[Any]) -> list[int]:
    """The indices of the members a value filter selects.

    Indices rather than the members themselves, because PATCH mutates them in
    place and a caller holding copies would change nothing.
    """
    return [
        index
        for index, member in enumerate(members)
        if isinstance(member, dict) and matches(predicate, member)
    ]


def _compare(node: Comparison, resource: dict[str, Any]) -> bool:
    actual = _read(resource, node.path)

    if isinstance(actual, list):
        # A comparison against a multi-valued attribute matches when any value
        # does — `emails eq "sam@campus.test"` is a reasonable thing to ask.
        return any(_compare_one(value, node.operator, node.value) for value in actual)
    return _compare_one(actual, node.operator, node.value)


def _compare_one(actual: Any, operator: Operator, expected: Any) -> bool:
    if operator is Operator.NE:
        # The one operator a missing attribute satisfies: an attribute that is
        # not there is not equal to anything.
        return not _equal(actual, expected)
    if actual is None:
        # Everything else against a missing attribute is a non-match rather
        # than an error. A client filtering a mixed collection cannot be
        # expected to know which attributes every resource carries.
        return False
    if operator is Operator.EQ:
        return _equal(actual, expected)

    if operator in SUBSTRING:
        if not isinstance(actual, str) or not isinstance(expected, str):
            # Defined only for strings. `co` against a boolean is a question
            # with no meaning, and coercing would invent an answer.
            return False
        haystack, needle = actual.lower(), expected.lower()
        if operator is Operator.CO:
            return needle in haystack
        if operator is Operator.SW:
            return haystack.startswith(needle)
        return haystack.endswith(needle)

    return _ordered(actual, operator, expected)


def _ordered(actual: Any, operator: Operator, expected: Any) -> bool:
    """`gt`, `ge`, `lt`, `le`.

    Types that cannot be ordered against each other produce no match rather
    than a `TypeError`. A filter is client input; a 500 is the wrong answer to
    a question that simply does not apply.
    """
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    comparable = (isinstance(actual, str) and isinstance(expected, str)) or (
        isinstance(actual, int | float) and isinstance(expected, int | float)
    )
    if not comparable:
        return False

    left = actual.lower() if isinstance(actual, str) else actual
    right = expected.lower() if isinstance(expected, str) else expected
    if operator is Operator.GT:
        return bool(left > right)
    if operator is Operator.GE:
        return bool(left >= right)
    if operator is Operator.LT:
        return bool(left < right)
    return bool(left <= right)


def _equal(actual: Any, expected: Any) -> bool:
    """SCIM equality: case-insensitive for strings unless the attribute says
    otherwise (RFC 7643 §2.2).

    Getting this backwards is not cosmetic. A provisioning client checking
    whether `userName eq "SAM.OBRIEN"` already exists would find nothing, and
    create a second person.
    """
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual is expected
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    if isinstance(actual, int | float) and isinstance(expected, int | float):
        return bool(actual == expected)
    return bool(actual == expected)


def _present(value: Any) -> bool:
    """`pr`: present, non-null, and not an empty string or collection."""
    if value is None:
        return False
    if isinstance(value, str | list | dict):
        return len(value) > 0
    return True


def _read(resource: dict[str, Any], path: AttrPath) -> Any:
    """Read an attribute, honouring a schema URN when one is given.

    Attribute names are case-insensitive (RFC 7643 §2.1), so a client sending
    `USERNAME` addresses `userName`. Doing that lookup here means every operator
    inherits it rather than each one remembering.
    """
    container: Any = resource
    if path.urn:
        extension = _get_insensitive(resource, path.urn)
        if not isinstance(extension, dict):
            return None
        container = extension

    value = _get_insensitive(container, path.attribute)
    if path.sub_attribute is None:
        return value

    if isinstance(value, list):
        # A sub-attribute of a multi-valued attribute is the collection of that
        # sub-attribute across the members: `emails.value` is every address.
        collected = [
            _get_insensitive(member, path.sub_attribute)
            for member in value
            if isinstance(member, dict)
        ]
        return [item for item in collected if item is not None] or None
    if isinstance(value, dict):
        return _get_insensitive(value, path.sub_attribute)
    return None


def _get_insensitive(container: dict[str, Any], name: str) -> Any:
    if name in container:
        return container[name]
    lowered = name.lower()
    for key, value in container.items():
        if key.lower() == lowered:
            return value
    return None


def _unquote(token: str) -> str:
    """Undo the JSON-style escaping the grammar allows in a string literal."""
    body = token[1:-1]
    return (
        body.replace('\\"', '"')
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\/", "/")
    )


def _is_decimal(text: str) -> bool:
    return "." in text or "e" in text.lower()
