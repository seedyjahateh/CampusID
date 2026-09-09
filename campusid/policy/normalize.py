"""Attribute normalisation (FR-ARP-08).

Attributes arrive from an IdP as whatever that IdP's directory happens to hold:
`Sam.OBrien@CAMPUS.TEST` from one, `sam.obrien@campus.test` from another, an
affiliation of `Student` where the vocabulary says `student`. Downstream
everything compares these as strings — a release rule's value filter, an
authorisation check, a pairwise identifier's stability — so normalising once, at
the boundary, is the difference between a policy that works and one that works
on Tuesdays.

Two rules here are security decisions rather than tidying.

**Scoped values are checked against our own scope.** An `eduPersonPrincipalName`
of `attacker@elsewhere.test`, asserted by our campus IdP, is that IdP claiming
authority over a namespace it does not have. It is dropped, not corrected: there
is no safe interpretation of it, and rewriting the scope would manufacture an
identity nobody asserted.

**A value that fails validation is dropped, not the attribute.** A person with
three affiliations, one of them misspelled, keeps the two that are valid. The
alternative — refusing the whole attribute — turns one bad directory entry into
a login that silently loses its group memberships, and the operator sees an
authorisation failure rather than a data problem.

Everything dropped is recorded. An attribute that quietly shrank between the
assertion and the release log is a support ticket nobody can answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from campusid.policy.attributes import (
    AFFILIATION,
    EPPN,
    MAIL,
    PRIMARY_AFFILIATION,
    SCOPED_AFFILIATION,
)

AFFILIATION_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        "faculty",
        "student",
        "staff",
        "alum",
        "member",
        "affiliate",
        "employee",
        "library-walk-in",
    }
)
"""The eduPerson controlled vocabulary, in full.

Closed on purpose. An SP's authorisation rules are written against these exact
strings, so a local invention like `adjunct-faculty` is a value no relying party
knows how to interpret — it either does nothing or, worse, falls into somebody's
default branch.
"""


@dataclass(frozen=True, slots=True)
class DroppedValue:
    """One value that did not survive, and why."""

    attribute: str
    value: str
    reason: str


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """What survived normalisation, and what did not."""

    attributes: dict[str, list[str]]
    dropped: tuple[DroppedValue, ...]


def normalize(attributes: dict[str, list[str]], *, scope: str) -> NormalizationResult:
    """Normalise everything the broker holds about a person.

    ``scope`` is this deployment's own scope — the domain the local IdP is
    authoritative for. Values scoped to anything else are dropped.
    """
    normalized: dict[str, list[str]] = {}
    dropped: list[DroppedValue] = []

    for name, values in attributes.items():
        kept: list[str] = []
        for raw in values:
            value, reason = _normalize_value(name, raw.strip(), scope)
            if value is None:
                dropped.append(DroppedValue(name, raw, reason or "invalid"))
                continue
            if value not in kept:
                # Deduplicated after normalisation, not before: `Student` and
                # `student` are one value once the case is settled, and a
                # duplicate in a released attribute reads as a data error.
                kept.append(value)
        if kept:
            normalized[name] = kept

    return NormalizationResult(attributes=normalized, dropped=tuple(dropped))


def _normalize_value(name: str, value: str, scope: str) -> tuple[str | None, str | None]:
    """Normalise one value, or explain why it cannot be."""
    if not value:
        return None, "empty"

    if name == EPPN:
        return _scoped(value.lower(), scope, vocabulary=None)
    if name == SCOPED_AFFILIATION:
        return _scoped(value.lower(), scope, vocabulary=AFFILIATION_VOCABULARY)
    if name in (AFFILIATION, PRIMARY_AFFILIATION):
        lowered = value.lower()
        if lowered not in AFFILIATION_VOCABULARY:
            return None, "outside the eduPerson controlled vocabulary"
        return lowered, None
    if name == MAIL:
        return _mail(value)
    return value, None


def _scoped(
    value: str, scope: str, *, vocabulary: frozenset[str] | None
) -> tuple[str | None, str | None]:
    """Validate a `local@scope` value against our own scope.

    Split on the *last* `@`: an `eduPersonPrincipalName` local part may legally
    contain one, and splitting on the first would read `a@b@campus.test` as
    scoped to `b@campus.test` — which is exactly the confusion an attacker
    registering an unusual username would be aiming for.
    """
    local, separator, asserted_scope = value.rpartition("@")
    if not separator or not local:
        return None, "not scoped"
    if asserted_scope != scope:
        return None, f"scoped to {asserted_scope!r}, not {scope!r}"
    if vocabulary is not None and local not in vocabulary:
        return None, "outside the eduPerson controlled vocabulary"
    return value, None


def _mail(value: str) -> tuple[str | None, str | None]:
    """Lowercase the domain, leave the local part alone.

    Lowercasing the whole address is what most systems do and it is wrong: RFC
    5321 makes the local part case-sensitive and the domain not. In practice
    almost every provider folds case, but "almost every" is not a property to
    build an identifier on, and the cost of being correct here is one line.
    """
    local, separator, domain = value.rpartition("@")
    if not separator or not local or not domain:
        return None, "not an address"
    return f"{local}@{domain.lower()}", None
