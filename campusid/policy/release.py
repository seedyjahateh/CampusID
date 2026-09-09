"""The attribute release policy engine (FR-ARP-01 to 08).

What a service provider learns about a person, and why. The gate decides
whether an assertion is genuine; this decides how much of it anyone downstream
is entitled to see.

**Default deny.** An attribute with no rule permitting it is not released. That
is the whole design: the alternative — release everything not explicitly
forbidden — fails open every time somebody adds an attribute, and "somebody
added an attribute" is a weekly event at a university.

Evaluation runs in a fixed order, and the order encodes the policy:

1. **Classification.** `restricted` attributes are education records and are
   never released, by any policy, to anyone. Not overridable, because a
   disclosure cannot be undone.
2. **FERPA suppression.** A student who has opted out (34 CFR 99.37) has their
   directory information withheld from every SP that is not operating under the
   school-official exception, whatever that SP's rules say.
3. **Explicit denial**, lowest precedence number first.
4. **Explicit permission**, optionally filtered by value.
5. **Entity category**, so an SP that has earned R&S needs no per-attribute
   configuration.
6. **Deny**, because nothing above said otherwise.

Steps 1 and 2 come before any rule can speak, so a policy file cannot widen
them by mistake. Every decision — released *and* denied — is recorded with the
rule that made it, because "why does this app see my name?" is where every
incident starts (FR-ARP-06).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from campusid.policy.attributes import (
    PAIRWISE_ID,
    RS_BUNDLE,
    SUBJECT_ID,
    AttributeDefinition,
    Classification,
    definition,
)

Effect = Literal["allow", "allow-value", "deny", "require-consent"]
SubjectIdMode = Literal["pairwise", "shared"]


class Basis(StrEnum):
    """Why an attribute was released or withheld.

    Recorded on every decision. A release with no basis is unauditable, and an
    unauditable release cannot be defended to a registrar.
    """

    RESTRICTED = "restricted"
    FERPA_SUPPRESSED = "ferpa_suppressed"
    UNKNOWN_ATTRIBUTE = "unknown_attribute"
    EXPLICIT_DENY = "explicit_deny"
    EXPLICIT_ALLOW = "explicit_allow"
    VALUE_FILTER = "value_filter"
    ENTITY_CATEGORY = "entity_category"
    CONSENT_GIVEN = "consent_given"
    CONSENT_REQUIRED = "consent_required"
    """Withheld pending the subject's decision. Distinct from a denial: nothing
    is wrong, and the same request will succeed once they agree. An SP told
    "denied" would stop asking; one told "consent required" can prompt."""

    DEFAULT_DENY = "default_deny"


@dataclass(frozen=True, slots=True)
class ReleaseRule:
    """One line of an SP's policy."""

    id: str
    effect: Effect
    attribute: str
    value_filter: str | None = None
    precedence: int = 100
    """Lower runs first. Denials are conventionally given a low number so they
    are evaluated before the permissions they are meant to override."""

    def matches(self, value: str) -> bool:
        """Whether a single value survives this rule's filter.

        Anchored at both ends. An unanchored pattern would let
        `student@campus.edu.attacker.test` satisfy a filter meant for
        `student@campus.edu`, which is the same class of mistake as a
        prefix-matched redirect URL.
        """
        if self.value_filter is None:
            return True
        return re.fullmatch(self.value_filter, value) is not None


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    """What one service provider is entitled to."""

    sp_entity_id: str
    display_name: str = ""
    entity_categories: frozenset[str] = field(default_factory=frozenset)
    subject_id_mode: SubjectIdMode = "pairwise"
    """`pairwise` by default. An SP has to justify being able to correlate its
    users with another SP's, rather than getting that ability for free."""

    internal_school_official: bool = False
    """FERPA 99.31(a)(1). Set only for SPs operating under the school-official
    exception; it is what lets a suppressed student still use the LMS."""

    require_encrypted_assertion: bool = False
    rules: tuple[ReleaseRule, ...] = ()


@dataclass(frozen=True, slots=True)
class Subject:
    """The person the assertion is about, as far as release is concerned."""

    person_key: str
    """Stable and internal. Feeds pairwise derivation; never released."""

    ferpa_directory_suppressed: bool = False


@dataclass(frozen=True, slots=True)
class Decision:
    """What happened to one attribute, and why."""

    attribute: str
    released: bool
    values: tuple[str, ...]
    basis: Basis
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    """Everything released, and the reasoning behind all of it."""

    attributes: dict[str, list[str]]
    decisions: tuple[Decision, ...]

    @property
    def released_names(self) -> frozenset[str]:
        return frozenset(self.attributes)

    @property
    def denied_names(self) -> frozenset[str]:
        return frozenset(d.attribute for d in self.decisions if not d.released)


def evaluate(
    policy: ReleasePolicy,
    subject: Subject,
    available: dict[str, list[str]],
    *,
    consented: frozenset[str] = frozenset(),
) -> ReleaseResult:
    """Decide what this SP may see of this subject.

    ``available`` is everything the broker holds; the result is the subset the
    SP is entitled to. Attributes the broker does not hold are simply absent —
    a policy may permit an attribute nobody has.

    ``consented`` names the attributes this subject has already agreed to
    release to this SP. It is passed in rather than looked up so the engine
    stays a pure function of its inputs: consent lives in a store with its own
    lifecycle, and a policy decision that reached into a database would be
    untestable at the granularity the negative suite needs.
    """
    decisions: list[Decision] = []
    released: dict[str, list[str]] = {}

    for name in sorted(available):
        values = tuple(available[name])
        decision = _decide(policy, subject, name, values, consented)
        decisions.append(decision)
        if decision.released and decision.values:
            released[name] = list(decision.values)

    return ReleaseResult(attributes=released, decisions=tuple(decisions))


def _decide(
    policy: ReleasePolicy,
    subject: Subject,
    name: str,
    values: tuple[str, ...],
    consented: frozenset[str],
) -> Decision:
    attribute = definition(name)

    # 1. Unknown attributes are not released. The broker cannot reason about
    #    the sensitivity of something it has never heard of, and guessing in
    #    the permissive direction is how a restricted field escapes.
    if attribute is None:
        return Decision(name, False, (), Basis.UNKNOWN_ATTRIBUTE)

    # 2. Education records. No rule reaches this decision.
    if attribute.classification is Classification.RESTRICTED:
        return Decision(name, False, (), Basis.RESTRICTED)

    # 3. FERPA suppression, ahead of every rule so a policy file cannot
    #    accidentally widen it.
    if _suppressed(policy, subject, attribute):
        return Decision(name, False, (), Basis.FERPA_SUPPRESSED)

    for rule in sorted(policy.rules, key=lambda r: r.precedence):
        if rule.attribute != name:
            continue
        if rule.effect == "deny":
            return Decision(name, False, (), Basis.EXPLICIT_DENY, rule.id)
        if rule.effect == "allow":
            return Decision(name, True, values, Basis.EXPLICIT_ALLOW, rule.id)
        if rule.effect == "require-consent":
            # Withheld until the subject agrees, and recorded as its own basis
            # so an SP can be told "ask them" rather than "no". Fails closed:
            # an attribute nobody has consented to is simply not released, so a
            # consent store that is empty, unreachable or not yet built cannot
            # cause a disclosure.
            if name in consented:
                return Decision(name, True, values, Basis.CONSENT_GIVEN, rule.id)
            return Decision(name, False, (), Basis.CONSENT_REQUIRED, rule.id)
        # allow-value: the attribute passes, but only the values that match.
        # A partial release is still a release, and the values that did not
        # survive are recorded on the decision.
        kept = tuple(value for value in values if rule.matches(value))
        return Decision(name, bool(kept), kept, Basis.VALUE_FILTER, rule.id)

    if _in_entity_category_bundle(policy, name):
        return Decision(name, True, values, Basis.ENTITY_CATEGORY)

    return Decision(name, False, (), Basis.DEFAULT_DENY)


def _suppressed(policy: ReleasePolicy, subject: Subject, attribute: AttributeDefinition) -> bool:
    """Whether FERPA suppression withholds this attribute from this SP.

    The school-official exception is the deliberate hole: a suppressed student
    still has to be able to use the learning management system. It is set per
    SP and is what makes suppression usable rather than a blanket lockout.
    """
    return (
        subject.ferpa_directory_suppressed
        and attribute.ferpa_directory_item
        and not policy.internal_school_official
    )


def _in_entity_category_bundle(policy: ReleasePolicy, name: str) -> bool:
    from campusid.policy.attributes import RESEARCH_AND_SCHOLARSHIP

    return RESEARCH_AND_SCHOLARSHIP in policy.entity_categories and name in RS_BUNDLE


def subject_identifier_attribute(policy: ReleasePolicy) -> str:
    """Which identifier this SP receives.

    `pairwise-id` unless the policy asks for `subject-id`. The difference is
    whether two SPs can work out that they are talking about the same person by
    comparing notes.
    """
    return SUBJECT_ID if policy.subject_id_mode == "shared" else PAIRWISE_ID
