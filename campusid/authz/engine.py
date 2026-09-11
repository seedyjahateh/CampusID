"""The authorization decision (FR-AZ-03, FR-AZ-04, FR-AZ-05).

Given who is asking, what they want, what they want to do with it and the
circumstances, return permit, deny, or a challenge — and say which rule decided.

Four decisions carry the module.

**Deny overrides, always.** Every matching rule is evaluated and a single deny
beats any number of permits. The alternative — first match wins — makes the
*order* of a policy file part of its meaning, so adding a rule in the wrong place
silently grants access and the diff looks fine. Deny-overrides has no such
ordering, which is why XACML made it a named algorithm rather than leaving it to
whoever writes the file.

**Default deny, with a decision to point at.** A request that matches nothing is
denied, and the decision says so explicitly rather than returning an empty
result the caller has to interpret. Every denial names a rule or names the
default; there is no third answer, and "the log did not say" is not a state this
can be in (FR-AZ-04).

**Assurance is an obligation, not a matching condition.** This is the one that
looks like a detail and is the whole of FR-AZ-05. If a rule required `aal2` as a
condition, a single-factor session would simply fail to match it and fall
through to default deny — the person would be told no, when the right answer is
"prove it is you". So the rule matches on everything else and the assurance
shortfall becomes a challenge.

**A decision is about attributes, not about identity.** Nothing here knows a
person's name. It reads entitlements, affiliations, roles and assurance, which
is what makes the same engine usable for a resource the broker has never heard
of.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import time
from enum import StrEnum
from typing import Any, Final

from campusid.logging import get_logger

log = get_logger(__name__)

AAL1: Final = "urn:campusid:aal1"
AAL2: Final = "urn:campusid:aal2"

ASSURANCE_ORDER: Final[dict[str, int]] = {"": 0, AAL1: 1, AAL2: 2}
"""How the levels compare. An unknown or absent assurance ranks below AAL1,
which is the safe direction: a session whose assurance we cannot read is treated
as the weakest rather than as whatever the caller claimed."""

DEFAULT_RULE: Final = "default-deny"
"""What decided when nothing else did. A named value rather than None so a
dashboard counting decisions by rule has something to count, and so "denied by
the default" is visibly different from "denied by a rule somebody wrote"."""


class Effect(StrEnum):
    """What the engine decided."""

    PERMIT = "permit"
    DENY = "deny"
    CHALLENGE = "challenge"
    """FR-AZ-05. Everything about the request was acceptable except the strength
    of the authentication, so the answer is "prove it is you" rather than "no".
    A denial here would send somebody to a help desk over something they can fix
    in ten seconds."""


@dataclass(frozen=True, slots=True)
class Subject:
    """Who is asking, as attributes rather than as a person."""

    entitlements: frozenset[str] = field(default_factory=frozenset)
    affiliations: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    assurance: str = AAL1
    person_uuid: str | None = None
    """Carried for the audit record only. Nothing in the evaluation reads it —
    a decision that depended on *which* person was asking rather than on what
    they hold would be an access-control list wearing a policy engine's
    clothes."""


@dataclass(frozen=True, slots=True)
class Resource:
    """What is being asked for."""

    id: str
    classification: str = "internal"
    requires_aal2: bool = False
    """FR-AZ-05. A property of the resource rather than of the rule, so a policy
    author cannot forget it on the rule they add next year."""


@dataclass(frozen=True, slots=True)
class Environment:
    """The circumstances. Everything here is server-observed.

    Nothing on this comes from the request body. A client that could assert its
    own network or its own time of day would be choosing which rules apply to
    it, which is the whole game.
    """

    network: str = ""
    at: time | None = None


@dataclass(frozen=True, slots=True)
class Request:
    subject: Subject
    resource: Resource
    action: str
    environment: Environment = field(default_factory=Environment)


@dataclass(frozen=True, slots=True)
class Decision:
    """What was decided, and by what."""

    effect: Effect
    rule_id: str
    reason: str = ""
    required_assurance: str | None = None
    """Set on a challenge, so the caller knows what to ask for rather than
    guessing at the strongest thing it supports."""

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.PERMIT


@dataclass(frozen=True, slots=True)
class Rule:
    """One policy statement."""

    id: str
    effect: Effect
    description: str = ""

    entitlements: frozenset[str] = field(default_factory=frozenset)
    """The subject must hold at least one. Any rather than all: a rule listing
    three entitlements reads as "somebody with LMS access, or library access, or
    VPN", and a rule that needed all three would be written as three
    conditions."""

    affiliations: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)

    actions: frozenset[str] = field(default_factory=frozenset)
    resources: frozenset[str] = field(default_factory=frozenset)
    resource_prefix: str = ""
    classifications: frozenset[str] = field(default_factory=frozenset)

    networks: frozenset[str] = field(default_factory=frozenset)
    between: tuple[time, time] | None = None

    assurance: str = ""
    """What this rule demands of the authentication. Checked *after* matching,
    so a shortfall becomes a challenge rather than a failure to match."""

    def matches(self, request: Request) -> bool:
        """Whether this rule speaks to this request at all.

        Assurance is deliberately not consulted. See the module docstring: a
        rule that failed to match on assurance would turn a step-up into a
        denial.
        """
        subject, resource = request.subject, request.resource

        if self.entitlements and not (self.entitlements & subject.entitlements):
            return False
        if self.affiliations and not (self.affiliations & subject.affiliations):
            return False
        if self.roles and not (self.roles & subject.roles):
            return False
        if self.actions and request.action not in self.actions:
            return False
        if self.resources and resource.id not in self.resources:
            return False
        if self.resource_prefix and not resource.id.startswith(self.resource_prefix):
            return False
        if self.classifications and resource.classification not in self.classifications:
            return False
        if self.networks and request.environment.network not in self.networks:
            return False
        return not (self.between and not _within(request.environment.at, self.between))

    def required_assurance(self, resource: Resource) -> str:
        """The strongest assurance this rule and this resource ask for.

        The resource's own requirement is honoured even by a rule that names
        none, which is what makes `requires_aal2` a property somebody sets once
        rather than a condition every future rule has to remember.
        """
        demanded = self.assurance or ""
        if resource.requires_aal2:
            demanded = _stronger(demanded, AAL2)
        return demanded


class PolicySet:
    """The rules, and the algorithm that combines them."""

    def __init__(self, rules: tuple[Rule, ...] = ()) -> None:
        self._rules = rules

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def decide(self, request: Request) -> Decision:
        """Evaluate every rule and combine with deny-overrides (FR-AZ-04).

        Every rule, not the first match. Stopping early would make the order of
        the file part of its meaning — and a deny that happened to sit below a
        permit would never be reached.
        """
        matched = [rule for rule in self._rules if rule.matches(request)]

        for rule in matched:
            if rule.effect is Effect.DENY:
                # One deny beats any number of permits, whatever order they are
                # written in.
                return _decided(
                    Effect.DENY, rule, request, reason=rule.description or "denied by policy"
                )

        for rule in matched:
            if rule.effect is Effect.PERMIT:
                demanded = rule.required_assurance(request.resource)
                if _falls_short(request.subject.assurance, demanded):
                    # FR-AZ-05: everything was acceptable except how strongly
                    # they authenticated, so ask them to prove it rather than
                    # sending them to a help desk.
                    return Decision(
                        effect=Effect.CHALLENGE,
                        rule_id=rule.id,
                        reason=f"{demanded} required, session is {request.subject.assurance}",
                        required_assurance=demanded,
                    )
                return _decided(
                    Effect.PERMIT, rule, request, reason=rule.description or "permitted"
                )

        return Decision(
            effect=Effect.DENY,
            rule_id=DEFAULT_RULE,
            reason="no rule permitted this request",
        )


def _decided(effect: Effect, rule: Rule, request: Request, *, reason: str) -> Decision:
    log.info(
        "authz.decision",
        effect=effect.value,
        rule=rule.id,
        action=request.action,
        resource=request.resource.id,
        subject=request.subject.person_uuid,
    )
    return Decision(effect=effect, rule_id=rule.id, reason=reason)


def _stronger(left: str, right: str) -> str:
    return left if ASSURANCE_ORDER.get(left, 0) >= ASSURANCE_ORDER.get(right, 0) else right


def _falls_short(held: str, demanded: str) -> bool:
    """Whether the session is weaker than the rule asks for.

    Compared by rank rather than by equality: a rule asking for AAL1 is
    satisfied by an AAL2 session, and an equality check would challenge somebody
    who had already done more than was asked.
    """
    if not demanded:
        return False
    return ASSURANCE_ORDER.get(held, 0) < ASSURANCE_ORDER.get(demanded, 0)


def _within(moment: time | None, window: tuple[time, time]) -> bool:
    """Whether a time falls inside a window, including one that wraps midnight.

    A window of 22:00 to 06:00 is an ordinary way to express "overnight", and an
    implementation that only handled `start <= end` would silently match nothing
    for exactly the rules somebody wrote at two in the morning.
    """
    if moment is None:
        # No time was observed, so a time-bounded rule cannot be satisfied. The
        # safe direction: a rule that only applies during office hours must not
        # apply when we do not know the hour.
        return False
    start, end = window
    if start <= end:
        return start <= moment <= end
    return moment >= start or moment <= end


def subject_from(attributes: dict[str, Any], *, assurance: str = AAL1) -> Subject:
    """Build a subject from a session's released attributes.

    Takes what the session already holds rather than querying: the attributes
    were settled when the session was established, and a decision engine that
    went back to the database would make every authorization call a query and
    every stale cache a security question.
    """
    from campusid.policy.attributes import ENTITLEMENT, SCOPED_AFFILIATION

    return Subject(
        entitlements=frozenset(attributes.get(ENTITLEMENT, [])),
        affiliations=frozenset(
            value.split("@", 1)[0] for value in attributes.get(SCOPED_AFFILIATION, [])
        ),
        assurance=assurance,
    )
