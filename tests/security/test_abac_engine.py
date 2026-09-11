"""The authorization decision (FR-AZ-03, FR-AZ-04, FR-AZ-05).

Fifteen cases against the policy the broker actually ships, so an edit to
`config/authorization.yaml` fails here rather than in somebody's access review.

Three of them carry the design. The deny-overrides conflict proves a single deny
beats a matching permit whatever order they are written in. The default-deny
case proves a request nobody wrote a rule for is refused rather than allowed.
And the step-up case proves that a single-factor session asking for something
that needs two factors is *challenged* rather than denied — a rule that required
assurance as a condition would simply fail to match, and the person would be told
no when the right answer is "prove it is you".
"""

from __future__ import annotations

from datetime import time
from pathlib import Path

import pytest

from campusid.authz.engine import (
    AAL1,
    AAL2,
    DEFAULT_RULE,
    Decision,
    Effect,
    Environment,
    PolicySet,
    Request,
    Resource,
    Rule,
    Subject,
    subject_from,
)
from campusid.authz.loader import load_policies
from campusid.policy.attributes import ENTITLEMENT, SCOPED_AFFILIATION

pytestmark = pytest.mark.security

POLICY_FILE = Path(__file__).resolve().parents[2] / "config" / "authorization.yaml"

LMS = "urn:mace:campus.edu:entitlement:lms:access"
LIBRARY = "urn:mace:campus.edu:entitlement:library:eresources"
HR = "urn:mace:campus.edu:entitlement:hr:selfservice"
VPN = "urn:mace:campus.edu:entitlement:vpn:access"
GRANTS = "urn:mace:campus.edu:entitlement:grants:submit"
ALUMNI = "urn:mace:campus.edu:entitlement:alumni:portal"

MIDDAY = time(12, 0)
MIDNIGHT = time(0, 30)


@pytest.fixture(scope="module")
def policies() -> PolicySet:
    """The shipped policy. Loading it here is also the test that it loads."""
    return load_policies(POLICY_FILE)


def _ask(
    policies: PolicySet,
    *,
    entitlements: set[str] | None = None,
    affiliations: set[str] | None = None,
    roles: set[str] | None = None,
    assurance: str = AAL1,
    resource: str = "lms:course/101",
    classification: str = "internal",
    requires_aal2: bool = False,
    action: str = "read",
    network: str = "campus",
    at: time | None = MIDDAY,
) -> Decision:
    return policies.decide(
        Request(
            subject=Subject(
                entitlements=frozenset(entitlements or set()),
                affiliations=frozenset(affiliations or set()),
                roles=frozenset(roles or set()),
                assurance=assurance,
                person_uuid="6f9619ff-8b86-4d01-b42d-00cf4fc964ff",
            ),
            resource=Resource(
                id=resource, classification=classification, requires_aal2=requires_aal2
            ),
            action=action,
            environment=Environment(network=network, at=at),
        )
    )


# --- the fifteen cases ------------------------------------------------------


def test_1_a_student_reaches_the_learning_environment(policies: PolicySet) -> None:
    decision = _ask(policies, entitlements={LMS})

    assert decision.effect is Effect.PERMIT
    assert decision.rule_id == "lms-for-current-students"


def test_2_somebody_without_the_entitlement_does_not(policies: PolicySet) -> None:
    """And is denied by the *default*, not by a rule. Nothing in the file speaks
    to this request at all."""
    decision = _ask(policies, entitlements=set())

    assert decision.effect is Effect.DENY
    assert decision.rule_id == DEFAULT_RULE


def test_3_a_permitted_action_is_not_every_action(policies: PolicySet) -> None:
    """The library rule permits reading. Nothing permits writing to it, so the
    default refuses — which is the difference between an allow-list and a
    resource somebody remembered to lock."""
    decision = _ask(policies, entitlements={LIBRARY}, resource="library:journals", action="write")

    assert decision.effect is Effect.DENY
    assert decision.rule_id == DEFAULT_RULE


def test_4_restricted_data_is_denied_by_a_rule(policies: PolicySet) -> None:
    """Not by the default. An explicit deny is the one an auditor can point
    at."""
    decision = _ask(
        policies, entitlements={LMS}, resource="lms:grades", classification="restricted"
    )

    assert decision.effect is Effect.DENY
    assert decision.rule_id == "no-restricted-data"


def test_5_a_deny_beats_a_matching_permit(policies: PolicySet) -> None:
    """The deny-overrides conflict the requirement asks for. The LMS rule
    permits this exact request; the restricted-data rule refuses it; the refusal
    wins, and it wins from anywhere in the file."""
    decision = _ask(
        policies,
        entitlements={LMS},
        resource="lms:course/101",
        classification="restricted",
        action="write",
    )

    assert decision.effect is Effect.DENY
    assert decision.rule_id == "no-restricted-data"


def test_6_a_second_factor_is_a_challenge_not_a_denial(policies: PolicySet) -> None:
    """FR-AZ-05, and the case most likely to be got wrong. A rule requiring
    aal2 as a *condition* would not match a single-factor session, and the
    person would be denied over something they can fix in ten seconds."""
    decision = _ask(policies, entitlements={HR}, resource="hr:payslips", assurance=AAL1)

    assert decision.effect is Effect.CHALLENGE
    assert decision.rule_id == "hr-self-service"
    assert decision.required_assurance == AAL2


def test_7_the_same_request_with_two_factors_is_permitted(policies: PolicySet) -> None:
    decision = _ask(policies, entitlements={HR}, resource="hr:payslips", assurance=AAL2)

    assert decision.effect is Effect.PERMIT
    assert decision.rule_id == "hr-self-service"


def test_8_a_challenge_still_requires_everything_else(policies: PolicySet) -> None:
    """Somebody with no HR entitlement is denied rather than challenged.
    Challenging them would tell an attacker that a second factor is all that
    stands between them and the payroll system."""
    decision = _ask(policies, entitlements={LMS}, resource="hr:payslips", assurance=AAL1)

    assert decision.effect is Effect.DENY


def test_9_the_admin_surface_is_closed_from_outside(policies: PolicySet) -> None:
    """Even to somebody who holds the role. Network and role are separate
    conditions, and the deny does not care about the role at all."""
    decision = _ask(
        policies,
        roles={"iam-admin"},
        resource="admin:clients",
        assurance=AAL2,
        network="public",
    )

    assert decision.effect is Effect.DENY
    assert decision.rule_id == "admin-from-campus-only"


def test_10_the_admin_surface_is_open_to_the_right_role_on_campus(
    policies: PolicySet,
) -> None:
    decision = _ask(
        policies, roles={"iam-admin"}, resource="admin:clients", assurance=AAL2, network="campus"
    )

    assert decision.effect is Effect.PERMIT
    assert decision.rule_id == "admin-for-iam-staff"


def test_11_a_role_somebody_does_not_hold_grants_nothing(policies: PolicySet) -> None:
    decision = _ask(policies, roles=set(), resource="admin:clients", assurance=AAL2)

    assert decision.effect is Effect.DENY
    assert decision.rule_id == DEFAULT_RULE


def test_12_a_time_window_closes_outside_office_hours(policies: PolicySet) -> None:
    """Submission is time-bounded; the rule permitting it simply does not match
    at half past midnight."""
    decision = _ask(
        policies, entitlements={GRANTS}, resource="grants:submit", action="write", at=MIDNIGHT
    )

    assert decision.effect is Effect.DENY


def test_13_reading_is_not_time_bounded(policies: PolicySet) -> None:
    """A second rule covers it, which is how a narrower window on one action is
    expressed without narrowing the other."""
    decision = _ask(
        policies, entitlements={GRANTS}, resource="grants:submit", action="read", at=MIDNIGHT
    )

    assert decision.effect is Effect.PERMIT
    assert decision.rule_id == "grant-reading-any-time"


def test_14_an_ended_affiliation_is_denied_outright(policies: PolicySet) -> None:
    """Belt to the braces. Their entitlements should already be gone, and this
    catches the case where a revocation has not propagated yet."""
    decision = _ask(
        policies, entitlements={LMS}, affiliations={"former-member"}, resource="lms:course/101"
    )

    assert decision.effect is Effect.DENY
    assert decision.rule_id == "no-former-members"


def test_15_an_alum_reaches_their_portal_and_nothing_else(policies: PolicySet) -> None:
    permitted = _ask(policies, entitlements={ALUMNI}, resource="alumni:news")
    refused = _ask(policies, entitlements={ALUMNI}, resource="lms:course/101")

    assert permitted.effect is Effect.PERMIT
    assert refused.effect is Effect.DENY


# --- the algorithm itself ---------------------------------------------------


def test_order_does_not_change_the_outcome() -> None:
    """The property deny-overrides exists for. With first-match-wins, where a
    rule is pasted decides what it means — and the diff looks identical either
    way."""
    permit = Rule(id="permit-all", effect=Effect.PERMIT, resource_prefix="thing:")
    deny = Rule(id="deny-all", effect=Effect.DENY, resource_prefix="thing:")
    request = Request(subject=Subject(), resource=Resource(id="thing:one"), action="read")

    first = PolicySet((permit, deny)).decide(request)
    second = PolicySet((deny, permit)).decide(request)

    assert first.effect is second.effect is Effect.DENY
    assert first.rule_id == second.rule_id == "deny-all"


def test_an_empty_policy_denies_everything() -> None:
    """A policy set that failed to load is not a policy set that permits."""
    decision = PolicySet().decide(
        Request(subject=Subject(), resource=Resource(id="anything"), action="read")
    )

    assert decision.effect is Effect.DENY
    assert decision.rule_id == DEFAULT_RULE


def test_every_decision_names_what_decided_it() -> None:
    """FR-AZ-04. There is no answer that leaves the log unable to say why."""
    policies = PolicySet((Rule(id="r", effect=Effect.PERMIT, resource_prefix="a:"),))
    permitted = policies.decide(
        Request(subject=Subject(), resource=Resource(id="a:one"), action="read")
    )
    denied = policies.decide(
        Request(subject=Subject(), resource=Resource(id="b:one"), action="read")
    )

    assert permitted.rule_id and denied.rule_id


def test_a_resource_can_demand_a_second_factor_on_its_own() -> None:
    """So a policy author cannot forget it on the rule they add next year. The
    requirement travels with the resource rather than with every rule that
    mentions it."""
    policies = PolicySet((Rule(id="open", effect=Effect.PERMIT, resource_prefix="x:"),))

    decision = policies.decide(
        Request(
            subject=Subject(assurance=AAL1),
            resource=Resource(id="x:one", requires_aal2=True),
            action="read",
        )
    )

    assert decision.effect is Effect.CHALLENGE


def test_a_stronger_session_satisfies_a_weaker_requirement() -> None:
    """Compared by rank rather than equality, so somebody who already did more
    than was asked is not challenged for it."""
    policies = PolicySet(
        (Rule(id="weak", effect=Effect.PERMIT, resource_prefix="x:", assurance=AAL1),)
    )

    decision = policies.decide(
        Request(subject=Subject(assurance=AAL2), resource=Resource(id="x:one"), action="read")
    )

    assert decision.effect is Effect.PERMIT


def test_an_unreadable_assurance_ranks_below_the_weakest() -> None:
    """The safe direction. A session whose assurance we cannot read is treated
    as the weakest rather than as whatever the value happened to say."""
    policies = PolicySet(
        (Rule(id="needs-one", effect=Effect.PERMIT, resource_prefix="x:", assurance=AAL1),)
    )

    decision = policies.decide(
        Request(
            subject=Subject(assurance="urn:something:else"),
            resource=Resource(id="x:one"),
            action="read",
        )
    )

    assert decision.effect is Effect.CHALLENGE


def test_a_window_that_wraps_midnight_works() -> None:
    """An overnight window is an ordinary thing to write, and an implementation
    that only handled start-before-end would match nothing for exactly the rules
    somebody wrote at two in the morning."""
    overnight = Rule(
        id="night",
        effect=Effect.PERMIT,
        resource_prefix="x:",
        between=(time(22, 0), time(6, 0)),
    )
    policies = PolicySet((overnight,))

    def _at(moment: time) -> Effect:
        return policies.decide(
            Request(
                subject=Subject(),
                resource=Resource(id="x:one"),
                action="read",
                environment=Environment(at=moment),
            )
        ).effect

    assert _at(time(23, 0)) is Effect.PERMIT
    assert _at(time(3, 0)) is Effect.PERMIT
    assert _at(time(12, 0)) is Effect.DENY


def test_a_time_bounded_rule_does_not_match_when_the_time_is_unknown() -> None:
    """The safe direction again: a rule that only applies during office hours
    must not apply when we do not know the hour."""
    policies = PolicySet(
        (
            Rule(
                id="hours",
                effect=Effect.PERMIT,
                resource_prefix="x:",
                between=(time(8, 0), time(18, 0)),
            ),
        )
    )

    decision = policies.decide(
        Request(subject=Subject(), resource=Resource(id="x:one"), action="read")
    )

    assert decision.effect is Effect.DENY


# --- building a subject -----------------------------------------------------


def test_a_subject_is_built_from_what_the_session_holds() -> None:
    """Rather than from a query. A decision engine that went back to the
    database would make every authorization call a query and every stale cache a
    security question."""
    subject = subject_from(
        {ENTITLEMENT: [LMS], SCOPED_AFFILIATION: ["student@campus.test"]}, assurance=AAL2
    )

    assert subject.entitlements == {LMS}
    assert subject.affiliations == {"student"}
    assert subject.assurance == AAL2


def test_the_scope_is_stripped_from_an_affiliation() -> None:
    """Rules are written about `student`, not `student@campus.test`, because the
    scope is an authority boundary rather than part of the role."""
    subject = subject_from({SCOPED_AFFILIATION: ["faculty@partner.edu"]})

    assert subject.affiliations == {"faculty"}
