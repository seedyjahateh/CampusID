"""The attribute release policy engine (FR-ARP-01 to 08).

Over-release is the failure this project is most concerned with: it is silent,
it is permanent, and it is what turns a working integration into a FERPA
incident. So most of these tests assert what an SP does *not* receive.
"""

from __future__ import annotations

import pytest

from campusid.policy.attributes import (
    CATALOGUE,
    DISPLAY_NAME,
    EMPLOYEE_ID,
    ENTITLEMENT,
    EPPN,
    MAIL,
    ORG_UNIT,
    PAIRWISE_ID,
    RESEARCH_AND_SCHOLARSHIP,
    RS_BUNDLE,
    SCOPED_AFFILIATION,
    STUDENT_ID,
    SUBJECT_ID,
    Classification,
)
from campusid.policy.release import (
    Basis,
    ReleasePolicy,
    ReleaseResult,
    ReleaseRule,
    Subject,
    evaluate,
    subject_identifier_attribute,
)

pytestmark = pytest.mark.security

SAM = Subject(person_key="person-1")
SUPPRESSED = Subject(person_key="person-2", ferpa_directory_suppressed=True)

HELD = {
    EPPN: ["sam.obrien@campus.edu"],
    MAIL: ["sam.obrien@campus.edu"],
    DISPLAY_NAME: ["Samira O'Brien"],
    SCOPED_AFFILIATION: ["student@campus.edu", "member@campus.edu"],
    ENTITLEMENT: [
        "urn:mace:campus.edu:entitlement:lms:access",
        "urn:mace:campus.edu:entitlement:hr:payroll",
    ],
    ORG_UNIT: ["CS"],
    STUDENT_ID: ["S00184213"],
    EMPLOYEE_ID: ["E00184213"],
}


def _basis(result: ReleaseResult, attribute: str) -> Basis:
    return next(d.basis for d in result.decisions if d.attribute == attribute)


# --- default deny ----------------------------------------------------------


def test_a_policy_with_no_rules_releases_nothing() -> None:
    """The design in one assertion.

    The alternative — release everything not explicitly forbidden — fails open
    every time somebody adds an attribute, and that happens weekly.
    """
    result = evaluate(ReleasePolicy("https://sp.test"), SAM, HELD)

    assert result.attributes == {}
    assert _basis(result, EPPN) is Basis.DEFAULT_DENY


def test_an_unknown_attribute_is_not_released() -> None:
    """The broker cannot reason about the sensitivity of something it has
    never heard of, and guessing permissively is how a restricted field
    escapes."""
    result = evaluate(
        ReleasePolicy("https://sp.test", rules=(ReleaseRule("r", "allow", "urn:made:up"),)),
        SAM,
        {"urn:made:up": ["value"]},
    )

    assert result.attributes == {}
    assert _basis(result, "urn:made:up") is Basis.UNKNOWN_ATTRIBUTE


# --- restricted attributes -------------------------------------------------


@pytest.mark.parametrize("attribute", [STUDENT_ID, EMPLOYEE_ID])
def test_restricted_attributes_are_never_released(attribute: str) -> None:
    """Education records under FERPA. No policy reaches this decision, which
    is why the check runs before any rule is consulted."""
    policy = ReleasePolicy(
        "https://sp.test",
        internal_school_official=True,
        rules=(ReleaseRule("r", "allow", attribute, precedence=1),),
    )

    result = evaluate(policy, SAM, HELD)

    assert attribute not in result.attributes
    assert _basis(result, attribute) is Basis.RESTRICTED


def test_no_catalogued_attribute_is_restricted_by_accident() -> None:
    """Pins the classification of the two that are.

    Promoting an attribute to `restricted` stops it being releasable anywhere,
    so it should be a deliberate edit rather than a silent one.
    """
    restricted = {
        name
        for name, attribute in CATALOGUE.items()
        if attribute.classification is Classification.RESTRICTED
    }

    assert restricted == {STUDENT_ID, EMPLOYEE_ID}


# --- FERPA suppression -----------------------------------------------------


def test_suppression_withholds_directory_information() -> None:
    """34 CFR 99.37. The student opted out; the SP's rules do not matter."""
    policy = ReleasePolicy(
        "https://sp.test",
        rules=(
            ReleaseRule("a", "allow", MAIL),
            ReleaseRule("b", "allow", DISPLAY_NAME),
            ReleaseRule("c", "allow", EPPN),
        ),
    )

    result = evaluate(policy, SUPPRESSED, HELD)

    assert MAIL not in result.attributes
    assert DISPLAY_NAME not in result.attributes
    assert _basis(result, MAIL) is Basis.FERPA_SUPPRESSED


def test_suppression_does_not_withhold_non_directory_attributes() -> None:
    """`eduPersonPrincipalName` is an identifier, not directory information.

    Suppressing it would break the student's own logins, which is not what
    opting out of the directory means.
    """
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("a", "allow", EPPN),))

    result = evaluate(policy, SUPPRESSED, HELD)

    assert result.attributes[EPPN] == ["sam.obrien@campus.edu"]


def test_a_school_official_still_receives_directory_information() -> None:
    """FERPA 99.31(a)(1), and the reason suppression is usable at all: a
    suppressed student must still be able to use the LMS."""
    policy = ReleasePolicy(
        "https://lms.test",
        internal_school_official=True,
        rules=(ReleaseRule("a", "allow", DISPLAY_NAME),),
    )

    result = evaluate(policy, SUPPRESSED, HELD)

    assert result.attributes[DISPLAY_NAME] == ["Samira O'Brien"]


def test_suppression_overrides_an_entity_category() -> None:
    """A category is a statement about the SP; suppression is a statement about
    the person. The person wins."""
    policy = ReleasePolicy(
        "https://rs.test", entity_categories=frozenset({RESEARCH_AND_SCHOLARSHIP})
    )

    result = evaluate(policy, SUPPRESSED, HELD)

    assert MAIL not in result.attributes
    assert DISPLAY_NAME not in result.attributes


# --- explicit rules --------------------------------------------------------


def test_an_allow_rule_releases_every_value() -> None:
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("a", "allow", ENTITLEMENT),))

    result = evaluate(policy, SAM, HELD)

    assert result.attributes[ENTITLEMENT] == HELD[ENTITLEMENT]
    assert _basis(result, ENTITLEMENT) is Basis.EXPLICIT_ALLOW


def test_a_deny_rule_beats_a_later_allow() -> None:
    """Precedence, so a blanket permission can be carved back without
    rewriting it."""
    policy = ReleasePolicy(
        "https://sp.test",
        rules=(
            ReleaseRule("deny-first", "deny", MAIL, precedence=1),
            ReleaseRule("allow-later", "allow", MAIL, precedence=100),
        ),
    )

    result = evaluate(policy, SAM, HELD)

    assert MAIL not in result.attributes
    assert _basis(result, MAIL) is Basis.EXPLICIT_DENY


def test_a_value_filter_releases_only_matching_values() -> None:
    """The LMS may know a student holds LMS access; it has no business knowing
    they are on the payroll."""
    policy = ReleasePolicy(
        "https://lms.test",
        rules=(
            ReleaseRule(
                "lms-only",
                "allow-value",
                ENTITLEMENT,
                value_filter=r"urn:mace:campus\.edu:entitlement:lms:.*",
            ),
        ),
    )

    result = evaluate(policy, SAM, HELD)

    assert result.attributes[ENTITLEMENT] == ["urn:mace:campus.edu:entitlement:lms:access"]
    assert _basis(result, ENTITLEMENT) is Basis.VALUE_FILTER


def test_a_value_filter_is_anchored_at_both_ends() -> None:
    """An unanchored pattern would admit `student@campus.edu.attacker.test` —
    the same class of mistake as a prefix-matched redirect URL."""
    policy = ReleasePolicy(
        "https://sp.test",
        rules=(
            ReleaseRule(
                "affiliation",
                "allow-value",
                SCOPED_AFFILIATION,
                value_filter=r"(student|member)@campus\.edu",
            ),
        ),
    )

    result = evaluate(
        policy,
        SAM,
        {SCOPED_AFFILIATION: ["student@campus.edu", "student@campus.edu.attacker.test"]},
    )

    assert result.attributes[SCOPED_AFFILIATION] == ["student@campus.edu"]


def test_allow_value_without_a_filter_releases_everything() -> None:
    """A filter is optional on `allow-value`, and its absence must not silently
    drop the attribute — that would make an incomplete policy look like a
    deliberate denial."""
    policy = ReleasePolicy(
        "https://sp.test", rules=(ReleaseRule("all", "allow-value", ENTITLEMENT),)
    )

    result = evaluate(policy, SAM, HELD)

    assert result.attributes[ENTITLEMENT] == HELD[ENTITLEMENT]


def test_a_filter_matching_nothing_releases_nothing() -> None:
    policy = ReleasePolicy(
        "https://sp.test",
        rules=(ReleaseRule("none", "allow-value", ENTITLEMENT, value_filter="no-match"),),
    )

    result = evaluate(policy, SAM, HELD)

    assert ENTITLEMENT not in result.attributes


# --- entity categories -----------------------------------------------------


def test_the_rs_bundle_is_released_without_per_attribute_rules() -> None:
    """A category an SP earns once is reviewable; two hundred hand-written
    per-SP rules are not."""
    policy = ReleasePolicy(
        "https://rs.test", entity_categories=frozenset({RESEARCH_AND_SCHOLARSHIP})
    )

    result = evaluate(policy, SAM, HELD)

    assert result.released_names == (RS_BUNDLE & set(HELD))
    assert _basis(result, MAIL) is Basis.ENTITY_CATEGORY


def test_the_rs_bundle_does_not_include_entitlements() -> None:
    """R&S is a fixed federation-wide set. An SP wanting more asks for it
    explicitly, which is the reviewable path."""
    policy = ReleasePolicy(
        "https://rs.test", entity_categories=frozenset({RESEARCH_AND_SCHOLARSHIP})
    )

    result = evaluate(policy, SAM, HELD)

    assert ENTITLEMENT not in result.attributes
    assert ORG_UNIT not in result.attributes


def test_the_rs_bundle_contents_are_pinned() -> None:
    """Adding to this is a federation-wide decision, not a local convenience."""
    assert {
        SUBJECT_ID,
        EPPN,
        MAIL,
        DISPLAY_NAME,
        "urn:oid:2.5.4.42",
        "urn:oid:2.5.4.4",
        SCOPED_AFFILIATION,
    } == RS_BUNDLE


def test_an_explicit_deny_overrides_the_category() -> None:
    policy = ReleasePolicy(
        "https://rs.test",
        entity_categories=frozenset({RESEARCH_AND_SCHOLARSHIP}),
        rules=(ReleaseRule("no-mail", "deny", MAIL, precedence=1),),
    )

    result = evaluate(policy, SAM, HELD)

    assert MAIL not in result.attributes


# --- the demonstration case ------------------------------------------------


def test_the_analytics_sp_receives_only_a_pairwise_identifier() -> None:
    """The example the README leads with.

    An analytics service needs to count returning users. It does not need to
    know who they are, and a policy that gives it a name anyway is the ordinary
    way over-release happens.
    """
    policy = ReleasePolicy(
        "https://analytics.test",
        subject_id_mode="pairwise",
        rules=(
            ReleaseRule(
                "affiliation",
                "allow-value",
                SCOPED_AFFILIATION,
                value_filter=r"[a-z]+@campus\.edu",
            ),
        ),
    )

    result = evaluate(policy, SAM, HELD)

    assert result.released_names == {SCOPED_AFFILIATION}
    assert subject_identifier_attribute(policy) == PAIRWISE_ID


# --- auditability ----------------------------------------------------------


def test_every_attribute_produces_a_decision() -> None:
    """FR-ARP-06. "Why does this app see my name?" is where every incident
    starts, and it cannot be answered from a list of what was released."""
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("a", "allow", EPPN),))

    result = evaluate(policy, SAM, HELD)

    assert {d.attribute for d in result.decisions} == set(HELD)
    assert result.denied_names == set(HELD) - {EPPN}


def test_a_release_decision_names_the_rule_that_made_it() -> None:
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("rule-7", "allow", EPPN),))

    result = evaluate(policy, SAM, HELD)

    decision = next(d for d in result.decisions if d.attribute == EPPN)
    assert decision.rule_id == "rule-7"


def test_decisions_are_deterministic_in_order() -> None:
    """An audit record whose order varied between runs would be needlessly
    hard to diff."""
    policy = ReleasePolicy("https://sp.test")

    first = evaluate(policy, SAM, HELD)
    second = evaluate(policy, SAM, HELD)

    assert [d.attribute for d in first.decisions] == [d.attribute for d in second.decisions]


# --- consent (FR-ARP-01, the `require-consent` rule kind) -------------------


def test_an_attribute_requiring_consent_is_withheld_by_default() -> None:
    """Fails closed. An attribute nobody has consented to is simply not
    released, so a consent store that is empty, unreachable, or not yet built
    cannot cause a disclosure."""
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("c", "require-consent", MAIL),))

    result = evaluate(policy, SAM, HELD)

    assert MAIL not in result.attributes
    assert _basis(result, MAIL) is Basis.CONSENT_REQUIRED


def test_consent_releases_the_attribute() -> None:
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("c", "require-consent", MAIL),))

    result = evaluate(policy, SAM, HELD, consented=frozenset({MAIL}))

    assert result.attributes[MAIL] == HELD[MAIL]
    assert _basis(result, MAIL) is Basis.CONSENT_GIVEN


def test_consent_is_recorded_as_its_own_basis_not_as_a_denial() -> None:
    """An SP told "denied" stops asking; one told "consent required" can
    prompt. Collapsing the two loses the only difference that matters to the
    person deciding."""
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("c", "require-consent", MAIL),))

    assert _basis(evaluate(policy, SAM, HELD), MAIL) is not Basis.EXPLICIT_DENY


def test_consent_does_not_override_ferpa_suppression() -> None:
    """Suppression runs ahead of every rule. A student who opted out of the
    directory has not consented to it by consenting to something else, and a
    consent record predating the opt-out must not resurrect the release."""
    policy = ReleasePolicy("https://sp.test", rules=(ReleaseRule("c", "require-consent", MAIL),))

    result = evaluate(policy, SUPPRESSED, HELD, consented=frozenset({MAIL}))

    assert MAIL not in result.attributes
    assert _basis(result, MAIL) is Basis.FERPA_SUPPRESSED


def test_consent_cannot_release_an_education_record() -> None:
    """Nothing overrides classification, consent included. A student agreeing to
    disclose their student number does not make it disclosable."""
    policy = ReleasePolicy(
        "https://sp.test", rules=(ReleaseRule("c", "require-consent", STUDENT_ID),)
    )

    result = evaluate(policy, SAM, HELD, consented=frozenset({STUDENT_ID}))

    assert STUDENT_ID not in result.attributes
    assert _basis(result, STUDENT_ID) is Basis.RESTRICTED


def test_consent_for_one_attribute_does_not_release_another() -> None:
    policy = ReleasePolicy(
        "https://sp.test",
        rules=(
            ReleaseRule("c1", "require-consent", MAIL),
            ReleaseRule("c2", "require-consent", DISPLAY_NAME),
        ),
    )

    result = evaluate(policy, SAM, HELD, consented=frozenset({MAIL}))

    assert set(result.attributes) == {MAIL}
