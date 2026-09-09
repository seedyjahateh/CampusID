"""The policies shipped in this repository must load.

Everything in `policies/` is documentation that runs. A README example that
stopped parsing after a loader change would be worse than no example: it would
be an authoritative-looking file that nobody could use.

This also pins the README's demonstration case — the analytics SP receiving a
pairwise identifier and a filtered affiliation and nothing else — to a real
policy file rather than to prose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from campusid.policy.attributes import (
    DISPLAY_NAME,
    ENTITLEMENT,
    EPPN,
    MAIL,
    ORG_UNIT,
    RESEARCH_AND_SCHOLARSHIP,
    SCOPED_AFFILIATION,
    Classification,
    definition,
)
from campusid.policy.loader import load_directory
from campusid.policy.release import Basis, ReleasePolicy, Subject, evaluate

POLICY_DIR = Path(__file__).resolve().parents[2] / "policies"

ANALYTICS = "https://analytics.campus.test/sp"
PORTAL = "https://portal.campus.test/oidc"
COLLAB = "https://collab.research.example/sp"

SAM = Subject(person_key="person-1")
SUPPRESSED = Subject(person_key="person-2", ferpa_directory_suppressed=True)

HELD = {
    EPPN: ["sam.obrien@campus.test"],
    MAIL: ["sam.obrien@campus.test"],
    DISPLAY_NAME: ["Samira O'Brien"],
    SCOPED_AFFILIATION: ["student@campus.test", "member@campus.test"],
    ORG_UNIT: ["Computer Science"],
    ENTITLEMENT: [
        "urn:mace:campus.test:entitlement:portal:dashboard",
        "urn:mace:campus.test:entitlement:hr:payroll",
    ],
}


@pytest.fixture(scope="module")
def policies() -> dict[str, ReleasePolicy]:
    return load_directory(POLICY_DIR)


def test_every_shipped_policy_loads(policies: dict[str, ReleasePolicy]) -> None:
    assert set(policies) == {ANALYTICS, PORTAL, COLLAB}


def test_no_shipped_policy_names_a_restricted_attribute(
    policies: dict[str, ReleasePolicy],
) -> None:
    """The loader refuses these, so this asserts the loader was actually applied
    to what shipped rather than to a test fixture."""
    for policy in policies.values():
        for rule in policy.rules:
            attribute = definition(rule.attribute)
            assert attribute is not None
            assert attribute.classification is not Classification.RESTRICTED


def test_the_analytics_sp_receives_only_what_the_readme_claims(
    policies: dict[str, ReleasePolicy],
) -> None:
    """The demonstration case, as an assertion.

    An analytics service needs to count distinct users and separate students
    from staff. It does not need to know who anybody is.
    """
    result = evaluate(policies[ANALYTICS], SAM, HELD)

    assert result.attributes == {SCOPED_AFFILIATION: ["student@campus.test"]}


def test_the_analytics_filter_drops_the_non_student_affiliation(
    policies: dict[str, ReleasePolicy],
) -> None:
    """A partial release: `member@campus.test` does not survive the filter, and
    the decision records that it was a value filter rather than a denial."""
    result = evaluate(policies[ANALYTICS], SAM, HELD)

    decision = next(d for d in result.decisions if d.attribute == SCOPED_AFFILIATION)
    assert decision.basis is Basis.VALUE_FILTER
    assert "member@campus.test" not in decision.values


def test_the_portal_receives_the_research_and_scholarship_bundle(
    policies: dict[str, ReleasePolicy],
) -> None:
    result = evaluate(policies[PORTAL], SAM, HELD)

    assert {EPPN, MAIL, DISPLAY_NAME} <= result.released_names
    assert RESEARCH_AND_SCHOLARSHIP in policies[PORTAL].entity_categories


def test_the_portal_receives_only_its_own_entitlements(
    policies: dict[str, ReleasePolicy],
) -> None:
    """An HR payroll entitlement in a student portal is a disclosure waiting to
    be noticed by the wrong person."""
    result = evaluate(policies[PORTAL], SAM, HELD)

    assert result.attributes[ENTITLEMENT] == ["urn:mace:campus.test:entitlement:portal:dashboard"]


def test_the_portal_still_works_for_a_suppressed_student(
    policies: dict[str, ReleasePolicy],
) -> None:
    """The school-official exception is the deliberate hole in FERPA
    suppression: opting out of the directory is not opting out of the systems
    you have to use to be a student."""
    result = evaluate(policies[PORTAL], SUPPRESSED, HELD)

    assert MAIL in result.attributes


def test_an_external_sp_withholds_from_a_suppressed_student(
    policies: dict[str, ReleasePolicy],
) -> None:
    """The same student, the same attributes, a party outside the university."""
    result = evaluate(policies[COLLAB], SUPPRESSED, HELD)

    assert MAIL not in result.attributes
    decision = next(d for d in result.decisions if d.attribute == MAIL)
    assert decision.basis is Basis.FERPA_SUPPRESSED


def test_the_collaboration_platform_gets_no_org_unit(
    policies: dict[str, ReleasePolicy],
) -> None:
    """Denied at a lower precedence than the R&S bundle would grant. Which
    building someone works in is not research metadata."""
    result = evaluate(policies[COLLAB], SAM, HELD)

    assert ORG_UNIT not in result.attributes


def test_a_shared_subject_id_is_the_documented_exception(
    policies: dict[str, ReleasePolicy],
) -> None:
    """Pairwise is the default and everything else has to justify itself. Only
    the collaboration platform, which needs co-authors to find each other by one
    identifier across several services, asks for shared."""
    shared = {
        entity_id for entity_id, policy in policies.items() if policy.subject_id_mode == "shared"
    }

    assert shared == {COLLAB}
