"""Affiliation transition rules (FR-LC-04).

The matrix the requirement asks for, run against the rules the broker actually
ships rather than a fixture written to pass. If somebody edits
`config/lifecycle_rules.yaml`, these fail — which is the point: the file is the
decision, and a change to it is a change to who has access.

The transition that names the requirement is a graduating student. They become
an alum, lose the LMS after a grace period, and keep the mail alias. The second
half is the one that gets implemented wrong: the alias survives because a rule
still justifies it for alumni, not because anything was grandfathered.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from campusid.lifecycle.rules import (
    Delta,
    Grant,
    LifecycleRules,
    LifecycleRulesError,
    RulesStore,
    load_rules,
)
from campusid.lifecycle.store import event_type, justification_ref

RULES_FILE = Path(__file__).resolve().parents[2] / "config" / "lifecycle_rules.yaml"

LMS = "urn:mace:campus.edu:entitlement:lms:access"
MAIL = "urn:mace:campus.edu:entitlement:mail:alias"
LIBRARY = "urn:mace:campus.edu:entitlement:library:eresources"
VPN = "urn:mace:campus.edu:entitlement:vpn:access"
HR = "urn:mace:campus.edu:entitlement:hr:selfservice"
GRANTS = "urn:mace:campus.edu:entitlement:grants:submit"
ALUMNI = "urn:mace:campus.edu:entitlement:alumni:portal"

TODAY = date(2026, 6, 30)


@pytest.fixture(scope="module")
def rules() -> LifecycleRules:
    """The shipped rules. Loading them here is also the test that they load."""
    return load_rules(RULES_FILE)


def _urns(grants: tuple[Grant, ...]) -> set[str]:
    return {grant.urn for grant in grants}


def _revoked(delta: Delta) -> set[str]:
    return {revocation.urn for revocation in delta.revoked}


# --- the matrix -------------------------------------------------------------

TRANSITIONS = [
    # (name, before, after, granted, revoked)
    ("a new student joins", set(), {"student"}, {LMS, MAIL, LIBRARY}, set()),
    ("a new member of staff joins", set(), {"staff"}, {MAIL, LIBRARY, HR, VPN}, set()),
    (
        "a new academic joins",
        set(),
        {"faculty"},
        {MAIL, LIBRARY, HR, VPN, LMS, GRANTS},
        set(),
    ),
    ("a student graduates", {"student"}, {"alum"}, {ALUMNI}, {LMS, LIBRARY}),
    ("a student takes a job on campus", {"student"}, {"student", "staff"}, {HR, VPN}, set()),
    (
        "a student employee stops studying",
        {"student", "staff"},
        {"staff"},
        set(),
        {LMS},
    ),
    (
        "a member of staff joins the faculty",
        {"staff"},
        {"faculty"},
        {LMS, GRANTS},
        set(),
    ),
    (
        "an academic leaves entirely",
        {"faculty"},
        set(),
        set(),
        {LMS, MAIL, LIBRARY, HR, VPN, GRANTS},
    ),
    ("a member of staff is terminated", {"staff"}, set(), set(), {MAIL, LIBRARY, HR, VPN}),
    ("an alum enrols again", {"alum"}, {"student"}, {LMS, LIBRARY}, {ALUMNI}),
    ("a visitor arrives", set(), {"affiliate"}, set(), set()),
    (
        "a visitor becomes a contractor",
        {"affiliate"},
        {"employee"},
        {MAIL, LIBRARY, HR, VPN},
        set(),
    ),
]


@pytest.mark.parametrize(
    ("name", "before", "after", "granted", "revoked"),
    TRANSITIONS,
    ids=[transition[0] for transition in TRANSITIONS],
)
def test_a_transition_produces_the_expected_delta(
    rules: LifecycleRules,
    name: str,
    before: set[str],
    after: set[str],
    granted: set[str],
    revoked: set[str],
) -> None:
    delta = rules.transition(before, after, on=TODAY)

    assert _urns(delta.granted) == granted
    assert _revoked(delta) == revoked


# --- the transition the requirement names -----------------------------------


def test_a_graduating_student_keeps_their_email_alias(rules: LifecycleRules) -> None:
    """And keeps it because a rule justifies it for alumni, not because the old
    grant was left alone. The distinction is the whole design: nothing survives
    on the grounds that removing it looked risky."""
    delta = rules.transition({"student"}, {"alum"}, on=TODAY)

    assert MAIL in _urns(delta.retained)
    assert MAIL not in _revoked(delta)
    assert any(grant.rule_id == "alumni-keep-mail-and-the-portal" for grant in delta.retained)


def test_a_graduating_student_keeps_the_lms_for_thirty_days(rules: LifecycleRules) -> None:
    """Coursework does not stop mattering the day somebody graduates, and a
    transcript dispute in July is exactly when they need it."""
    delta = rules.transition({"student"}, {"alum"}, on=TODAY)

    lms = next(revocation for revocation in delta.revoked if revocation.urn == LMS)
    assert lms.grace_days == 30
    assert lms.effective == TODAY + timedelta(days=30)


def test_a_licensed_resource_ends_with_the_affiliation(rules: LifecycleRules) -> None:
    """Licence terms bind electronic resources to current members, so a grace
    period there would be a contract breach rather than a kindness."""
    delta = rules.transition({"student"}, {"alum"}, on=TODAY)

    library = next(revocation for revocation in delta.revoked if revocation.urn == LIBRARY)
    assert library.grace_days == 0
    assert library.effective == TODAY


def test_deferred_and_immediate_revocations_are_separable(rules: LifecycleRules) -> None:
    """A caller has to schedule the deferred ones, and forgetting is the failure
    that leaves access in place forever — so it has to ask for them by name."""
    delta = rules.transition({"student"}, {"alum"}, on=TODAY)

    assert {revocation.urn for revocation in delta.deferred} == {LMS}
    assert {revocation.urn for revocation in delta.immediate} == {LIBRARY}


# --- justification ----------------------------------------------------------


def test_an_entitlement_justified_twice_is_recorded_twice(rules: LifecycleRules) -> None:
    """Somebody who is both student and faculty holds the LMS through two rules.
    Collapsing them would make losing one affiliation look like losing the
    entitlement."""
    grants = rules.grants_for({"student", "faculty"})

    lms = [grant for grant in grants if grant.urn == LMS]
    assert {grant.rule_id for grant in lms} == {"students-get-the-lms", "faculty-get-the-lms"}


def test_an_entitlement_survives_losing_one_of_two_justifications(
    rules: LifecycleRules,
) -> None:
    """The mover case, and it needs no code that knows about movers: recompute,
    and what is still justified is still there."""
    delta = rules.transition({"student", "faculty"}, {"faculty"}, on=TODAY)

    assert LMS not in _revoked(delta)
    assert LMS in _urns(delta.retained)


def test_a_transition_that_changes_nothing_is_empty(rules: LifecycleRules) -> None:
    delta = rules.transition({"student"}, {"student"}, on=TODAY)

    assert delta.is_empty
    assert _urns(delta.retained) == {LMS, MAIL, LIBRARY}


# --- naming a transition ----------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (set(), {"student"}, "joiner"),
        ({"student"}, {"student", "staff"}, "mover"),
        ({"student"}, {"alum"}, "mover"),
        ({"staff"}, set(), "leaver"),
    ],
)
def test_a_transition_is_named_from_the_affiliations(
    before: set[str], after: set[str], expected: str
) -> None:
    """Not from what the caller thinks it is doing. A SCIM update that happens
    to remove somebody's last affiliation is a leaver, and recording it as an
    ordinary update is how a termination goes unnoticed."""
    assert event_type(before, after) == expected


def test_a_justification_names_the_rule_and_the_affiliation(rules: LifecycleRules) -> None:
    """The rule alone cannot tell the student justification for LMS access from
    the faculty one, and that distinction is exactly what a mover turns on."""
    grant = next(
        grant for grant in rules.grants_for({"student"}) if grant.rule_id == "students-get-the-lms"
    )

    assert justification_ref(grant) == "students-get-the-lms:student"


# --- the file is a trust boundary -------------------------------------------


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(body, encoding="utf-8")
    return path


VALID_ENTITLEMENT = """
entitlements:
  - urn: urn:mace:campus.edu:entitlement:lms:access
    display_name: LMS
"""


def test_a_grant_naming_an_undeclared_entitlement_is_refused(tmp_path: Path) -> None:
    """Otherwise the rule silently grants nothing, and the reflex fix for "they
    did not get their access" is a broader rule."""
    path = _write(
        tmp_path,
        VALID_ENTITLEMENT
        + """
rules:
  - id: typo
    affiliations: [student]
    grants: [urn:mace:campus.edu:entitlement:lms:acess]
""",
    )

    with pytest.raises(LifecycleRulesError, match="undeclared"):
        load_rules(path)


def test_an_affiliation_outside_the_vocabulary_is_refused(tmp_path: Path) -> None:
    """It could never match a normalised value, so the rule would never fire."""
    path = _write(
        tmp_path,
        VALID_ENTITLEMENT
        + """
rules:
  - id: invented
    affiliations: [postgrad]
    grants: []
""",
    )

    with pytest.raises(LifecycleRulesError, match="eduPerson"):
        load_rules(path)


def test_a_duplicate_rule_id_is_refused(tmp_path: Path) -> None:
    """Ids appear in every grant's justification; two rules sharing one makes an
    access review unable to say which fired."""
    path = _write(
        tmp_path,
        VALID_ENTITLEMENT
        + """
rules:
  - id: same
    affiliations: [student]
    grants: []
  - id: same
    affiliations: [staff]
    grants: []
""",
    )

    with pytest.raises(LifecycleRulesError, match="twice"):
        load_rules(path)


def test_a_duplicate_entitlement_is_refused(tmp_path: Path) -> None:
    """Two definitions mean two grace periods, and whichever loses is the one
    somebody thought they had set."""
    path = _write(
        tmp_path,
        """
entitlements:
  - urn: urn:x:a
    display_name: A
  - urn: urn:x:a
    display_name: A again
rules:
  - id: r
    affiliations: [student]
    grants: []
""",
    )

    with pytest.raises(LifecycleRulesError, match="declared twice"):
        load_rules(path)


@pytest.mark.parametrize("grace", ["forever", -1, 400, True])
def test_a_nonsensical_grace_period_is_refused(tmp_path: Path, grace: object) -> None:
    """A year is the ceiling. Longer is not a grace period, it is a decision not
    to deprovision, and it should be argued for rather than typed."""
    path = _write(
        tmp_path,
        f"""
entitlements:
  - urn: urn:x:a
    display_name: A
    grace_days: {grace}
rules:
  - id: r
    affiliations: [student]
    grants: []
""",
    )

    with pytest.raises(LifecycleRulesError):
        load_rules(path)


def test_an_unknown_classification_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
entitlements:
  - urn: urn:x:a
    display_name: A
    classification: secret
rules:
  - id: r
    affiliations: [student]
    grants: []
""",
    )

    with pytest.raises(LifecycleRulesError, match="classification"):
        load_rules(path)


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LifecycleRulesError):
        load_rules(_write(tmp_path, "- just\n- a\n- list\n"))


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LifecycleRulesError):
        load_rules(tmp_path / "absent.yaml")


def test_yaml_that_would_construct_objects_is_not_executed(tmp_path: Path) -> None:
    """`safe_load`, never `load`. A rules file is edited by the most people under
    the most time pressure, and the full loader would make it a code-execution
    surface."""
    path = _write(tmp_path, "entitlements: !!python/object/apply:os.system ['echo pwned']\n")

    with pytest.raises(LifecycleRulesError):
        load_rules(path)


# --- the store --------------------------------------------------------------


def test_the_store_loads_the_shipped_rules() -> None:
    store = RulesStore(RULES_FILE)

    assert store.current.rules
    assert LMS in store.current.entitlements


def test_a_broken_reload_keeps_the_last_known_good_rules(tmp_path: Path) -> None:
    """The alternative on a syntax error is choosing between revoking every
    entitlement on campus at once and granting them all. Keeping what was
    working and shouting about the file is the only recoverable failure."""
    path = _write(
        tmp_path,
        VALID_ENTITLEMENT
        + """
rules:
  - id: students
    affiliations: [student]
    grants: [urn:mace:campus.edu:entitlement:lms:access]
""",
    )
    store = RulesStore(path)
    assert store.current.rules

    path.write_text("entitlements: [\n", encoding="utf-8")
    store.reload()

    assert [rule.id for rule in store.current.rules] == ["students"]


def test_the_store_picks_up_an_edit(tmp_path: Path) -> None:
    """The people who own these decisions are analysts, and a rule change should
    not need a deployment."""
    path = _write(
        tmp_path,
        VALID_ENTITLEMENT
        + """
rules:
  - id: first
    affiliations: [student]
    grants: []
""",
    )
    store = RulesStore(path)
    assert [rule.id for rule in store.current.rules] == ["first"]

    path.write_text(
        VALID_ENTITLEMENT
        + """
rules:
  - id: second
    affiliations: [staff]
    grants: []
""",
        encoding="utf-8",
    )
    # The fingerprint is the modification time, which on a fast filesystem can
    # match the previous write to the resolution the stat provides.
    import os

    os.utime(path, (0, 0))

    assert [rule.id for rule in store.current.rules] == ["second"]
