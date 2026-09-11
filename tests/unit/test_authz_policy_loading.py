"""Loading authorization policy (FR-AZ-03, FR-AZ-04).

A policy file is a trust boundary: declarative, edited by people who are not
deploying the broker, and load-bearing for who can reach what. These are the
refusals.

The one worth reading is the duplicate rule id. Ids appear in every audit
record, so two rules sharing one makes "which rule decided this" unanswerable —
which is the exact question FR-AZ-04 exists to make answerable.
"""

from __future__ import annotations

from datetime import time
from pathlib import Path

import pytest

from campusid.authz.engine import AAL2, Effect
from campusid.authz.loader import (
    AuthorizationPolicyError,
    PolicyEngineStore,
    load_policies,
)

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "authorization.yaml"

MINIMAL = """
rules:
  - id: only-rule
    effect: permit
    resource_prefix: "thing:"
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "authorization.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --- the shipped file -------------------------------------------------------


def test_the_shipped_policy_loads() -> None:
    """If this fails, the broker starts with no rules and denies everything."""
    assert load_policies(SHIPPED).rules


def test_every_shipped_rule_has_a_description() -> None:
    """The description is what a denial says back. A rule without one reports
    "denied by policy", which tells an operator nothing they did not know."""
    for rule in load_policies(SHIPPED).rules:
        assert rule.description, rule.id


def test_the_shipped_policy_has_both_permits_and_denies() -> None:
    """A file of only permits has no floor, and one of only denies has no
    purpose. Asserted so a bad edit that deletes a section is visible here."""
    effects = {rule.effect for rule in load_policies(SHIPPED).rules}

    assert effects == {Effect.PERMIT, Effect.DENY}


def test_a_time_window_is_parsed_into_times() -> None:
    """Parsed at load rather than at the request, so a malformed window fails
    the load. A rule with an unreadable window matches nothing, and a rule that
    matches nothing is a denial somebody believes is in place."""
    rules = {rule.id: rule for rule in load_policies(SHIPPED).rules}

    assert rules["grant-submission-in-hours"].between == (time(8, 0), time(18, 0))


def test_assurance_survives_the_load() -> None:
    rules = {rule.id: rule for rule in load_policies(SHIPPED).rules}

    assert rules["hr-self-service"].assurance == AAL2


# --- refusals ---------------------------------------------------------------


def test_a_duplicate_rule_id_is_refused(tmp_path: Path) -> None:
    """Ids appear in every audit record, and two rules sharing one makes "which
    rule decided this" unanswerable."""
    path = _write(
        tmp_path,
        """
rules:
  - id: same
    effect: permit
    resource_prefix: "a:"
  - id: same
    effect: deny
    resource_prefix: "b:"
""",
    )

    with pytest.raises(AuthorizationPolicyError, match="twice"):
        load_policies(path)


def test_a_rule_with_no_id_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "rules:\n  - effect: permit\n")

    with pytest.raises(AuthorizationPolicyError, match="needs an id"):
        load_policies(path)


def test_an_unknown_effect_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "rules:\n  - id: r\n    effect: maybe\n")

    with pytest.raises(AuthorizationPolicyError, match="permit or deny"):
        load_policies(path)


def test_challenge_cannot_be_written_by_hand(tmp_path: Path) -> None:
    """It is an outcome the engine reaches when a permit's assurance falls
    short, not a decision a policy author makes. One written by hand would
    challenge somebody the policy never intended to permit at all."""
    path = _write(tmp_path, "rules:\n  - id: r\n    effect: challenge\n")

    with pytest.raises(AuthorizationPolicyError, match="permit or deny"):
        load_policies(path)


def test_an_unknown_assurance_is_refused(tmp_path: Path) -> None:
    """A typo would otherwise become a requirement no session can ever meet,
    which reads as a permanent challenge loop rather than as a broken file."""
    path = _write(
        tmp_path,
        "rules:\n  - id: r\n    effect: permit\n    assurance: urn:campusid:aal3\n",
    )

    with pytest.raises(AuthorizationPolicyError, match="assurance"):
        load_policies(path)


def test_a_malformed_time_window_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'rules:\n  - id: r\n    effect: permit\n    between: ["breakfast", "lunch"]\n',
    )

    with pytest.raises(AuthorizationPolicyError):
        load_policies(path)


def test_a_one_sided_window_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, 'rules:\n  - id: r\n    effect: permit\n    between: ["08:00"]\n')

    with pytest.raises(AuthorizationPolicyError, match="two times"):
        load_policies(path)


def test_a_condition_that_is_not_a_list_is_refused(tmp_path: Path) -> None:
    """`actions: read` instead of `actions: [read]` is the typo everybody makes
    once, and it would otherwise iterate the string into four single-letter
    actions that match nothing."""
    path = _write(tmp_path, "rules:\n  - id: r\n    effect: permit\n    actions: read\n")

    with pytest.raises(AuthorizationPolicyError, match="list of strings"):
        load_policies(path)


def test_a_file_with_no_rules_is_refused(tmp_path: Path) -> None:
    """An empty policy denies everything, which is safe and is also not what
    anybody meant by writing an empty file."""
    with pytest.raises(AuthorizationPolicyError, match="non-empty"):
        load_policies(_write(tmp_path, "rules: []\n"))


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationPolicyError):
        load_policies(_write(tmp_path, "- just\n- a\n- list\n"))


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationPolicyError):
        load_policies(tmp_path / "absent.yaml")


def test_yaml_that_would_construct_objects_is_not_executed(tmp_path: Path) -> None:
    """`safe_load`, never `load`. A policy file is the last place to hand
    somebody arbitrary object construction."""
    path = _write(tmp_path, "rules: !!python/object/apply:os.system ['echo pwned']\n")

    with pytest.raises(AuthorizationPolicyError):
        load_policies(path)


# --- the store --------------------------------------------------------------


def test_the_store_loads_the_shipped_policy() -> None:
    assert PolicyEngineStore(SHIPPED).current.rules


def test_a_broken_reload_keeps_the_last_known_good_policy(tmp_path: Path) -> None:
    """On a syntax error, an empty policy set denies everything at once and a
    permissive default grants everything at once. Neither is a state to be in at
    three in the morning."""
    path = _write(tmp_path, MINIMAL)
    store = PolicyEngineStore(path)
    assert store.current.rules

    path.write_text("rules: [\n", encoding="utf-8")
    store.reload()

    assert [rule.id for rule in store.current.rules] == ["only-rule"]


def test_the_store_picks_up_an_edit(tmp_path: Path) -> None:
    """The people who own these decisions are analysts, and a policy change
    should not need a deployment."""
    import os

    path = _write(tmp_path, MINIMAL)
    store = PolicyEngineStore(path)
    assert [rule.id for rule in store.current.rules] == ["only-rule"]

    path.write_text(
        'rules:\n  - id: replaced\n    effect: deny\n    resource_prefix: "thing:"\n',
        encoding="utf-8",
    )
    os.utime(path, (0, 0))

    assert [rule.id for rule in store.current.rules] == ["replaced"]
