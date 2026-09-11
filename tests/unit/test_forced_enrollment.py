"""Who must enrol a second factor (FR-MFA-07).

Somebody holding an entitlement marked `requires_aal2` will be challenged the
first time they reach it. With no factor registered, that challenge is not a
prompt but a dead end, and the person's experience is a system asking for
something it never offered them a way to have.

These tests are about closing that gap without opening a worse one: forcing
enrolment on people who need it, leaving everybody else alone, and never mistaking
a half-finished enrolment for a working factor.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from campusid.authz.roles import RoleCatalogue, load_roles
from campusid.lifecycle.rules import LifecycleRules, load_rules
from campusid.mfa.enrolment import Requirement, requirement

RULES = Path(__file__).resolve().parents[2] / "config" / "lifecycle_rules.yaml"
ROLES = Path(__file__).resolve().parents[2] / "config" / "roles.yaml"

VPN = "urn:mace:campus.edu:entitlement:vpn:access"
HR = "urn:mace:campus.edu:entitlement:hr:selfservice"
LMS = "urn:mace:campus.edu:entitlement:lms:access"
MAIL = "urn:mace:campus.edu:entitlement:mail:alias"


@pytest.fixture(scope="module")
def rules() -> LifecycleRules:
    return load_rules(RULES)


@pytest.fixture(scope="module")
def catalogue() -> RoleCatalogue:
    return load_roles(ROLES)


def _ask(
    rules: LifecycleRules,
    catalogue: RoleCatalogue,
    *,
    entitlements: set[str] | None = None,
    roles: set[str] | None = None,
    has_factor: bool = False,
) -> Requirement:
    return requirement(
        entitlements=entitlements or set(),
        roles=roles or set(),
        rules=rules,
        catalogue=catalogue,
        has_factor=has_factor,
    )


# --- who is asked -----------------------------------------------------------


def test_an_entitlement_that_needs_aal2_forces_enrolment(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    """The requirement's own case, against the entitlements the broker ships."""
    assert _ask(rules, catalogue, entitlements={VPN}).required is True


def test_an_ordinary_entitlement_does_not(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    """Forcing enrolment on everybody with an email alias would make the prompt
    noise, and a prompt that is noise is a prompt people click past."""
    assert _ask(rules, catalogue, entitlements={LMS, MAIL}).required is False


def test_holding_nothing_asks_nothing(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    assert _ask(rules, catalogue).required is False


def test_a_role_that_needs_aal2_forces_enrolment_too(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    """The requirement names entitlements, but a role marked the same way is the
    same statement about the same person made in the other file. Honouring only
    one would let an administrator walk into the wall this exists to prevent."""
    assert _ask(rules, catalogue, roles={"iam-admin"}).required is True


def test_an_ordinary_role_does_not(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    assert _ask(rules, catalogue, roles={"student"}).required is False


def test_an_unknown_entitlement_demands_nothing(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    """A grant from an older version of the file or from another system.
    Inventing a requirement for it would force enrolment on a row nobody can
    explain."""
    assert _ask(rules, catalogue, entitlements={"urn:something:else"}).required is False


def test_an_unknown_role_demands_nothing(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    assert _ask(rules, catalogue, roles={"not-a-role"}).required is False


# --- who is not asked again -------------------------------------------------


def test_somebody_already_enrolled_is_left_alone(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    assert _ask(rules, catalogue, entitlements={HR}, has_factor=True).required is False


def test_the_reasons_are_reported_even_when_nothing_is_required(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    """So an operator can see that somebody is already covered rather than only
    that nothing is being asked of them."""
    result = _ask(rules, catalogue, entitlements={HR}, has_factor=True)

    assert result.required is False
    assert result.reasons == (HR,)


# --- why -------------------------------------------------------------------


def test_the_reasons_name_what_demanded_it(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    """ "You must enrol" with no reason reads as an arbitrary imposition, and an
    operator asked why somebody is being prompted is otherwise comparing two
    config files by hand."""
    result = _ask(rules, catalogue, entitlements={VPN, LMS}, roles={"auditor"})

    assert set(result.reasons) == {VPN, "auditor"}


def test_the_reasons_are_ordered(rules: LifecycleRules, catalogue: RoleCatalogue) -> None:
    """Deterministic, so a message built from them does not reshuffle between
    two loads of the same page."""
    result = _ask(rules, catalogue, entitlements={HR, VPN})

    assert list(result.reasons) == sorted(result.reasons)


def test_only_the_demanding_things_are_named(
    rules: LifecycleRules, catalogue: RoleCatalogue
) -> None:
    result = _ask(rules, catalogue, entitlements={VPN, LMS, MAIL})

    assert result.reasons == (VPN,)


# --- the shipped configuration ----------------------------------------------


def test_something_in_the_shipped_rules_actually_demands_it(rules: LifecycleRules) -> None:
    """A requirement nothing in the deployed configuration triggers is a control
    that has never run."""
    assert [urn for urn, e in rules.entitlements.items() if e.requires_aal2]


def test_something_in_the_shipped_roles_does_too(catalogue: RoleCatalogue) -> None:
    assert [name for name, role in catalogue.roles.items() if role.requires_aal2]
