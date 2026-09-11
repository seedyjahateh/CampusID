"""Roles, derivation and separation of duties (FR-AZ-01, FR-AZ-07).

Against the catalogue the broker actually ships, so an edit to `config/roles.yaml`
fails here rather than in an access review.

The derivation returns assignments rather than bare role names, and that is the
design rather than a detail: a derivation that returned names would make "they
are an instructor" unfalsifiable the moment the affiliation changed, because
nothing would record *why* they were one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from campusid.authz.roles import (
    Origin,
    RoleCatalogue,
    RoleError,
    RoleStore,
    load_roles,
)

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "roles.yaml"

MINIMAL = """
roles:
  - id: only-role
    display_name: Only role
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "roles.yaml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def catalogue() -> RoleCatalogue:
    return load_roles(SHIPPED)


# --- derivation -------------------------------------------------------------


def test_an_affiliation_derives_a_role(catalogue: RoleCatalogue) -> None:
    """Being a student makes you a student. Somebody re-typing that into a role
    table is somebody who will one day forget to un-type it."""
    derived = catalogue.derive(affiliations={"student"})

    assert {item.role for item in derived} == {"student"}
    assert derived[0].origin is Origin.AFFILIATION
    assert derived[0].reference == "student"


def test_a_group_derives_a_role(catalogue: RoleCatalogue) -> None:
    derived = catalogue.derive(groups={"iam-administrators"})

    assert {item.role for item in derived} == {"iam-admin"}
    assert derived[0].origin is Origin.GROUP


def test_one_fact_can_derive_several_roles(catalogue: RoleCatalogue) -> None:
    """Faculty are both instructors and employees, and both are true."""
    derived = catalogue.derive(affiliations={"faculty"})

    assert {item.role for item in derived} == {"instructor", "employee"}


def test_a_role_can_be_derived_twice(catalogue: RoleCatalogue) -> None:
    """`employee` comes from staff and from faculty. Two reasons for one role is
    the case the whole assignment model is shaped around."""
    derived = catalogue.derive(affiliations={"staff", "faculty"})

    employee = [item for item in derived if item.role == "employee"]
    assert {item.reference for item in employee} == {"staff", "faculty"}


def test_facts_nobody_has_derive_nothing(catalogue: RoleCatalogue) -> None:
    assert catalogue.derive(affiliations={"library-walk-in"}) == ()


def test_no_facts_derive_nothing(catalogue: RoleCatalogue) -> None:
    assert catalogue.derive() == ()


def test_every_derivation_records_what_produced_it(catalogue: RoleCatalogue) -> None:
    """An investigation asks "how did they get this?", and a derived role that
    could not say would be indistinguishable from one somebody granted."""
    derived = catalogue.derive(affiliations={"student", "faculty"}, groups={"audit-readers"})

    assert all(item.reference for item in derived)
    assert {item.origin for item in derived} == {Origin.AFFILIATION, Origin.GROUP}


# --- separation of duties ---------------------------------------------------


def test_the_classic_pair_conflicts(catalogue: RoleCatalogue) -> None:
    """One person who can raise a payment and approve it can pay themselves, and
    no amount of logging turns that back into a control."""
    conflicts = catalogue.conflicting({"finance-requester", "finance-approver"})

    assert len(conflicts) == 1
    assert "expenditure" in conflicts[0].reason


def test_holding_one_half_is_fine(catalogue: RoleCatalogue) -> None:
    assert catalogue.conflicting({"finance-requester"}) == ()


def test_an_incompatible_set_is_refused_with_the_reason(catalogue: RoleCatalogue) -> None:
    """The refusal names the conflict, because the person doing the assigning is
    the one who can undo it."""
    with pytest.raises(RoleError, match="expenditure"):
        catalogue.assert_compatible({"finance-requester", "finance-approver"})


def test_a_compatible_set_passes(catalogue: RoleCatalogue) -> None:
    catalogue.assert_compatible({"student", "instructor", "employee"})


def test_every_violated_pair_is_reported_at_once(catalogue: RoleCatalogue) -> None:
    """Reporting the first only would take as many rounds to discover a role
    somebody cannot have as there are conflicts."""
    conflicts = catalogue.conflicting(
        {"finance-requester", "finance-approver", "iam-admin", "auditor"}
    )

    assert len(conflicts) == 2


def test_an_administrator_may_not_audit_themselves(catalogue: RoleCatalogue) -> None:
    assert catalogue.conflicting({"iam-admin", "auditor"})


# --- assurance --------------------------------------------------------------


def test_an_administrative_role_demands_a_second_factor(catalogue: RoleCatalogue) -> None:
    assert catalogue.requires_aal2({"iam-admin"})


def test_an_ordinary_role_does_not(catalogue: RoleCatalogue) -> None:
    assert not catalogue.requires_aal2({"student", "instructor"})


def test_an_unknown_role_does_not_raise(catalogue: RoleCatalogue) -> None:
    """A session carrying a role the catalogue no longer defines should not
    crash a decision; the role simply grants nothing."""
    assert not catalogue.requires_aal2({"role-that-was-deleted"})


# --- the file is a trust boundary -------------------------------------------


def test_the_shipped_catalogue_loads() -> None:
    assert load_roles(SHIPPED).roles


def test_every_shipped_role_has_a_description() -> None:
    """The description is what an access review reads. A role called
    `course-admin` with nothing else said about it is a name, not a job."""
    for role in load_roles(SHIPPED).roles.values():
        assert role.description, role.id


def test_a_derivation_naming_an_unknown_role_is_refused(tmp_path: Path) -> None:
    """It would produce an assignment nothing can interpret, and the access it
    was meant to grant simply never arrives."""
    path = _write(tmp_path, MINIMAL + "\nderivations:\n  - role: typo\n    affiliation: student\n")

    with pytest.raises(RoleError, match="undeclared role"):
        load_roles(path)


def test_a_derivation_with_no_source_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, MINIMAL + "\nderivations:\n  - role: only-role\n")

    with pytest.raises(RoleError, match="exactly one"):
        load_roles(path)


def test_a_derivation_with_two_sources_is_refused(tmp_path: Path) -> None:
    """Whether it means "and" or "or" is not something to leave to whoever reads
    it next."""
    path = _write(
        tmp_path,
        MINIMAL + "\nderivations:\n  - role: only-role\n    affiliation: student\n    group: g\n",
    )

    with pytest.raises(RoleError, match="exactly one"):
        load_roles(path)


def test_a_direct_origin_cannot_be_derived(tmp_path: Path) -> None:
    """A direct assignment is somebody's decision, not a fact the registry can
    produce — and a derivation rule making one would grant it to everybody who
    matched."""
    path = _write(tmp_path, MINIMAL + "\nderivations:\n  - role: only-role\n    direct: someone\n")

    with pytest.raises(RoleError, match="exactly one"):
        load_roles(path)


def test_a_conflict_naming_an_unknown_role_is_refused(tmp_path: Path) -> None:
    """It could never fire, so the control somebody believes is in place is
    not."""
    path = _write(
        tmp_path,
        MINIMAL + "\nseparation_of_duties:\n  - roles: [only-role, ghost]\n    reason: because\n",
    )

    with pytest.raises(RoleError, match="undeclared"):
        load_roles(path)


def test_a_conflict_without_a_reason_is_refused(tmp_path: Path) -> None:
    """The reason is what the refusal says back. Without it an administrator is
    told no and has nobody to argue with."""
    path = _write(
        tmp_path,
        MINIMAL + "\nroles2: []\nseparation_of_duties:\n  - roles: [only-role, only-role]\n",
    )

    with pytest.raises(RoleError):
        load_roles(path)


def test_a_duplicate_role_id_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "roles:\n  - id: same\n    display_name: One\n  - id: same\n    display_name: Two\n",
    )

    with pytest.raises(RoleError, match="twice"):
        load_roles(path)


def test_a_file_with_no_roles_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoleError, match="non-empty"):
        load_roles(_write(tmp_path, "roles: []\n"))


def test_yaml_that_would_construct_objects_is_not_executed(tmp_path: Path) -> None:
    path = _write(tmp_path, "roles: !!python/object/apply:os.system ['echo pwned']\n")

    with pytest.raises(RoleError):
        load_roles(path)


# --- the store --------------------------------------------------------------


def test_the_store_loads_the_shipped_catalogue() -> None:
    assert RoleStore(SHIPPED).current.roles


def test_a_broken_reload_keeps_the_last_known_good_catalogue(tmp_path: Path) -> None:
    """An empty catalogue derives no roles at all, which silently removes
    everybody's access rather than failing loudly."""
    path = _write(tmp_path, MINIMAL)
    store = RoleStore(path)
    assert store.current.roles

    path.write_text("roles: [\n", encoding="utf-8")
    store.reload()

    assert set(store.current.roles) == {"only-role"}
