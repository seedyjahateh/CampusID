"""Schema metadata conventions (see ADR-002 and PRD section 8)."""

from __future__ import annotations

from campusid.models import Base, metadata


def test_base_shares_the_project_metadata() -> None:
    assert Base.metadata is metadata


def test_constraint_naming_convention_is_set() -> None:
    """Set before the first table exists, on purpose.

    Without it, Alembic autogenerate emits whatever names the database chose,
    and a later migration that must drop a constraint has nothing stable to
    name. Retrofitting means renaming every constraint in a live schema.
    """
    convention = metadata.naming_convention

    assert convention["pk"] == "pk_%(table_name)s"
    assert convention["fk"] == ("fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s")
    assert set(convention) == {"ix", "uq", "ck", "fk", "pk"}


def test_no_tables_are_defined_yet() -> None:
    """The registry lands in M1-M3; this pins the current baseline."""
    assert metadata.tables == {}
