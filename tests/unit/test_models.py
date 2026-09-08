"""Schema metadata conventions (see ADR-002 and PRD section 8)."""

from __future__ import annotations

import campusid.federation.models  # noqa: F401 - registers tables on `metadata`
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


def test_declared_tables_match_the_migrations() -> None:
    """Pins the schema surface.

    Migrations are forward-only (ADR-002), so a table appearing here without a
    matching revision — or vice versa — is a divergence that only shows up at
    deploy time. The identity registry (`person`, `account`, `identifier`)
    joins this set in M3.
    """
    assert set(metadata.tables) == {"federation_entity"}


def test_constraint_names_follow_the_convention() -> None:
    """The reason the convention was set before the first table existed: a
    later migration that must drop a constraint needs a stable name."""
    table = metadata.tables["federation_entity"]

    assert table.primary_key.name == "pk_federation_entity"
    assert {index.name for index in table.indexes} == {"ix_federation_entity_role_enabled"}
