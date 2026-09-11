"""Schema metadata conventions (see ADR-002 and PRD section 8)."""

from __future__ import annotations

from sqlalchemy import UniqueConstraint

# Imported for their side effect: each registers its tables on the shared
# `metadata` this file asserts against.
import campusid.audit.models
import campusid.federation.models
import campusid.identity.models
import campusid.oidc.models
import campusid.scim.models  # noqa: F401
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
    assert set(metadata.tables) == {
        "federation_entity",
        "oidc_client",
        "audit_event",
        "person",
        "identifier",
        "account",
        "affiliation",
        "scim_source_record",
        "scim_group",
        "scim_group_member",
        "entitlement_grant",
        "lifecycle_event",
        "provisioning_dead_letter",
        "role_assignment",
        "mfa_factor",
    }


def test_an_identifier_is_unique_regardless_of_release() -> None:
    """FR-LC-08 as a schema property rather than an application rule.

    The constraint covers tombstoned rows, so reissuing a released ePPN is a
    write the database refuses. Asserted here because it is the kind of clause
    that a later migration could relax without anybody noticing what it was
    protecting.
    """
    unique = {
        constraint.name: {column.name for column in constraint.columns}
        for constraint in metadata.tables["identifier"].constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert unique["uq_identifier_type_value_scope"] == {"id_type", "value", "scope"}


def test_constraint_names_follow_the_convention() -> None:
    """The reason the convention was set before the first table existed: a
    later migration that must drop a constraint needs a stable name."""
    table = metadata.tables["federation_entity"]

    assert table.primary_key.name == "pk_federation_entity"
    assert {index.name for index in table.indexes} == {"ix_federation_entity_role_enabled"}


def test_no_column_could_hold_a_plaintext_client_secret() -> None:
    """A registration endpoint returns the secret once and the broker cannot
    show it again. That guarantee is only as good as there being nowhere to put
    it, so the schema is asserted rather than the code path."""
    columns = set(metadata.tables["oidc_client"].columns.keys())

    assert "secret_hash" in columns
    assert not {name for name in columns if name in {"secret", "client_secret", "password"}}
