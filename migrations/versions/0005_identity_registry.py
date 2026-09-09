"""The identity registry.

PRD §8.2's first four entities: `person`, `identifier`, `account`,
`affiliation`. Four rather than twenty because these are what account linking
(§8.4) and SCIM both need, and migrations are forward-only (ADR-002) — a table
added later is cheap, a column shaped wrongly now is permanent.

The constraint worth reading twice is `uq_identifier_type_value_scope`. It
covers *released* rows as well as live ones, which is what makes FR-LC-08's
"an ePPN released to a previous person is never reassigned" a write the database
refuses rather than a rule the application remembers.

Revision ID: 0005_identity_registry
Revises: 0004_audit_event
Created: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_identity_registry"
down_revision: str | None = "0004_audit_event"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AFFILIATIONS = (
    "faculty",
    "student",
    "staff",
    "alum",
    "member",
    "affiliate",
    "employee",
    "library-walk-in",
)


def upgrade() -> None:
    op.create_table(
        "person",
        sa.Column(
            "person_uuid",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("edu_person_unique_id", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("given_name", sa.String(length=255), nullable=True),
        sa.Column("surname", sa.String(length=255), nullable=True),
        sa.Column("preferred_language", sa.String(length=35), nullable=True),
        sa.Column(
            "ferpa_directory_suppressed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column(
            "provisioning_source", sa.String(length=16), nullable=False, server_default="sis"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("person_uuid", name="pk_person"),
        # Never reused even across people, so uniqueness is the whole contract.
        sa.UniqueConstraint("edu_person_unique_id", name="uq_person_edu_person_unique_id"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deactivated', 'archived')",
            name="ck_person_status",
        ),
        sa.CheckConstraint(
            "provisioning_source IN ('sis', 'jit', 'manual')",
            name="ck_person_provisioning_source",
        ),
    )
    op.create_index("ix_person_status", "person", ["status"])
    op.create_index("ix_person_provisioning_source", "person", ["provisioning_source"])

    op.create_table(
        "identifier",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("id_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("scope", sa.String(length=255), nullable=True),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # The tombstone. The row survives release forever so the constraint
        # below keeps refusing to reissue the value.
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_identifier"),
        sa.ForeignKeyConstraint(
            ["person_uuid"], ["person.person_uuid"], name="fk_identifier_person_uuid_person"
        ),
        # Deliberately covers released rows: this is FR-LC-08, enforced by the
        # database rather than by the application remembering.
        sa.UniqueConstraint("id_type", "value", "scope", name="uq_identifier_type_value_scope"),
        sa.CheckConstraint(
            "id_type IN ('eppn', 'mail', 'netid', 'sam_account', 'employee_id', "
            "'student_id', 'orcid', 'unique_id')",
            name="ck_identifier_id_type",
        ),
    )
    op.create_index("ix_identifier_person", "identifier", ["person_uuid", "id_type"])
    op.create_index("ix_identifier_lookup", "identifier", ["id_type", "value"])

    op.create_table(
        "account",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idp_entity_id", sa.String(length=1024), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("subject_at_idp", sa.String(length=512), nullable=False),
        sa.Column("link_confidence", sa.String(length=8), nullable=False, server_default="high"),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_account"),
        sa.ForeignKeyConstraint(
            ["person_uuid"], ["person.person_uuid"], name="fk_account_person_uuid_person"
        ),
        # A subject is meaningful only within its issuer, so the pair is the
        # identity. Without this, two people at different IdPs sharing a
        # NameID would collide.
        sa.UniqueConstraint("idp_entity_id", "subject_at_idp", name="uq_account_idp_subject"),
        sa.CheckConstraint("protocol IN ('saml', 'oidc')", name="ck_account_protocol"),
        sa.CheckConstraint(
            "link_confidence IN ('high', 'medium')", name="ck_account_link_confidence"
        ),
    )
    op.create_index("ix_account_person", "account", ["person_uuid"])

    op.create_table(
        "affiliation",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("affiliation", sa.String(length=32), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("org_unit", sa.String(length=255), nullable=True),
        sa.Column("valid_from", sa.Date(), nullable=False),
        # Null means current. A row rather than a column, so ending an
        # affiliation keeps the history instead of erasing it.
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="sis"),
        sa.PrimaryKeyConstraint("id", name="pk_affiliation"),
        sa.ForeignKeyConstraint(
            ["person_uuid"], ["person.person_uuid"], name="fk_affiliation_person_uuid_person"
        ),
        # The eduPerson controlled vocabulary, enforced here as well as in the
        # release engine: a value that could never be released should not be
        # storable either.
        sa.CheckConstraint(
            "affiliation IN (" + ", ".join(f"'{value}'" for value in AFFILIATIONS) + ")",
            name="ck_affiliation_vocabulary",
        ),
        sa.CheckConstraint(
            "valid_until IS NULL OR valid_until >= valid_from",
            name="ck_affiliation_valid_range",
        ),
    )
    op.create_index("ix_affiliation_person_current", "affiliation", ["person_uuid", "valid_until"])
    op.create_index("ix_affiliation_value", "affiliation", ["affiliation"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
