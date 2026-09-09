"""The provisioning client's view of a person.

One row per provisioned person, holding what SCIM needs and the registry has no
opinion about: the SIS's own key, the ETag a client's `If-Match` is compared
against, and the last document they sent.

`external_id` is unique because FR-SCIM-14's idempotency depends on it. Two
people sharing one would make a replayed create ambiguous, which is worse than a
duplicate — a duplicate is visible, while an ambiguous replay silently returns
the wrong person.

Revision ID: 0006_scim_source_record
Revises: 0005_identity_registry
Created: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_scim_source_record"
down_revision: str | None = "0005_identity_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scim_source_record",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=True),
        # The last document the client sent, verbatim. Kept for reconciliation:
        # when the registry and the SIS disagree the question is always "what
        # did they actually send", which a reconstruction cannot answer.
        sa.Column(
            "raw_resource",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column(
            "last_sync_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scim_source_record"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_scim_source_record_person_uuid_person",
        ),
        # One record per person: a second would mean two systems claiming to own
        # the same human being.
        sa.UniqueConstraint("person_uuid", name="uq_scim_source_record_person_uuid"),
        sa.UniqueConstraint("external_id", name="uq_scim_source_record_external_id"),
    )
    op.create_index("ix_scim_source_record_person", "scim_source_record", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
