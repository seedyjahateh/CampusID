"""Entitlement grants and the lifecycle timeline (FR-LC-04, FR-LC-05, FR-LC-06).

`entitlement_grant` records why every access exists, so removing it is a matter
of removing the justification rather than a judgement call. `revoke_at` carries
the end of a grace period in the database rather than in a timer, because a
thirty-day grace period outlives any process and an access that ends only if a
container stays alive does not end.

`lifecycle_event` is the timeline: person, what happened, what asked for it, the
state either side, and the correlation id of the request that caused it.

Revision ID: 0008_lifecycle
Revises: 0007_scim_group
Created: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_lifecycle"
down_revision: str | None = "0007_scim_group"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entitlement_grant",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entitlement_urn", sa.String(length=256), nullable=False),
        sa.Column(
            "justification_kind",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'affiliation'"),
        ),
        sa.Column("justification_ref", sa.String(length=256), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # The end of a grace period, in the database rather than in a timer.
        sa.Column("revoke_at", sa.Date(), nullable=True),
        # Set rather than deleted: "had LMS access until August" is a question
        # an auditor asks, and a deleted row cannot answer it.
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_entitlement_grant"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_entitlement_grant_person_uuid_person",
        ),
        sa.CheckConstraint(
            "justification_kind in ('affiliation', 'group', 'role', 'manual')",
            name="ck_entitlement_grant_justification_kind",
        ),
        # Two justifications for one entitlement are legitimate and expected;
        # two identical ones are a replayed write.
        sa.UniqueConstraint(
            "person_uuid",
            "entitlement_urn",
            "justification_ref",
            name="uq_entitlement_grant_person_urn_justification",
        ),
    )
    op.create_index("ix_entitlement_grant_person", "entitlement_grant", ["person_uuid"])
    op.create_index("ix_entitlement_grant_due", "entitlement_grant", ["revoke_at"])

    op.create_table(
        "lifecycle_event",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        # Both sides rather than a diff: a diff is derivable from the states and
        # the states are not derivable from the diff.
        sa.Column(
            "before_state",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "after_state", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_lifecycle_event"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_lifecycle_event_person_uuid_person",
        ),
    )
    op.create_index("ix_lifecycle_event_person", "lifecycle_event", ["person_uuid", "occurred_at"])
    op.create_index("ix_lifecycle_event_correlation", "lifecycle_event", ["correlation_id"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
