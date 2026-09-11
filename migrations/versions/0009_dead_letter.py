"""Provisioning dead letters (FR-LC-09).

A downstream write that failed every attempt becomes a row here rather than a
log line. The alternative to giving up is retrying forever, and the alternative
to a durable record is an account nobody knows is still enabled.

`payload` carries the login as well as the person, because by the time somebody
replays the item the person's identifiers may have been released and the
registry would no longer volunteer one.

`replayed_at` is set rather than the row deleted, so "this was stuck for three
days" stays answerable after somebody fixes it.

Revision ID: 0009_dead_letter
Revises: 0008_lifecycle
Created: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_dead_letter"
down_revision: str | None = "0008_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "provisioning_dead_letter",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target", sa.String(length=32), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column(
            "payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        # Per attempt, because "refused four times then timed out" and "timed
        # out five times" are different incidents.
        sa.Column(
            "attempts", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("replayed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_provisioning_dead_letter"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_provisioning_dead_letter_person_uuid_person",
        ),
    )
    # The query an operator actually runs is "what is still outstanding", so the
    # index is on the column that answers it rather than on creation time.
    op.create_index("ix_dead_letter_outstanding", "provisioning_dead_letter", ["replayed_at"])
    op.create_index("ix_dead_letter_person", "provisioning_dead_letter", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
