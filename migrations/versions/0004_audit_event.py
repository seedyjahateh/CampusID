"""The audit trail.

Append-only from the application's perspective (FR-AUD-04). No `UPDATE` or
`DELETE` path exists in `campusid/audit/`, and M5 backs that with a database
role holding only INSERT and SELECT here — the grant protects against a
compromised process, while having no code that can modify a row protects
against the ordinary bug.

The indexes are the three questions FR-AUD-03 says the trail must answer:
what happened to this person, what did this SP receive, and what failed in this
window. The fourth pulls one login's whole chain by correlation id (FR-AUD-02).

Revision ID: 0004_audit_event
Revises: 0003_oidc_client
Created: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_audit_event"
down_revision: str | None = "0003_oidc_client"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_event",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        # When it happened, not when it was written. The distinction matters the
        # moment writes are ever batched or retried.
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=512), nullable=True),
        sa.Column("subject", sa.String(length=512), nullable=True),
        sa.Column("target", sa.String(length=1024), nullable=True),
        sa.Column("reason", sa.String(length=64), nullable=True),
        # 45 characters: an IPv6 address with an embedded IPv4 suffix is the
        # longest textual form.
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column(
            "detail", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_event"),
        # A retried insert cannot duplicate an event. An audit trail that
        # double-counts is as misleading as one that misses.
        sa.UniqueConstraint("event_id", name="uq_audit_event_event_id"),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')", name="ck_audit_event_outcome"
        ),
    )
    op.create_index("ix_audit_event_subject_time", "audit_event", ["subject", "occurred_at"])
    op.create_index("ix_audit_event_target_time", "audit_event", ["target", "occurred_at"])
    op.create_index(
        "ix_audit_event_type_outcome_time",
        "audit_event",
        ["event_type", "outcome", "occurred_at"],
    )
    op.create_index("ix_audit_event_correlation", "audit_event", ["correlation_id"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
