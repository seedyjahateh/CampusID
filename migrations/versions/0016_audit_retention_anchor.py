"""Retention anchors, so a pruned trail still verifies (FR-AUD-08).

Deleting old events breaks the hash chain by construction: the oldest surviving
row links to a predecessor that is no longer there, and a verifier cannot tell
that apart from somebody having removed it to hide something. Without this table
a deployment has to choose between a retention policy and a verifiable trail.

A pass records where it cut and what the last removed event hashed to, and the
verifier starts from that value instead of from the genesis constant. Forging one
means writing a row, and this table is append-only to the application for the
same reason `audit_event` is — pruning is an owner operation run deliberately,
not something the broker does while serving requests.

The row carries who ran the pass and why, so "the trail starts in March because
we prune at 400 days" and "the trail starts in March because somebody deleted
February" are different-looking facts.

Revision ID: 0016_audit_retention_anchor
Revises: 0015_least_privilege_app_role
Created: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_audit_retention_anchor"
down_revision: str | None = "0015_least_privilege_app_role"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "campusid_app"
TABLE = "audit_retention_anchor"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("removed_through_seq", sa.BigInteger(), nullable=False),
        sa.Column("removed_through_hash", sa.String(length=64), nullable=False),
        sa.Column("removed_count", sa.BigInteger(), nullable=False),
        sa.Column("cutoff", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "performed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("performed_by", sa.String(length=256), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False),
        sa.PrimaryKeyConstraint("id", name=f"pk_{TABLE}"),
    )
    op.create_index(f"ix_{TABLE}_seq", TABLE, ["removed_through_seq"])

    # Read-only to the application. An anchor is a claim about what was legitimately
    # removed, so it has to be as hard to forge as the trail it vouches for —
    # and the broker has no reason to write one while serving a request.
    op.execute(f"REVOKE ALL ON {TABLE} FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {TABLE} TO {APP_ROLE}")


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
