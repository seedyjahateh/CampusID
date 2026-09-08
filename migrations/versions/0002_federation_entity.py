"""Federation entity registry.

FR-FED-02 requires an IdP to become usable without a process restart, and
`Settings` is frozen and `lru_cache`d, so the trusted set has to live in the
database rather than in configuration.

Deliberately narrow. The `person`/`account`/`identifier` shape belongs to the
identity registry in M3, and these migrations are forward-only (ADR-002), so
guessing that shape now would make a wrong guess permanent. Adding columns
later is cheap; dropping them is not.

Revision ID: 0002_federation_entity
Revises: 0001_baseline
Created: 2026-09-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_federation_entity"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "federation_entity",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_id", sa.String(length=1024), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        # The descriptor verbatim: every trust decision re-parses this, so a
        # later tightening of the parser applies to entities registered before
        # the change rather than leaving stale extracted values behind.
        sa.Column("metadata_document", sa.Text(), nullable=False),
        sa.Column("metadata_url", sa.String(length=2048), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_refreshed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
        sa.PrimaryKeyConstraint("id", name="pk_federation_entity"),
        sa.UniqueConstraint("entity_id", name="uq_federation_entity_entity_id"),
        sa.CheckConstraint("role IN ('idp', 'sp')", name="ck_federation_entity_role"),
    )
    op.create_index("ix_federation_entity_role_enabled", "federation_entity", ["role", "enabled"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
