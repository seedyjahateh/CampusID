"""OIDC client registrations.

An application must become usable without restarting the broker, and `Settings`
is frozen and `lru_cache`d, so registrations live in the database for the same
reason federation entities do.

Unlike a SAML entity there is no signed document to keep verbatim — an OIDC
registration is a set of fields we chose — so these are real columns. The
URI and scope lists are JSONB rather than joined tables: they are matched as
exact sets, never queried across clients, and a join on the authorization
endpoint's hottest path would buy nothing.

There is deliberately no column that could hold a plaintext secret.

Revision ID: 0003_oidc_client
Revises: 0002_federation_entity
Created: 2026-09-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_oidc_client"
down_revision: str | None = "0002_federation_entity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_client",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_type", sa.String(length=16), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("redirect_uris", postgresql.JSONB(), nullable=False),
        sa.Column("allowed_scopes", postgresql.JSONB(), nullable=False),
        sa.Column(
            "post_logout_redirect_uris",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # SHA-256 hex, 64 characters. Null for public and native clients, which
        # hold no secret - null by design rather than by omission.
        sa.Column("secret_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "require_pushed_authorization_requests",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("backchannel_logout_uri", sa.String(length=2048), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_oidc_client"),
        sa.UniqueConstraint("client_id", name="uq_oidc_client_client_id"),
        sa.CheckConstraint(
            "client_type IN ('confidential', 'public', 'native')",
            name="ck_oidc_client_type",
        ),
        # The database enforces what the dataclass enforces. A row inserted by
        # hand - during an incident, by a migration, by a well-meaning script -
        # must not be able to create a confidential client with no secret or a
        # public client that appears to have one.
        sa.CheckConstraint(
            "(client_type = 'confidential') = (secret_hash IS NOT NULL)",
            name="ck_oidc_client_secret_matches_type",
        ),
        sa.CheckConstraint(
            "jsonb_array_length(redirect_uris) > 0",
            name="ck_oidc_client_has_redirect_uri",
        ),
    )
    op.create_index("ix_oidc_client_enabled", "oidc_client", ["enabled"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
