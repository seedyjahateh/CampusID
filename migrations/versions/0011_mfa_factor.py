"""Registered second factors (FR-MFA-01).

One table for every kind of factor. Everything that reads factors asks the same
question — does this person have one, and of which categories — so a union across
three tables would be the wrong shape for the only query that matters.

The kind-specific material is nullable and guarded by a check constraint keyed on
the kind, so a TOTP factor without a seed, which could never verify anything, is
not storable. WebAuthn's columns arrive in their own migration rather than being
guessed at here; migrations are forward-only (ADR-002) and a wrong guess about a
credential format is permanent.

`confirmed_at` is what makes an enrolment finished. It stays null from the moment
the secret is issued until the person returns a code computed from it, because a
mistyped QR scan would otherwise register a factor that can never be used and
lock them out of the step-up it now claims they can do.

Revision ID: 0011_mfa_factor
Revises: 0010_role_assignment
Created: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_mfa_factor"
down_revision: str | None = "0010_role_assignment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mfa_factor",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        # Recoverable rather than hashed, because verifying a time-based code
        # means recomputing it. Inherent to TOTP, and the reason this column is
        # the first candidate for encryption at rest.
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("last_step", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_factor"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_mfa_factor_person_uuid_person",
        ),
        sa.CheckConstraint("kind in ('totp', 'webauthn', 'push')", name="ck_mfa_factor_kind"),
        sa.CheckConstraint(
            "kind <> 'totp' or secret is not null",
            name="ck_mfa_factor_totp_secret",
        ),
    )
    # One label per person, so "my phone" means one thing when they are choosing
    # which factor to reach for.
    op.create_index("uq_mfa_factor_label", "mfa_factor", ["person_uuid", "label"], unique=True)
    op.create_index("ix_mfa_factor_person", "mfa_factor", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
