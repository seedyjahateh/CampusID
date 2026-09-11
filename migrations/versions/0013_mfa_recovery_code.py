"""Recovery codes (FR-MFA-05).

A row per code rather than a set on the person, because "which code was used and
when" is the question an investigation asks after somebody recovers an account
they should not have, and a column holding ten hashes could not answer it.

Codes are spent rather than deleted, for the same reason: the row stays with a
`used_at`, so a sheet used twice is visible instead of merely absent. A reissue
sets `superseded_at` rather than the same column, because a person recovering
their account and a sheet being replaced are different events to anybody reading
the trail.

Revision ID: 0013_mfa_recovery_code
Revises: 0012_mfa_webauthn
Created: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_mfa_recovery_code"
down_revision: str | None = "0012_mfa_webauthn"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mfa_recovery_code",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        # Argon2id, encoded in the PHC string format, which carries its own
        # parameters — so raising the cost later does not invalidate the codes
        # already issued under the old ones.
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_recovery_code"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_mfa_recovery_code_person_uuid_person",
        ),
    )
    # Every query here is "this person's codes". There is deliberately no index
    # on the hash: a lookup key on a credential is a value an attacker can
    # enumerate against, and verification is a scan of ten rows by design.
    op.create_index("ix_mfa_recovery_code_person", "mfa_recovery_code", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
