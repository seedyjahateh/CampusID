"""WebAuthn credentials on the factor table (FR-MFA-02).

Columns rather than a second table, for the reason 0011 gave: everything that
reads factors asks one question — does this person have one, and of which
categories — and a union across two tables would be the wrong shape for it.

The credential id is unique across the whole table rather than per person. The
same physical authenticator registering against two accounts produces two
different credentials, so a collision means one credential was presented for two
people, which is either a bug or somebody attaching a key they already control to
an account they do not.

The counter is its own column rather than sharing `last_step`. Both are
monotonic, but a TOTP step is derived from the clock and a sign count is chosen
by the authenticator, so one column would carry two things that fail in different
ways and mean different things when they go backwards.

Revision ID: 0012_mfa_webauthn
Revises: 0011_mfa_factor
Created: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_mfa_webauthn"
down_revision: str | None = "0011_mfa_factor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("mfa_factor", sa.Column("credential_id", sa.LargeBinary(), nullable=True))
    op.add_column("mfa_factor", sa.Column("public_key", sa.LargeBinary(), nullable=True))
    op.add_column("mfa_factor", sa.Column("sign_count", sa.BigInteger(), nullable=True))
    op.add_column("mfa_factor", sa.Column("algorithm", sa.Integer(), nullable=True))

    op.create_check_constraint(
        "ck_mfa_factor_webauthn_material",
        "mfa_factor",
        "kind <> 'webauthn' or (credential_id is not null and public_key is not null)",
    )
    op.create_index("uq_mfa_factor_credential", "mfa_factor", ["credential_id"], unique=True)


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
