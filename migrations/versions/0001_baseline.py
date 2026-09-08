"""Baseline: extensions and schema conventions.

Establishes the migration chain and the database-level prerequisites the
identity registry depends on. No domain tables yet — those arrive with the
registry in M1.

``pgcrypto`` provides ``gen_random_uuid()`` for surrogate keys and
``digest()`` for the audit hash chain (FR-AUD-05). ``citext`` backs
case-insensitive identifier comparison: ePPNs are normalised to lowercase on
write (FR-ARP-08), but a case-insensitive uniqueness constraint is the
belt-and-braces that stops ``Sam@campus.edu`` and ``sam@campus.edu`` becoming
two people.

Revision ID: 0001_baseline
Revises:
Created: 2026-09-08
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
