"""Role assignments with recorded origins and time bounds (FR-AZ-01, FR-AZ-06).

One row per *reason* somebody holds a role rather than one per person and role.
A person who is a course administrator both because they teach and because an
administrator granted it keeps the role when they stop teaching; a table keyed on
(person, role) would silently take it away.

The unique index is on the origin, not on the role: a second identical
derivation is a replay rather than a second reason, and deduplicating it there is
what lets the derivation run on every login without the table growing.

Time bounds are columns rather than a scheduled deletion, so a role that expires
at the end of term expires whether or not a job ran, and "was this person an
approver in March?" stays answerable.

Revision ID: 0010_role_assignment
Revises: 0009_dead_letter
Created: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_role_assignment"
down_revision: str | None = "0009_dead_letter"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "role_assignment",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("origin_kind", sa.String(length=16), nullable=False),
        sa.Column("origin_ref", sa.String(length=256), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=False, server_default=sa.text("current_date")),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("granted_by", sa.String(length=256), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_role_assignment"),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_role_assignment_person_uuid_person",
        ),
        sa.CheckConstraint(
            "origin_kind in ('affiliation', 'group', 'direct')",
            name="ck_role_assignment_origin_kind",
        ),
        # A window that ends before it starts is a typo the database can catch,
        # and one that reaches the table is a role nobody ever holds.
        sa.CheckConstraint(
            "valid_until is null or valid_until >= valid_from",
            name="ck_role_assignment_dates",
        ),
    )
    op.create_index(
        "uq_role_assignment_origin",
        "role_assignment",
        ["person_uuid", "role", "origin_kind", "origin_ref"],
        unique=True,
    )
    op.create_index("ix_role_assignment_person", "role_assignment", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
