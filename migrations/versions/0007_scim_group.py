"""Groups and their membership (FR-SCIM-11).

Membership is its own table, so adding one person to a ten-thousand-member group
is one insert rather than a rewrite of the collection. The composite primary key
does the deduplication, and `ON DELETE CASCADE` on both sides means a deleted
group takes its membership with it rather than leaving rows pointing at nothing.

`revision` is what the group's ETag is derived from. A counter rather than a
hash of the representation, because hashing would mean loading every member to
answer a one-member PATCH — the read the requirement exists to avoid.

Revision ID: 0007_scim_group
Revises: 0006_scim_source_record
Created: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_scim_group"
down_revision: str | None = "0006_scim_source_record"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scim_group",
        sa.Column(
            "group_uuid",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
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
        sa.PrimaryKeyConstraint("group_uuid", name="pk_scim_group"),
        # Two groups called `lms-students` are indistinguishable to the person
        # deciding who gets access.
        sa.UniqueConstraint("display_name", name="uq_scim_group_display_name"),
        sa.UniqueConstraint("external_id", name="uq_scim_group_external_id"),
    )

    op.create_table(
        "scim_group_member",
        sa.Column("group_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("person_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "added_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        # The composite key is the idempotency guarantee: adding somebody who is
        # already a member is a conflict the database resolves, not a duplicate
        # row the projection has to deduplicate.
        sa.PrimaryKeyConstraint("group_uuid", "person_uuid", name="pk_scim_group_member"),
        sa.ForeignKeyConstraint(
            ["group_uuid"],
            ["scim_group.group_uuid"],
            name="fk_scim_group_member_group_uuid_scim_group",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["person_uuid"],
            ["person.person_uuid"],
            name="fk_scim_group_member_person_uuid_person",
            ondelete="CASCADE",
        ),
    )
    # "Which groups is this person in" is asked once per user projection and is
    # a full scan of the membership table without this.
    op.create_index("ix_scim_group_member_person", "scim_group_member", ["person_uuid"])


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
