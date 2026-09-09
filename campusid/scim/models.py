"""What a SCIM client's view of a person looks like (PRD §8.2).

One row per provisioned person, holding the things SCIM needs that the registry
itself has no opinion about: the SIS's own key, and the version a client's
`If-Match` is compared against.

`external_id` is the load-bearing column. FR-SCIM-14 requires that replaying a
create returns the existing resource rather than making a second one, and the
only thing that can decide "this is the same create" is a key the *client*
chose — our `person_uuid` did not exist when the client built the request. An
SIS that loses a response and retries is the ordinary case, not an edge one.

Groups live here too, and they are shaped by one requirement: FR-SCIM-11 asks
that adding a member to a ten-thousand-member group not rewrite the collection.
So membership is a table of rows rather than a list on the group, and the
group's version is a counter rather than a hash of its representation — a hash
would mean reading all ten thousand members on every write, which is the read
the requirement exists to avoid.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class ScimSourceRecord(Base):
    """The provisioning client's view of one person."""

    __tablename__ = "scim_source_record"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), unique=True, nullable=False
    )
    """One record per person. A second would mean two systems claiming to own
    the same human being, which is a governance problem rather than a data
    shape — and it is better to refuse the write than to discover it later."""

    external_id: Mapped[str | None] = mapped_column(String(512))
    """The SIS primary key. Unique when present, because two people sharing one
    would make an idempotent replay ambiguous — which is worse than a duplicate,
    since it silently returns the wrong person."""

    raw_resource: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    """The last document the client sent, verbatim.

    Kept for reconciliation: when the registry and the SIS disagree, the
    question is always "what did they actually send", and a reconstruction from
    our own columns cannot answer it. It contains whatever the client sent
    including restricted values, which is why it is never projected outward and
    never reaches the audit trail.
    """

    version: Mapped[str] = mapped_column(String(64), nullable=False)
    """The ETag as of the last write. Compared against `If-Match` (FR-SCIM-09).
    Stored rather than recomputed so a concurrent write is detected even if the
    projection would happen to hash the same."""

    last_sync_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("external_id", name="uq_scim_source_record_external_id"),
        Index("ix_scim_source_record_person", "person_uuid"),
    )


class ScimGroup(Base):
    """A group of people (FR-SCIM-11)."""

    __tablename__ = "scim_group"

    group_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    """Unique, because RFC 7643 §4.2 makes it the group's human name and two
    groups called `lms-students` are indistinguishable to the person deciding
    who gets access."""

    external_id: Mapped[str | None] = mapped_column(String(512))

    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    """What the ETag is derived from, incremented on every change.

    Deliberately a counter rather than a hash of the projected document, which
    is what `scim_source_record.version` holds for a person. A group may have
    ten thousand members; hashing its representation would mean loading all of
    them to answer a one-member PATCH, which is precisely the full-collection
    read FR-SCIM-11 forbids. A weak ETag only has to change when the resource
    changes, and a counter does that without reading anything.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("display_name", name="uq_scim_group_display_name"),
        UniqueConstraint("external_id", name="uq_scim_group_external_id"),
    )


class ScimGroupMember(Base):
    """One person's membership of one group.

    A row rather than an entry in a list on the group. That is the whole of
    FR-SCIM-11's performance requirement: adding a member is one insert whose
    cost does not depend on how many members are already there, and removing one
    is one delete.
    """

    __tablename__ = "scim_group_member"

    group_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scim_group.group_uuid", ondelete="CASCADE"),
        primary_key=True,
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("person.person_uuid", ondelete="CASCADE"),
        primary_key=True,
    )
    """The composite primary key is also the idempotency guarantee: adding a
    member who is already one is a conflict the database resolves, not a
    duplicate row the projection has to deduplicate."""

    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_scim_group_member_person", "person_uuid"),)
    """Indexed the other way round as well, because "which groups is this person
    in" is asked once per user projection and is a full scan without it."""
