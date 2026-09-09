"""What a SCIM client's view of a person looks like (PRD §8.2).

One row per provisioned person, holding the things SCIM needs that the registry
itself has no opinion about: the SIS's own key, and the version a client's
`If-Match` is compared against.

`external_id` is the load-bearing column. FR-SCIM-14 requires that replaying a
create returns the existing resource rather than making a second one, and the
only thing that can decide "this is the same create" is a key the *client*
chose — our `person_uuid` did not exist when the client built the request. An
SIS that loses a response and retries is the ordinary case, not an edge one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
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
