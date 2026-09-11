"""Role assignments (FR-AZ-01, FR-AZ-06).

One row per *reason* somebody holds a role, not one per person and role. That is
the whole shape of the table and it is what FR-AZ-01's test turns on: somebody
who is a course administrator because they teach and because an administrator
granted it directly keeps the role when they stop teaching, and a table keyed on
(person, role) would silently take it away.

Time bounds are columns rather than a scheduled deletion. A role that expires at
the end of term expires whether or not a job ran, and "was this person an
approver in March?" stays answerable afterwards — which a deleted row cannot
answer.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class RoleAssignment(Base):
    """One reason one person holds one role."""

    __tablename__ = "role_assignment"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False)

    origin_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    """affiliation | group | direct (FR-AZ-01).

    An investigation asks "how did they get this?", and the honest answer
    differs: a derived role is a fact about the person, while a direct one is a
    decision somebody made and should be able to be asked about.
    """

    origin_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    """Which affiliation, which group, or who granted it."""

    valid_from: Mapped[date] = mapped_column(
        Date, nullable=False, server_default=func.current_date()
    )
    valid_until: Mapped[date | None] = mapped_column(Date)
    """FR-AZ-06. Null means open-ended, and the bound is *exclusive*.

    The same half-open convention the affiliation table uses. A revocation
    taking effect today sets this to today and the role is gone today; with an
    inclusive bound it would survive until midnight, which is exactly the window
    an immediate revocation exists to close.

    Enforced at decision time rather than only at assignment time, because an
    assignment that expires tonight is still in the table tomorrow and a system
    that only checked on the way in would honour it forever.
    """

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    granted_by: Mapped[str | None] = mapped_column(String(256))
    """Who made a direct assignment. Null for a derived one, which nobody
    made."""

    __table_args__ = (
        CheckConstraint(
            "origin_kind in ('affiliation', 'group', 'direct')",
            name="ck_role_assignment_origin_kind",
        ),
        CheckConstraint(
            "valid_until is null or valid_until >= valid_from",
            name="ck_role_assignment_dates",
        ),
        # One row per person, role and origin. A second identical one is a
        # replayed derivation rather than a second reason, and deduplicating it
        # here is what lets the derivation run on every login without the table
        # growing.
        Index(
            "uq_role_assignment_origin",
            "person_uuid",
            "role",
            "origin_kind",
            "origin_ref",
            unique=True,
        ),
        Index("ix_role_assignment_person", "person_uuid"),
    )
