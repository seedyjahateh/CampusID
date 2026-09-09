"""Entitlement grants and the lifecycle timeline (PRD §8.2, FR-LC-06).

Two tables that answer two questions an auditor asks in this order: *why does
this person have this access*, and *what happened to them*.

**Every grant records its justification.** `justification_kind` and
`justification_ref` say which rule and which affiliation produced it, so removal
is a matter of removing the justification rather than a judgement call. A grant
with no reason recorded is one nobody can ever safely take away, which is how
access accumulates.

**A revocation is scheduled, not hoped for.** `revoke_at` carries the moment a
grace period ends, in the database rather than in a timer, so a broker that
restarts mid-grace still revokes on time (FR-LC-05).

**The timeline is append-only and correlated.** Each event names the person, what
happened, what asked for it, the state either side, and the correlation id of the
request that caused it — so a deprovisioning can be followed from the SIS message
that triggered it to the session that was killed.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class EntitlementGrant(Base):
    """One entitlement a person holds, and the reason it exists."""

    __tablename__ = "entitlement_grant"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    entitlement_urn: Mapped[str] = mapped_column(String(256), nullable=False)

    justification_kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="affiliation"
    )
    """affiliation | group | role | manual.

    A grant may outlive one justification and survive on another — somebody who
    is both student and staff keeps the LMS when they stop being a student — so
    the kind and reference are on the grant rather than derived from the person.
    """

    justification_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    """The rule id and affiliation that produced it, so an access review can ask
    why without re-running the rules against a state that has since changed."""

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    revoke_at: Mapped[date | None] = mapped_column(Date)
    """When a grace period ends. Null for a grant nothing is scheduled against.

    In the database rather than in a timer: a thirty-day grace period outlives
    any process, and an access that ends only if a particular container stays
    alive does not end.
    """

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Set rather than deleted. "This person had LMS access until August" is a
    question an auditor asks, and a deleted row cannot answer it."""

    __table_args__ = (
        CheckConstraint(
            "justification_kind in ('affiliation', 'group', 'role', 'manual')",
            name="ck_entitlement_grant_justification_kind",
        ),
        # One live grant per person per entitlement per justification. Two
        # justifications for the same entitlement are legitimate and expected;
        # two identical ones are a replayed write.
        UniqueConstraint(
            "person_uuid",
            "entitlement_urn",
            "justification_ref",
            name="uq_entitlement_grant_person_urn_justification",
        ),
        Index("ix_entitlement_grant_person", "person_uuid"),
        Index("ix_entitlement_grant_due", "revoke_at"),
    )


class LifecycleEvent(Base):
    """One thing that happened to a person (FR-LC-06)."""

    __tablename__ = "lifecycle_event"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )

    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    """joiner | mover | leaver | grace_expiry | reconciliation."""

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    """What asked for it — `scim`, `admin`, `scheduler`, `reconciliation`.

    Recorded because "the SIS did it" and "somebody did it by hand" are
    different answers to the same question, and only one of them means the
    upstream record agrees.
    """

    before_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    after_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    """Both sides, not a diff. A diff is derivable from the two states and the
    states are not derivable from the diff, and the question an auditor asks a
    year later is what the record actually said."""

    correlation_id: Mapped[str | None] = mapped_column(String(64))
    """Ties the event to the request that caused it, so a deprovisioning can be
    followed from the SIS message to the session that was terminated."""

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_lifecycle_event_person", "person_uuid", "occurred_at"),
        Index("ix_lifecycle_event_correlation", "correlation_id"),
    )
