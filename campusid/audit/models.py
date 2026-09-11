"""Persistence for audit events.

Append-only from the application's perspective (FR-AUD-04): there is no `update`
or `delete` path in `campusid/audit/` at all, and M5 backs that with a database
role holding only INSERT and SELECT on this table. The application-side half
matters on its own — a role grant protects against a compromised process, while
having no code that can modify a row protects against the ordinary bug.

The columns are FR-AUD-01's field list, indexed for the three questions
FR-AUD-03 says the trail has to answer: what happened to this person, what did
this SP receive, and what failed in this window.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Identity, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class AuditEventRecord(Base):
    """One audit event, as stored."""

    __tablename__ = "audit_event"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    """The id the emitter generated. Unique so a retried insert cannot duplicate
    an event — an audit trail that double-counts is as misleading as one that
    misses."""

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    """When the event happened, not when it was written. The distinction matters
    the moment writes are ever batched or retried."""

    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(512))
    subject: Mapped[str | None] = mapped_column(String(512))
    target: Mapped[str | None] = mapped_column(String(1024))
    reason: Mapped[str | None] = mapped_column(String(512))
    """Why, in the actor's own words, for an action somebody chose to take
    (FR-ADM-07). Long enough to hold a sentence: a justification truncated to a
    fragment is one nobody can act on, and a write that failed because it was too
    long would lose the event entirely, since audit writes never raise."""
    source_ip: Mapped[str | None] = mapped_column(String(45))
    """45 characters: an IPv6 address with an embedded IPv4 suffix is the
    longest textual form."""

    user_agent: Mapped[str | None] = mapped_column(String(512))
    session_id: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=False), nullable=False)
    """The chain's ordering (FR-AUD-05).

    A sequence rather than a timestamp, because two events can share a
    microsecond and a chain needs a total order. Allocated while the writer holds
    the chain lock, so allocation order and link order are the same thing.
    """

    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    """`SHA256(prev_hash || canonical_json(event))`.

    Stored rather than recomputed on read, which is the point: a verifier
    compares what was written against what the content now hashes to, and a value
    derived on read would agree with a tampered row by construction.
    """

    __table_args__ = (
        # The subject-centric timeline (FR-AUD-03, US-02): "every attribute
        # released to every SP in the last 90 days".
        Index("ix_audit_event_subject_time", "subject", "occurred_at"),
        # "What did this SP receive", and the disclosure record under §99.32.
        Index("ix_audit_event_target_time", "target", "occurred_at"),
        # "All authentication failures in this window" (US-11).
        Index("ix_audit_event_type_outcome_time", "event_type", "outcome", "occurred_at"),
        # FR-AUD-02: pull the whole chain for one login.
        Index("ix_audit_event_correlation", "correlation_id"),
        # The chain is walked in sequence order, and the writer reads the tail on
        # every insert. Unique because two events sharing a position would make
        # the order the verifier walks ambiguous — which is precisely where a
        # row could be hidden.
        Index("uq_audit_event_seq", "seq", unique=True),
    )
