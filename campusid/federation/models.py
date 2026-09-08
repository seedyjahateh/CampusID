"""Persistence for registered federation entities.

In Postgres rather than configuration because FR-FED-02 requires an IdP to
become usable without a process restart, and `Settings` is frozen and cached
for the life of the process.

The parsed metadata is deliberately *not* stored in columns. Only the raw
document is kept, and every read re-parses it. That costs a few milliseconds
and buys the guarantee that the trust decision is always made by the current
parser: a tightening of `metadata_idp.py` applies to entities registered
before the change, rather than leaving pre-parsed values that were extracted
under looser rules.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class FederationEntity(Base):
    """A registered SAML entity."""

    __tablename__ = "federation_entity"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_id: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))

    metadata_document: Mapped[str] = mapped_column(Text, nullable=False)
    """The descriptor as fetched, verbatim. The source of every trust decision."""

    metadata_url: Mapped[str | None] = mapped_column(String(2048))
    """Where to refresh from. Null for a descriptor uploaded by hand."""

    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    """Disabling is preferred to deleting: an entity that authenticated people
    should remain nameable in the audit trail after it stops being trusted."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_federation_entity_role_enabled", "role", "enabled"),)
