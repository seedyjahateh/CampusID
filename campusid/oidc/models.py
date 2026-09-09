"""Persistence for registered OIDC clients.

In Postgres rather than configuration for the same reason the federation
registry is (FR-FED-02): an application must become usable without restarting
the broker, and `Settings` is frozen and cached for the life of the process.

Unlike a SAML entity, there is no metadata document to keep verbatim — an OIDC
client registration is a set of fields we chose, not a document a peer signed.
So these are real columns, and the row *is* the registration.

The secret is stored as a hash and there is no column that could hold the
plaintext. A registration endpoint returns the secret once, at creation, and the
broker cannot show it again; that is a deliberate operational cost, because a
secret a system can display is a secret that ends up in a screenshot.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class OidcClientRecord(Base):
    """One registered relying party."""

    __tablename__ = "oidc_client"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    client_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    client_type: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))

    redirect_uris: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    """JSONB rather than a joined table: they are matched as an exact set,
    never queried across clients, and a second table would add a join to the
    hottest path in the authorization endpoint for no query we ever run."""

    allowed_scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    post_logout_redirect_uris: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )

    secret_hash: Mapped[str | None] = mapped_column(String(64))
    """SHA-256, hex. Null for public and native clients, which hold no secret —
    a column that is null by design rather than by omission."""

    require_pushed_authorization_requests: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    backchannel_logout_uri: Mapped[str | None] = mapped_column(String(2048))

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    """Disabling is preferred to deleting: a client that issued tokens should
    stay nameable in the audit trail after it stops being trusted."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_oidc_client_enabled", "enabled"),)
