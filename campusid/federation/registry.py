"""Registering and resolving federation entities (FR-FED-02/03).

The registry is the boundary between "a document someone uploaded" and "an
entity this broker will accept assertions from". Registration parses and
validates before anything is stored, so a descriptor that could never work is
refused at the point an operator can still do something about it — not at 3am
when a login fails.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.errors import MetadataRejected, ReasonCode
from campusid.federation.models import FederationEntity
from campusid.saml.gate import TrustedIdP
from campusid.saml.metadata_idp import IdentityProviderDescriptor, parse_idp_metadata
from campusid.saml.stores import utcnow

ROLE_IDP = "idp"


class FederationRegistry:
    """Reads and writes the set of trusted entities."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def register_idp(
        self,
        document: bytes,
        *,
        metadata_url: str | None = None,
        display_name: str | None = None,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> IdentityProviderDescriptor:
        """Register or update an IdP from its metadata.

        Upserts on `entityID`, so re-registering after a key rollover replaces
        the stored descriptor rather than creating a second, conflicting entry
        — which would leave which certificate wins a matter of row order.
        """
        now = now or utcnow()
        descriptor = parse_idp_metadata(document, now=now)

        async with self._sessions() as session, session.begin():
            existing = await session.scalar(
                select(FederationEntity).where(FederationEntity.entity_id == descriptor.entity_id)
            )
            if existing is None:
                session.add(
                    FederationEntity(
                        entity_id=descriptor.entity_id,
                        role=ROLE_IDP,
                        display_name=display_name,
                        metadata_document=document.decode("utf-8"),
                        metadata_url=metadata_url,
                        valid_until=descriptor.valid_until,
                        last_refreshed_at=now,
                        enabled=enabled,
                    )
                )
            else:
                existing.metadata_document = document.decode("utf-8")
                existing.metadata_url = metadata_url or existing.metadata_url
                existing.display_name = display_name or existing.display_name
                existing.valid_until = descriptor.valid_until
                existing.last_refreshed_at = now
                existing.enabled = enabled

        return descriptor

    async def describe(
        self, entity_id: str, *, now: datetime | None = None
    ) -> IdentityProviderDescriptor | None:
        """Return the parsed descriptor for an enabled entity, if any.

        Re-parses on every call rather than trusting stored columns, so the
        current parser decides. Returns None for a disabled or unknown entity;
        raises only when a *registered* document has become unusable, which is
        an operator problem worth surfacing rather than a silent miss.
        """
        async with self._sessions() as session:
            entity = await session.scalar(
                select(FederationEntity).where(
                    FederationEntity.entity_id == entity_id,
                    FederationEntity.enabled.is_(True),
                )
            )
        if entity is None:
            return None
        return parse_idp_metadata(
            entity.metadata_document.encode("utf-8"),
            entity_id=entity_id,
            now=now or utcnow(),
        )

    async def resolve_trusted_idp(self, entity_id: str) -> TrustedIdP | None:
        """The gate's `IdPResolver`.

        Expired metadata resolves to None rather than raising: from the gate's
        point of view an entity whose descriptor has lapsed is simply not
        trusted, and `unknown_issuer` is the honest reason code. The operator
        sees the difference through `describe`, which does raise.
        """
        try:
            descriptor = await self.describe(entity_id)
        except MetadataRejected:
            return None
        if descriptor is None:
            return None
        return TrustedIdP(
            entity_id=descriptor.entity_id,
            signing_certificates=descriptor.signing_certificates,
        )

    async def list_idps(self) -> list[FederationEntity]:
        """Every registered IdP, enabled or not, for the admin view."""
        async with self._sessions() as session:
            result = await session.scalars(
                select(FederationEntity)
                .where(FederationEntity.role == ROLE_IDP)
                .order_by(FederationEntity.entity_id)
            )
            return list(result.all())

    async def set_enabled(self, entity_id: str, enabled: bool) -> None:
        """Turn an entity's trust on or off without losing its history."""
        async with self._sessions() as session, session.begin():
            entity = await session.scalar(
                select(FederationEntity).where(FederationEntity.entity_id == entity_id)
            )
            if entity is None:
                raise MetadataRejected(
                    ReasonCode.METADATA_INVALID, f"{entity_id!r} is not registered"
                )
            entity.enabled = enabled
