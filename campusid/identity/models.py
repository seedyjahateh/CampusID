"""The identity registry's tables (PRD §8.2).

Four to start with — `person`, `identifier`, `account`, `affiliation` — because
they are what account linking and SCIM both need, and because migrations are
forward-only (ADR-002): a table added later is cheap, a column shaped wrongly
now is permanent.

Three of the design principles from §8.1 are load-bearing here and each shows up
as a constraint rather than as a convention:

**The key is internal.** `person_uuid` is the primary key and never leaves the
system. `identifier` rows point at it, never the reverse.

**Identifiers are tombstoned, never recycled.** The unique constraint on
`identifier` covers *every* row including released ones, so reissuing a released
ePPN is not a policy the application enforces — it is a write the database
refuses. That is the difference between a rule and a rule somebody remembers.

**Affiliation is temporal.** A person's relationship to the institution is a set
of time-bounded rows, so "was this person a student on 2024-03-01?" is a query
rather than an archaeology exercise.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base


class Person(Base):
    """One human being, as far as the broker is concerned."""

    __tablename__ = "person"

    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    """Immutable and never released. Every external identifier is an attribute
    of this row rather than the row's key, which is what makes tombstoning an
    ePPN possible at all."""

    edu_person_unique_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    """`eduPersonUniqueId`: opaque, scoped, and never reused even across people.
    Released to SPs that need a stable non-reassigned handle, unlike
    `person_uuid`, which is released to nobody."""

    display_name: Mapped[str | None] = mapped_column(String(255))
    given_name: Mapped[str | None] = mapped_column(String(255))
    surname: Mapped[str | None] = mapped_column(String(255))
    preferred_language: Mapped[str | None] = mapped_column(String(35))

    ferpa_directory_suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """34 CFR §99.37. Read by the release engine on every decision, which is why
    it lives on the person rather than in a separate opt-out table."""

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    """active | suspended | deactivated | archived. A leaver is suspended rather
    than deleted: the audit trail has to keep naming them."""

    provisioning_source: Mapped[str] = mapped_column(String(16), nullable=False, default="sis")
    """sis | jit | manual. A record created just-in-time by a login is flagged
    so SIS reconciliation can find and merge it later (§8.4 rule 5)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_person_status", "status"),
        Index("ix_person_provisioning_source", "provisioning_source"),
    )


class Identifier(Base):
    """One external name for a person, and its whole history."""

    __tablename__ = "identifier"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    id_type: Mapped[str] = mapped_column(String(32), nullable=False)
    """eppn | mail | netid | sam_account | employee_id | student_id | orcid."""

    value: Mapped[str] = mapped_column(String(512), nullable=False)
    scope: Mapped[str | None] = mapped_column(String(255))
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """The tombstone (FR-LC-08). A released identifier keeps its row forever so
    the unique constraint keeps refusing to reissue it — the row *is* the
    protection, not a flag some code checks."""

    __table_args__ = (
        # Covers released rows too, on purpose. This is what makes ePPN reuse
        # impossible rather than merely forbidden.
        UniqueConstraint("id_type", "value", "scope", name="uq_identifier_type_value_scope"),
        Index("ix_identifier_person", "person_uuid", "id_type"),
        Index("ix_identifier_lookup", "id_type", "value"),
    )


class Account(Base):
    """A way one person authenticates: one subject at one IdP or OP."""

    __tablename__ = "account"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    idp_entity_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    """A SAML entityID or an OIDC issuer. One column for both because the
    question — "which authority asserted this?" — is the same either way."""

    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    subject_at_idp: Mapped[str] = mapped_column(String(512), nullable=False)
    """The `NameID` or `sub`. Meaningful only within its issuer, which is why
    the unique constraint pairs the two."""

    link_confidence: Mapped[str] = mapped_column(String(8), nullable=False, default="high")
    """high | medium. Records *how* this account was matched to its person
    (§8.4), because a link made on an ePPN match is a weaker claim than one made
    on a never-reassigned identifier, and an investigation needs to know which."""

    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("idp_entity_id", "subject_at_idp", name="uq_account_idp_subject"),
        Index("ix_account_person", "person_uuid"),
    )


class Affiliation(Base):
    """A time-bounded relationship between a person and the institution."""

    __tablename__ = "affiliation"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    affiliation: Mapped[str] = mapped_column(String(32), nullable=False)
    """From the eduPerson controlled vocabulary. Validated by the same set
    `policy.normalize` uses, so a value that could never be released cannot be
    stored either."""

    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    org_unit: Mapped[str | None] = mapped_column(String(255))

    valid_from: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date | None] = mapped_column(Date)
    """Null means current. A row rather than a column, so ending an affiliation
    is a write that keeps the history rather than one that erases it."""

    source: Mapped[str] = mapped_column(String(16), nullable=False, default="sis")

    __table_args__ = (
        Index("ix_affiliation_person_current", "person_uuid", "valid_until"),
        Index("ix_affiliation_value", "affiliation"),
    )
