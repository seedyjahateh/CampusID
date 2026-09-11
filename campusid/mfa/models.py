"""Registered second factors (FR-MFA-01, FR-MFA-02, FR-MFA-05).

One table for every kind of factor rather than one per kind, because everything
that reads factors asks the same question — "does this person have one, and which
categories?" — and a union across three tables to answer it would be the wrong
shape for the only query that matters (FR-MFA-07, FR-MFA-08).

The material each kind needs differs, so the kind-specific columns are nullable
and guarded by check constraints keyed on `kind`. That is the trade: a nullable
column the database still refuses to leave empty for the kind that needs it,
against a join nobody wants to write.

**An enrolment is not finished until it is proved.** `confirmed_at` is null from
the moment the secret is issued until the person returns a code computed from it,
and an unconfirmed factor satisfies nothing. Without that, a mistyped QR scan
would register a factor that can never be used and lock the person out of the
step-up it now claims they can do.

**Nothing here is deleted.** A removed factor is disabled, because "which factor
approved that transaction in March" has to stay answerable, and a deleted row
cannot answer it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from campusid.models import Base

TOTP = "totp"
WEBAUTHN = "webauthn"
PUSH = "push"

KINDS = (TOTP, WEBAUTHN, PUSH)

CATEGORY = {TOTP: "otp", WEBAUTHN: "hwk", PUSH: "push"}
"""Which `amr` value each kind contributes (FR-MFA-08).

A category rather than the kind itself, because `acr` is `aal2` only when two
distinct *categories* were used, and two TOTP apps holding the same secret are
one factor however many phones it is on.
"""


class MfaFactor(Base):
    """One registered second factor belonging to one person."""

    __tablename__ = "mfa_factor"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_uuid: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("person.person_uuid"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)

    label: Mapped[str] = mapped_column(String(128), nullable=False)
    """What the person called it. Somebody with three factors needs to know which
    one to reach for, and "TOTP factor 2" is not that."""

    secret: Mapped[str | None] = mapped_column(Text)
    """The base32 TOTP seed. Null for every other kind.

    Stored recoverable rather than hashed, because verifying a time-based code
    means recomputing it, which needs the seed. That is inherent to TOTP and the
    reason the column is worth encrypting at rest — noted as an M5 item rather
    than claimed here.
    """

    last_step: Mapped[int | None] = mapped_column(BigInteger)
    """The highest TOTP step this factor has accepted (FR-MFA-01).

    The high-water mark that makes the password one-time. A monotonic bound
    rather than a set of consumed steps: a set has to be expired, and until it is
    an attacker holding the previous code can still spend it inside the drift
    window.
    """

    credential_id: Mapped[bytes | None] = mapped_column(LargeBinary)
    """The WebAuthn credential id, as the authenticator chose it (FR-MFA-02).

    Unique across the whole table rather than per person. The same physical
    authenticator registering against two accounts produces two different
    credentials, so a collision here means the same credential was presented for
    two people — which is either a bug or somebody trying to attach a key they
    already control to an account they do not.
    """

    public_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    """The COSE key, in the exact bytes it arrived in.

    Stored encoded rather than as parsed parameters, so a later change to the
    parser cannot change what an existing credential means.
    """

    sign_count: Mapped[int | None] = mapped_column(BigInteger)
    """The authenticator's counter, for clone detection (FR-MFA-02).

    Distinct from `last_step` even though both are monotonic: a TOTP step is
    derived from the clock and a sign count is chosen by the authenticator, so
    the same column would carry two things that fail in different ways.
    """

    algorithm: Mapped[int | None] = mapped_column(Integer)
    """The COSE algorithm, recorded so the verification path is the one chosen at
    enrolment rather than one named by the assertion."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """When the person first proved they hold it. Null means enrolment never
    finished, and an unconfirmed factor satisfies nothing."""

    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            f"kind in ({', '.join(repr(k) for k in KINDS)})", name="ck_mfa_factor_kind"
        ),
        # The nullable-columns trade, made explicit: a TOTP factor without a seed
        # is a row that can never verify anything, and it should not be storable.
        CheckConstraint(
            "kind <> 'totp' or secret is not null",
            name="ck_mfa_factor_totp_secret",
        ),
        CheckConstraint(
            "kind <> 'webauthn' or (credential_id is not null and public_key is not null)",
            name="ck_mfa_factor_webauthn_material",
        ),
        # One label per person, so "my phone" means one thing when they are
        # choosing which factor to use.
        Index("uq_mfa_factor_label", "person_uuid", "label", unique=True),
        Index("ix_mfa_factor_person", "person_uuid"),
        # Across everybody, not per person: a credential presented for two people
        # is either a bug or somebody attaching a key they already control to an
        # account they do not.
        Index("uq_mfa_factor_credential", "credential_id", unique=True),
    )
