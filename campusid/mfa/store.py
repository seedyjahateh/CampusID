"""Enrolling and using second factors (FR-MFA-01, FR-MFA-07, FR-MFA-08).

The database half of TOTP. The arithmetic lives in `totp.py` and has no idea a
database exists; this is what makes a code single-use, which is the only part of
the requirement that needs durable state.

**Enrolment is two steps and the second one matters.** `begin_totp` issues a
secret and stores it unconfirmed; `confirm_totp` accepts it only once the person
returns a code computed from it. An unconfirmed factor satisfies nothing, so a
QR code scanned into the wrong app never becomes a factor the person cannot use
but the broker believes in.

**The replay check and the write are one transaction.** Verifying against the
high-water mark and then raising it in a second statement is a race two parallel
submissions of the same code both win. The update is conditional on the mark not
having moved — `where last_step is distinct from <what we read>` — so the loser
of the race sees no row updated and is told it was a replay, which it was.

**Verification does not say whether the factor exists.** A person with no
confirmed factor and a person with the wrong code get the same refusal, because
the difference is useful to somebody enumerating who is worth phishing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.logging import get_logger
from campusid.mfa import totp
from campusid.mfa.models import CATEGORY, TOTP, MfaFactor

log = get_logger(__name__)

NO_FACTOR = "mfa.no_such_factor"
DUPLICATE_LABEL = "mfa.duplicate_label"


class MfaError(Exception):
    """An enrolment or verification that could not proceed, with a reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Enrolment:
    """A secret issued but not yet proved.

    Carries the provisioning URI rather than only the secret, because the QR code
    is what the person actually uses and building the URI in the route would put
    the parameters that have to match the algorithm somewhere the algorithm
    cannot see.
    """

    __slots__ = ("factor_id", "secret", "uri")

    def __init__(self, factor_id: uuid.UUID, secret: str, uri: str) -> None:
        self.factor_id = factor_id
        self.secret = secret
        self.uri = uri


class FactorStore:
    """Second factors for one deployment."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], *, issuer: str = "CampusID"
    ) -> None:
        self._sessions = session_factory
        self._issuer = issuer

    # --- enrolment --------------------------------------------------------

    async def begin_totp(self, person_uuid: str, *, label: str, account: str) -> Enrolment:
        """Issue a secret and store it unconfirmed (FR-MFA-01).

        The row exists from here so the confirmation has something to attach to,
        and so a person who abandons a half-finished enrolment can be shown that
        they did rather than silently starting again.
        """
        secret = totp.new_secret()
        factor = MfaFactor(
            person_uuid=uuid.UUID(person_uuid), kind=TOTP, label=label, secret=secret
        )
        try:
            async with self._sessions() as session, session.begin():
                session.add(factor)
        except IntegrityError as exc:
            # The label index. Two factors called "my phone" would make the
            # choice of which to use meaningless.
            raise MfaError(DUPLICATE_LABEL) from exc

        log.info("mfa.totp.enrolment_started", person=person_uuid, factor=str(factor.id))
        return Enrolment(
            factor_id=factor.id,
            secret=secret,
            uri=totp.provisioning_uri(secret, account=account, issuer=self._issuer),
        )

    async def confirm_totp(
        self, person_uuid: str, factor_id: uuid.UUID, code: str, *, at: datetime | None = None
    ) -> None:
        """Finish an enrolment by proving the secret arrived (FR-MFA-01).

        Raises `totp.TotpRejected` for a code that does not hold, so a mistyped
        one is indistinguishable from a mistyped one at login, and the same rate
        limit covers both.
        """
        now = at or datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            factor = await self._live(session, person_uuid, factor_id)
            if factor is None or factor.secret is None:
                raise MfaError(NO_FACTOR)
            verified = totp.verify(factor.secret, code, at=now, last_step=factor.last_step)
            factor.confirmed_at = now
            factor.last_used_at = now
            factor.last_step = verified.step
        log.info("mfa.totp.confirmed", person=person_uuid, factor=str(factor_id))

    # --- use --------------------------------------------------------------

    async def verify_totp(self, person_uuid: str, code: str, *, at: datetime | None = None) -> str:
        """Check a code against every confirmed TOTP factor this person holds.

        Returns the id of the factor that accepted it, so the audit record can
        name which phone was used rather than only that one was.

        Somebody with two authenticator apps enrolled is one person with two
        factors, and asking them which one they used before they type the code
        would be an interface nobody wants. Every confirmed factor is tried.
        """
        now = at or datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            factors = await self._confirmed(session, person_uuid, TOTP)
            last: Exception | None = None
            for factor in factors:
                if factor.secret is None:  # pragma: no cover - forbidden by a constraint
                    continue
                try:
                    verified = totp.verify(factor.secret, code, at=now, last_step=factor.last_step)
                except totp.TotpRejected as exc:
                    last = exc
                    continue
                if not await self._advance(session, factor, verified.step, now):
                    # Another request spent this step between the read and the
                    # write. That is precisely a replay, so it is reported as
                    # one rather than retried.
                    raise totp.TotpRejected(totp.REPLAY)
                log.info("mfa.totp.verified", person=person_uuid, factor=str(factor.id))
                return str(factor.id)

        if isinstance(last, totp.TotpRejected):
            raise last
        # No confirmed factor at all. Reported as a mismatch rather than as a
        # missing factor, because which of the two it is tells somebody
        # enumerating accounts who is worth phishing.
        raise totp.TotpRejected(totp.MISMATCH)

    # --- questions other requirements ask ---------------------------------

    async def categories_for(self, person_uuid: str) -> set[str]:
        """Which `amr` categories this person could satisfy (FR-MFA-08).

        Categories rather than factors, because `acr` is `aal2` only when two
        distinct categories were used and two phones holding the same TOTP seed
        are one category however many devices it is on.
        """
        async with self._sessions() as session:
            rows = await self._confirmed(session, person_uuid)
            return {CATEGORY[row.kind] for row in rows}

    async def has_factor(self, person_uuid: str) -> bool:
        """Whether forced enrolment applies at next login (FR-MFA-07)."""
        return bool(await self.categories_for(person_uuid))

    async def factors_for(self, person_uuid: str) -> list[MfaFactor]:
        """Everything registered, confirmed or not, for the person's own page."""
        async with self._sessions() as session:
            return list(
                await session.scalars(
                    select(MfaFactor)
                    .where(MfaFactor.person_uuid == uuid.UUID(person_uuid))
                    .order_by(MfaFactor.created_at)
                )
            )

    async def disable(self, person_uuid: str, factor_id: uuid.UUID) -> None:
        """Retire a factor without deleting it.

        "Which factor approved that in March" has to stay answerable, and a
        deleted row cannot answer it.
        """
        async with self._sessions() as session, session.begin():
            factor = await self._live(session, person_uuid, factor_id)
            if factor is None:
                raise MfaError(NO_FACTOR)
            factor.disabled_at = datetime.now(UTC)
        log.info("mfa.factor.disabled", person=person_uuid, factor=str(factor_id))

    # --- helpers ----------------------------------------------------------

    async def _live(
        self, session: AsyncSession, person_uuid: str, factor_id: uuid.UUID
    ) -> MfaFactor | None:
        """One factor belonging to this person, if it is not retired.

        Scoped by person as well as by id: a factor id is not a secret, and a
        lookup by id alone would let anybody disable anybody's factor.
        """
        factor: MfaFactor | None = await session.scalar(
            select(MfaFactor).where(
                MfaFactor.id == factor_id,
                MfaFactor.person_uuid == uuid.UUID(person_uuid),
                MfaFactor.disabled_at.is_(None),
            )
        )
        return factor

    async def _confirmed(
        self, session: AsyncSession, person_uuid: str, kind: str | None = None
    ) -> list[MfaFactor]:
        query = select(MfaFactor).where(
            MfaFactor.person_uuid == uuid.UUID(person_uuid),
            MfaFactor.disabled_at.is_(None),
            MfaFactor.confirmed_at.is_not(None),
        )
        if kind is not None:
            query = query.where(MfaFactor.kind == kind)
        return list(await session.scalars(query.order_by(MfaFactor.created_at)))

    async def _advance(
        self, session: AsyncSession, factor: MfaFactor, step: int, now: datetime
    ) -> bool:
        """Raise the high-water mark, but only if nobody else moved it first.

        The conditional update is the whole race defence: two requests carrying
        the same code both pass the arithmetic, and exactly one of them finds a
        row to update.
        """
        result: Any = await session.execute(
            update(MfaFactor)
            .where(
                MfaFactor.id == factor.id,
                MfaFactor.last_step.is_not_distinct_from(factor.last_step),
            )
            .values(last_step=step, last_used_at=now)
        )
        return bool(result.rowcount)
