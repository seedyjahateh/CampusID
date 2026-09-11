"""Enrolling and using a TOTP factor (FR-MFA-01, FR-MFA-07, FR-MFA-08).

Against live Postgres, because the part of the requirement this store carries is
the durable part: the high-water mark that makes a code single-use survives a
restart, and the conditional update that makes two submissions of the same code
resolve to one winner is a property of the database rather than of the process.

The arithmetic is tested without any of this in `tests/security/test_totp.py`.
What is here is what the arithmetic cannot know on its own.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Person
from campusid.mfa import totp
from campusid.mfa.models import MfaFactor
from campusid.mfa.store import DUPLICATE_LABEL, NO_FACTOR, FactorStore, MfaError

pytestmark = pytest.mark.integration

NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(Person.person_uuid)))

    yield factory

    async with factory() as session, session.begin():
        keep = pre_existing or {uuid.UUID(int=0)}
        await session.execute(delete(MfaFactor).where(MfaFactor.person_uuid.not_in(keep)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep)))


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> FactorStore:
    return FactorStore(sessions)


async def _person(sessions: async_sessionmaker[AsyncSession]) -> str:
    async with sessions() as session, session.begin():
        person = Person(
            edu_person_unique_id=f"{uuid.uuid4().hex}@campus.test",
            status="active",
            provisioning_source="sis",
        )
        session.add(person)
        await session.flush()
        return str(person.person_uuid)


async def _enrol(store: FactorStore, person: str, *, label: str = "my phone") -> str:
    """Enrol and confirm, which is what every test about *using* a factor needs."""
    enrolment = await store.begin_totp(person, label=label, account="sam.obrien@campus.test")
    code = totp.code_at(enrolment.secret, totp.step_at(NOW))
    await store.confirm_totp(person, enrolment.factor_id, code, at=NOW)
    return enrolment.secret


# --- enrolment is two steps -------------------------------------------------


async def test_an_unconfirmed_factor_counts_for_nothing(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-MFA-07 reads this to decide whether to force enrolment. A QR code
    scanned into the wrong app must not register a factor the person cannot use
    but the broker believes in."""
    person = await _person(sessions)

    await store.begin_totp(person, label="my phone", account="sam@campus.test")

    assert await store.has_factor(person) is False
    assert await store.categories_for(person) == set()


async def test_confirming_finishes_the_enrolment(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)

    await _enrol(store, person)

    assert await store.has_factor(person) is True
    assert await store.categories_for(person) == {"otp"}


async def test_a_wrong_code_does_not_confirm(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    enrolment = await store.begin_totp(person, label="my phone", account="sam@campus.test")

    with pytest.raises(totp.TotpRejected):
        await store.confirm_totp(person, enrolment.factor_id, "000000", at=NOW)

    assert await store.has_factor(person) is False


async def test_the_enrolment_carries_a_provisioning_uri(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The QR code is what the person actually uses, and building the URI where
    the algorithm's constants live is what keeps them in step."""
    person = await _person(sessions)

    enrolment = await store.begin_totp(person, label="my phone", account="sam@campus.test")

    assert enrolment.uri.startswith("otpauth://totp/CampusID%3Asam%40campus.test")
    assert f"secret={enrolment.secret}" in enrolment.uri


async def test_two_factors_cannot_share_a_label(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Somebody choosing which factor to reach for needs the names to mean
    something."""
    person = await _person(sessions)
    await store.begin_totp(person, label="my phone", account="sam@campus.test")

    with pytest.raises(MfaError) as raised:
        await store.begin_totp(person, label="my phone", account="sam@campus.test")

    assert raised.value.reason == DUPLICATE_LABEL


async def test_two_people_may_use_the_same_label(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The index is per person. Everybody calls it "my phone"."""
    await store.begin_totp(await _person(sessions), label="my phone", account="a@campus.test")
    await store.begin_totp(await _person(sessions), label="my phone", account="b@campus.test")


async def test_confirming_somebody_elses_factor_is_refused(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A factor id is not a secret, so a lookup by id alone would be an
    authorization bug wearing a primary key."""
    owner = await _person(sessions)
    stranger = await _person(sessions)
    enrolment = await store.begin_totp(owner, label="my phone", account="sam@campus.test")
    code = totp.code_at(enrolment.secret, totp.step_at(NOW))

    with pytest.raises(MfaError) as raised:
        await store.confirm_totp(stranger, enrolment.factor_id, code, at=NOW)

    assert raised.value.reason == NO_FACTOR


# --- using a factor ---------------------------------------------------------


async def test_a_confirmed_factor_verifies(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    secret = await _enrol(store, person)
    later = NOW + timedelta(seconds=totp.PERIOD)

    factor_id = await store.verify_totp(person, totp.code_at(secret, totp.step_at(later)), at=later)

    assert uuid.UUID(factor_id)


async def test_a_used_code_is_refused_on_the_second_try(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-MFA-01's acceptance test, through the store rather than the
    arithmetic: the high-water mark is a column, so it holds across processes
    and across restarts."""
    person = await _person(sessions)
    secret = await _enrol(store, person)
    later = NOW + timedelta(seconds=totp.PERIOD)
    code = totp.code_at(secret, totp.step_at(later))
    await store.verify_totp(person, code, at=later)

    with pytest.raises(totp.TotpRejected) as raised:
        await store.verify_totp(person, code, at=later)

    assert raised.value.reason == totp.REPLAY


async def test_the_code_used_to_confirm_cannot_be_used_to_log_in(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Enrolment spends a step like any other use. Otherwise the code on screen
    at enrolment would also be a free first login."""
    person = await _person(sessions)
    secret = await _enrol(store, person)

    with pytest.raises(totp.TotpRejected) as raised:
        await store.verify_totp(person, totp.code_at(secret, totp.step_at(NOW)), at=NOW)

    assert raised.value.reason == totp.REPLAY


async def test_two_submissions_of_one_code_resolve_to_one_winner(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The race the conditional update exists for. Reading the mark and then
    raising it in a second statement is a race both requests win, and a
    one-time password that two requests can spend is not one."""
    person = await _person(sessions)
    secret = await _enrol(store, person)
    later = NOW + timedelta(seconds=totp.PERIOD)
    code = totp.code_at(secret, totp.step_at(later))

    outcomes = await asyncio.gather(
        store.verify_totp(person, code, at=later),
        store.verify_totp(person, code, at=later),
        return_exceptions=True,
    )

    accepted = [o for o in outcomes if isinstance(o, str)]
    refused = [o for o in outcomes if isinstance(o, totp.TotpRejected)]
    assert len(accepted) == 1
    assert len(refused) == 1


async def test_a_second_enrolled_app_also_works(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Asking somebody which of their phones they are holding before they type
    the code would be an interface nobody wants, so every confirmed factor is
    tried."""
    person = await _person(sessions)
    await _enrol(store, person, label="my phone")
    second = await _enrol(store, person, label="my tablet")
    later = NOW + timedelta(seconds=totp.PERIOD)

    assert await store.verify_totp(person, totp.code_at(second, totp.step_at(later)), at=later)


async def test_a_person_with_no_factor_is_told_the_code_is_wrong(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Not that they have no factor. Which of the two it is tells somebody
    enumerating accounts who is worth phishing."""
    person = await _person(sessions)

    with pytest.raises(totp.TotpRejected) as raised:
        await store.verify_totp(person, "000000", at=NOW)

    assert raised.value.reason == totp.MISMATCH


# --- retiring ---------------------------------------------------------------


async def test_a_disabled_factor_no_longer_verifies(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    enrolment = await store.begin_totp(person, label="my phone", account="sam@campus.test")
    await store.confirm_totp(
        person, enrolment.factor_id, totp.code_at(enrolment.secret, totp.step_at(NOW)), at=NOW
    )
    await store.disable(person, enrolment.factor_id)
    later = NOW + timedelta(seconds=totp.PERIOD)

    with pytest.raises(totp.TotpRejected):
        await store.verify_totp(
            person, totp.code_at(enrolment.secret, totp.step_at(later)), at=later
        )

    assert await store.has_factor(person) is False


async def test_a_disabled_factor_is_still_on_the_record(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "Which factor approved that in March" has to stay answerable, and a
    deleted row cannot answer it."""
    person = await _person(sessions)
    enrolment = await store.begin_totp(person, label="my phone", account="sam@campus.test")
    await store.disable(person, enrolment.factor_id)

    factors = await store.factors_for(person)

    assert [f.id for f in factors] == [enrolment.factor_id]
    assert factors[0].disabled_at is not None


async def test_disabling_somebody_elses_factor_is_refused(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    owner = await _person(sessions)
    stranger = await _person(sessions)
    enrolment = await store.begin_totp(owner, label="my phone", account="sam@campus.test")

    with pytest.raises(MfaError) as raised:
        await store.disable(stranger, enrolment.factor_id)

    assert raised.value.reason == NO_FACTOR
