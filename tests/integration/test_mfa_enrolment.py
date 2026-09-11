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
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Person
from campusid.mfa import totp, webauthn
from campusid.mfa.models import MfaFactor, RecoveryCode
from campusid.mfa.store import (
    DUPLICATE_CREDENTIAL,
    DUPLICATE_LABEL,
    NO_FACTOR,
    NO_SUCH_CODE,
    FactorStore,
    MfaError,
)
from tests.support.authenticator import VirtualAuthenticator

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
        await session.execute(delete(RecoveryCode).where(RecoveryCode.person_uuid.not_in(keep)))
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


# --- WebAuthn ---------------------------------------------------------------

ORIGIN = "https://broker.campus.test"
RP_ID = "broker.campus.test"


async def _passkey(
    store: FactorStore, person: str, *, label: str = "my key"
) -> tuple[VirtualAuthenticator, uuid.UUID]:
    authenticator = VirtualAuthenticator()
    challenge = os.urandom(32)
    client_data, attestation = authenticator.register(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID
    )
    factor_id = await store.register_webauthn(
        person,
        label=label,
        client_data=client_data,
        attestation_object=attestation,
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
    )
    return authenticator, factor_id


async def _assert(
    store: FactorStore, person: str, authenticator: VirtualAuthenticator, **overrides: Any
) -> webauthn.Assertion:
    challenge = os.urandom(32)
    client_data, data, signature = authenticator.assert_(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID, **overrides
    )
    return await store.verify_webauthn(
        person,
        credential_id=authenticator.credential_id,
        client_data=client_data,
        authenticator_data=data,
        signature=signature,
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
    )


async def test_a_passkey_registers_confirmed(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """One step rather than two. The response already carries a signature over a
    challenge we issued, so the ceremony is the proof and a second round trip
    would establish nothing."""
    person = await _person(sessions)

    await _passkey(store, person)

    assert await store.categories_for(person) == {"hwk"}


async def test_a_registered_passkey_asserts(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    authenticator, factor_id = await _passkey(store, person)

    assertion = await _assert(store, person, authenticator)

    assert assertion is not None
    assert (await store.credential_ids(person)) == [authenticator.credential_id]


async def test_the_counter_moves_forward_across_assertions(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The stored counter is what the next assertion is compared against, so a
    store that never wrote it back would detect nothing."""
    person = await _person(sessions)
    authenticator, _ = await _passkey(store, person)
    await _assert(store, person, authenticator)

    await _assert(store, person, authenticator)

    factor = next(f for f in await store.factors_for(person) if f.kind == "webauthn")
    assert factor.sign_count == 2


async def test_a_replayed_counter_is_refused(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    authenticator, _ = await _passkey(store, person)
    await _assert(store, person, authenticator)

    with pytest.raises(webauthn.WebAuthnRejected) as raised:
        await _assert(store, person, authenticator, sign_count=1)

    assert raised.value.reason == webauthn.CLONED


async def test_somebody_elses_credential_is_not_found(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Looked up by credential *and* person. By credential alone the signature
    would verify against the owner's public key, and the result would be an
    authentication as the wrong person."""
    owner = await _person(sessions)
    stranger = await _person(sessions)
    authenticator, _ = await _passkey(store, owner)

    with pytest.raises(MfaError) as raised:
        await _assert(store, stranger, authenticator)

    assert raised.value.reason == NO_FACTOR


async def test_one_credential_cannot_be_registered_twice(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Across everybody, not per person. A collision means one credential was
    presented for two people."""
    owner = await _person(sessions)
    stranger = await _person(sessions)
    authenticator, _ = await _passkey(store, owner)
    challenge = os.urandom(32)
    client_data, attestation = authenticator.register(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID
    )

    with pytest.raises(MfaError) as raised:
        await store.register_webauthn(
            stranger,
            label="stolen",
            client_data=client_data,
            attestation_object=attestation,
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == DUPLICATE_CREDENTIAL


async def test_a_disabled_passkey_no_longer_asserts(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    authenticator, factor_id = await _passkey(store, person)
    await store.disable(person, factor_id)

    with pytest.raises(MfaError):
        await _assert(store, person, authenticator)


async def test_both_kinds_count_as_different_categories(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-MFA-08 turns on this: `acr` is `aal2` only when two distinct categories
    were used, so the categories have to be distinct in the first place."""
    person = await _person(sessions)
    await _enrol(store, person, label="my phone")
    await _passkey(store, person, label="my key")

    assert await store.categories_for(person) == {"otp", "hwk"}


# --- recovery codes ---------------------------------------------------------


async def test_a_sheet_of_ten_is_issued(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)

    codes = await store.issue_recovery_codes(person)

    assert len(set(codes)) == 10
    assert await store.recovery_codes_remaining(person) == 10


async def test_a_code_can_be_redeemed_once(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)

    remaining = await store.redeem_recovery_code(person, codes[0])

    assert remaining == 9
    with pytest.raises(MfaError) as raised:
        await store.redeem_recovery_code(person, codes[0])
    assert raised.value.reason == NO_SUCH_CODE


async def test_the_other_codes_still_work(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Single-use means that code, not the sheet."""
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)
    await store.redeem_recovery_code(person, codes[0])

    assert await store.redeem_recovery_code(person, codes[1]) == 8


async def test_a_code_typed_without_its_grouping_works(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)

    assert await store.redeem_recovery_code(person, codes[0].replace("-", "").lower()) == 9


async def test_somebody_elses_code_does_not_work(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    owner = await _person(sessions)
    stranger = await _person(sessions)
    codes = await store.issue_recovery_codes(owner)

    with pytest.raises(MfaError):
        await store.redeem_recovery_code(stranger, codes[0])

    assert await store.recovery_codes_remaining(owner) == 10


async def test_reissuing_retires_the_old_sheet(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Leaving the old sheet valid would mean the person who printed one last
    year and the person who printed one today can both get in, and only one of
    them knows the other exists."""
    person = await _person(sessions)
    old = await store.issue_recovery_codes(person)
    new = await store.issue_recovery_codes(person)

    with pytest.raises(MfaError):
        await store.redeem_recovery_code(person, old[0])
    assert await store.redeem_recovery_code(person, new[0]) == 9


async def test_reissuing_after_spending_some_restores_the_full_sheet(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)
    await store.redeem_recovery_code(person, codes[0])

    await store.issue_recovery_codes(person)

    assert await store.recovery_codes_remaining(person) == 10


async def test_a_spent_code_stays_on_the_record(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """ "Which code was used and when" is the question after somebody recovers an
    account they should not have, and a deleted row cannot answer it."""
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)
    await store.redeem_recovery_code(person, codes[0])

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(RecoveryCode).where(RecoveryCode.person_uuid == uuid.UUID(person))
            )
        )

    assert len(rows) == 10
    assert len([row for row in rows if row.used_at is not None]) == 1


async def test_a_person_with_no_sheet_has_none_remaining(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    assert await store.recovery_codes_remaining(await _person(sessions)) == 0


async def test_the_codes_are_not_stored_in_the_clear(
    store: FactorStore, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The one credential here that gets written down, so the database is the
    second place it can leak from."""
    person = await _person(sessions)
    codes = await store.issue_recovery_codes(person)

    async with sessions() as session:
        stored = list(
            await session.scalars(
                select(RecoveryCode.code_hash).where(RecoveryCode.person_uuid == uuid.UUID(person))
            )
        )

    assert all(digest.startswith("$argon2id$") for digest in stored)
    assert not any(codes[0].replace("-", "") in digest for digest in stored)


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
