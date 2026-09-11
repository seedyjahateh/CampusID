"""Rate limiting second-factor attempts (FR-MFA-06).

A six-digit code has a million values and a thirty-second life, so unlimited
guesses against it are not a theoretical problem — an attacker sending a few
thousand a second expects to land one inside the window. The limit is what makes
the factor worth having, which is why these read like tests of a security control
rather than of a counter.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fakeredis import aioredis

from campusid.mfa.ratelimit import (
    LOCKED,
    THRESHOLD,
    UNAVAILABLE,
    WINDOW,
    AttemptLimiter,
    Failure,
    RateLimited,
)

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
OTHER = "c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b"
TOTP = "totp"
WEBAUTHN = "webauthn"


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def limiter(redis: aioredis.FakeRedis) -> AttemptLimiter:
    return AttemptLimiter(redis)


async def _fail(
    limiter: AttemptLimiter, times: int, *, kind: str = TOTP, person: str = PERSON
) -> Failure | None:
    last: Failure | None = None
    for _ in range(times):
        last = await limiter.record_failure(person, kind)
    return last


# --- the count --------------------------------------------------------------


async def test_attempts_are_accepted_to_begin_with(limiter: AttemptLimiter) -> None:
    await limiter.check(PERSON, TOTP)


async def test_four_failures_do_not_lock(limiter: AttemptLimiter) -> None:
    """Five is more than anybody mistypes. Four must not be a lockout."""
    await _fail(limiter, THRESHOLD - 1)

    await limiter.check(PERSON, TOTP)


async def test_the_fifth_failure_locks(limiter: AttemptLimiter) -> None:
    outcome = await _fail(limiter, THRESHOLD)

    assert outcome is not None
    assert outcome.locked is True
    with pytest.raises(RateLimited) as raised:
        await limiter.check(PERSON, TOTP)
    assert raised.value.reason == LOCKED


async def test_only_the_crossing_attempt_reports_a_lock(limiter: AttemptLimiter) -> None:
    """So the audit record and the alert fire once rather than on every attempt
    behind the lock."""
    outcomes = [await limiter.record_failure(PERSON, TOTP) for _ in range(THRESHOLD)]

    assert [o.locked for o in outcomes] == [False] * (THRESHOLD - 1) + [True]


async def test_the_refusal_says_how_long(limiter: AttemptLimiter) -> None:
    """Somebody locked out needs to know whether to wait or to call the service
    desk, and an attacker already knows they are being refused."""
    await _fail(limiter, THRESHOLD)

    with pytest.raises(RateLimited) as raised:
        await limiter.check(PERSON, TOTP)

    assert 0 < raised.value.retry_after <= 15 * 60


# --- what the lock covers ---------------------------------------------------


async def test_a_lock_does_not_reach_the_other_kind(limiter: AttemptLimiter) -> None:
    """One lost phone must not be a complete lockout: the security key is a
    different credential with different failure modes."""
    await _fail(limiter, THRESHOLD, kind=TOTP)

    await limiter.check(PERSON, WEBAUTHN)


async def test_a_lock_does_not_reach_anybody_else(limiter: AttemptLimiter) -> None:
    await _fail(limiter, THRESHOLD, person=PERSON)

    await limiter.check(OTHER, TOTP)


async def test_each_kind_counts_separately(limiter: AttemptLimiter) -> None:
    """Four of each is eight failures and no lock, which is the intended
    reading: the two are different credentials."""
    await _fail(limiter, THRESHOLD - 1, kind=TOTP)
    await _fail(limiter, THRESHOLD - 1, kind=WEBAUTHN)

    await limiter.check(PERSON, TOTP)
    await limiter.check(PERSON, WEBAUTHN)


# --- forgetting -------------------------------------------------------------


async def test_a_success_clears_the_count(limiter: AttemptLimiter) -> None:
    """Otherwise four mistypes over a month add up to a lockout on the fifth,
    and the experience is a system that locks people out at random."""
    await _fail(limiter, THRESHOLD - 1)
    await limiter.record_success(PERSON, TOTP)

    outcome = await _fail(limiter, THRESHOLD - 1)

    assert outcome is not None
    assert outcome.locked is False
    await limiter.check(PERSON, TOTP)


async def test_a_success_does_not_lift_a_lock(
    limiter: AttemptLimiter, redis: aioredis.FakeRedis
) -> None:
    """There is no way to succeed while locked — the check comes first — so this
    pins that clearing the counter is not a back door into clearing the lock."""
    await _fail(limiter, THRESHOLD)

    await limiter.record_success(PERSON, TOTP)

    with pytest.raises(RateLimited):
        await limiter.check(PERSON, TOTP)


async def test_an_administrator_can_lift_a_lock(limiter: AttemptLimiter) -> None:
    """Somebody verified by other means should not wait out a timer. Separate
    from a success because it is somebody deciding rather than proving."""
    await _fail(limiter, THRESHOLD)

    await limiter.clear(PERSON, TOTP)

    await limiter.check(PERSON, TOTP)


async def test_the_remaining_time_is_visible(limiter: AttemptLimiter) -> None:
    """FR-MFA-06 asks that lockouts be visible to administrators."""
    assert await limiter.locked(PERSON, TOTP) == 0

    await _fail(limiter, THRESHOLD)

    assert await limiter.locked(PERSON, TOTP) > 0


# --- the window -------------------------------------------------------------


async def test_the_window_is_set_from_the_first_failure(
    limiter: AttemptLimiter, redis: aioredis.FakeRedis
) -> None:
    """Sliding it forward on every attempt would let a patient attacker hold it
    open indefinitely and never accumulate a count."""
    await limiter.record_failure(PERSON, TOTP)
    first = await redis.ttl(f"mfa:attempts:{TOTP}:{PERSON}")
    await limiter.record_failure(PERSON, TOTP)

    assert await redis.ttl(f"mfa:attempts:{TOTP}:{PERSON}") <= first


async def test_the_counter_expires(limiter: AttemptLimiter, redis: aioredis.FakeRedis) -> None:
    await limiter.record_failure(PERSON, TOTP)

    ttl = await redis.ttl(f"mfa:attempts:{TOTP}:{PERSON}")

    assert 0 < ttl <= WINDOW.total_seconds()


async def test_the_numbers_are_the_requirements(limiter: AttemptLimiter) -> None:
    """Pinned, because they are the whole control and a quiet edit to either
    would weaken it invisibly."""
    assert THRESHOLD == 5
    assert timedelta(minutes=15) == WINDOW


async def test_a_short_window_can_be_configured() -> None:
    """So a test of something downstream can exercise the lock without waiting
    fifteen minutes."""
    limiter = AttemptLimiter(
        aioredis.FakeRedis(decode_responses=True), threshold=1, lockout=timedelta(seconds=1)
    )

    assert (await limiter.record_failure(PERSON, TOTP)).locked is True


# --- when the store is gone -------------------------------------------------


class _Broken:
    async def ttl(self, key: str) -> int:
        raise ConnectionError("redis is gone")

    async def incr(self, key: str) -> int:
        raise ConnectionError("redis is gone")

    async def delete(self, key: str) -> None:
        raise ConnectionError("redis is gone")


async def test_a_limiter_outage_refuses_rather_than_passes() -> None:
    """The opposite of the decision cache's choice, for a different reason: a
    cache miss costs an evaluation, an unenforced rate limit costs the control.
    There is also nothing to protect, since the session store is the same Redis."""
    limiter = AttemptLimiter(_Broken())

    with pytest.raises(RateLimited) as raised:
        await limiter.check(PERSON, TOTP)

    assert raised.value.reason == UNAVAILABLE


async def test_an_outage_while_recording_a_failure_also_refuses() -> None:
    limiter = AttemptLimiter(_Broken())

    with pytest.raises(RateLimited) as raised:
        await limiter.record_failure(PERSON, TOTP)

    assert raised.value.reason == UNAVAILABLE


async def test_an_outage_does_not_undo_a_success() -> None:
    """The authentication already happened. Turning it into a failure because a
    counter would not reset punishes the person for an outage."""
    await AttemptLimiter(_Broken()).record_success(PERSON, TOTP)
