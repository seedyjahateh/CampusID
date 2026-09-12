"""Rate limiting the authentication endpoints (NFR-SEC-10).

Different in kind from the second-factor limiter tested next door, and both are
needed: that one counts failures and locks an account, this one counts attempts
and refuses the eleventh in a minute. A failure counter does not stop somebody
hammering an endpoint with requests that never reach a credential check.

The test worth reading is the window boundary. A fixed window resets on the
minute, so an attacker who sends the limit at :59 and again at :00 gets twice the
allowance in two seconds — which is exactly the burst the limit exists to
prevent.
"""

from __future__ import annotations

from typing import Any

import pytest
from fakeredis import aioredis

from campusid.security.throttle import (
    ACCOUNT,
    ADDRESS,
    PER_ACCOUNT,
    PER_ADDRESS,
    THROTTLED,
    UNAVAILABLE,
    Throttle,
    Throttled,
)

pytestmark = pytest.mark.security

HERE = "198.51.100.7"
THERE = "203.0.113.9"
CLIENT = "campus-portal"
OTHER = "analytics"

# A window boundary, so "the same minute" and "the next minute" are exact rather
# than whatever the clock happens to be doing.
MINUTE = 1_756_999_980.0


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def throttle(redis: aioredis.FakeRedis) -> Throttle:
    return Throttle(redis)


async def _attempts(
    throttle: Throttle, count: int, *, at: float, tolerate: bool = False, **who: Any
) -> None:
    """Make `count` attempts.

    `tolerate` swallows refusals, for the tests whose point is what happens to a
    *different* bucket afterwards.
    """
    for _ in range(count):
        try:
            await throttle.check(now=at, **who)
        except Throttled:
            if not tolerate:
                raise


# --- the address bucket -----------------------------------------------------


async def test_an_ordinary_burst_is_allowed(throttle: Throttle) -> None:
    """Ten a minute is generous for a person and tight for a script."""
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE)


async def test_the_eleventh_attempt_is_refused(throttle: Throttle) -> None:
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE)

    with pytest.raises(Throttled) as raised:
        await throttle.check(address=HERE, now=MINUTE)

    assert raised.value.reason == THROTTLED
    assert raised.value.bucket == ADDRESS


async def test_another_address_is_unaffected(throttle: Throttle) -> None:
    """One machine tripping a limit must not take a campus offline."""
    await _attempts(throttle, PER_ADDRESS + 5, address=HERE, at=MINUTE, tolerate=True)

    await throttle.check(address=THERE, now=MINUTE)


async def test_the_refusal_says_when_to_come_back(throttle: Throttle) -> None:
    """Somebody who has tripped a limit needs to know whether to wait a moment or
    to stop, and an attacker already knows they are being refused."""
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE)

    with pytest.raises(Throttled) as raised:
        await throttle.check(address=HERE, now=MINUTE)

    assert 0 < raised.value.retry_after <= 60


# --- the account bucket -----------------------------------------------------


async def test_an_account_has_a_tighter_limit(throttle: Throttle) -> None:
    """An address legitimately carries a whole building's traffic. An account
    does not."""
    assert PER_ACCOUNT < PER_ADDRESS

    await _attempts(throttle, PER_ACCOUNT, account=CLIENT, at=MINUTE)

    with pytest.raises(Throttled) as raised:
        await throttle.check(account=CLIENT, now=MINUTE)

    assert raised.value.bucket == ACCOUNT


async def test_rotating_addresses_does_not_refill_the_account(
    throttle: Throttle,
) -> None:
    """The case a per-address limit cannot see: one account, a thousand
    addresses. Both buckets are charged on every attempt, so alternating
    addresses spends the account's allowance just the same."""
    for n in range(PER_ACCOUNT):
        await throttle.check(address=f"192.0.2.{n}", account=CLIENT, now=MINUTE)

    with pytest.raises(Throttled) as raised:
        await throttle.check(address="192.0.2.99", account=CLIENT, now=MINUTE)

    assert raised.value.bucket == ACCOUNT


async def test_another_account_is_unaffected(throttle: Throttle) -> None:
    await _attempts(throttle, PER_ACCOUNT + 3, account=CLIENT, at=MINUTE, tolerate=True)

    await throttle.check(account=OTHER, now=MINUTE)


async def test_an_attempt_with_neither_is_not_counted(throttle: Throttle) -> None:
    """A caller that can identify nothing gets no bucket rather than a shared
    one, which would let any unattributable request exhaust everybody's."""
    for _ in range(50):
        await throttle.check(now=MINUTE)


# --- the sliding window -----------------------------------------------------


async def test_the_window_boundary_is_not_a_free_burst(throttle: Throttle) -> None:
    """The reason this is a sliding window. A fixed one resets on the minute, so
    the limit sent at :59 and again at :00 is twice the allowance in two
    seconds."""
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE + 59)

    with pytest.raises(Throttled):
        await throttle.check(address=HERE, now=MINUTE + 61)


async def test_the_previous_window_decays(throttle: Throttle) -> None:
    """It weighs less as it slides out of view, so a minute of quiet restores the
    allowance rather than a clock tick doing it."""
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE)

    await throttle.check(address=HERE, now=MINUTE + 119)


async def test_a_long_quiet_period_restores_the_full_allowance(
    throttle: Throttle,
) -> None:
    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE)

    await _attempts(throttle, PER_ADDRESS, address=HERE, at=MINUTE + 600)


async def test_the_estimate_errs_towards_refusing(throttle: Throttle) -> None:
    """Halfway through the next window, half of the previous one still counts.

    Eight attempts land in one window; thirty seconds into the next, four of them
    are still in view. Seven more reaches eleven by the weighted count and seven
    by a naive one — and eleven is the honest answer, because eleven attempts did
    happen inside the last sixty seconds.
    """
    await _attempts(throttle, 8, address=HERE, at=MINUTE + 30)

    with pytest.raises(Throttled):
        await _attempts(throttle, 7, address=HERE, at=MINUTE + 90)


# --- when the store is gone -------------------------------------------------


class _Broken:
    async def incr(self, key: str) -> int:
        raise ConnectionError("redis is gone")

    async def get(self, key: str) -> str | None:
        raise ConnectionError("redis is gone")

    async def expire(self, key: str, seconds: int) -> None:
        raise ConnectionError("redis is gone")


async def test_an_outage_refuses_rather_than_passes() -> None:
    """An unenforced rate limit costs the whole control, and every path that
    reaches here needs Redis for its session anyway."""
    throttle = Throttle(_Broken())

    with pytest.raises(Throttled) as raised:
        await throttle.check(address=HERE)

    assert raised.value.reason == UNAVAILABLE


# --- what the keys carry ----------------------------------------------------


async def test_the_key_does_not_carry_the_address(
    throttle: Throttle, redis: aioredis.FakeRedis
) -> None:
    """An account name or an address in a Redis key name is personal data in a
    place nobody thinks to redact."""
    await throttle.check(address=HERE, account=CLIENT, now=MINUTE)

    keys = await redis.keys("throttle:*")
    assert keys
    assert not any(HERE in key or CLIENT in key for key in keys)


async def test_the_counters_expire(throttle: Throttle, redis: aioredis.FakeRedis) -> None:
    """Otherwise the one structure here grows a key per address per minute for
    the life of the deployment."""
    await throttle.check(address=HERE, now=MINUTE)

    ttls = [await redis.ttl(key) for key in await redis.keys("throttle:*")]
    assert all(0 < ttl <= 120 for ttl in ttls)


def test_the_limits_are_the_requirements() -> None:
    """Pinned, because they are the control and a quiet edit to either would
    weaken it invisibly."""
    assert PER_ADDRESS == 10
    assert PER_ACCOUNT == 5
