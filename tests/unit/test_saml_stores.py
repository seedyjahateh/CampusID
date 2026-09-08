"""Redis-backed replay cache and request store.

Run against `fakeredis`, which implements the actual Redis command semantics —
so `SET NX` and `GETDEL` behave as they will in production, without a
container. The point of these tests is the atomicity contract: both stores
promise that two concurrent callers cannot both win.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import aioredis

from campusid.saml.stores import (
    REPLAY_KEY_PREFIX,
    OutstandingRequest,
    RedisReplayCache,
    RedisRequestStore,
    utcnow,
)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def outstanding() -> OutstandingRequest:
    return OutstandingRequest(
        request_id="_request1",
        idp_entity_id="https://idp.test/saml",
        relay_state="relay-token",
        created_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
    )


# --- replay cache ---------------------------------------------------------


async def test_the_first_sighting_is_remembered(redis: aioredis.FakeRedis) -> None:
    cache = RedisReplayCache(redis)

    assert await cache.remember("_a1", timedelta(minutes=5)) is True
    assert await cache.remember("_a1", timedelta(minutes=5)) is False


async def test_distinct_assertions_do_not_collide(redis: aioredis.FakeRedis) -> None:
    cache = RedisReplayCache(redis)

    assert await cache.remember("_a1", timedelta(minutes=5)) is True
    assert await cache.remember("_a2", timedelta(minutes=5)) is True


async def test_concurrent_replays_produce_exactly_one_winner(
    redis: aioredis.FakeRedis,
) -> None:
    """The atomicity requirement in the protocol.

    A check-then-set would let both coroutines observe "unseen" and both
    succeed, which is precisely the race a replay attack would try to open.
    """
    cache = RedisReplayCache(redis)

    results = await asyncio.gather(
        *(cache.remember("_a1", timedelta(minutes=5)) for _ in range(20))
    )

    assert results.count(True) == 1


async def test_the_entry_carries_the_requested_ttl(redis: aioredis.FakeRedis) -> None:
    """Bounded so the cache cannot grow without limit, but long enough to cover
    the whole window in which the assertion would still be accepted."""
    cache = RedisReplayCache(redis)
    await cache.remember("_a1", timedelta(minutes=5))

    ttl = await redis.ttl(f"{REPLAY_KEY_PREFIX}_a1")

    assert 0 < ttl <= 300


async def test_a_sub_second_ttl_still_stores(redis: aioredis.FakeRedis) -> None:
    """An assertion on the edge of expiry must still be recorded.

    Redis rejects `EX 0`, so a naive int conversion of a fractional TTL would
    raise and let the replay through.
    """
    cache = RedisReplayCache(redis)

    assert await cache.remember("_a1", timedelta(milliseconds=10)) is True


# --- request store --------------------------------------------------------


async def test_a_request_round_trips(
    redis: aioredis.FakeRedis, outstanding: OutstandingRequest
) -> None:
    store = RedisRequestStore(redis)
    await store.remember(outstanding, timedelta(minutes=5))

    assert await store.consume("_request1") == outstanding


async def test_a_request_is_consumed_exactly_once(
    redis: aioredis.FakeRedis, outstanding: OutstandingRequest
) -> None:
    """An AuthnRequest authorises one response. Fetch-without-delete would let
    a captured response be replayed for as long as the entry lived."""
    store = RedisRequestStore(redis)
    await store.remember(outstanding, timedelta(minutes=5))

    assert await store.consume("_request1") is not None
    assert await store.consume("_request1") is None


async def test_consuming_an_unknown_request_returns_none(
    redis: aioredis.FakeRedis,
) -> None:
    assert await RedisRequestStore(redis).consume("_never-sent") is None


async def test_concurrent_consumers_produce_exactly_one_winner(
    redis: aioredis.FakeRedis, outstanding: OutstandingRequest
) -> None:
    store = RedisRequestStore(redis)
    await store.remember(outstanding, timedelta(minutes=5))

    results = await asyncio.gather(*(store.consume("_request1") for _ in range(20)))

    assert sum(1 for result in results if result is not None) == 1


# --- time -----------------------------------------------------------------


def test_utcnow_is_timezone_aware() -> None:
    """A naive datetime compared against SAML's aware instants raises at
    runtime — inside the gate, on a real login."""
    assert utcnow().tzinfo is not None
