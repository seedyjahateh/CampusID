"""Redis client lifecycle and connectivity probe.

Redis carries session state, the SAML assertion replay cache, rate-limit
counters, and the provisioning queue. Losing it is a readiness failure, not a
degradation: without the replay cache the broker cannot honour FR-SAML-07.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import cast

from redis.asyncio import Redis

from campusid.config import Settings


def create_redis(settings: Settings) -> Redis:
    """Build the async Redis client."""
    client: Redis = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )
    return client


async def check_redis(client: Redis) -> None:
    """Raise if Redis is not reachable. Used by the readiness probe."""
    await client.ping()


# --- set commands, typed -----------------------------------------------------
#
# redis-py declares its set commands as `Awaitable[T] | T` because one class
# serves both the sync and async clients, so `await` on them fails `--strict`.
# The cast is centralised in these three functions rather than repeated at a
# dozen call sites: one place asserting "this client is the async one", with the
# reason beside it, instead of a scattering of identical `cast(...)` noise that
# nobody would read twice.


async def set_add(client: Redis, key: str, member: str) -> None:
    """`SADD`, awaited."""
    await cast("Awaitable[int]", client.sadd(key, member))


async def set_remove(client: Redis, key: str, member: str) -> None:
    """`SREM`, awaited."""
    await cast("Awaitable[int]", client.srem(key, member))


async def set_members(client: Redis, key: str) -> list[str]:
    """`SMEMBERS`, sorted so callers get a stable order.

    Redis sets are unordered, and an unsorted result would make an audit record
    or an administrator's report differ between identical runs.
    """
    members = await cast("Awaitable[set[str]]", client.smembers(key))
    return sorted(str(member) for member in members)


async def expire_key(client: Redis, key: str, seconds: int) -> None:
    """`EXPIRE`, awaited."""
    await cast("Awaitable[int]", client.expire(key, seconds))
