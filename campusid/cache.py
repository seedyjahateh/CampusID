"""Redis client lifecycle and connectivity probe.

Redis carries session state, the SAML assertion replay cache, rate-limit
counters, and the provisioning queue. Losing it is a readiness failure, not a
degradation: without the replay cache the broker cannot honour FR-SAML-07.
"""

from __future__ import annotations

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
