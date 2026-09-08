"""Short-lived state the validation gate depends on.

Both stores are declared as protocols first and implemented against Redis
second. That is not ceremony: the gate is the most security-critical code in
the broker and has to be exhaustively testable without containers, so its
dependencies must be substitutable. `tests/support/stores.py` holds in-memory
implementations used by the negative suite.

Neither store belongs in Postgres. Both hold entries that expire in minutes,
are written on every login, and are worthless after a restart — which is the
shape Redis is for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

REPLAY_KEY_PREFIX = "saml:replay:"
REQUEST_KEY_PREFIX = "saml:request:"


@dataclass(frozen=True, slots=True)
class OutstandingRequest:
    """An `AuthnRequest` the broker sent and is still waiting on."""

    request_id: str
    idp_entity_id: str
    relay_state: str
    created_at: datetime

    def to_json(self) -> str:
        return json.dumps(
            {
                "request_id": self.request_id,
                "idp_entity_id": self.idp_entity_id,
                "relay_state": self.relay_state,
                "created_at": self.created_at.isoformat(),
            }
        )

    @classmethod
    def from_json(cls, payload: str) -> OutstandingRequest:
        data = json.loads(payload)
        return cls(
            request_id=data["request_id"],
            idp_entity_id=data["idp_entity_id"],
            relay_state=data["relay_state"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


class ReplayCache(Protocol):
    """Records assertion IDs that have already been accepted."""

    async def remember(self, assertion_id: str, ttl: timedelta) -> bool:
        """Record ``assertion_id``; return True if it had not been seen.

        Must be atomic. A check-then-set would let two concurrent replays of
        the same assertion both observe "unseen" and both succeed.
        """
        ...


class RequestStore(Protocol):
    """Tracks outstanding `AuthnRequest`s so responses can be correlated."""

    async def remember(self, request: OutstandingRequest, ttl: timedelta) -> None: ...

    async def consume(self, request_id: str) -> OutstandingRequest | None:
        """Fetch and delete in one step.

        An `AuthnRequest` is single-use: returning a record without removing it
        would let one solicited request authorise several responses.
        """
        ...


class RedisReplayCache:
    """Replay cache backed by Redis `SET NX EX`."""

    def __init__(self, redis: Redis, prefix: str = REPLAY_KEY_PREFIX) -> None:
        self._redis = redis
        self._prefix = prefix

    async def remember(self, assertion_id: str, ttl: timedelta) -> bool:
        # SET NX is the atomicity requirement in the protocol, in one round trip.
        stored = await self._redis.set(
            f"{self._prefix}{assertion_id}",
            "1",
            nx=True,
            ex=max(int(ttl.total_seconds()), 1),
        )
        return bool(stored)


class RedisRequestStore:
    """Outstanding-request store backed by Redis."""

    def __init__(self, redis: Redis, prefix: str = REQUEST_KEY_PREFIX) -> None:
        self._redis = redis
        self._prefix = prefix

    async def remember(self, request: OutstandingRequest, ttl: timedelta) -> None:
        await self._redis.set(
            f"{self._prefix}{request.request_id}",
            request.to_json(),
            ex=max(int(ttl.total_seconds()), 1),
        )

    async def consume(self, request_id: str) -> OutstandingRequest | None:
        # GETDEL keeps fetch-and-delete atomic (Redis 6.2+).
        payload = await self._redis.getdel(f"{self._prefix}{request_id}")
        if payload is None:
            return None
        return OutstandingRequest.from_json(payload)


def utcnow() -> datetime:
    """Current time, always timezone-aware.

    Naive datetimes compared against SAML's timezone-aware instants raise at
    runtime, and the containers are pinned to UTC precisely so this is boring.
    """
    return datetime.now(UTC)
