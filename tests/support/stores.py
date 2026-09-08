"""In-memory store implementations for tests.

The gate depends on protocols rather than Redis so the negative suite runs with
no containers. These are the substitutes, and they honour the same contracts:
`remember` is atomic-by-construction here, and `consume` deletes.
"""

from __future__ import annotations

from datetime import timedelta

from campusid.saml.stores import OutstandingRequest


class InMemoryReplayCache:
    """Records assertion IDs. TTLs are recorded but never expire."""

    def __init__(self) -> None:
        self.remembered: dict[str, timedelta] = {}

    async def remember(self, assertion_id: str, ttl: timedelta) -> bool:
        if assertion_id in self.remembered:
            return False
        self.remembered[assertion_id] = ttl
        return True


class InMemoryRequestStore:
    """Outstanding requests, consumed on read."""

    def __init__(self) -> None:
        self.requests: dict[str, OutstandingRequest] = {}

    async def remember(self, request: OutstandingRequest, ttl: timedelta) -> None:
        self.requests[request.request_id] = request

    async def consume(self, request_id: str) -> OutstandingRequest | None:
        return self.requests.pop(request_id, None)
