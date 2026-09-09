"""Back-channel logout (FR-OP-12) and the client-session index.

Logging out of the broker has to mean something at the applications the person
actually used, or "sign out" is a button that clears one cookie and leaves five
live sessions behind it. OpenID Connect Back-Channel Logout is how a provider
says so: a signed `logout_token` POSTed server-to-server to each client's
registered endpoint.

Two pieces here.

**The index** records which clients hold a session for a given `sid`. Without it
there is nothing to notify: an authorization code is the only moment we learn
that a particular client now has a session for a particular person, and by
logout time that moment is long past. It is written when a code is issued and
read when a session ends.

**The notifier** delivers, and its interesting property is that it *cannot
fail the logout*. A client whose endpoint is down, slow, or returning 500 must
not keep the user signed in at the broker — FR-SES-04 is explicit that partial
failures do not block local destruction. So delivery is best-effort with
bounded retries, every outcome is recorded, and the local session is already
gone by the time any of it runs.

The retry schedule is short on purpose. Three attempts over a few seconds is
enough to ride out a restart or a blip; anything longer is a queue, and a queue
that outlives the request needs durability, ordering and a dead-letter story
that this does not pretend to have. What it does instead is say so, and audit
the failures loudly enough that an operator can see which clients never got the
message.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

import httpx
from redis.asyncio import Redis

from campusid.cache import expire_key, set_add, set_members
from campusid.logging import get_logger
from campusid.oidc.clients import OidcClient
from campusid.oidc.jwt import SigningKey
from campusid.oidc.tokens import TokenContext, logout_token

log = get_logger(__name__)

CLIENT_SESSION_PREFIX: Final = "oidc:session-clients:"
CLIENT_SESSION_TTL: Final = timedelta(hours=12)
"""Matched to the session's absolute timeout: an index entry that outlived the
session it describes would have us notifying clients about a `sid` nobody
holds."""

DELIVERY_TIMEOUT: Final = 5.0
"""Seconds. A client that cannot answer in five is not going to answer, and the
person waiting for a logout page should not be held up by it."""

RETRY_DELAYS: Final[tuple[float, ...]] = (0.5, 2.0)
"""Backoff between the three attempts. Short on purpose — see the module
docstring."""


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """What happened when we tried to tell one client."""

    client_id: str
    delivered: bool
    attempts: int
    detail: str | None = None


class ClientSessionIndex:
    """Which clients hold a session for a given `sid`."""

    def __init__(self, redis: Redis, *, ttl: timedelta = CLIENT_SESSION_TTL) -> None:
        self._redis = redis
        self._ttl = ttl

    async def record(self, sid: str, client_id: str) -> None:
        """Note that this client now has a session for this `sid`.

        Called when an authorization code is issued, which is the only moment
        the fact becomes true. Idempotent, because a person signing into the
        same application twice has one session there, not two.
        """
        key = f"{CLIENT_SESSION_PREFIX}{sid}"
        await set_add(self._redis, key, client_id)
        await expire_key(self._redis, key, max(int(self._ttl.total_seconds()), 1))

    async def clients_for(self, sid: str) -> list[str]:
        return await set_members(self._redis, f"{CLIENT_SESSION_PREFIX}{sid}")

    async def forget(self, sid: str) -> None:
        await self._redis.delete(f"{CLIENT_SESSION_PREFIX}{sid}")


class LogoutNotifier:
    """Delivers back-channel logout tokens."""

    def __init__(
        self,
        *,
        issuer: str,
        client: httpx.AsyncClient,
        retry_delays: tuple[float, ...] = RETRY_DELAYS,
    ) -> None:
        self._issuer = issuer
        self._http = client
        self._retry_delays = retry_delays

    async def notify(
        self,
        clients: list[OidcClient],
        *,
        sid: str,
        subject: str,
        key: SigningKey,
        now: datetime,
    ) -> list[DeliveryOutcome]:
        """Tell every client that this session has ended.

        Concurrently, because one slow client must not delay the rest — a
        sequential loop makes the worst client the cost of every logout.
        """
        targets = [client for client in clients if client.backchannel_logout_uri]
        if not targets:
            return []

        return list(
            await asyncio.gather(
                *(self._deliver(client, sid, subject, key, now) for client in targets)
            )
        )

    async def _deliver(
        self,
        client: OidcClient,
        sid: str,
        subject: str,
        key: SigningKey,
        now: datetime,
    ) -> DeliveryOutcome:
        token = logout_token(
            TokenContext(
                issuer=self._issuer,
                client_id=client.client_id,
                subject=subject,
                sid=sid,
                family_id="",
                scopes=frozenset(),
                auth_time=now,
            ),
            key,
            now=now,
        )

        detail: str | None = None
        for attempt in range(1, len(self._retry_delays) + 2):
            try:
                response = await self._http.post(
                    str(client.backchannel_logout_uri),
                    data={"logout_token": token},
                    timeout=DELIVERY_TIMEOUT,
                )
            except httpx.HTTPError as exc:
                detail = type(exc).__name__
            else:
                if response.status_code < 400:
                    return DeliveryOutcome(client.client_id, True, attempt)
                detail = f"HTTP {response.status_code}"

            if attempt <= len(self._retry_delays):
                await asyncio.sleep(self._retry_delays[attempt - 1])

        # Audited rather than raised. The session is already destroyed by the
        # time this runs, and a client that cannot be reached must not be able
        # to keep somebody signed in at the broker.
        log.error(
            "logout.delivery_failed",
            client_id=client.client_id,
            attempts=len(self._retry_delays) + 1,
            detail=detail,
        )
        return DeliveryOutcome(client.client_id, False, len(self._retry_delays) + 1, detail)
