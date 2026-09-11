"""Talking to the push-approval service (FR-MFA-03).

The service on the other end is a simulator, and the README and its own approval
page say so. What is real here is the *shape*: a request raised, waited on, and
resolved as approved, denied or timed out, with the broker handling each outcome
correctly. That part transfers to a genuine provider unchanged; the trust does
not.

**The broker binds the request to the person, not the service.** A request id
comes back from the simulator and then goes to a browser, so anything that
accepted a decision on the strength of the id alone would let one person's
approval elevate another person's session. The binding is kept here, in Redis,
keyed by the id and holding the person it was raised for — and it is checked
before the decision is read.

**Polling, not waiting.** Holding a request open for a minute would tie up a
worker per pending approval and make a slow simulator into a broker outage. The
browser asks again; the broker asks the service once per ask.

**A push request expires on our clock as well as theirs.** The binding's TTL is
the window, so a decision arriving after it has nothing to attach to even if the
service were willing to settle it late. Two clocks agreeing is not something to
depend on when one of them is a container somebody can restart.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

import httpx

from campusid.logging import get_logger

log = get_logger(__name__)

BINDING_PREFIX: Final = "mfa:push:"
WINDOW: Final = timedelta(seconds=60)
"""FR-MFA-03's response window, held on this side too."""

PENDING: Final = "pending"
APPROVED: Final = "approved"
DENIED: Final = "denied"
EXPIRED: Final = "expired"
UNAVAILABLE: Final = "unavailable"
"""The service could not be reached. Distinct from `denied`, because telling
somebody their approval was refused when the service was simply down sends them
to the service desk for the wrong problem."""

TIMEOUT: Final = 5.0
"""Seconds to wait on the service itself. Short, because this sits inside a
request somebody is watching, and a push provider that takes five seconds to
acknowledge a request is already failing."""


class PushUnavailable(Exception):
    """The push service could not be reached or would not answer."""


class PushClient:
    """Raises push requests and reads their outcome."""

    def __init__(
        self,
        base_url: str,
        redis: Any,
        *,
        client: httpx.AsyncClient | None = None,
        window: timedelta = WINDOW,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._redis = redis
        self._client = client
        self._window = window

    @property
    def configured(self) -> bool:
        """Whether push is available at all.

        Absent is a state an operator chose, the same as the directory. A broker
        with no push service simply has no push factor, which is different from
        one whose push service is broken.
        """
        return bool(self._base)

    async def send(self, person_uuid: str, *, context: str = "sign-in") -> str:
        """Raise a request and remember whose it is.

        The binding is written before the id is returned, so there is no window
        in which a browser holds an id the broker cannot attribute.
        """
        payload = {"subject": person_uuid, "context": context}
        try:
            response = await self._post("/push", payload)
            request_id = str(response["id"])
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("mfa.push.unavailable", error=str(exc))
            raise PushUnavailable(str(exc)) from exc

        await self._redis.set(
            f"{BINDING_PREFIX}{request_id}",
            person_uuid,
            ex=int(self._window.total_seconds()),
        )
        log.info("mfa.push.sent", person=person_uuid, request=request_id)
        return request_id

    async def outcome(self, person_uuid: str, request_id: str) -> str:
        """What happened to a request this person raised.

        A request bound to somebody else is `expired` rather than refused
        outright: from the caller's side the two are the same answer, and
        distinguishing them would say whether the id was real.
        """
        bound = await self._redis.get(f"{BINDING_PREFIX}{request_id}")
        if bound != person_uuid:
            return EXPIRED

        try:
            response = await self._get(f"/push/{request_id}")
        except httpx.HTTPError as exc:
            log.warning("mfa.push.unavailable", error=str(exc))
            return UNAVAILABLE

        status = str(response.get("status", PENDING))
        if status in (APPROVED, DENIED, EXPIRED):
            # Settled, so the binding has done its job. Deleting it here is what
            # makes an approval single-use: a second poll finds nothing bound
            # and cannot elevate a second session.
            await self._redis.delete(f"{BINDING_PREFIX}{request_id}")
        return status

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with self._session() as client:
            response = await client.post(f"{self._base}{path}", json=payload, timeout=TIMEOUT)
            response.raise_for_status()
            body: dict[str, Any] = response.json()
            return body

    async def _get(self, path: str) -> dict[str, Any]:
        async with self._session() as client:
            response = await client.get(f"{self._base}{path}", timeout=TIMEOUT)
            response.raise_for_status()
            body: dict[str, Any] = response.json()
            return body

    def _session(self) -> Any:
        """The injected client if there is one, otherwise a throwaway.

        Injected in tests and in the application, where one client for the life
        of the process reuses connections. The throwaway exists so this class is
        usable without arranging one.
        """
        if self._client is not None:
            return _Borrowed(self._client)
        return httpx.AsyncClient()


class _Borrowed:
    """Lends a shared client to an `async with` without closing it."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self._client

    async def __aexit__(self, *exc: Any) -> None:
        return None
