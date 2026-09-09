"""Pushed Authorization Requests (FR-OP-07), RFC 9126.

A client POSTs its authorization request to us directly, authenticating itself,
and receives an opaque `request_uri` to put in the browser redirect instead. The
whole request then travels over a channel we control rather than through the
user agent.

Three things follow from that, and they are the reason to bother:

**The request is authenticated at the point it is made.** An ordinary
authorization request arrives with no proof that the named client sent it —
anyone can construct one. Here the client proves itself before the request
exists, so `client_id` means something.

**The request cannot be tampered with in the browser.** Query parameters pass
through the user agent, extensions, and anything that can rewrite a URL; a
`request_uri` is a reference to a record only we can read.

**The request stops leaking.** Scopes, `login_hint`, `acr_values` and the
redirect URI no longer appear in browser history, referrer headers, or the
access logs of every proxy between the user and us.

The record is bound to the client that pushed it and is single-use. Both matter:
an unbound `request_uri` would let one client redeem another's request, and a
reusable one would let a captured URL start the same authorization repeatedly
long after the user thought they had finished.
"""

from __future__ import annotations

import json
import secrets
from datetime import timedelta
from typing import Any, Final

from redis.asyncio import Redis

REQUEST_URI_PREFIX: Final = "urn:ietf:params:oauth:request_uri:"
"""RFC 9126 §2.2 fixes the scheme. A client that treats the value as opaque —
which it should — never sees this, but a client that pattern-matches on it will
find what the specification told it to expect."""

PAR_KEY_PREFIX: Final = "oidc:par:"

PAR_TTL: Final = timedelta(seconds=90)
"""The window between pushing a request and the browser arriving with it. Short
because nothing legitimate takes longer: the client redirects immediately, and a
reference that outlives the redirect is only useful to somebody who captured
it."""

REFERENCE_BYTES: Final = 32
"""The reference is the only thing standing between an observer and a request
that has already been authenticated, so it is sized like a session id."""


class PushedRequestStore:
    """Holds authorization requests pushed by clients."""

    def __init__(self, redis: Redis, *, ttl: timedelta = PAR_TTL) -> None:
        self._redis = redis
        self._ttl = ttl

    async def push(self, client_id: str, parameters: dict[str, Any]) -> tuple[str, int]:
        """Store a request and return its `request_uri` and lifetime."""
        reference = secrets.token_urlsafe(REFERENCE_BYTES)
        seconds = max(int(self._ttl.total_seconds()), 1)
        await self._redis.set(
            f"{PAR_KEY_PREFIX}{reference}",
            json.dumps({"client_id": client_id, "parameters": parameters}),
            ex=seconds,
        )
        return f"{REQUEST_URI_PREFIX}{reference}", seconds

    async def consume(self, request_uri: str, *, client_id: str) -> dict[str, Any] | None:
        """Spend a `request_uri`, or return None.

        Fetch-and-delete in one step, so two browsers arriving with the same
        reference cannot both proceed. The client binding is checked *after* the
        delete rather than before: a mismatched reference is still spent, so a
        client cannot probe for another's pending requests by presenting
        references until one is accepted.
        """
        if not request_uri.startswith(REQUEST_URI_PREFIX):
            return None

        reference = request_uri[len(REQUEST_URI_PREFIX) :]
        raw = await self._redis.getdel(f"{PAR_KEY_PREFIX}{reference}")
        if raw is None:
            return None

        record = json.loads(raw)
        if record.get("client_id") != client_id:
            return None
        parameters: dict[str, Any] = record["parameters"]
        return parameters
