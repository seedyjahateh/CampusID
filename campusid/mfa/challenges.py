"""Outstanding WebAuthn challenges (FR-MFA-02).

A challenge is the only thing standing between a captured ceremony response and
a replay of it, so the rules are the ones any nonce store needs: unpredictable,
scoped to who asked for it, short-lived, and spent exactly once.

**Single use is enforced by the read, not by the caller.** `consume` deletes
atomically and returns what was there, so two requests carrying one captured
response cannot both find it — the second gets nothing whether or not the first
has finished. A check-then-delete would be a race with a replay on the other
side of it.

**Scoped to the person and the ceremony.** A challenge issued for a
registration cannot be answered with an assertion, because the two live under
different keys. That is a second line behind the ceremony type inside
`clientDataJSON`, which the authenticator signs and the verifier checks.

**Five minutes.** Long enough to find a security key in a drawer, short enough
that a challenge captured from a browser's memory has usually expired by the
time it is useful. Redis does the expiry, so nothing has to sweep.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any, Final

from campusid.logging import get_logger

log = get_logger(__name__)

PREFIX: Final = "mfa:challenge:"
TTL: Final = timedelta(minutes=5)
LENGTH: Final = 32
"""256 bits. The specification asks for at least 16 bytes; this is the usual
doubling, and the cost of the extra 16 is nothing."""

REGISTER: Final = "register"
AUTHENTICATE: Final = "authenticate"


class ChallengeStore:
    """Issues and spends one-time challenges."""

    def __init__(self, redis: Any, *, ttl: timedelta = TTL) -> None:
        self._redis = redis
        self._ttl = ttl

    async def issue(self, person_uuid: str, ceremony: str) -> bytes:
        """A fresh challenge, replacing any outstanding one for this ceremony.

        Replacing rather than accumulating: somebody who opens the enrolment
        page twice has one enrolment in mind, and a store that kept both would
        leave the abandoned one spendable for its whole lifetime.
        """
        challenge = secrets.token_bytes(LENGTH)
        await self._redis.set(
            self._key(person_uuid, ceremony),
            challenge.hex(),
            ex=int(self._ttl.total_seconds()),
        )
        return challenge

    async def consume(self, person_uuid: str, ceremony: str) -> bytes | None:
        """The outstanding challenge, spent in the same operation that reads it.

        `GETDEL` rather than a read and a delete, so two requests carrying one
        captured response cannot both find it.
        """
        raw = await self._redis.getdel(self._key(person_uuid, ceremony))
        if raw is None:
            return None
        try:
            return bytes.fromhex(raw)
        except ValueError:  # pragma: no cover - only a corrupted entry
            log.warning("mfa.challenge.unreadable", person=person_uuid, ceremony=ceremony)
            return None

    def _key(self, person_uuid: str, ceremony: str) -> str:
        return f"{PREFIX}{ceremony}:{person_uuid}"
