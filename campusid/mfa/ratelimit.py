"""Rate limiting second-factor attempts (FR-MFA-06).

A six-digit code has a million values and a thirty-second life. Unlimited guesses
against it are not a brute force in any dramatic sense — an attacker who can send
a few thousand attempts a second expects to land one inside the window — so the
limit is not a hardening measure, it is the thing that makes the factor worth
having at all.

**Five failures, then fifteen minutes of nothing.** The requirement's numbers.
Five is more than anybody mistypes and far fewer than anybody guesses; fifteen
minutes turns a million-value search into something that takes years rather than
minutes.

**Per person and per kind.** Somebody locked out of their authenticator app can
still use their security key, because the two are different credentials with
different failure modes, and a lock that covered both would make one lost phone a
complete lockout. Locking per *credential* would be worse: an attacker guessing
against one of somebody's three TOTP apps would leave the other two open.

**A success clears the count.** Otherwise four mistypes spread over a month add
up to a lockout on the fifth, and the person's experience is that the system
locks them out at random.

**The lock outlives the counter deliberately.** The counter expires fifteen
minutes after the first failure, so an attacker pacing themselves across the
boundary gets at most nine wrong codes before a lock rather than five. The bound
that matters is the lock: once it is set nothing is accepted for fifteen minutes
whatever the counter says, and a ten-in-thirty-minutes rate against a million
values is not an attack, it is a rounding error.

**Redis being unavailable is a refusal, not a pass.** The opposite of the
decision cache's, and for a different reason: a cache miss costs an evaluation,
while an unenforced rate limit costs the whole control. There is also nothing to
protect — the session store is Redis too, so a broker that cannot reach it has no
session to step up.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final

from campusid.logging import get_logger

log = get_logger(__name__)

ATTEMPTS_PREFIX: Final = "mfa:attempts:"
LOCK_PREFIX: Final = "mfa:lock:"

THRESHOLD: Final = 5
WINDOW: Final = timedelta(minutes=15)
LOCKOUT: Final = timedelta(minutes=15)

LOCKED: Final = "mfa.locked_out"
UNAVAILABLE: Final = "mfa.rate_limiter_unavailable"


class RateLimited(Exception):
    """The attempt was not made, because attempts are not being accepted."""

    def __init__(self, reason: str, retry_after: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after
        """Seconds until attempts resume, so the response can say so.

        Told rather than withheld: somebody locked out needs to know whether to
        wait or to call the service desk, and an attacker already knows they are
        being refused.
        """


@dataclass(frozen=True, slots=True)
class Failure:
    """What a recorded failure did."""

    attempts: int
    locked: bool
    """True only on the attempt that crossed the threshold, so the audit record
    and the alert fire once rather than on every attempt behind the lock."""


class AttemptLimiter:
    """Counts failed second-factor attempts and refuses once there are too many."""

    def __init__(
        self,
        redis: Any,
        *,
        threshold: int = THRESHOLD,
        window: timedelta = WINDOW,
        lockout: timedelta = LOCKOUT,
    ) -> None:
        self._redis = redis
        self._threshold = threshold
        self._window = window
        self._lockout = lockout

    async def check(self, person_uuid: str, kind: str) -> None:
        """Raise if attempts are not being accepted for this person and kind.

        Called before verifying rather than after, so a locked-out account costs
        no signature check — which is both the point and a small denial-of-service
        defence of its own.
        """
        try:
            remaining = await self._redis.ttl(self._lock_key(person_uuid, kind))
        except Exception as exc:
            # Refused, not passed. An unenforced limit costs the whole control.
            log.error("mfa.ratelimit.unavailable", error=str(exc))
            raise RateLimited(UNAVAILABLE, int(self._lockout.total_seconds())) from exc

        if remaining is not None and remaining > 0:
            raise RateLimited(LOCKED, int(remaining))

    async def record_failure(self, person_uuid: str, kind: str) -> Failure:
        """Count one failure, locking if it was the last one allowed."""
        key = self._attempts_key(person_uuid, kind)
        try:
            attempts = int(await self._redis.incr(key))
            if attempts == 1:
                # Set only on the first, so the window runs from the first
                # failure rather than sliding forward with every attempt — which
                # would let a patient attacker hold it open indefinitely.
                await self._redis.expire(key, int(self._window.total_seconds()))
            if attempts < self._threshold:
                return Failure(attempts=attempts, locked=False)

            await self._redis.set(
                self._lock_key(person_uuid, kind),
                "1",
                ex=int(self._lockout.total_seconds()),
            )
            await self._redis.delete(key)
        except Exception as exc:
            log.error("mfa.ratelimit.unavailable", error=str(exc))
            raise RateLimited(UNAVAILABLE, int(self._lockout.total_seconds())) from exc

        log.warning("mfa.locked_out", person=person_uuid, kind=kind, attempts=attempts)
        return Failure(attempts=attempts, locked=True)

    async def record_success(self, person_uuid: str, kind: str) -> None:
        """Forget the failures. Four mistypes over a month must not add up.

        Errors are logged and swallowed: a successful authentication has already
        happened, and turning it into a failure because the counter would not
        reset would punish the person for an outage.
        """
        try:
            await self._redis.delete(self._attempts_key(person_uuid, kind))
        except Exception as exc:
            log.warning("mfa.ratelimit.reset_failed", error=str(exc))

    async def clear(self, person_uuid: str, kind: str) -> None:
        """Lift a lock, for an administrator who has verified somebody by other
        means (FR-MFA-06). Separate from `record_success` because it is somebody
        deciding rather than somebody proving."""
        await self._redis.delete(self._lock_key(person_uuid, kind))
        await self._redis.delete(self._attempts_key(person_uuid, kind))
        log.info("mfa.lock_cleared", person=person_uuid, kind=kind)

    async def locked(self, person_uuid: str, kind: str) -> int:
        """Seconds remaining on a lock, or zero. For the admin view."""
        remaining = await self._redis.ttl(self._lock_key(person_uuid, kind))
        return max(0, int(remaining or 0))

    def _attempts_key(self, person_uuid: str, kind: str) -> str:
        return f"{ATTEMPTS_PREFIX}{kind}:{person_uuid}"

    def _lock_key(self, person_uuid: str, kind: str) -> str:
        return f"{LOCK_PREFIX}{kind}:{person_uuid}"
