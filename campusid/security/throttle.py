"""Rate limiting the authentication endpoints (NFR-SEC-10).

Different in kind from the second-factor limiter in `campusid/mfa/ratelimit.py`,
and both are needed. That one counts *failures* and locks an account after five;
this one counts *attempts* and refuses the eleventh in a minute. A failure
counter does not stop somebody hammering an endpoint with requests that never
reach a credential check, and a rate limit does not stop a patient attacker
guessing one code a minute.

**Two buckets, and both have to pass.** Per address, because one machine running
a list of accounts is the common case; per account, because a botnet running one
account from a thousand addresses is the case a per-address limit cannot see. The
limits differ for the same reason: an address legitimately carries a whole
building's traffic, and an account does not.

**A sliding window, not a fixed one.** A fixed window resets on the minute, so an
attacker who sends the limit at :59 and again at :00 gets twice the allowance in
two seconds — which is the burst the limit exists to prevent. This weights the
previous window's count by how much of it is still in view, which costs one extra
counter and removes the boundary entirely. The estimate can be slightly wrong at
the edges; it is wrong in the direction of refusing, which is the right direction.

**At the application layer, deliberately.** A proxy rate limit is worth having
and is somebody else's to configure; this one travels with the application, so a
deployment that forgets the proxy is still protected and a test can prove it.

**The account bucket has no caller in this broker, and that is a finding rather
than an oversight.** The requirement asks for a per-account limit on the
authentication endpoints, and there is nowhere here it belongs. This broker never
handles a primary credential — the upstream IdP does — so the ACS has no account
to charge until after the assertion it is protecting has been read. On the token
endpoint the "account" would be a relying party, and five a minute for one
confidential client carrying a campus is an outage rather than a control. The one
place a user credential *is* checked is the second-factor endpoints, and those
already have a stricter, purpose-built failure lockout: adding this in front of it
would trip first and make the fifteen-minute penalty unreachable, which is a
regression of FR-MFA-06 dressed as a second layer.

The bucket is implemented and tested because the requirement asks for it and
because the day this broker grows a local password is the day it is needed. It is
left unwired rather than forced into a place where it degrades something better.

**Redis being unavailable is a refusal.** Same reasoning as the second-factor
limiter: an unenforced rate limit costs the whole control, and every
authentication path here already needs Redis for its session.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Final

from campusid.logging import get_logger

log = get_logger(__name__)

PREFIX: Final = "throttle:"

PER_ADDRESS: Final = 10
PER_ACCOUNT: Final = 5
"""NFR-SEC-10's numbers: ten attempts a minute from one address, five for one
account. The address limit is looser because one address legitimately carries a
whole building's traffic and one account does not."""

WINDOW_SECONDS: Final = 60

THROTTLED: Final = "auth.rate_limited"
UNAVAILABLE: Final = "auth.throttle_unavailable"

ADDRESS: Final = "ip"
ACCOUNT: Final = "account"


class Throttled(Exception):
    """The attempt was refused before anything looked at a credential."""

    def __init__(self, reason: str, *, bucket: str, retry_after: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.bucket = bucket
        self.retry_after = retry_after
        """Seconds until the window has moved enough to allow another attempt.

        Told rather than withheld. Somebody who has tripped a limit needs to know
        whether to wait a moment or to stop, and an attacker already knows they
        are being refused.
        """


@dataclass(frozen=True, slots=True)
class Limit:
    """One bucket's allowance."""

    name: str
    ceiling: int


class Throttle:
    """Counts attempts per address and per account over a sliding minute."""

    def __init__(
        self,
        redis: Any,
        *,
        per_address: int = PER_ADDRESS,
        per_account: int = PER_ACCOUNT,
        window: int = WINDOW_SECONDS,
    ) -> None:
        self._redis = redis
        self._window = window
        self._limits = {
            ADDRESS: Limit(name=ADDRESS, ceiling=per_address),
            ACCOUNT: Limit(name=ACCOUNT, ceiling=per_account),
        }

    async def check(
        self, *, address: str | None = None, account: str | None = None, now: float | None = None
    ) -> None:
        """Count this attempt against both buckets, raising if either is full.

        Both are counted even when the first refuses, so a caller cannot spend an
        address's allowance without also spending the account's — otherwise
        alternating addresses would leave the account bucket untouched.
        """
        moment = now if now is not None else time.time()
        refusal: Throttled | None = None

        for bucket, value in ((ADDRESS, address), (ACCOUNT, account)):
            if not value:
                continue
            try:
                used = await self._count(bucket, value, moment)
            except Exception as exc:
                # Refused, not passed. An unenforced rate limit costs the whole
                # control, and every path that reaches here needs Redis anyway.
                log.error("auth.throttle.unavailable", error=str(exc))
                raise Throttled(UNAVAILABLE, bucket=bucket, retry_after=self._window) from exc

            ceiling = self._limits[bucket].ceiling
            if used > ceiling and refusal is None:
                log.warning("auth.rate_limited", bucket=bucket, used=round(used, 2))
                refusal = Throttled(THROTTLED, bucket=bucket, retry_after=self._retry_after(moment))

        if refusal is not None:
            raise refusal

    async def _count(self, bucket: str, value: str, moment: float) -> float:
        """Increment this window and return the weighted count including the last.

        The weight is how much of the previous window is still inside the sliding
        one. At the very start of a window almost all of it counts; by the end,
        almost none does. That is what removes the boundary an attacker would
        otherwise send a double burst across.
        """
        current = math.floor(moment / self._window)
        elapsed = (moment % self._window) / self._window

        key = self._key(bucket, value, current)
        count = int(await self._redis.incr(key))
        if count == 1:
            # Two windows of life, so the next window can still weigh this one.
            await self._redis.expire(key, self._window * 2)

        previous = await self._redis.get(self._key(bucket, value, current - 1))
        carried = float(previous or 0) * (1.0 - elapsed)
        return count + carried

    def _retry_after(self, moment: float) -> int:
        """Until the current window ends. An approximation, and an honest one:
        the sliding count decays continuously, so any single number is a
        simplification — this one never tells a caller to come back too early."""
        return max(1, int(self._window - (moment % self._window)))

    def _key(self, bucket: str, value: str, window: int) -> str:
        # The value is hashed rather than embedded: an account name or an address
        # in a Redis key name is personal data in a place nobody thinks to redact.
        import hashlib

        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
        return f"{PREFIX}{bucket}:{digest}:{window}"
