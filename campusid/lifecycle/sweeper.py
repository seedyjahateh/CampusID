"""The sweep that ends grace periods (FR-LC-05).

A grace period is a date in a row, so what ends it is somebody looking. This is
the somebody: a task that wakes periodically and revokes every grant whose
deadline has passed.

**The sweep is not what makes the deadline durable — the column is.** That is
the whole point of storing it. A broker that was down for a week revokes on its
next sweep rather than never, and running two brokers means the work is done
twice with no harm rather than raced: the update selects only grants that are
not yet revoked, so the second one finds nothing.

**In-process rather than a cron container.** The alternative is a scheduler that
has to be deployed, monitored and kept in step with the schema, to run one query.
The cost of in-process is that the sweep stops when the broker does, and the
column is exactly the reason that does not matter.

**A failed sweep is logged and retried, never fatal.** It runs beside request
handling, and a database blip at three in the morning must not take the broker
down — it must take the sweep down for one interval.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import timedelta
from typing import Any

from campusid.logging import get_logger

log = get_logger(__name__)

DEFAULT_INTERVAL = timedelta(hours=1)
"""Hourly, which is far more often than daily deadlines need.

Chosen for the restart case rather than the steady state: a broker that comes up
after a long outage should not wait most of a day before catching up, and the
query costs one indexed scan of grants that are due.
"""

STARTUP_DELAY = timedelta(seconds=5)
"""Long enough for readiness probes to pass first.

A sweep racing the first request for a connection makes a slow startup look like
a broken one, and nothing about a grace period is urgent to the second.
"""


class GraceSweeper:
    """Runs `expire_due` on a timer for the life of the process."""

    def __init__(
        self,
        lifecycle: Any,
        *,
        interval: timedelta = DEFAULT_INTERVAL,
        startup_delay: timedelta = STARTUP_DELAY,
    ) -> None:
        self._lifecycle = lifecycle
        self._interval = interval
        self._startup_delay = startup_delay
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:  # pragma: no cover - guarded by the caller
            return
        self._task = asyncio.create_task(self._run(), name="lifecycle-grace-sweep")

    async def stop(self) -> None:
        """Cancel the task and wait for it, so shutdown does not race a query.

        Awaited rather than fired and forgotten: a cancelled task still holds a
        database connection until it unwinds, and disposing the pool underneath
        it is how a clean shutdown produces an alarming traceback.
        """
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def sweep_once(self) -> int:
        """One pass. Separate from the loop so an operator can run it by hand
        and so the loop has nothing in it but timing."""
        expired = await self._lifecycle.expire_due()
        if expired:
            log.info("lifecycle.grace.swept", expired=expired)
        return int(expired)

    async def _run(self) -> None:
        await asyncio.sleep(self._startup_delay.total_seconds())
        while True:
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Beside request handling: a database blip at three in the
                # morning takes the sweep down for one interval, not the broker.
                log.exception("lifecycle.grace.sweep_failed")
            await asyncio.sleep(self._interval.total_seconds())
