"""The sweep that ends grace periods (FR-LC-05).

What makes a grace period durable is the deadline being a column; what makes it
*happen* is somebody reading that column. These tests are about the reader, and
mostly about the two ways it can go wrong quietly: stopping on the first error,
and not stopping when the broker does.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from campusid.lifecycle.sweeper import DEFAULT_INTERVAL, STARTUP_DELAY, GraceSweeper

NOTHING = timedelta(0)
BRIEF = timedelta(seconds=0.01)


class _Lifecycle:
    def __init__(self, results: list[int | Exception]) -> None:
        self._results = list(results)
        self.calls = 0

    async def expire_due(self) -> int:
        self.calls += 1
        outcome = self._results.pop(0) if self._results else 0
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def _run_briefly(sweeper: GraceSweeper, seconds: float = 0.05) -> None:
    sweeper.start()
    await asyncio.sleep(seconds)
    await sweeper.stop()


async def test_a_sweep_revokes_what_is_due() -> None:
    lifecycle = _Lifecycle([3])
    sweeper = GraceSweeper(lifecycle)

    assert await sweeper.sweep_once() == 3


async def test_the_loop_keeps_sweeping() -> None:
    lifecycle = _Lifecycle([1, 1, 1])
    sweeper = GraceSweeper(lifecycle, interval=BRIEF, startup_delay=NOTHING)

    await _run_briefly(sweeper)

    assert lifecycle.calls > 1


async def test_a_failed_sweep_does_not_stop_the_loop() -> None:
    """A database blip at three in the morning takes the sweep down for one
    interval, not the broker — and definitely not for good."""
    lifecycle = _Lifecycle([RuntimeError("connection reset"), 1, 1])
    sweeper = GraceSweeper(lifecycle, interval=BRIEF, startup_delay=NOTHING)

    await _run_briefly(sweeper)

    assert lifecycle.calls > 1


async def test_stopping_waits_for_the_task() -> None:
    """Awaited rather than fired and forgotten: a cancelled task still holds a
    database connection until it unwinds, and disposing the pool underneath it
    is how a clean shutdown produces an alarming traceback."""
    sweeper = GraceSweeper(_Lifecycle([0]), interval=BRIEF, startup_delay=NOTHING)
    sweeper.start()

    await sweeper.stop()

    assert sweeper._task is None


async def test_stopping_a_sweeper_that_never_started_is_harmless() -> None:
    """Shutdown runs the same teardown whether startup got that far or not."""
    await GraceSweeper(_Lifecycle([])).stop()


async def test_the_first_sweep_waits_for_startup() -> None:
    """A sweep racing the first request for a connection makes a slow startup
    look like a broken one, and nothing about a grace period is urgent to the
    second."""
    lifecycle = _Lifecycle([1])
    sweeper = GraceSweeper(lifecycle, interval=BRIEF, startup_delay=timedelta(seconds=5))

    await _run_briefly(sweeper, seconds=0.02)

    assert lifecycle.calls == 0


@pytest.mark.parametrize(
    ("name", "value"),
    [("interval", DEFAULT_INTERVAL), ("startup delay", STARTUP_DELAY)],
)
def test_the_defaults_are_deliberate(name: str, value: timedelta) -> None:
    """Hourly is far more often than daily deadlines need, and that is the
    point: it is chosen for the restart case, so a broker coming up after a long
    outage does not wait most of a day to catch up."""
    assert value > NOTHING
    assert timedelta(hours=24) >= DEFAULT_INTERVAL
