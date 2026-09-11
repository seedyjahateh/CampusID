"""Retrying a downstream write (FR-LC-09).

The requirement names five attempts, exponential backoff and jitter. The test
the requirement asks for is a target that fails four times and then succeeds,
which is the shape of a directory restarting: the write is fine, the far end was
not there for a few seconds.

Time is injected rather than slept through. A test that really waited out the
backoff would take half a minute to prove arithmetic.
"""

from __future__ import annotations

import pytest

from campusid.lifecycle.retry import (
    BASE_DELAY,
    MAX_ATTEMPTS,
    MAX_DELAY,
    RetriesExhausted,
    backoff,
    full_jitter,
    with_retries,
)


class _Clock:
    """Records what it was asked to wait for, and waits for none of it."""

    def __init__(self) -> None:
        self.slept: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.slept.append(seconds)


class _NoJitter:
    """A generator that always returns the top of the range.

    So a test can assert the backoff schedule without asserting a particular
    random number, and still exercise the jitter call path.
    """

    @staticmethod
    def uniform(low: float, high: float) -> float:
        return high


class _Flaky:
    """Fails a fixed number of times, then succeeds."""

    def __init__(self, failures: int, error: type[Exception] = ConnectionError) -> None:
        self._remaining = failures
        self._error = error
        self.calls = 0

    async def __call__(self) -> str:
        self.calls += 1
        if self._remaining:
            self._remaining -= 1
            raise self._error(f"attempt {self.calls} refused")
        return "done"


# --- the case the requirement names -----------------------------------------


async def test_a_target_that_fails_four_times_then_succeeds() -> None:
    """The shape of a directory restarting: the write is fine, the far end was
    not there for a few seconds."""
    operation = _Flaky(failures=4)
    clock = _Clock()

    result = await with_retries(operation, sleep=clock, rng=_NoJitter)

    assert result == "done"
    assert operation.calls == 5


async def test_the_fifth_failure_gives_up() -> None:
    """Five attempts, not six. The alternative to giving up is retrying
    forever."""
    operation = _Flaky(failures=MAX_ATTEMPTS)
    clock = _Clock()

    with pytest.raises(RetriesExhausted):
        await with_retries(operation, sleep=clock, rng=_NoJitter)

    assert operation.calls == MAX_ATTEMPTS


async def test_a_first_attempt_that_works_waits_for_nothing() -> None:
    """A scheme that slept before the first try would add latency to every
    successful write in the system."""
    clock = _Clock()

    await with_retries(_Flaky(failures=0), sleep=clock, rng=_NoJitter)

    assert clock.slept == []


async def test_every_failure_is_kept_not_just_the_last() -> None:
    """ "Refused four times then timed out" and "timed out five times" are
    different incidents, and only the first suggests the write itself is
    wrong."""
    with pytest.raises(RetriesExhausted) as raised:
        await with_retries(_Flaky(failures=MAX_ATTEMPTS), sleep=_Clock(), rng=_NoJitter)

    assert [attempt.number for attempt in raised.value.attempts] == [1, 2, 3, 4, 5]
    assert "attempt 3" in raised.value.attempts[2].error


# --- backoff ----------------------------------------------------------------


def test_the_first_attempt_has_no_delay() -> None:
    assert backoff(1) == 0.0


def test_the_delay_doubles() -> None:
    """A directory that refused a connection because it is restarting will
    accept one in four seconds and not in forty milliseconds."""
    assert backoff(2) == BASE_DELAY
    assert backoff(3) == BASE_DELAY * 2
    assert backoff(4) == BASE_DELAY * 4


def test_the_delay_is_capped() -> None:
    """Without a ceiling the later attempts belong to a scheduler rather than to
    a request."""
    assert backoff(20) == MAX_DELAY


async def test_the_waits_grow_across_a_run() -> None:
    clock = _Clock()

    with pytest.raises(RetriesExhausted):
        await with_retries(_Flaky(failures=MAX_ATTEMPTS), sleep=clock, rng=_NoJitter)

    assert clock.slept == sorted(clock.slept)
    assert clock.slept[0] < clock.slept[-1]


# --- jitter -----------------------------------------------------------------


def test_jitter_spans_the_whole_window() -> None:
    """Full jitter rather than a small fuzz. A small fuzz leaves callers almost
    as correlated as no jitter at all, which is the finding the original
    write-up is known for."""

    class _Bottom:
        @staticmethod
        def uniform(low: float, high: float) -> float:
            assert (low, high) == (0, 4.0)
            return low

    assert full_jitter(4.0, rng=_Bottom) == 0.0
    assert full_jitter(4.0, rng=_NoJitter) == 4.0


def test_jitter_of_nothing_is_nothing() -> None:
    assert full_jitter(0.0, rng=_NoJitter) == 0.0


async def test_a_run_of_callers_does_not_retry_in_lockstep() -> None:
    """A deprovisioning that fans out to a hundred people fails at the same
    moment and, without jitter, retries at the same moment — repeatedly, for
    five rounds, against a server that is already struggling."""
    waits: set[float] = set()
    for _ in range(20):
        clock = _Clock()
        with pytest.raises(RetriesExhausted):
            await with_retries(_Flaky(failures=MAX_ATTEMPTS), sleep=clock)
        waits.add(clock.slept[-1])

    assert len(waits) > 1


# --- what is worth retrying -------------------------------------------------


async def test_only_transient_failures_are_retried() -> None:
    """A directory refusing a write because the entry does not exist will refuse
    it identically five times, and the retries buy nothing but five multiples of
    the backoff before the same dead letter."""
    operation = _Flaky(failures=MAX_ATTEMPTS, error=ValueError)

    with pytest.raises(ValueError):
        await with_retries(operation, retry_on=ConnectionError, sleep=_Clock(), rng=_NoJitter)

    assert operation.calls == 1


async def test_a_transient_failure_is_still_retried_when_narrowed() -> None:
    operation = _Flaky(failures=2, error=ConnectionError)

    result = await with_retries(operation, retry_on=ConnectionError, sleep=_Clock(), rng=_NoJitter)

    assert result == "done"
