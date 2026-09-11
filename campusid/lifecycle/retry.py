"""Retrying a downstream write, and giving up visibly (FR-LC-09).

Five attempts with exponential backoff and jitter, then a dead letter. The
requirement names those numbers; what matters is what each of them is for.

**Backoff, because the failure is usually the far end being busy.** A directory
that refused a connection because it is restarting will accept one in four
seconds and not in forty milliseconds. Retrying immediately turns one outage
into a thundering herd against a server that is already struggling.

**Jitter, because every broker in the estate is retrying the same thing.** A
deprovisioning run that fans out to a hundred people all fail at the same moment
and, without jitter, all retry at the same moment — repeatedly, in lockstep, for
five rounds. Full jitter rather than a small fuzz: the sleep is uniform over the
whole window, which is what actually decorrelates callers.

**A dead letter, because the alternative to giving up is retrying forever.** An
account that could not be disabled is a security finding, and the way it becomes
one is by being written down somewhere a human looks. The item carries enough to
replay it later, because "we know it failed" and "we can do something about it"
are different states.

Only *transient* failures are retried. A directory refusing a write because the
entry does not exist will refuse it identically five times, and the retries buy
nothing but five multiples of the backoff before the same dead letter.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final, TypeVar

from campusid.logging import get_logger

log = get_logger(__name__)

MAX_ATTEMPTS: Final = 5
"""FR-LC-09. Five attempts over roughly thirty seconds of backoff, which rides
out a restart without holding a provisioning run open for minutes."""

BASE_DELAY: Final = 0.5
"""Seconds before the second attempt. Doubling from here."""

MAX_DELAY: Final = 8.0
"""The ceiling on one wait. Without it the fifth attempt would be eight seconds
after the fourth and sixteen after that, which is a scheduler's job rather than
a request's."""

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Attempt:
    """One try, recorded so a dead letter can say what actually happened."""

    number: int
    error: str


class RetriesExhausted(Exception):
    """Every attempt failed.

    Carries the attempts rather than only the last error: "refused, refused,
    refused, timed out, refused" and "timed out five times" are different
    incidents, and only the first suggests the write itself is wrong.
    """

    def __init__(self, attempts: list[Attempt]) -> None:
        self.attempts = attempts
        super().__init__(f"{len(attempts)} attempts failed: {attempts[-1].error}")


def full_jitter(delay: float, *, rng: Any = None) -> float:
    """AWS's "full jitter": uniform over `[0, delay]`.

    A small fuzz around the delay leaves callers almost as correlated as no
    jitter at all, which is the finding the original write-up is known for. The
    generator is injectable so a test can assert the *window* without asserting
    a particular random number.
    """
    source = rng or random
    return float(source.uniform(0, delay))


def backoff(attempt: int, *, base: float = BASE_DELAY, ceiling: float = MAX_DELAY) -> float:
    """How long to wait before `attempt`, before jitter.

    Attempt 1 waits nothing: the first try is not a retry, and a scheme that
    slept before it would add latency to every successful write in the system.
    """
    if attempt <= 1:
        return 0.0
    return float(min(base * float(2 ** (attempt - 2)), ceiling))


async def with_retries(
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int = MAX_ATTEMPTS,
    retry_on: type[Exception] | tuple[type[Exception], ...] = Exception,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    rng: Any = None,
    description: str = "",
) -> T:
    """Run `operation`, retrying transient failures with jittered backoff.

    `retry_on` narrows what counts as transient. Retrying everything means
    retrying a write the far end will refuse identically five times, which buys
    nothing but five multiples of the backoff before the same dead letter.
    """
    waiter = sleep or asyncio.sleep
    history: list[Attempt] = []

    for attempt in range(1, attempts + 1):
        delay = full_jitter(backoff(attempt), rng=rng)
        if delay:
            await waiter(delay)
        try:
            return await operation()
        except retry_on as exc:
            history.append(Attempt(number=attempt, error=str(exc)))
            log.warning(
                "provisioning.attempt_failed",
                attempt=attempt,
                of=attempts,
                operation=description,
                error=str(exc),
            )

    raise RetriesExhausted(history)
