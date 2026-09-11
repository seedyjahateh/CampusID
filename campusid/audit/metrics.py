"""Turning audit rows into the numbers a dashboard shows (FR-AUD-07).

Every function here is pure: rows in, panel out. That is not tidiness — a
dashboard is the place where a subtly wrong number lives longest, because nobody
checks a chart that looks plausible. Keeping the arithmetic away from the SQL
means it can be tested against cases somebody chose rather than against whatever
happens to be in the database.

**Empty buckets are filled in.** A series that omits the hours with no logins
draws a line straight across an outage, which is the single most misleading thing
a chart of "logins over time" can do — the gap *is* the signal. Every bucket in
the window appears, with a zero when nothing happened.

**Percentiles use nearest-rank.** `ceil(p/100 x n)`, so p50 of an even-length
sample is a value that actually occurred rather than the average of two that did.
Interpolation is defensible for a smooth distribution and latency is not one: the
interesting values are the tail, and a p99 that nothing ever measured is a number
nobody can go and look at.

**Rates report their denominator.** "Four per cent of logins failed" means one
thing out of a hundred attempts and another out of twenty-five, and a panel that
shows only the percentage invites the second to be read as the first.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

DEFAULT_PERCENTILES: Final = (50, 95, 99)
"""p50, p95, p99 — the requirement's three.

p99 rather than a maximum, because a maximum is one sample and therefore one
network hiccup away from meaning nothing.
"""


@dataclass(frozen=True, slots=True)
class Point:
    """One bucket of a time series."""

    at: datetime
    count: int


@dataclass(frozen=True, slots=True)
class Series:
    """A labelled line on a chart."""

    label: str
    points: tuple[Point, ...]

    @property
    def total(self) -> int:
        return sum(point.count for point in self.points)


@dataclass(frozen=True, slots=True)
class Rate:
    """A proportion, with the numbers it came from.

    Both, always. A panel showing only the percentage invites "four per cent of
    logins failed" to be read the same way whether it was four attempts in a
    hundred or one in twenty-five.
    """

    failed: int
    total: int

    @property
    def ratio(self) -> float:
        """Zero when nothing happened, rather than undefined.

        A quiet hour is not a hundred per cent failure and not an error; it is an
        hour in which nothing failed because nothing was tried.
        """
        return (self.failed / self.total) if self.total else 0.0


def buckets(since: datetime, until: datetime, step: timedelta) -> tuple[datetime, ...]:
    """Every bucket start in a window, so the gaps can be filled.

    The window is half-open — `since` counts and `until` does not — matching every
    other range in this project, so a day is twenty-four hourly buckets rather
    than twenty-five.
    """
    if step <= timedelta(0):
        raise ValueError("a bucket has to have a width")

    out: list[datetime] = []
    moment = since
    while moment < until:
        out.append(moment)
        moment += step
    return tuple(out)


def series(
    label: str,
    counted: dict[datetime, int],
    *,
    since: datetime,
    until: datetime,
    step: timedelta,
) -> Series:
    """One line, with every bucket present.

    `counted` holds only the buckets that had something in them, which is what a
    `GROUP BY` returns. The zeros are added here, because a chart that omits them
    draws a line straight across an outage — and the gap is the signal.
    """
    return Series(
        label=label,
        points=tuple(Point(at=at, count=counted.get(at, 0)) for at in buckets(since, until, step)),
    )


def floor_to(moment: datetime, step: timedelta) -> datetime:
    """The start of the bucket a moment falls in.

    Computed from the epoch rather than from the window's start, so two panels
    over different windows put the same event in buckets that line up — otherwise
    comparing them means comparing two different grids.
    """
    seconds = int(step.total_seconds())
    stamp = int(moment.timestamp())
    return datetime.fromtimestamp(stamp - (stamp % seconds), tz=moment.tzinfo)


def percentiles(
    values: list[float], which: tuple[int, ...] = DEFAULT_PERCENTILES
) -> dict[int, float]:
    """Nearest-rank percentiles of a sample.

    `ceil(p/100 x n)`, clamped into the sample, so every result is a value that
    actually occurred. Interpolation would be defensible for a smooth
    distribution; latency is not one, and a p99 nothing ever measured is a number
    nobody can go and look at.

    An empty sample gives zeros rather than an error. A panel for a quiet week
    should read zero, not fail to render.
    """
    if not values:
        return dict.fromkeys(which, 0.0)

    ordered = sorted(values)
    out: dict[int, float] = {}
    for p in which:
        rank = math.ceil((p / 100) * len(ordered))
        # Clamped at both ends: rank 0 happens when p is 0, and rank n+1 cannot
        # happen with ceil but costs nothing to rule out.
        index = min(max(rank, 1), len(ordered)) - 1
        out[p] = ordered[index]
    return out


def top(counted: Counter[str], n: int = 10) -> tuple[tuple[str, int], ...]:
    """The n most frequent, ties broken by name.

    Deterministic, because a "top ten" that reshuffles equal entries between two
    loads of the same page reads as activity that did not happen.
    """
    return tuple(sorted(counted.items(), key=lambda item: (-item[1], item[0]))[:n])


def mix(counted: Counter[str]) -> dict[str, float]:
    """Each category's share of the whole.

    Shares rather than counts, because the question a factor-mix panel answers is
    "what are people actually using", and raw counts make a campus of ten
    thousand look different from one of a hundred doing the same thing.
    """
    total = sum(counted.values())
    if not total:
        return {}
    return {name: count / total for name, count in sorted(counted.items())}


def within(durations: list[float], target: timedelta) -> Rate:
    """How many durations met a target — an SLA panel, as a rate.

    Expressed as a rate rather than a pass or fail, because an SLA is a statement
    about a population and a single breach is not a failed month. The breaches are
    the numerator so the panel reads the same way as the failure-rate one beside
    it, rather than one counting up and the other down.
    """
    seconds = target.total_seconds()
    missed = sum(1 for duration in durations if duration > seconds)
    return Rate(failed=missed, total=len(durations))
