"""The arithmetic behind the dashboard (FR-AUD-07).

A dashboard is where a subtly wrong number lives longest, because nobody checks a
chart that looks plausible. These test the cases somebody chose rather than
whatever happens to be in the database: the empty bucket, the even-length sample,
the tie, the quiet hour.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from campusid.audit.metrics import (
    DEFAULT_PERCENTILES,
    Rate,
    buckets,
    floor_to,
    mix,
    percentiles,
    series,
    top,
    within,
)

NOON = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


# --- bucketing --------------------------------------------------------------


def test_a_window_is_divided_into_buckets() -> None:
    assert len(buckets(NOON, NOON + timedelta(hours=24), HOUR)) == 24


def test_the_window_is_half_open() -> None:
    """`since` counts and `until` does not, so a day is twenty-four hourly
    buckets rather than twenty-five."""
    made = buckets(NOON, NOON + timedelta(hours=3), HOUR)

    assert made[0] == NOON
    assert made[-1] == NOON + timedelta(hours=2)


def test_a_window_of_nothing_has_no_buckets() -> None:
    assert buckets(NOON, NOON, HOUR) == ()


def test_a_bucket_has_to_have_a_width() -> None:
    """Otherwise the loop that fills the window never ends."""
    with pytest.raises(ValueError, match="width"):
        buckets(NOON, NOON + HOUR, timedelta(0))


def test_a_moment_falls_into_its_bucket() -> None:
    assert floor_to(NOON + timedelta(minutes=37), HOUR) == NOON


def test_buckets_are_aligned_to_the_epoch_not_to_the_window() -> None:
    """So two panels over different windows put the same event in buckets that
    line up. Aligning to each window's start would mean comparing two charts is
    comparing two different grids."""
    odd = NOON + timedelta(minutes=17)

    assert floor_to(odd, HOUR) == floor_to(NOON + timedelta(minutes=50), HOUR)


# --- series -----------------------------------------------------------------


def test_empty_buckets_are_filled_in() -> None:
    """The single most misleading thing a chart of logins over time can do is
    omit the hours with none, which draws a line straight across an outage. The
    gap is the signal."""
    line = series(
        "campus",
        {NOON: 5, NOON + timedelta(hours=3): 2},
        since=NOON,
        until=NOON + timedelta(hours=4),
        step=HOUR,
    )

    assert [point.count for point in line.points] == [5, 0, 0, 2]


def test_a_series_keeps_its_label() -> None:
    """Two lines on one chart are only readable if each says which IdP it is."""
    assert series("campus", {}, since=NOON, until=NOON + HOUR, step=HOUR).label == "campus"


def test_a_series_totals_itself() -> None:
    line = series(
        "campus", {NOON: 3, NOON + HOUR: 4}, since=NOON, until=NOON + timedelta(hours=2), step=HOUR
    )

    assert line.total == 7


def test_a_series_with_nothing_in_it_is_still_a_line() -> None:
    """A quiet day draws a flat line at zero rather than an empty chart, which
    would look the same as a broken panel."""
    line = series("campus", {}, since=NOON, until=NOON + timedelta(hours=3), step=HOUR)

    assert len(line.points) == 3
    assert line.total == 0


def test_counts_outside_the_window_are_not_drawn() -> None:
    """A GROUP BY that overran its range would otherwise smuggle a bucket onto
    the end of the chart."""
    line = series(
        "campus",
        {NOON: 1, NOON + timedelta(days=9): 99},
        since=NOON,
        until=NOON + timedelta(hours=2),
        step=HOUR,
    )

    assert line.total == 1


# --- percentiles ------------------------------------------------------------


def test_percentiles_are_values_that_occurred() -> None:
    """Nearest-rank rather than interpolated. Latency is not a smooth
    distribution, and a p99 nothing ever measured is a number nobody can go and
    look at."""
    sample = [float(n) for n in range(1, 101)]

    result = percentiles(sample)

    assert result[50] in sample
    assert result[95] in sample
    assert result[99] in sample


def test_the_percentiles_are_the_requirements_three() -> None:
    assert DEFAULT_PERCENTILES == (50, 95, 99)


def test_an_even_sample_does_not_average_its_middle() -> None:
    """The case that separates nearest-rank from interpolation, and the reason
    the choice is worth making explicitly."""
    assert percentiles([10.0, 20.0], which=(50,))[50] == 10.0


@pytest.mark.parametrize(("p", "expected"), [(50, 5.0), (95, 10.0), (99, 10.0), (100, 10.0)])
def test_nearest_rank_on_a_small_sample(p: int, expected: float) -> None:
    sample = [float(n) for n in range(1, 11)]

    assert percentiles(sample, which=(p,))[p] == expected


def test_a_percentile_of_zero_is_the_smallest_value() -> None:
    """Rank zero is clamped into the sample rather than reaching past its
    start."""
    assert percentiles([3.0, 1.0, 2.0], which=(0,))[0] == 1.0


def test_an_empty_sample_reads_zero() -> None:
    """A panel for a quiet week should read zero, not fail to render."""
    assert percentiles([]) == {50: 0.0, 95: 0.0, 99: 0.0}


def test_a_single_sample_is_every_percentile() -> None:
    assert set(percentiles([7.0]).values()) == {7.0}


def test_the_sample_is_not_assumed_sorted() -> None:
    """It arrives from a database in whatever order the planner chose."""
    assert percentiles([9.0, 1.0, 5.0], which=(50,))[50] == 5.0


# --- top n ------------------------------------------------------------------


def test_the_most_frequent_come_first() -> None:
    counted = Counter({"portal": 10, "analytics": 3, "library": 7})

    assert [name for name, _ in top(counted)] == ["portal", "library", "analytics"]


def test_ties_are_broken_by_name() -> None:
    """A top ten that reshuffles equal entries between two loads of the same page
    reads as activity that did not happen."""
    counted = Counter({"beta": 5, "alpha": 5, "gamma": 5})

    assert [name for name, _ in top(counted)] == ["alpha", "beta", "gamma"]


def test_the_list_is_capped() -> None:
    counted = Counter({f"sp-{n}": n for n in range(20)})

    assert len(top(counted, n=3)) == 3


def test_nothing_tops_nothing() -> None:
    assert top(Counter()) == ()


# --- mix --------------------------------------------------------------------


def test_a_mix_reports_shares() -> None:
    """The question a factor-mix panel answers is what people are actually using,
    and raw counts make a campus of ten thousand look different from one of a
    hundred doing the same thing."""
    assert mix(Counter({"otp": 3, "hwk": 1})) == {"hwk": 0.25, "otp": 0.75}


def test_the_shares_add_up() -> None:
    assert sum(mix(Counter({"otp": 7, "hwk": 2, "push": 1})).values()) == pytest.approx(1.0)


def test_an_empty_mix_is_empty_rather_than_a_division_by_zero() -> None:
    assert mix(Counter()) == {}


def test_a_mix_is_ordered() -> None:
    """So the legend does not reorder itself between two loads."""
    result = mix(Counter({"push": 1, "otp": 1, "hwk": 1}))

    assert list(result) == sorted(result)


# --- rates ------------------------------------------------------------------


def test_a_rate_carries_its_denominator() -> None:
    """ "Four per cent of logins failed" means one thing out of a hundred attempts
    and another out of twenty-five."""
    rate = Rate(failed=1, total=25)

    assert rate.ratio == 0.04
    assert rate.total == 25


def test_a_quiet_hour_is_not_a_total_failure() -> None:
    """Nor an error. It is an hour in which nothing failed because nothing was
    tried."""
    assert Rate(failed=0, total=0).ratio == 0.0


def test_everything_failing_reads_as_everything() -> None:
    assert Rate(failed=4, total=4).ratio == 1.0


# --- service levels ---------------------------------------------------------


def test_an_sla_counts_the_breaches() -> None:
    """The breaches are the numerator so the panel reads the same way as the
    failure-rate one beside it, rather than one counting up and the other down."""
    result = within([1.0, 2.0, 90.0, 120.0], target=timedelta(seconds=60))

    assert result.failed == 2
    assert result.total == 4


def test_a_duration_exactly_at_the_target_is_met() -> None:
    """A target of sixty seconds is met at sixty seconds. The other reading turns
    every round number into a breach."""
    assert within([60.0], target=timedelta(seconds=60)).failed == 0


def test_an_sla_over_nothing_is_not_a_breach() -> None:
    assert within([], target=timedelta(seconds=60)).ratio == 0.0
