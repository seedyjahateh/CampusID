"""How the dashboard's panels reach a browser (FR-AUD-07).

The shaping, without a database. What a panel *looks like* is where a chart
quietly becomes misleading: a rate without its denominator, a service level
without its target, a panel that is absent rather than empty.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from campusid.audit.dashboard import (
    DEPROVISION_TARGET,
    MAX_WINDOW,
    Panels,
    Window,
    as_json,
)
from campusid.audit.metrics import Point, Rate, Series

NOON = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


def _line(label: str = "campus") -> Series:
    return Series(
        label=label,
        points=(Point(at=NOON, count=3), Point(at=NOON + HOUR, count=0)),
    )


# --- the window -------------------------------------------------------------


def test_a_reasonable_window_is_left_alone() -> None:
    window = Window(since=NOON - timedelta(days=7), until=NOON, step=HOUR)

    assert window.clamped() == window


def test_an_absurd_window_is_clamped_rather_than_refused() -> None:
    """An operator who asks for a decade means "as much as you have", and an
    error page teaches them to stop asking."""
    clamped = Window(since=NOON - timedelta(days=3650), until=NOON, step=HOUR).clamped()

    assert clamped.until - clamped.since == MAX_WINDOW
    assert clamped.until == NOON


def test_clamping_keeps_the_end_rather_than_the_start() -> None:
    """The recent end is the one somebody is looking at. Keeping the start would
    answer a question about a decade ago with a chart of a decade ago."""
    clamped = Window(since=NOON - timedelta(days=3650), until=NOON, step=HOUR).clamped()

    assert clamped.until == NOON


def test_clamping_keeps_the_resolution_asked_for() -> None:
    clamped = Window(since=NOON - timedelta(days=3650), until=NOON, step=timedelta(days=1))

    assert clamped.clamped().step == timedelta(days=1)


def test_a_window_exactly_at_the_ceiling_is_not_clamped() -> None:
    window = Window(since=NOON - MAX_WINDOW, until=NOON, step=HOUR)

    assert window.clamped() == window


# --- rendering --------------------------------------------------------------


def test_every_panel_is_present_even_when_empty() -> None:
    """An absent panel and an empty one look the same in a browser, and only one
    of them is a broken console."""
    body = as_json(Panels())

    assert set(body) == {
        "logins_by_idp",
        "logins_by_protocol",
        "factor_mix",
        "top_relying_parties",
        "provisioning_latency_seconds",
        "failed_auth",
        "deprovisioning_sla",
        "drift",
    }


def test_a_line_carries_its_label_total_and_points() -> None:
    """Two lines on one chart are only readable if each says which IdP it is,
    and the total saves the browser summing the points to label the legend."""
    body = as_json(Panels(logins_by_idp=(_line(),)))

    rendered = body["logins_by_idp"][0]
    assert rendered["label"] == "campus"
    assert rendered["total"] == 3
    assert len(rendered["points"]) == 2


def test_a_point_renders_its_time_as_text() -> None:
    body = as_json(Panels(logins_by_idp=(_line(),)))

    assert body["logins_by_idp"][0]["points"][0]["at"].startswith("2026-09-11T12:00")


def test_the_quiet_buckets_survive_rendering() -> None:
    """They are the whole reason the series fills them in. A renderer that
    dropped the zeros would undo that one step from the browser."""
    body = as_json(Panels(logins_by_idp=(_line(),)))

    assert [point["count"] for point in body["logins_by_idp"][0]["points"]] == [3, 0]


def test_a_rate_shows_both_numbers() -> None:
    """A panel that shows only the ratio hides how much it is a ratio of."""
    body = as_json(Panels(failed_auth=Rate(failed=1, total=25)))

    assert body["failed_auth"] == {"failed": 1, "total": 25, "ratio": 0.04}


def test_a_ratio_is_rounded_rather_than_carried_to_seventeen_places() -> None:
    """Because a browser rendering 0.3333333333333333 as a percentage produces a
    number nobody typed and nobody wants."""
    body = as_json(Panels(failed_auth=Rate(failed=1, total=3)))

    assert body["failed_auth"]["ratio"] == 0.3333


def test_the_service_level_carries_its_target() -> None:
    """A breach count with no target is a number nobody can interpret."""
    body = as_json(Panels(deprovisioning_sla=Rate(failed=2, total=10)))

    assert body["deprovisioning_sla"]["failed"] == 2
    assert body["deprovisioning_sla"]["target_seconds"] == int(DEPROVISION_TARGET.total_seconds())


def test_latency_is_labelled_by_percentile() -> None:
    """`p95` rather than `95`, so a chart legend reads as a percentile rather
    than as a value."""
    body = as_json(Panels(provisioning_latency={50: 1.0, 95: 4.5, 99: 12.25}))

    assert body["provisioning_latency_seconds"] == {"p50": 1.0, "p95": 4.5, "p99": 12.25}


def test_latency_is_rounded_to_milliseconds() -> None:
    """Three decimal places of a second. More is measurement noise presented as
    precision."""
    body = as_json(Panels(provisioning_latency={50: 1.23456789}))

    assert body["provisioning_latency_seconds"]["p50"] == 1.235


def test_relying_parties_are_named_rather_than_positional() -> None:
    """A list of pairs would make the browser remember which side is which."""
    body = as_json(Panels(top_relying_parties=(("portal", 7),)))

    assert body["top_relying_parties"] == [{"target": "portal", "count": 7}]


@pytest.mark.parametrize("drift", [0, 5])
def test_the_drift_count_is_reported_as_given(drift: int) -> None:
    """Zero is a number worth showing. An empty panel would look the same as a
    reconciliation that never ran."""
    assert as_json(Panels(drift=drift))["drift"] == drift
