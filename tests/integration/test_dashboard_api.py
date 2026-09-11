"""Every dashboard panel, against live Postgres (FR-AUD-07).

The arithmetic is tested without a database in `test_dashboard_metrics.py`. What
is here is that each panel's query finds the events it is supposed to find and
ignores the ones it is not — which is the half a pure test cannot reach, and the
half where a panel quietly starts counting the wrong thing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.audit.dashboard import (
    DEPROVISION_TARGET,
    MAX_WINDOW,
    DashboardStore,
    Window,
    as_json,
)
from campusid.audit.events import EventType, Outcome
from campusid.audit.log import AuditLog, set_correlation_id
from campusid.audit.models import AuditEventRecord, AuditRetentionAnchor
from campusid.config import get_settings
from campusid.db import create_owner_engine, create_session_factory

pytestmark = pytest.mark.integration

NOON = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

CAMPUS = "https://idp.campus.test/saml"
PARTNER = "https://idp.partner.test/saml"
PORTAL = "https://portal.campus.test/sp"
ANALYTICS = "https://analytics.campus.test/sp"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_owner_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)
    await _clear(factory)
    yield factory
    await _clear(factory)


async def _clear(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session, session.begin():
        await session.execute(delete(AuditRetentionAnchor))
        await session.execute(delete(AuditEventRecord))


@pytest.fixture
def audit(sessions: async_sessionmaker[AsyncSession]) -> AuditLog:
    return AuditLog(sessions)


@pytest.fixture
def store(sessions: async_sessionmaker[AsyncSession]) -> DashboardStore:
    return DashboardStore(sessions)


def _window(hours: int = 24) -> Window:
    return Window(since=NOON, until=NOON + timedelta(hours=hours), step=HOUR)


async def _login(
    audit: AuditLog, *, idp: str, protocol: str = "saml", at: datetime, ok: bool = True
) -> None:
    await audit.record(
        EventType.AUTH_SUCCESS if ok else EventType.AUTH_FAILURE,
        Outcome.SUCCESS if ok else Outcome.FAILURE,
        subject="somebody",
        detail={"idp": idp, "protocol": protocol},
        now=at,
    )


# --- logins over time -------------------------------------------------------


async def test_logins_are_split_by_idp(store: DashboardStore, audit: AuditLog) -> None:
    await _login(audit, idp=CAMPUS, at=NOON)
    await _login(audit, idp=CAMPUS, at=NOON + timedelta(minutes=20))
    await _login(audit, idp=PARTNER, at=NOON + timedelta(hours=2))

    panels = await store.panels(_window())

    lines = {line.label: line.total for line in panels.logins_by_idp}
    assert lines == {CAMPUS: 2, PARTNER: 1}


async def test_logins_are_also_split_by_protocol(store: DashboardStore, audit: AuditLog) -> None:
    await _login(audit, idp=CAMPUS, protocol="saml", at=NOON)
    await _login(audit, idp=CAMPUS, protocol="oidc", at=NOON + HOUR)

    panels = await store.panels(_window())

    assert {line.label for line in panels.logins_by_protocol} == {"saml", "oidc"}


async def test_the_quiet_hours_are_drawn(store: DashboardStore, audit: AuditLog) -> None:
    """The gap is the signal. A chart that omits the hours with no logins draws
    a line straight across an outage."""
    await _login(audit, idp=CAMPUS, at=NOON)
    await _login(audit, idp=CAMPUS, at=NOON + timedelta(hours=3))

    panels = await store.panels(_window(hours=4))

    counts = [point.count for point in panels.logins_by_idp[0].points]
    assert counts == [1, 0, 0, 1]


async def test_failures_are_not_drawn_as_logins(store: DashboardStore, audit: AuditLog) -> None:
    """A chart of "logins over time" that counted the failures would make an
    outage look like a busy afternoon."""
    await _login(audit, idp=CAMPUS, at=NOON, ok=False)

    panels = await store.panels(_window())

    assert panels.logins_by_idp == ()


async def test_events_outside_the_window_are_not_counted(
    store: DashboardStore, audit: AuditLog
) -> None:
    await _login(audit, idp=CAMPUS, at=NOON - DAY)
    await _login(audit, idp=CAMPUS, at=NOON + timedelta(hours=2))

    panels = await store.panels(_window())

    assert panels.logins_by_idp[0].total == 1


# --- the factor mix ---------------------------------------------------------


async def test_the_factor_mix_reports_shares(store: DashboardStore, audit: AuditLog) -> None:
    for kind, count in (("totp", 3), ("webauthn", 1)):
        for _ in range(count):
            await audit.record(
                EventType.MFA_STEP_UP,
                Outcome.SUCCESS,
                subject="somebody",
                detail={"kind": kind},
                now=NOON,
            )

    panels = await store.panels(_window())

    assert panels.factor_mix == {"totp": 0.75, "webauthn": 0.25}


async def test_a_campus_using_no_second_factor_has_no_mix(
    store: DashboardStore, audit: AuditLog
) -> None:
    await _login(audit, idp=CAMPUS, at=NOON)

    assert (await store.panels(_window())).factor_mix == {}


# --- relying parties --------------------------------------------------------


async def test_the_busiest_relying_parties_come_first(
    store: DashboardStore, audit: AuditLog
) -> None:
    """Counted from attribute releases rather than logins: one login can reach
    several services, and the question is which are carrying the load."""
    for _ in range(3):
        await audit.record(EventType.ATTRIBUTE_RELEASE, Outcome.SUCCESS, target=PORTAL, now=NOON)
    await audit.record(EventType.ATTRIBUTE_RELEASE, Outcome.SUCCESS, target=ANALYTICS, now=NOON)

    panels = await store.panels(_window())

    assert panels.top_relying_parties == ((PORTAL, 3), (ANALYTICS, 1))


# --- failure rate -----------------------------------------------------------


async def test_the_failure_rate_carries_its_denominator(
    store: DashboardStore, audit: AuditLog
) -> None:
    await _login(audit, idp=CAMPUS, at=NOON)
    await _login(audit, idp=CAMPUS, at=NOON + HOUR)
    await _login(audit, idp=CAMPUS, at=NOON + timedelta(hours=2), ok=False)

    rate = (await store.panels(_window())).failed_auth

    assert rate.failed == 1
    assert rate.total == 3


async def test_a_quiet_window_is_not_a_total_failure(store: DashboardStore) -> None:
    assert (await store.panels(_window())).failed_auth.ratio == 0.0


# --- latency and the service level ------------------------------------------


async def test_provisioning_latency_spans_a_correlation_chain(
    store: DashboardStore, audit: AuditLog
) -> None:
    """A provisioning request and the directory write it caused share a
    correlation id, so the span between the ends of that chain is the latency
    somebody actually waited for."""
    set_correlation_id("provision-one")
    await audit.record(EventType.LIFECYCLE_JOINER, Outcome.SUCCESS, subject="new", now=NOON)
    await audit.record(
        EventType.ENTITLEMENT_GRANTED,
        Outcome.SUCCESS,
        subject="new",
        now=NOON + timedelta(seconds=4),
    )

    latency = (await store.panels(_window())).provisioning_latency

    assert latency[50] == pytest.approx(4.0)


async def test_a_quiet_window_has_no_latency_rather_than_an_error(
    store: DashboardStore,
) -> None:
    assert (await store.panels(_window())).provisioning_latency == {50: 0.0, 95: 0.0, 99: 0.0}


async def test_a_slow_deprovisioning_is_a_breach(store: DashboardStore, audit: AuditLog) -> None:
    set_correlation_id("leaver-slow")
    await audit.record(EventType.LIFECYCLE_LEAVER, Outcome.SUCCESS, subject="gone", now=NOON)
    await audit.record(
        EventType.DEPROVISION_STEP,
        Outcome.SUCCESS,
        subject="gone",
        now=NOON + DEPROVISION_TARGET + timedelta(seconds=5),
    )

    sla = (await store.panels(_window())).deprovisioning_sla

    assert sla.failed == 1
    assert sla.total == 1


async def test_a_prompt_deprovisioning_is_not(store: DashboardStore, audit: AuditLog) -> None:
    set_correlation_id("leaver-fast")
    await audit.record(EventType.LIFECYCLE_LEAVER, Outcome.SUCCESS, subject="gone", now=NOON)
    await audit.record(
        EventType.DEPROVISION_STEP,
        Outcome.SUCCESS,
        subject="gone",
        now=NOON + timedelta(seconds=2),
    )

    sla = (await store.panels(_window())).deprovisioning_sla

    assert sla.failed == 0
    assert sla.total == 1


# --- the window -------------------------------------------------------------


async def test_an_absurd_window_is_clamped_rather_than_refused(
    store: DashboardStore, audit: AuditLog
) -> None:
    """An operator who asks for a decade means "as much as you have", and an
    error page teaches them to stop asking."""
    wide = Window(since=NOON - timedelta(days=3650), until=NOON + HOUR, step=DAY)

    clamped = wide.clamped()

    assert clamped.until - clamped.since == MAX_WINDOW
    assert await store.panels(wide) is not None


# --- rendering --------------------------------------------------------------


async def test_the_panels_render_as_json(store: DashboardStore, audit: AuditLog) -> None:
    await _login(audit, idp=CAMPUS, at=NOON)

    body = as_json(await store.panels(_window(), drift=3))

    assert body["logins_by_idp"][0]["label"] == CAMPUS
    assert body["drift"] == 3
    assert "p95" in body["provisioning_latency_seconds"]


async def test_a_rendered_rate_shows_both_numbers(store: DashboardStore, audit: AuditLog) -> None:
    """A panel that shows only the ratio hides how much it is a ratio of."""
    await _login(audit, idp=CAMPUS, at=NOON, ok=False)

    body = as_json(await store.panels(_window()))

    assert body["failed_auth"] == {"failed": 1, "total": 1, "ratio": 1.0}


async def test_the_service_level_renders_its_target(
    store: DashboardStore,
) -> None:
    """A breach count with no target is a number nobody can interpret."""
    body = as_json(await store.panels(_window()))

    assert body["deprovisioning_sla"]["target_seconds"] == int(DEPROVISION_TARGET.total_seconds())
