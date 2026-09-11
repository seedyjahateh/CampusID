"""The dashboard's panels (FR-AUD-07).

Everything here is derived from the audit trail rather than from a separate
metrics store, and that is a deliberate limitation worth stating plainly. A
metrics pipeline would give cheaper reads and a longer history at lower
resolution; it would also be a second source of truth about what happened, which
is precisely what an identity broker should not have. When the dashboard and the
trail disagree, one of them is wrong, and the one an auditor believes should be
the one the console draws from.

The cost is that every panel is a `GROUP BY` over a window, so the windows are
bounded and the aggregation is pushed into Postgres rather than pulled into
Python. The arithmetic that shapes the results lives in `metrics.py`, which has
no idea a database exists.

**Latency is measured between the ends of a correlation chain.** A provisioning
request and the directory write it caused share a correlation id (FR-AUD-02), so
the span between the first and last event of that chain is the latency the
requirement asks about. That is an honest measure of the thing somebody waited
for, and it is available without instrumenting anything separately.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import Float, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.events import EventType, Outcome
from campusid.audit.metrics import (
    DEFAULT_PERCENTILES,
    Rate,
    Series,
    mix,
    percentiles,
    series,
    top,
    within,
)
from campusid.audit.models import AuditEventRecord

DEFAULT_WINDOW: Final = timedelta(days=7)
DEFAULT_STEP: Final = timedelta(hours=1)

MAX_WINDOW: Final = timedelta(days=90)
"""How far back a panel will look.

Bounded because every panel is an aggregate over the trail itself, and an
unbounded window is a request to read the whole table — which on the one table
nobody may delete from is a request that only gets slower.
"""

DEPROVISION_TARGET: Final = timedelta(seconds=60)
"""FR-LC-03's ordered sequence should complete inside a minute.

A target rather than a guarantee: the panel reports the breaches so a month with
three of them reads as a month with three of them, rather than as a failure.
"""

LOGIN_EVENTS: Final = (EventType.AUTH_SUCCESS.value, EventType.AUTH_FAILURE.value)

PROVISIONING_EVENTS: Final = (
    EventType.LIFECYCLE_JOINER.value,
    EventType.LIFECYCLE_MOVER.value,
    EventType.LIFECYCLE_LEAVER.value,
)


@dataclass(frozen=True, slots=True)
class Window:
    """The span a panel covers, and how finely."""

    since: datetime
    until: datetime
    step: timedelta = DEFAULT_STEP

    def clamped(self) -> Window:
        """The same window, no longer than the ceiling.

        Clamped rather than refused: an operator who asks for a year means "as
        much as you have", and an error page teaches them to stop asking.
        """
        if self.until - self.since <= MAX_WINDOW:
            return self
        return Window(since=self.until - MAX_WINDOW, until=self.until, step=self.step)


@dataclass(frozen=True, slots=True)
class Panels:
    """Everything the dashboard shows, in one read."""

    logins_by_idp: tuple[Series, ...] = ()
    logins_by_protocol: tuple[Series, ...] = ()
    factor_mix: dict[str, float] = field(default_factory=dict)
    top_relying_parties: tuple[tuple[str, int], ...] = ()
    provisioning_latency: dict[int, float] = field(default_factory=dict)
    # Factories rather than shared instances: `Rate` is frozen, so sharing one
    # would be harmless today and a bug the moment it is not.
    failed_auth: Rate = field(default_factory=lambda: Rate(failed=0, total=0))
    deprovisioning_sla: Rate = field(default_factory=lambda: Rate(failed=0, total=0))
    drift: int = 0


class DashboardStore:
    """Reads the trail and returns the panels."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def panels(self, window: Window, *, drift: int = 0) -> Panels:
        """Every panel for one window.

        Assembled in one call rather than as seven endpoints, because a dashboard
        drawn from seven separate reads shows seven slightly different moments —
        and the one thing worse than a stale number is a set of numbers that
        cannot all have been true at once.
        """
        bounded = window.clamped()
        return Panels(
            logins_by_idp=await self._logins(bounded, "idp"),
            logins_by_protocol=await self._logins(bounded, "protocol"),
            factor_mix=await self._factor_mix(bounded),
            top_relying_parties=await self._top_relying_parties(bounded),
            provisioning_latency=await self._latency(bounded, PROVISIONING_EVENTS),
            failed_auth=await self._failed_auth(bounded),
            deprovisioning_sla=await self._deprovisioning(bounded),
            drift=drift,
        )

    async def _logins(self, window: Window, key: str) -> tuple[Series, ...]:
        """Logins over time, split by whatever `detail` key names the dimension.

        Grouped in Postgres rather than counted in Python: the difference on a
        week of a busy campus is a few hundred rows against a few hundred
        thousand.
        """
        bucket = func.to_timestamp(
            func.floor(
                func.extract("epoch", AuditEventRecord.occurred_at) / window.step.total_seconds()
            )
            * window.step.total_seconds()
        )
        label = AuditEventRecord.detail[key].astext

        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(label, bucket, func.count())
                    .where(
                        AuditEventRecord.event_type == EventType.AUTH_SUCCESS.value,
                        AuditEventRecord.occurred_at >= window.since,
                        AuditEventRecord.occurred_at < window.until,
                        label.is_not(None),
                    )
                    .group_by(label, bucket)
                )
            )

        grouped: dict[str, dict[datetime, int]] = {}
        for name, at, count in rows:
            grouped.setdefault(str(name), {})[at] = int(count)

        return tuple(
            series(name, counted, since=window.since, until=window.until, step=window.step)
            for name, counted in sorted(grouped.items())
        )

    async def _factor_mix(self, window: Window) -> dict[str, float]:
        """Which second factors people actually used."""
        kind = AuditEventRecord.detail["kind"].astext
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(kind, func.count())
                    .where(
                        AuditEventRecord.event_type == EventType.MFA_STEP_UP.value,
                        AuditEventRecord.occurred_at >= window.since,
                        AuditEventRecord.occurred_at < window.until,
                        kind.is_not(None),
                    )
                    .group_by(kind)
                )
            )
        return mix(Counter({str(name): int(count) for name, count in rows}))

    async def _top_relying_parties(self, window: Window) -> tuple[tuple[str, int], ...]:
        """Who received the most assertions.

        Counted from attribute releases rather than from logins: one login can
        reach several services, and the question this panel answers is which
        services are carrying the load.
        """
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(AuditEventRecord.target, func.count())
                    .where(
                        AuditEventRecord.event_type == EventType.ATTRIBUTE_RELEASE.value,
                        AuditEventRecord.occurred_at >= window.since,
                        AuditEventRecord.occurred_at < window.until,
                        AuditEventRecord.target.is_not(None),
                    )
                    .group_by(AuditEventRecord.target)
                )
            )
        return top(Counter({str(name): int(count) for name, count in rows}))

    async def _latency(self, window: Window, kinds: tuple[str, ...]) -> dict[int, float]:
        """How long a provisioning chain took, end to end.

        The span between the first and last event sharing a correlation id, which
        is what somebody actually waited for. Chains of one event contribute
        zero, which is correct: nothing downstream happened, so nothing took time.
        """
        return percentiles(await self._chain_durations(window, kinds), DEFAULT_PERCENTILES)

    async def _chain_durations(self, window: Window, kinds: tuple[str, ...]) -> list[float]:
        span = cast(
            func.extract(
                "epoch",
                func.max(AuditEventRecord.occurred_at) - func.min(AuditEventRecord.occurred_at),
            ),
            Float,
        )
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(span)
                    .where(
                        AuditEventRecord.occurred_at >= window.since,
                        AuditEventRecord.occurred_at < window.until,
                        AuditEventRecord.correlation_id.in_(
                            select(AuditEventRecord.correlation_id).where(
                                AuditEventRecord.event_type.in_(kinds),
                                AuditEventRecord.occurred_at >= window.since,
                                AuditEventRecord.occurred_at < window.until,
                            )
                        ),
                    )
                    .group_by(AuditEventRecord.correlation_id)
                )
            )
        return [float(row[0] or 0.0) for row in rows]

    async def _failed_auth(self, window: Window) -> Rate:
        """The failure rate, with its denominator.

        Both numbers, because a rate without one invites "four per cent of logins
        failed" to be read the same way whether it was four in a hundred or one
        in twenty-five.
        """
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(AuditEventRecord.outcome, func.count())
                    .where(
                        AuditEventRecord.event_type.in_(LOGIN_EVENTS),
                        AuditEventRecord.occurred_at >= window.since,
                        AuditEventRecord.occurred_at < window.until,
                    )
                    .group_by(AuditEventRecord.outcome)
                )
            )
        counted = {str(outcome): int(count) for outcome, count in rows}
        failed = counted.get(Outcome.FAILURE.value, 0) + counted.get(Outcome.DENIED.value, 0)
        return Rate(failed=failed, total=sum(counted.values()))

    async def _deprovisioning(self, window: Window) -> Rate:
        """How often a leaver completed inside the target."""
        durations = await self._chain_durations(window, (EventType.LIFECYCLE_LEAVER.value,))
        return within(durations, DEPROVISION_TARGET)


def as_json(panels: Panels) -> dict[str, Any]:
    """The panels, in the shape the API returns.

    Rates are rendered with both numbers rather than as a percentage, for the
    reason the `Rate` type exists: a panel that shows only the ratio hides how
    much it is a ratio of.
    """
    return {
        "logins_by_idp": [_line(line) for line in panels.logins_by_idp],
        "logins_by_protocol": [_line(line) for line in panels.logins_by_protocol],
        "factor_mix": panels.factor_mix,
        "top_relying_parties": [
            {"target": name, "count": count} for name, count in panels.top_relying_parties
        ],
        "provisioning_latency_seconds": {
            f"p{p}": round(value, 3) for p, value in panels.provisioning_latency.items()
        },
        "failed_auth": _rate(panels.failed_auth),
        "deprovisioning_sla": {
            **_rate(panels.deprovisioning_sla),
            "target_seconds": int(DEPROVISION_TARGET.total_seconds()),
        },
        "drift": panels.drift,
    }


def _line(line: Series) -> dict[str, Any]:
    return {
        "label": line.label,
        "total": line.total,
        "points": [{"at": point.at.isoformat(), "count": point.count} for point in line.points],
    }


def _rate(rate: Rate) -> dict[str, Any]:
    return {"failed": rate.failed, "total": rate.total, "ratio": round(rate.ratio, 4)}
