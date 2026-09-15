"""Shared machinery for the latency runs.

Three things every run needs and one of them is a judgement rather than a
utility: **how to report a percentile from a sample small enough to count.**

With 200 samples, p99 is the second-worst observation. That is not a p99 in any
statistical sense — it is one number, and if the run had hit a garbage collection
pause at that moment it would be a different number. Reporting it as `p99: 4.2s`
invites a reader to treat it as a property of the system. So the report prints
the sample size next to every percentile and names the rank each came from, and
the runbook says to read the maximum rather than the p99 when the two disagree by
more than a little.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import httpx

BROKER: Final = "http://broker:8000"
CLIENT_ID: Final = "campus-sis"
# The development provisioning client `federation-init` creates, and the same
# value that script writes. Flagged by the bandit rule, which is right to flag a
# literal credential and wrong about this one: these runs target a development
# stack by definition, since a measurement against production would mean creating
# two hundred people in it.
SECRET: Final = "dev-only-provisioning-secret-not-for-production"  # noqa: S105


@dataclass(frozen=True, slots=True)
class Percentile:
    """One reported figure, with enough context to be read honestly."""

    name: str
    seconds: float
    rank: int
    """Which observation this is, counting from the fastest. Printed because a
    p99 drawn from 200 samples is the second-worst one, and a reader who knows
    that reads the number differently."""


@dataclass(frozen=True, slots=True)
class Run:
    """What one measured run produced."""

    label: str
    samples: list[float]
    started_at: datetime
    finished_at: datetime
    notes: list[str]
    """What was and was not in the measured path. The most important part of the
    report and the easiest to leave out: a latency figure whose path nobody
    recorded is a number without a claim attached."""

    @property
    def percentiles(self) -> list[Percentile]:
        ordered = sorted(self.samples)
        return [
            _at(ordered, "p50", 0.50),
            _at(ordered, "p95", 0.95),
            _at(ordered, "p99", 0.99),
            Percentile("max", ordered[-1], len(ordered)),
        ]

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples)


def seconds(value: float) -> str:
    """A duration with enough precision to be a number rather than a zero.

    Three decimals is right for a request and wrong for an in-process function
    call: an authorization decision taking 40 microseconds renders as `0.000`,
    which a reader takes for a broken harness rather than a fast one. Anything
    under a millisecond gets six decimals, which is the point at which the figure
    starts meaning something again.
    """
    return f"{value:.3f}" if value >= 0.001 else f"{value:.6f}"


def _at(ordered: Sequence[float], name: str, fraction: float) -> Percentile:
    """The nearest-rank percentile.

    Nearest-rank rather than interpolated, because an interpolated p95 is a value
    that never happened, and every figure in these reports should be an
    observation somebody could go and find in the logs.
    """
    rank = max(1, math.ceil(fraction * len(ordered)))
    return Percentile(name, ordered[rank - 1], rank)


def render(run: Run, *, target: dict[str, float]) -> str:
    """The committed report, as Markdown.

    Written to a file rather than printed, because the requirement asks for a
    report committed to the repository — a number in somebody's terminal is not
    evidence six months later.
    """
    lines = [
        f"# {run.label}",
        "",
        f"**Run at:** {run.started_at.isoformat(timespec='seconds')}",
        f"**Duration:** {(run.finished_at - run.started_at).total_seconds():.1f}s",
        f"**Samples:** {len(run.samples)}",
        "",
        "## What was measured",
        "",
    ]
    lines += [f"- {note}" for note in run.notes]
    lines += [
        "",
        "## Result",
        "",
        "| Figure | Seconds | Rank | Target | Verdict |",
        "|---|---|---|---|---|",
    ]
    for percentile in run.percentiles:
        limit = target.get(percentile.name)
        verdict = "—" if limit is None else ("pass" if percentile.seconds < limit else "FAIL")
        shown = "—" if limit is None else f"< {limit:g}s"
        lines.append(
            f"| {percentile.name} | {seconds(percentile.seconds)} | "
            f"{percentile.rank} of {len(run.samples)} | {shown} | {verdict} |"
        )
    lines += [
        f"| mean | {seconds(run.mean)} | — | — | — |",
        "",
        "## Reading this",
        "",
        f"Every figure is an observation rather than an interpolation, and the rank "
        f"column says which one. With {len(run.samples)} samples the p99 is the "
        f"{run.percentiles[2].rank}th slowest — one event, not a property of the "
        f"system. Where it and the maximum disagree by much, the maximum is the "
        f"number to ask about.",
        "",
        "This is a development stack on one host: the data tier, the broker and the "
        "directory share a machine with the process driving the load. The figures "
        "are useful for finding a regression against a previous run on the same "
        "hardware, and are not a capacity statement.",
    ]
    return "\n".join(lines) + "\n"


def render_all(title: str, runs: list[tuple[Run, dict[str, float]]], *, preamble: str) -> str:
    """Several runs in one report.

    The four latency budgets share a stack, a host and a moment, so splitting
    them across four files would invite somebody to compare a token-endpoint
    figure taken this morning against an authorization figure taken while the
    machine was building images. One file, one run, one set of conditions.
    """
    lines = [f"# {title}", "", preamble, ""]
    for run, target in runs:
        lines.append(render(run, target=target).replace("# ", "## ", 1))
        lines.append("")
    return "\n".join(lines)


def failed(run: Run, *, target: dict[str, float]) -> list[str]:
    """Which targets this run missed. Empty is the passing case."""
    return [
        f"{percentile.name} was {percentile.seconds:.3f}s against a {limit:g}s target"
        for percentile in run.percentiles
        if (limit := target.get(percentile.name)) is not None and percentile.seconds >= limit
    ]


async def token(client: httpx.AsyncClient, scope: str = "scim:read scim:write") -> str:
    """A real access token from the broker's own token endpoint.

    The same path a real SIS uses. Minting one by reading the signing key would
    measure a chain the client-credentials grant is not in, and that grant is
    part of every request being timed.
    """
    response = await client.post(
        f"{BROKER}/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": scope,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


async def directory_in_path(client: httpx.AsyncClient) -> bool:
    """Whether the broker has a directory at all.

    Asked rather than assumed, because the answer decides what the report may
    claim. A run against a broker with no directory measures the broker's own
    work and none of the downstream leg, and a report that did not say so would
    be the most misleading document in the repository.
    """
    response = await client.get(f"{BROKER}/readyz")
    checks: dict[str, Any] = response.json().get("checks", {})
    return "directory" in checks


def now() -> datetime:
    return datetime.now(UTC)
