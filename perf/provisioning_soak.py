"""Provisioning soak (NFR-PROV-03).

    docker compose run --rm --entrypoint python tests -m perf.provisioning_soak

A hundred provisioning events a minute for ten minutes, with no loss and no
growth in dead-letter depth.

**This measures something the latency runs cannot.** Those send one request,
wait for it, and send the next — so nothing accumulates and a leak has nowhere to
show. Ten minutes at a steady rate is where a connection that is never returned
to the pool, a queue that drains slower than it fills, or a retry that files a
second dead letter instead of extending the first becomes visible.

**The rate is paced, not maximal.** Sending a thousand requests as fast as
possible would measure throughput and finish in a minute. The requirement says a
hundred a minute *for ten minutes*, and the duration is the point: a resource
leak is a slope, and a slope needs a long enough baseline to have one.

**Loss is checked per request rather than at the end.** A create that returned
201 and then was not there is the failure this is looking for, and a count taken
at the end cannot tell that apart from a create that was refused.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx

from campusid.scim.schemas import CAMPUS_USER, CORE_USER
from perf.latency import BROKER, Run, failed, now, render, token

MINUTES: Final = 10
PER_MINUTE: Final = 100
INTERVAL: Final = 60.0 / PER_MINUTE

TARGET: Final = {"p95": 30.0}
"""The latency ceiling from NFR-PROV-01, applied here as a secondary check. The
requirement this run serves is about loss and dead-letter growth; a soak whose
latency had quietly tripled while losing nothing would still be a finding."""

REPORTS: Final = Path("docs/perf")


@dataclass
class Outcome:
    """What the soak saw, beyond the latencies."""

    refused: int = 0
    lost: int = 0
    created: list[str] = field(default_factory=list)
    depth: list[int] = field(default_factory=list)
    """Dead-letter depth, sampled once a minute. A list rather than a final
    number, because the requirement is about *growth* and one reading cannot
    have a slope."""


def _person() -> dict[str, Any]:
    handle = uuid.uuid4().hex[:12]
    return {
        "schemas": [CORE_USER, CAMPUS_USER],
        "userName": f"soak.{handle}@campus.test",
        "name": {"givenName": "Soak", "familyName": f"Subject{handle[:6]}"},
        "emails": [{"value": f"soak.{handle}@campus.test", "primary": True}],
        "active": True,
        CAMPUS_USER: {"affiliations": [{"value": "student", "primary": True}]},
    }


async def _dead_letter_depth() -> int:
    """How many items are stuck right now.

    Read from the store rather than through an API because there is no endpoint
    for it — a gap recorded in the provisioning-backlog runbook rather than
    worked around silently here.
    """
    from campusid.config import get_settings
    from campusid.db import create_engine, create_session_factory
    from campusid.lifecycle.deadletter import DeadLetterQueue

    engine = create_engine(get_settings())
    try:
        queue = DeadLetterQueue(create_session_factory(engine))
        return len(await queue.outstanding(limit=1000))
    finally:
        await engine.dispose()


async def _one(client: httpx.AsyncClient, headers: dict[str, str], outcome: Outcome) -> float:
    started = time.perf_counter()
    created = await client.post(f"{BROKER}/scim/v2/Users", json=_person(), headers=headers)
    elapsed = time.perf_counter() - started

    if created.status_code != 201:
        outcome.refused += 1
        return elapsed

    resource_id = str(created.json()["id"])
    outcome.created.append(resource_id)

    # Read back immediately. A create that returned 201 and is not there is the
    # loss this run exists to detect, and it is invisible to a count taken at the
    # end — which cannot tell a lost create from a refused one.
    readback = await client.get(f"{BROKER}/scim/v2/Users/{resource_id}", headers=headers)
    if readback.status_code != 200:
        outcome.lost += 1
    return elapsed


async def main() -> int:
    started_at = now()
    samples: list[float] = []
    outcome = Outcome()

    async with httpx.AsyncClient(timeout=120.0) as client:
        headers = {"Authorization": f"Bearer {await token(client)}"}
        outcome.depth.append(await _dead_letter_depth())

        start = time.perf_counter()
        deadline = start + MINUTES * 60
        next_at = start
        minute = 0

        try:
            while time.perf_counter() < deadline:
                samples.append(await _one(client, headers, outcome))

                # Paced against a fixed schedule rather than sleeping a fixed
                # interval after each request. Sleeping after the work makes the
                # real rate depend on how long the work took, so a slowing system
                # would quietly reduce its own load — and hide the slope.
                next_at += INTERVAL
                delay = next_at - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay)

                elapsed_minutes = int((time.perf_counter() - start) // 60)
                if elapsed_minutes > minute:
                    minute = elapsed_minutes
                    outcome.depth.append(await _dead_letter_depth())
                    print(
                        f"  minute {minute}: {len(samples)} sent, "
                        f"{outcome.refused} refused, {outcome.lost} lost, "
                        f"dead letters {outcome.depth[-1]}",
                        file=sys.stderr,
                    )
        finally:
            print(f"  cleaning up {len(outcome.created)} subjects", file=sys.stderr)
            for resource_id in outcome.created:
                await client.delete(f"{BROKER}/scim/v2/Users/{resource_id}", headers=headers)

        outcome.depth.append(await _dead_letter_depth())

    grew = outcome.depth[-1] - outcome.depth[0]
    run = Run(
        label="Provisioning soak (NFR-PROV-03)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{len(samples)} creates over {MINUTES} minutes, paced at {PER_MINUTE} a minute.",
            (
                f"**Loss: {outcome.lost}.** Every create that returned 201 was read back "
                "immediately; a 201 followed by a missing resource is the failure this run "
                "exists to detect."
            ),
            f"**Refused: {outcome.refused}.** Creates that did not return 201 at all.",
            (
                f"**Dead-letter depth: {outcome.depth[0]} at the start, {outcome.depth[-1]} at "
                f"the end, {grew:+d}.** Sampled each minute: {outcome.depth}."
            ),
            (
                "Paced against a fixed schedule rather than sleeping between requests, so a "
                "slowing system cannot quietly reduce its own load and hide the slope."
            ),
            (
                "Each subject was deleted afterwards. That is a SCIM delete, which is soft by "
                "design, so the rows remain deactivated — see perf/README.md for the purge."
            ),
        ],
    )

    REPORTS.mkdir(parents=True, exist_ok=True)
    destination = REPORTS / f"provisioning-soak-{started_at:%Y-%m-%d}.md"
    destination.write_text(render(run, target=TARGET), encoding="utf-8")
    print(f"wrote {destination}")

    misses = failed(run, target=TARGET)
    if outcome.lost:
        misses.append(f"{outcome.lost} creates returned 201 and were not readable")
    if outcome.refused:
        misses.append(f"{outcome.refused} creates were refused")
    if grew > 0:
        misses.append(f"dead-letter depth grew by {grew}")

    for miss in misses:
        print(f"MISSED: {miss}", file=sys.stderr)
    return 1 if misses else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(asyncio.run(main()))
