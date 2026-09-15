"""Provisioning latency (NFR-PROV-01).

    docker compose run --rm tests python -m perf.provisioning_latency

SCIM create through to the directory account existing, two hundred times,
sequentially. p95 under 30 seconds and p99 under 60.

**The chain is synchronous, so the request duration is the chain.** A SCIM create
commits the person, then calls the lifecycle hook outside the transaction, which
applies the entitlements and writes the downstream account before the handler
returns. So the 201 arrives after the directory entry exists, and the time to
that 201 is the figure the requirement asks for. An earlier draft of this file
polled for the person afterwards; that measured nothing and would have added a
poll interval of padding to every sample.

That is worth knowing for a second reason. A synchronous chain means the SIS
waits for the directory, so a slow directory is a slow SIS, and the requirement's
30-second p95 is a ceiling on the sum rather than on a queue.

**Sequential, because the requirement says so and because it measures a different
thing.** Two hundred concurrent creates would measure throughput — how much work
the stack can have in flight — and this SLO is about how long one joiner waits.
The two diverge exactly when it matters, under load, and conflating them produces
a better-looking number that answers nothing.

**Every person created here is deleted afterwards.** A run that left two hundred
behind would make the next run's searches slower and the one after that slower
still, and the figures would drift for a reason unrelated to the code.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Final

import httpx

from campusid.scim.schemas import CAMPUS_USER, CORE_USER
from perf.latency import BROKER, Run, directory_in_path, failed, now, render, token

JOINERS: Final = 200
TARGET: Final = {"p95": 30.0, "p99": 60.0}

REPORTS: Final = Path("docs/perf")


def _joiner() -> dict[str, Any]:
    handle = uuid.uuid4().hex[:12]
    return {
        "schemas": [CORE_USER, CAMPUS_USER],
        "userName": f"perf.{handle}@campus.test",
        "name": {"givenName": "Perf", "familyName": f"Subject{handle[:6]}"},
        "emails": [{"value": f"perf.{handle}@campus.test", "primary": True}],
        "active": True,
        # An affiliation, because a create with none is not a joiner: the
        # transition hook returns early when nothing changed, and the downstream
        # step would never run. A measurement of that would be a measurement of
        # the shortcut.
        CAMPUS_USER: {"affiliations": [{"value": "student", "primary": True}]},
    }


async def _one(client: httpx.AsyncClient, headers: dict[str, str]) -> tuple[float, str]:
    started = time.perf_counter()
    created = await client.post(f"{BROKER}/scim/v2/Users", json=_joiner(), headers=headers)
    elapsed = time.perf_counter() - started
    created.raise_for_status()
    return elapsed, str(created.json()["id"])


async def main() -> int:
    started_at = now()
    samples: list[float] = []
    created: list[str] = []

    async with httpx.AsyncClient(timeout=120.0) as client:
        headers = {"Authorization": f"Bearer {await token(client)}"}
        directory = await directory_in_path(client)

        try:
            for index in range(JOINERS):
                elapsed, resource_id = await _one(client, headers)
                samples.append(elapsed)
                created.append(resource_id)
                if (index + 1) % 25 == 0:
                    print(f"  {index + 1}/{JOINERS}", file=sys.stderr)
        finally:
            # Always, including after a failure part way. A partial run that left
            # its subjects behind would poison every run after it.
            for resource_id in created:
                await client.delete(f"{BROKER}/scim/v2/Users/{resource_id}", headers=headers)

    run = Run(
        label="Provisioning latency (NFR-PROV-01)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{JOINERS} sequential SCIM creates, each carrying a `student` affiliation.",
            (
                "Timed from the request to the 201. The provisioning chain is synchronous: "
                "the handler applies entitlements and writes the downstream account before "
                "returning, so the response is the completion signal rather than an "
                "acknowledgement."
            ),
            (
                "The directory **was** in the measured path: the broker has one configured, "
                "so each sample includes the downstream account write."
                if directory
                else "The directory was **not** in the measured path: this broker has none "
                "configured, so these figures cover everything up to the downstream write "
                "and omit the write itself, which NFR-PROV-01 also names."
            ),
            (
                "Each subject was deleted afterwards. That is a SCIM delete, which is "
                "soft by design, so the rows remain deactivated — see perf/README.md "
                "for the purge that actually removes them."
            ),
        ],
    )

    REPORTS.mkdir(parents=True, exist_ok=True)
    destination = REPORTS / f"provisioning-latency-{started_at:%Y-%m-%d}.md"
    destination.write_text(render(run, target=TARGET), encoding="utf-8")
    print(f"wrote {destination}")

    misses = failed(run, target=TARGET)
    for miss in misses:
        print(f"MISSED: {miss}", file=sys.stderr)
    return 1 if misses else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(asyncio.run(main()))
