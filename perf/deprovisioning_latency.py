"""Deprovisioning latency (NFR-PROV-02).

    docker compose run --rm tests python -m perf.deprovisioning_latency

SCIM `active: false` through to the directory account disabled, every session
terminated and every refresh token revoked. p95 under 15 seconds and p99 under
60.

**This is the tightest SLO in the system, and it is the one that matters after a
termination.** The provisioning run measures somebody waiting to start work; this
measures how long somebody who has been dismissed can still reach the campus. The
two have the same shape and nothing else in common.

Like the joiner chain it is synchronous end to end, so the response is the
completion signal. The four steps FR-LC-03 fixes — disable the account, terminate
every session, revoke every token, revoke the entitlements — all run before the
handler returns, and every sample here is their sum.

**The subjects hold no live session or refresh token, and that is a stated limit
rather than an oversight.** Giving each of two hundred subjects a real session
would mean two hundred SSO round trips through an upstream identity provider, and
a forged session would be measuring a state the broker did not produce. So the
session and token steps run and find nothing to revoke, which is the fast path:
a real termination of somebody with several active sessions will be slower than
these figures. The report says so, because a latency number whose path nobody
recorded is a number without a claim attached.
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

LEAVERS: Final = 200
TARGET: Final = {"p95": 15.0, "p99": 60.0}

REPORTS: Final = Path("docs/perf")


def _person() -> dict[str, Any]:
    handle = uuid.uuid4().hex[:12]
    return {
        "schemas": [CORE_USER, CAMPUS_USER],
        "userName": f"leaver.{handle}@campus.test",
        "name": {"givenName": "Perf", "familyName": f"Leaver{handle[:6]}"},
        "emails": [{"value": f"leaver.{handle}@campus.test", "primary": True}],
        "active": True,
        CAMPUS_USER: {"affiliations": [{"value": "staff", "primary": True}]},
    }


async def _seed(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    """Create somebody with an affiliation to lose.

    Not timed. Everything before the deactivation is setup, and including it
    would report the joiner chain and the leaver chain as one number.
    """
    created = await client.post(f"{BROKER}/scim/v2/Users", json=_person(), headers=headers)
    created.raise_for_status()
    return str(created.json()["id"])


async def _deactivate(
    client: httpx.AsyncClient, headers: dict[str, str], resource_id: str
) -> float:
    """The measured operation: `active: false`, which routes as a leaver.

    A PATCH rather than a DELETE, because the requirement names `active:false`
    and because they are different events to a reader of the trail even though
    both end in the same sequence.
    """
    started = time.perf_counter()
    response = await client.patch(
        f"{BROKER}/scim/v2/Users/{resource_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=headers,
    )
    elapsed = time.perf_counter() - started
    response.raise_for_status()
    return elapsed


async def main() -> int:
    started_at = now()
    samples: list[float] = []
    subjects: list[str] = []

    async with httpx.AsyncClient(timeout=120.0) as client:
        headers = {"Authorization": f"Bearer {await token(client)}"}
        directory = await directory_in_path(client)

        try:
            for index in range(LEAVERS):
                resource_id = await _seed(client, headers)
                subjects.append(resource_id)
                samples.append(await _deactivate(client, headers, resource_id))
                if (index + 1) % 25 == 0:
                    print(f"  {index + 1}/{LEAVERS}", file=sys.stderr)
        finally:
            for resource_id in subjects:
                await client.delete(f"{BROKER}/scim/v2/Users/{resource_id}", headers=headers)

    run = Run(
        label="Deprovisioning latency (NFR-PROV-02)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{LEAVERS} sequential deactivations, each of a person created immediately before.",
            (
                "Timed from the PATCH setting `active: false` to its response. The leaver "
                "chain is synchronous, so the sample is the sum of FR-LC-03's four ordered "
                "steps rather than an acknowledgement of a queued job."
            ),
            (
                "The directory **was** in the measured path: each sample includes the "
                "downstream disable."
                if directory
                else "The directory was **not** in the measured path: this broker has none "
                "configured, so the downstream disable that NFR-PROV-02 names is absent "
                "from these figures."
            ),
            (
                "The subjects held no live session or refresh token. Those steps therefore "
                "found nothing to revoke, which is the fast path — a real termination of "
                "somebody with several active sessions will be slower than this."
            ),
            (
                "Each subject was deleted afterwards. That is a SCIM delete, which is "
                "soft by design, so the rows remain deactivated — see perf/README.md "
                "for the purge that actually removes them."
            ),
        ],
    )

    REPORTS.mkdir(parents=True, exist_ok=True)
    destination = REPORTS / f"deprovisioning-latency-{started_at:%Y-%m-%d}.md"
    destination.write_text(render(run, target=TARGET), encoding="utf-8")
    print(f"wrote {destination}")

    misses = failed(run, target=TARGET)
    for miss in misses:
        print(f"MISSED: {miss}", file=sys.stderr)
    return 1 if misses else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(asyncio.run(main()))
