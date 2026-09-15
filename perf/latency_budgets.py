"""The four latency budgets (NFR-PERF-02 to 05).

    docker compose run --rm tests python -m perf.latency_budgets

Four figures the PRD states as p95 ceilings, measured in one run against one
stack so they share a host and a moment. Split across four files, somebody would
eventually compare a token-endpoint number taken on an idle machine against an
authorization number taken while it was building images, and conclude something
about the code.

| Budget | Target |
|---|---|
| NFR-PERF-02, SSO round trip, broker portion only | p95 < 800 ms |
| NFR-PERF-03, token endpoint | p95 < 150 ms |
| NFR-PERF-04, SCIM filter over a large directory | p95 < 300 ms |
| NFR-PERF-05, authorization decision, cache miss | p95 < 50 ms |

**NFR-PERF-02 says "broker portion only, excluding upstream IdP think time", and
that phrase does the work.** A round trip through Keycloak measures Keycloak.

What is timed here is one of the two legs the broker owns: building and signing
the `AuthnRequest`. The other — running the fifteen-check gate on the response —
is not, because driving it once per sample means completing a real login, and a
login contains the upstream the requirement excludes. So this section is a
partial answer and labels itself as one. The gate's own cost is covered by the
validation matrix, which exercises every check without a network.

**NFR-PERF-05 is measured in process, not over HTTP.** The decision engine is a
pure function of its inputs and no route calls it: there is no endpoint whose
latency would be the decision's. Timing an HTTP request would be timing the
request. The cache is bypassed because the requirement says cache miss, which is
the figure that matters — a cached decision is a Redis read and tells you about
Redis.

**NFR-PERF-04 needs a large directory to mean anything.** The requirement says
10,000 users. Seeding that through SCIM takes about half an hour at the measured
provisioning latency, so this run reports the size it actually found and says so
rather than quietly measuring a filter over twelve people and calling it 300ms.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import date
from pathlib import Path
from typing import Final

import httpx

from campusid.authz.engine import Environment, Request, Resource, Subject
from campusid.authz.loader import load_policies
from perf.latency import BROKER, CLIENT_ID, SECRET, Run, failed, now, render_all, token

REPETITIONS: Final = 200
REPORTS: Final = Path("docs/perf")

TOKEN_TARGET: Final = {"p95": 0.150}
FILTER_TARGET: Final = {"p95": 0.300}
DECISION_TARGET: Final = {"p95": 0.050}
SSO_TARGET: Final = {"p95": 0.800}

PERSON: Final = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"


# --- NFR-PERF-03: the token endpoint ----------------------------------------


async def token_endpoint(client: httpx.AsyncClient) -> Run:
    """A client-credentials grant, which is what an SIS does before every batch.

    The whole of it: client authentication against an Argon2 secret hash, the
    scope check, and signing a JWT. The hash is deliberately the expensive part
    and it is the reason this budget is 150ms rather than 15.
    """
    started_at = now()
    samples: list[float] = []
    for _ in range(REPETITIONS):
        begin = time.perf_counter()
        response = await client.post(
            f"{BROKER}/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "scope": "scim:read",
                "client_id": CLIENT_ID,
                "client_secret": SECRET,
            },
        )
        samples.append(time.perf_counter() - begin)
        response.raise_for_status()

    return Run(
        label="Token endpoint (NFR-PERF-03)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{REPETITIONS} sequential client-credentials grants.",
            (
                "Includes verifying the client secret against its Argon2 hash, which is "
                "the expensive step and the reason this budget is not smaller."
            ),
        ],
    )


# --- NFR-PERF-04: a filtered SCIM listing -----------------------------------


async def scim_filter(client: httpx.AsyncClient, headers: dict[str, str]) -> Run:
    """A filtered listing, at whatever size the directory happens to be.

    The size is reported rather than assumed. A filter over a dozen people
    answers in microseconds and says nothing about the requirement, so a run
    against a small database is honest about being one.
    """
    started_at = now()
    total = (
        (await client.get(f"{BROKER}/scim/v2/Users?count=1", headers=headers))
        .json()
        .get("totalResults", 0)
    )

    samples: list[float] = []
    for index in range(REPETITIONS):
        begin = time.perf_counter()
        response = await client.get(
            f"{BROKER}/scim/v2/Users",
            params={"filter": f'userName sw "perf.{index % 10}"', "count": 50},
            headers=headers,
        )
        samples.append(time.perf_counter() - begin)
        response.raise_for_status()

    return Run(
        label="SCIM filtered listing (NFR-PERF-04)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{REPETITIONS} filtered listings with a `sw` predicate, 50 per page.",
            (
                f"**The directory held {total} people.** The requirement states 10,000, so "
                "this figure does not answer it: a filter over a small table is an index "
                "lookup that never reaches the interesting behaviour. Seeding 10,000 "
                "through SCIM takes roughly half an hour at the measured provisioning "
                "latency and was not done."
                if total < 10_000
                else f"The directory held {total} people, above the 10,000 the requirement states."
            ),
        ],
    )


# --- NFR-PERF-05: an authorization decision ---------------------------------


def authorization_decision() -> Run:
    """The policy engine, in process and on a cache miss.

    Not over HTTP: the engine is a pure function and no route calls it, so an
    endpoint's latency would be the endpoint's. Not through the cache: the
    requirement says cache miss, and a cached decision measures Redis.

    The policy set is the shipped one, because a decision against three
    hand-written rules is a measurement of three hand-written rules.
    """
    policies = load_policies(Path("config/authorization.yaml"))
    request = Request(
        subject=Subject(person_uuid=PERSON, assurance="urn:campusid:aal1"),
        resource=Resource(id="lms:course/101"),
        action="read",
        environment=Environment(network="campus"),
    )

    started_at = now()
    samples: list[float] = []
    for _ in range(REPETITIONS):
        begin = time.perf_counter()
        policies.decide(request)
        samples.append(time.perf_counter() - begin)

    return Run(
        label="Authorization decision (NFR-PERF-05)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{REPETITIONS} evaluations of the shipped policy set, in process.",
            "Every evaluation is a cache miss: the engine is called directly.",
            (
                "Measured in process because no route calls the decider — timing an "
                "HTTP request would be timing the request."
            ),
        ],
    )


# --- NFR-PERF-02: the broker's half of an SSO round trip --------------------


async def sso_round_trip(client: httpx.AsyncClient) -> Run | None:
    """The leg the broker owns: building and signing an `AuthnRequest`.

    The requirement excludes upstream think time, so the hop to the identity
    provider is not timed. The consuming half — the fifteen-check gate — is not
    timed here either, and that is a stated shortfall rather than an oversight:
    driving it would mean completing a real login per sample, and a login
    includes the upstream the requirement excludes.

    Returns None when no identity provider is registered, because a redirect
    to nowhere is not a measurement.
    """
    probe = await client.get(f"{BROKER}/saml/sso", follow_redirects=False)
    if probe.status_code != 303 or "SAMLRequest" not in probe.headers.get("location", ""):
        return None

    started_at = now()
    samples: list[float] = []
    for _ in range(REPETITIONS):
        begin = time.perf_counter()
        response = await client.get(f"{BROKER}/saml/sso", follow_redirects=False)
        samples.append(time.perf_counter() - begin)
        # 303 is the success here, so `raise_for_status` would refuse every
        # sample. The probe above already established that the redirect carries
        # a `SAMLRequest`; this asserts each one still does.
        assert response.status_code == 303, response.text

    return Run(
        label="SSO request generation (NFR-PERF-02, partial)",
        samples=samples,
        started_at=started_at,
        finished_at=now(),
        notes=[
            f"{REPETITIONS} sequential `GET /saml/sso` calls.",
            (
                "Times the broker's outbound leg: resolving the IdP, building the "
                "`AuthnRequest`, deflating it, signing the redirect query, and storing "
                "the outstanding request and its binding nonce."
            ),
            (
                "**This is a partial measurement.** NFR-PERF-02 names the round trip; the "
                "consuming half — the fifteen-check validation gate — is not included, "
                "because driving it per sample needs a real login and a login includes "
                "the upstream think time the requirement excludes."
            ),
        ],
    )


async def main() -> int:
    runs: list[tuple[Run, dict[str, float]]] = []

    async with httpx.AsyncClient(timeout=60.0) as client:
        headers = {"Authorization": f"Bearer {await token(client)}"}

        print("token endpoint...", file=sys.stderr)
        runs.append((await token_endpoint(client), TOKEN_TARGET))

        print("scim filter...", file=sys.stderr)
        runs.append((await scim_filter(client, headers), FILTER_TARGET))

        print("authorization decision...", file=sys.stderr)
        runs.append((authorization_decision(), DECISION_TARGET))

        print("sso request generation...", file=sys.stderr)
        sso = await sso_round_trip(client)
        if sso is not None:
            runs.append((sso, SSO_TARGET))
        else:
            print("  skipped: no default IdP registered", file=sys.stderr)

    report = render_all(
        "Latency budgets",
        runs,
        preamble=(
            "The four p95 ceilings NFR-PERF-02 to 05 state, measured in one run so they "
            "share a host and a moment. Read each section's notes before its table: two "
            "of the four are partial measurements and say which part is missing."
        ),
    )

    REPORTS.mkdir(parents=True, exist_ok=True)
    destination = REPORTS / f"latency-budgets-{date.today():%Y-%m-%d}.md"
    destination.write_text(report, encoding="utf-8")
    print(f"wrote {destination}")

    misses = [miss for run, target in runs for miss in failed(run, target=target)]
    for miss in misses:
        print(f"MISSED: {miss}", file=sys.stderr)
    return 1 if misses else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(asyncio.run(main()))
