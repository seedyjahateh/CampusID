# Runbook: a provisioning backlog

**Verified on:** 2026-09-15
**Covers:** FR-LC-09, NFR-PROV-01, NFR-PROV-02, NFR-PROV-03

Writes to a downstream system are failing. What that means depends on which
direction the backlog runs, and the two have opposite urgencies:

- **Joiners are not appearing.** People cannot work. Loud, and somebody has
  already told you.
- **Leavers are not being disabled.** People who have left can still work. Quiet,
  and nobody will tell you. This is the one with the tighter SLO — 15 seconds at
  p95 — and the one worth checking first even when the complaint is about joiners.

---

## 1. Find out whether anything is actually stuck

A failed downstream write is retried five times with exponential backoff and then
dead-lettered. The queue is the answer to "is this a blip or a backlog":

```sh
docker compose exec broker python - <<'EOF'
import asyncio
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.lifecycle.deadletter import DeadLetterQueue

async def main() -> None:
    engine = create_engine(get_settings())
    try:
        queue = DeadLetterQueue(create_session_factory(engine))
        for item in await queue.outstanding():
            print(item.created_at, item.target, item.operation, item.person_uuid)
    finally:
        await engine.dispose()

asyncio.run(main())
EOF
```

Oldest first, which is the ordering somebody draining a queue wants and the
opposite of what a log gives them. **Read the oldest entry's date before anything
else.** An item stuck for a week that nobody noticed is a bigger finding than the
outage that caused it.

A `disable` operation in that list is a leaver whose downstream account is still
enabled. Treat it as a security finding rather than a provisioning one.

## 2. Decide whether the far end is fixed

Replaying into a directory that is still down files the same item again, with a
longer history. Check first:

```sh
curl -s https://broker.campus.test/readyz | jq '.checks.directory'
```

A directory outage is reported rather than fatal: the broker degrades to cached
group data rather than refusing logins, so `readyz` may say `ok` overall while the
directory line says otherwise. That is deliberate — an outage it can survive
should not take the broker out of rotation — and it means this line is the one to
read, not the summary.

## 3. Replay

```sh
docker compose exec broker python - <<'EOF'
import asyncio
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.lifecycle.deadletter import DeadLetterQueue

ITEM_ID = "…"  # from step 1

async def main() -> None:
    engine = create_engine(get_settings())
    try:
        queue = DeadLetterQueue(create_session_factory(engine))
        async def dispatch(item):
            raise NotImplementedError("wire the target the item names")
        print(await queue.replay(ITEM_ID, dispatch))
    finally:
        await engine.dispose()

asyncio.run(main())
EOF
```

A replay that fails again leaves the item outstanding with its history extended
rather than filing a second row, because two rows for one stuck account make the
queue grow as it is drained.

**Replay a single item first**, not the whole queue. If the far end is still
refusing on the merits rather than being unreachable, you want to learn that from
one item.

> **Gap, stated rather than hidden.** There is no admin endpoint for listing or
> replaying dead letters, and the dispatcher above has to be wired by hand to the
> target the item names. FR-LC-09 asks that dead-lettered items be "visible and
> replayable"; they are both, through the store rather than through an API. That
> is the first thing to fix if this runbook is ever needed twice in a month.

## 4. If the backlog is size rather than failure

Nothing may be dead-lettered at all — the writes are landing, just slowly. That
is a different problem and the metrics answer it:

```sh
curl -s https://broker.campus.test/metrics | grep campusid_provisioning_latency_seconds
```

The bucket edges are chosen around the numbers the SLOs are written about. If the
mass has moved from under a second into the 10–30 second buckets, the directory
is the bottleneck rather than the broker: every directory call runs in a worker
thread, and the pool is what saturates.

`campusid_scim_requests_total` broken down by status class says whether the SIS
is also being refused, which changes the conversation from "our provisioning is
slow" to "their client is retrying".

## 5. Confirm the outcome rather than the absence of errors

An empty queue is not proof that people exist downstream. Run a reconciliation:

```sh
docker compose run --rm tests python scripts/reconcile.py
```

Dry run unless `--apply` is given. See [drift remediation](drift-remediation.md)
for how to read the report — the categories mean different things and only one of
them is a security finding.

---

## Preventing the next one

- **Watch the dead-letter depth, not just its contents.** A queue that is never
  empty and never grows is being drained by hand by somebody who has stopped
  mentioning it.
- **Alert on the oldest item's age**, which catches the stuck-for-a-week case that
  a depth alert misses entirely.
- **A leaver that dead-letters deserves a page.** A joiner that dead-letters
  deserves a ticket. The queue does not distinguish them; your alerting should.
