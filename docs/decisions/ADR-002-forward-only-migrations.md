# ADR-002: Forward-only migrations behind a Postgres advisory lock

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Milestone | M0 |
| Affects | NFR-OPS-03, FR-AUD-04, FR-AUD-05 |

## Context

The broker applies `alembic upgrade head` at container startup so a clean clone
comes up working with no manual step (NFR-OPS-01). Two problems follow from
that convenience:

1. **Concurrency.** In any multi-replica deployment, every replica runs the
   upgrade simultaneously. Alembic takes no lock of its own, so the replicas
   race through the same DDL and the losers crash-loop.

2. **Downgrades.** Alembic scaffolds a `downgrade()` for every revision. On a
   system whose value is its audit trail, a downgrade that drops a column drops
   evidence — and it will be reached for during an incident, which is exactly
   when destroying evidence is worst.

## Decision

`migrations/env.py` acquires `pg_advisory_lock(8845213007)` before running
migrations and releases it afterwards. Every `downgrade()` raises
`NotImplementedError`; the revision template generates it that way, so the
default is correct without anyone remembering.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Advisory lock + forward-only** (chosen) | Safe under rolling deploys; audit data cannot be dropped by a routine command | Recovery from a bad migration requires a restore or a new forward migration | **Chosen** |
| Migrate in a separate job/init container | Clean separation; the standard Kubernetes answer | Adds an orchestration step to `docker compose up`, costing NFR-OPS-01's one-command promise | Rejected for now; revisit if the project ever gets a real deployment target |
| Leave downgrades generated | Fast local iteration | The recovery path most likely to be used under pressure is also the one that destroys audit rows | Rejected |

## Consequences

**Accepted costs.** Fixing a bad migration means writing another migration or
restoring from backup. Local development iterates by dropping the volume
(`docker compose down -v`), not by downgrading.

**Reversal cost.** Cheap. Removing the lock is a few lines; re-enabling
downgrades would mean writing them per revision.

**Follow-ups.**
- The audit table's INSERT+SELECT-only grant (FR-AUD-04) lands with the audit
  schema in M2 and is the second half of this protection.
- Document the restore path in `docs/runbooks/` when a backup story exists.

## Verification

`tests/integration/test_data_tier.py::test_baseline_migration_has_been_applied`
asserts the schema reaches `0001_baseline` and that both extensions exist. The
advisory lock is exercised implicitly on every CI run; a concurrent-startup
test lands with the multi-replica work, if it ever happens.
