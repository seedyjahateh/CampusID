# ADR-005: An audit trail that can prove it has not been edited

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-11 |
| Milestone | M5 |
| Affects | FR-AUD-04, FR-AUD-05, FR-AUD-08, NFR-SEC-06 |
| Builds on | ADR-002 (forward-only migrations) |

## Context

The audit trail is the artefact this project exists to produce. Every other
requirement is a claim about what the broker does; the trail is the evidence. So
the question is not whether it records enough, but whether anybody should believe
what it records.

Three things were true before this work and each undermined that.

1. **"Append-only" was a convention.** `campusid/audit/` had no `update` or
   `delete` path, which is real protection against the ordinary bug and none at
   all against a compromised process — and a compromised process is the case an
   audit trail exists for.
2. **A deleted row was invisible.** Nothing in the schema made the absence of an
   event detectable.
3. **Retention had no answer.** FR-AUD-08 asks for a configurable window, and a
   table nobody may delete from eventually fills a disk.

These interact. Solving the second with a hash chain makes the third impossible,
because deleting old events breaks the chain by construction.

## Decision

**A hash chain.** Each event stores `prev_hash` and
`hash = SHA256(prev_hash || canonical_json(event))`. The covered field list is
written out rather than derived from the model, so a new column is a decision
about whether it belongs in the digest. The writer takes a transaction-level
advisory lock, reads the tail and links to it.

**A least-privilege role.** The application connects as `campusid_app`, granted
`SELECT, INSERT` on `audit_event` and nothing else. Schema ownership stays with
the migration role, so the application cannot `ALTER` the grant away. Migrations
keep the owner connection; `create_engine` and `create_owner_engine` are separate
functions so request-handling code cannot reach DDL rights by passing a wrong
argument.

**A retention anchor.** A pruning pass exports the doomed events, records where
it cut and what the last removed event hashed to, then deletes. The verifier
resumes from that anchor instead of from the genesis constant. The anchor table
is read-only to the application for the same reason the trail is.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Chain + role + anchor** (chosen) | Partial tampering is detectable; the grant survives a compromised process; retention is possible without giving up either | Serialises audit writes; pruning becomes an operator task with a reason attached | **Chosen** |
| Chain with no anchor | Simpler | Retention and verifiability become mutually exclusive, and a deployment will eventually choose retention | Rejected |
| Signed events rather than a chain | Each event stands alone; no write serialisation | Detects modification and not *deletion*, which is the tampering an audit trail most needs to catch | Rejected |
| Ship the trail to an external store | Somebody else's problem | The two copies eventually disagree, and the question "which is right" has no answer | Rejected as the *only* answer; the NDJSON export makes it an additional one |
| Lazy sealing by a background job | No write contention | Leaves an unsealed tail, and a special case at the tail is where a row gets hidden | Rejected |

## Consequences

**What this proves, exactly.** Partial tampering is impossible to hide: an edited
field, a deleted row, an inserted event. Each breaks the link at that point and
every link after it.

**What it does not prove.** Somebody with write access to the whole table can
rewrite every row from a tamper point forward and produce a chain that verifies.
The defence is publishing the head hash somewhere they do not control, which is
an operational practice rather than code — `scripts/verify_audit_chain.py` prints
it for exactly that purpose. Truncating the tail is the same gap, and a test
states it rather than pretending otherwise.

**Audit writes are serialised.** One advisory lock, one writer at a time. Two
writers reading the same tail would produce two events claiming the same
predecessor, and a verifier reports a fork as tampering because from the outside
they are the same thing. This caps audit throughput at a few thousand a second,
far above what this broker emits, and buys a chain with no unsealed tail.

**Canonical serialisation is the whole security of it.** Two encodings of one
event that hash differently make the verifier cry tamper at an honest trail; two
different events that hash the same make tampering invisible. Timestamps are
rendered at microsecond precision in UTC to match what Postgres keeps — a hash
over a more precise value verifies on the way in and fails on the way back out,
which is a bug that only appears after a restart.

**An empty table is not necessarily a new one.** A retention pass can remove every
surviving event, and the writer had to learn this: linking to the genesis constant
then starts a second chain the verifier reads as a break at the first row after
the prune. The tests caught it; it is recorded here because the same mistake is
available to anybody adding a second writer.

**Migration 0014 is not safe to run while an older broker is writing.** Its new
columns are `NOT NULL`, so an instance built before that revision inserts rows the
table rejects — and audit writes are deliberately swallowed, so those events are
lost *silently*. Deploy the code first, then migrate.

**Reversal cost.** High, and deliberately so. Removing the chain means the trail
stops being evidence; relaxing the grant means it stops being append-only. Both
are migrations somebody would have to write on purpose.

## Verification

- `tests/unit/test_audit_hash_chain.py` — the arithmetic, and every shape of
  tampering: edited field, rehashed row, deleted row, inserted row, reordered
  rows, reused sequence.
- `tests/integration/test_audit_append_only.py` — the chain against live
  Postgres, twelve concurrent writes forming one chain rather than a fork, and
  four statements the application role is refused: `UPDATE`, `DELETE`,
  `TRUNCATE`, `ALTER`.
- `tests/integration/test_audit_export.py` — a pruned trail still verifies, a
  deletion beyond the anchor is still caught, and a failing export leaves the
  trail intact.
- `scripts/verify_audit_chain.py` — exits non-zero on a broken chain, so it can
  be a cron job that pages somebody rather than a thing an operator remembers.
