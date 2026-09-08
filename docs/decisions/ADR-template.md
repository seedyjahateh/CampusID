# ADR-NNN: <short title in the imperative, e.g. "Use Postgres advisory locks for migrations">

| Field | Value |
|---|---|
| Status | Proposed \| Accepted \| Superseded by ADR-NNN \| Deprecated |
| Date | YYYY-MM-DD |
| Milestone | M0 \| M1 \| M2 \| M3 \| M4 \| M5 |
| Affects | PRD requirement IDs, e.g. FR-SAML-07, NFR-OPS-03 |

## Context

What forces are in play? State the constraint, not the solution. Include what
was true at the time that might not be true later — a version, a deadline, a
skill gap, a spec ambiguity.

## Decision

What was decided, in one or two sentences, in the active voice.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A (chosen) | | | Chosen |
| B | | | Rejected because … |
| C | | | Rejected because … |

Rejecting an option is the part worth writing down. "We chose X" is worth
little without "we chose X over Y, and here is what Y would have cost."

## Consequences

**Accepted costs.** What this makes harder, slower, or more expensive.

**Reversal cost.** How hard is it to undo? Cheap (config change), moderate
(a migration), or expensive (breaks registered federation peers)?

**Follow-ups.** Work this decision creates, with requirement IDs.

## Verification

Which test or artifact proves the decision is actually in force? A decision
with no enforcing test decays into a comment.
