# Running this in production: the high-availability design

**Verified on:** 2026-09-15
**Covers:** NFR-AVAIL-01 (the design half)

The development stack is one of everything on one host. This is what a production
deployment would have to change, written from what the code actually does rather
than from a template — so most of it is about the four places where this broker is
*not* stateless, and none of those are the obvious one.

Sessions are not the problem. They live in Redis under an opaque identifier, the
cookie carries no identity data, and any node can serve any request. **Session
affinity is not required**, and a load balancer configured for it would only hide
a bug on the day it stopped working.

---

## What can scale out unchanged

**The application tier.** Three nodes or thirty. Every piece of request state —
sessions, the replay cache, outstanding SAML requests, authorization codes,
refresh-token families, rate-limit counters — is in Redis, and everything durable
is in Postgres. A node holds nothing another node needs.

**Schema migrations.** They run at startup behind a Postgres advisory lock
(ADR-002), so starting five nodes simultaneously produces one migration and four
nodes waiting for it. That is already the behaviour, not a change to make.

**The audit hash chain.** Appending takes a transaction-scoped advisory lock, and
a Postgres advisory lock is cluster-wide rather than per-connection-pool. Two
nodes writing audit events at the same instant serialise correctly, and the chain
stays verifiable. This is the piece most likely to be assumed broken by somebody
who has seen a hash chain behind a load balancer before; it is not.

---

## The four things that need attention

### 1. The key volume is the real constraint

`saml-keys` holds the SAML signing keypair, the SAML encryption keypair, and the
OIDC signing key set. All three are generated on first start if absent.

**Three nodes with three local volumes generate three identities.** Each would
advertise a different certificate in SP metadata, each would publish a different
JWKS, and which one a peer got would depend on which node answered. Logins would
fail intermittently and the failure would look like a signature problem.

The fix is not subtle, but it has to be deliberate:

- **Shared storage** (a network filesystem, or a Kubernetes `ReadWriteMany`
  volume) so every node reads the same files. Simplest, and it makes the storage a
  single point of failure for startup rather than for serving.
- **A secrets manager** — Vault, AWS Secrets Manager — with the keys injected at
  deploy time and the generate-on-first-start path disabled. Better operationally
  and the right answer if the organisation already runs one.

Either way, **generate the keys once, deliberately, before the first deploy**,
rather than letting whichever node starts first decide. The rotation procedure in
[key rotation](runbooks/key-rotation.md) assumes every node sees the same key set,
and a staged key on one node out of three is a rotation that half-works.

### 2. The grace sweeper runs on every node

`GraceSweeper` starts in the application lifespan, so *n* nodes run *n* sweeps.
The query selects entitlement grants whose grace period has ended and marks them
revoked, without `FOR UPDATE SKIP LOCKED`.

The revocation itself is idempotent — setting `revoked_at` twice reaches the same
state — so **this is not a correctness problem for access**. What it does produce
is duplicate `grace.expiry` events on a person's lifecycle timeline, one per node
that caught the same grant, which makes the timeline wrong in a way somebody reads
during an access review.

Three options, in the order I would consider them:

- **Take a row lock**: add `FOR UPDATE SKIP LOCKED` to the selection. Smallest
  change, keeps every node useful, and turns the redundancy into parallelism.
- **Advisory-lock the sweep** so only one node runs it at a time. Also small, and
  it leaves the other nodes doing nothing on each tick.
- **Move it out of the application** into a scheduled job. Cleanest separation and
  the most deployment machinery.

The first is the one to do. The others are what you choose if the sweep grows into
something that should not be inside a request-serving process at all.

### 3. Redis failover can lose a security control

Two things in Redis are security controls rather than caches:

**The SAML replay cache.** An assertion ID is recorded with `SET NX` after the
signature verifies. If a failover promotes a replica that had not yet received
that write, the assertion can be replayed once. Redis replication is asynchronous
by default, so this is a real window rather than a theoretical one.

**The rate-limit counters.** Losing these resets somebody's allowance, which is
the less alarming of the two.

What to do about it is a judgement rather than a fix. `WAIT` before returning
from the replay write would make the window smaller at the cost of latency on
every login. Redis Sentinel with `min-replicas-to-write` reduces the chance of
promoting a stale replica. Neither eliminates it, and an assertion is already
bounded by its own `NotOnOrAfter`, so the exposure is one replay inside a
five-minute window rather than an unbounded one.

**Do not solve this by moving the replay cache to Postgres** without measuring:
it is on the critical path of every login, and the current design deliberately
keeps it off the database that the audit trail is serialising writes to.

### 4. Provisioning is synchronous, which changes what a node restart costs

A SCIM write does its downstream work before responding — see
[STATUS.md](STATUS.md) for why that diverges from NFR-AVAIL-05. Under load
balancing this means **a node restarted mid-request loses that request**, and the
source system sees a connection error rather than a queued job.

The SIS must therefore retry, and its retries must be idempotent. They are:
creates are idempotent on `externalId` and return 200 rather than 201 on a replay.
That property is doing more work in a multi-node deployment than it does in the
development stack, and it is worth knowing before somebody optimises it away.

---

## The shape of it

| Tier | Production | Why |
|---|---|---|
| Application | 3+ nodes behind a load balancer, no session affinity | Stateless per request; affinity would mask a bug |
| Keys | Shared volume or secrets manager, generated once before first deploy | Three nodes otherwise publish three identities |
| Postgres | Primary with a streaming replica, automated failover | Audit and registry are the durable state |
| Redis | Sentinel or managed, replication on | Sessions, replay cache, rate limits |
| Directory | Whatever the campus already runs | The broker degrades to cached groups when it is unreachable |
| Migrations | Run on deploy, not on every node start | Already advisory-locked, so either works |

Health checks: `/healthz` for liveness and `/readyz` for load-balancer membership.
They are deliberately different — `/healthz` touches no dependency, so a Postgres
blip does not make an orchestrator restart every replica and turn a recoverable
data-tier problem into an outage.

---

## What is not claimed

**The 99.5% availability target is not measured.** NFR-AVAIL-01 asks for it over
the demo period, and there is no uptime monitor against a stack that runs on a
laptop when somebody is working on it. The number would be a fiction.

**This design has not been deployed.** It is derived from reading what the code
does — which volumes hold what, which locks are taken where, which background task
starts in the lifespan — and not from having run three nodes and watched them
argue. The four items above are the ones I would expect to bite first, in that
order, and the first one would bite immediately.
