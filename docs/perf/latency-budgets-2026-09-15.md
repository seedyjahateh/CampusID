# Latency budgets

The four p95 ceilings NFR-PERF-02 to 05 state, measured in one run so they share a host and a moment. Read each section's notes before its table: two of the four are partial measurements and say which part is missing.

## Token endpoint (NFR-PERF-03)

**Run at:** 2026-09-15T11:14:29+00:00
**Duration:** 4.5s
**Samples:** 200

## What was measured

- 200 sequential client-credentials grants.
- Includes verifying the client secret against its Argon2 hash, which is the expensive step and the reason this budget is not smaller.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.021 | 100 of 200 | — | — |
| p95 | 0.035 | 190 of 200 | < 0.15s | pass |
| p99 | 0.045 | 198 of 200 | — | — |
| max | 0.057 | 200 of 200 | — | — |
| mean | 0.023 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.


## SCIM filtered listing (NFR-PERF-04)

**Run at:** 2026-09-15T11:14:34+00:00
**Duration:** 3.3s
**Samples:** 200

## What was measured

- 200 filtered listings with a `sw` predicate, 50 per page.
- **The directory held 5 people.** The requirement states 10,000, so this figure does not answer it: a filter over a small table is an index lookup that never reaches the interesting behaviour. Seeding 10,000 through SCIM takes roughly half an hour at the measured provisioning latency and was not done.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.015 | 100 of 200 | — | — |
| p95 | 0.025 | 190 of 200 | < 0.3s | pass |
| p99 | 0.030 | 198 of 200 | — | — |
| max | 0.035 | 200 of 200 | — | — |
| mean | 0.016 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.


## Authorization decision (NFR-PERF-05)

**Run at:** 2026-09-15T11:14:37+00:00
**Duration:** 0.0s
**Samples:** 200

## What was measured

- 200 evaluations of the shipped policy set, in process.
- Every evaluation is a cache miss: the engine is called directly.
- Measured in process because no route calls the decider — timing an HTTP request would be timing the request.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.000004 | 100 of 200 | — | — |
| p95 | 0.000006 | 190 of 200 | < 0.05s | pass |
| p99 | 0.000009 | 198 of 200 | — | — |
| max | 0.000056 | 200 of 200 | — | — |
| mean | 0.000004 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.


## SSO request generation (NFR-PERF-02, partial)

**Run at:** 2026-09-15T11:14:37+00:00
**Duration:** 41.6s
**Samples:** 200

## What was measured

- 200 sequential `GET /saml/sso` calls.
- Times the broker's outbound leg: resolving the IdP, building the `AuthnRequest`, deflating it, signing the redirect query, and storing the outstanding request and its binding nonce.
- **This is a partial measurement.** NFR-PERF-02 names the round trip; the consuming half — the fifteen-check validation gate — is not included, because driving it per sample needs a real login and a login includes the upstream think time the requirement excludes.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.194 | 100 of 200 | — | — |
| p95 | 0.329 | 190 of 200 | < 0.8s | pass |
| p99 | 0.400 | 198 of 200 | — | — |
| max | 0.414 | 200 of 200 | — | — |
| mean | 0.208 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.

