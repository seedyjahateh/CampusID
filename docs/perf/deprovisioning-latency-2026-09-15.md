# Deprovisioning latency (NFR-PROV-02)

**Run at:** 2026-09-15T09:30:44+00:00
**Duration:** 106.0s
**Samples:** 200

## What was measured

- 200 sequential deactivations, each of a person created immediately before.
- Timed from the PATCH setting `active: false` to its response. The leaver chain is synchronous, so the sample is the sum of FR-LC-03's four ordered steps rather than an acknowledgement of a queued job.
- The directory **was** in the measured path: each sample includes the downstream disable.
- The subjects held no live session or refresh token. Those steps therefore found nothing to revoke, which is the fast path — a real termination of somebody with several active sessions will be slower than this.
- Each subject was deleted after its measurement.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.159 | 100 of 200 | — | — |
| p95 | 0.266 | 190 of 200 | < 15s | pass |
| p99 | 0.366 | 198 of 200 | < 60s | pass |
| max | 0.459 | 200 of 200 | — | — |
| mean | 0.176 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.
