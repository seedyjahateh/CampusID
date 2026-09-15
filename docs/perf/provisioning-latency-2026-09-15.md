# Provisioning latency (NFR-PROV-01)

**Run at:** 2026-09-15T09:28:55+00:00
**Duration:** 78.0s
**Samples:** 200

## What was measured

- 200 sequential SCIM creates, each carrying a `student` affiliation.
- Timed from the request to the 201. The provisioning chain is synchronous: the handler applies entitlements and writes the downstream account before returning, so the response is the completion signal rather than an acknowledgement.
- The directory **was** in the measured path: the broker has one configured, so each sample includes the downstream account write.
- Each subject was deleted after its measurement.

## Result

| Figure | Seconds | Rank | Target | Verdict |
|---|---|---|---|---|
| p50 | 0.139 | 100 of 200 | — | — |
| p95 | 0.221 | 190 of 200 | < 30s | pass |
| p99 | 0.262 | 198 of 200 | < 60s | pass |
| max | 0.531 | 200 of 200 | — | — |
| mean | 0.153 | — | — | — |

## Reading this

Every figure is an observation rather than an interpolation, and the rank column says which one. With 200 samples the p99 is the 198th slowest — one event, not a property of the system. Where it and the maximum disagree by much, the maximum is the number to ask about.

This is a development stack on one host: the data tier, the broker and the directory share a machine with the process driving the load. The figures are useful for finding a regression against a previous run on the same hardware, and are not a capacity statement.
