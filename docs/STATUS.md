# Status: what is built, what is not, and why

**Verified on:** 2026-09-15

The PRD states 148 requirements. This says which are not met and why, because a
project that lists only its achievements is asking to be read carelessly. Every
entry below is a decision somebody can disagree with rather than an omission
somebody has to discover.

`tests/unit/test_requirements_coverage.py` fails if a requirement is neither
cited in the repository nor named here, so this document cannot fall silently
behind the PRD.

## How this was checked

Every requirement identifier in the PRD was matched against every citation in
code, tests, configuration, CI and documentation. That finds requirements nobody
has referenced; it does not prove the ones that are referenced are *met*. A
citation is a claim, and the tests beside it are the evidence.

Three times this week a capability turned out to be implemented, tested, and
unreachable from the running application — the SAML decryption key, the retention
pass recording itself, and the directory write on a joiner. Each was found by
asking what the application wires rather than what the package contains, and none
would have been caught by a citation scan. Treat the table below as a floor.

## Measured

| Figure | Result |
|---|---|
| Unit and security tests | 2238 passing |
| Integration tests | 374 passing, including a live Keycloak login and a live OpenLDAP tree |
| Coverage, overall | 85.66% against an 85% gate |
| Coverage, `campusid/saml` | 95.56% against a 95% gate |
| Provisioning latency p95 | 0.221s against a 30s target ([report](perf/provisioning-latency-2026-09-15.md)) |
| Deprovisioning latency p95 | 0.266s against a 15s target ([report](perf/deprovisioning-latency-2026-09-15.md)) |
| Dependency audit | no known vulnerabilities, hash-pinned |
| Trace of one login | 7 connected spans against a 5-span requirement |
| Token endpoint p95 | 0.035s against a 0.15s target ([report](perf/latency-budgets-2026-09-15.md)) |
| Authorization decision p95 | 6 microseconds against a 50ms target |

---

## Not built, by reason

### The delivery plan never scheduled them

**FR-FED-04** (federation aggregate and MDQ endpoint), **FR-FED-06** (synthetic
SSO diagnostic against a registered IdP), **FR-FED-07** (entity attributes driving
default release policy).

These appear in the requirements section and in no milestone's deliverable list.
M1 delivers FR-FED-01, 02 and 03; nothing delivers these three. That is the PRD
disagreeing with itself rather than work quietly dropped, and the honest response
is to say so rather than to pick one side silently.

FR-FED-05 was in the same position and is now built, because the key-rotation
work needed exactly what it asks for: two signing keys published at once, signing
with one and accepting either.

### A deliberate architectural divergence

**NFR-AVAIL-05** asks that provisioning be asynchronous and durable, with a
persistent queue surviving a broker restart.

Provisioning here is **synchronous**. A SCIM create commits the person, then
applies the entitlements and writes the downstream account before the handler
returns, so the 201 is a completion signal rather than an acknowledgement.

The trade, stated both ways. In favour: the source system learns immediately
whether provisioning actually succeeded, there is no queue to inspect when
somebody asks where a joiner went, and the measured latency is milliseconds
rather than a scheduling interval. Against: a slow directory is a slow SIS, a
directory outage fails the request rather than deferring it, and a restart
mid-request loses that request rather than replaying it.

The durability the requirement is reaching for is partly there: a downstream write
that fails is retried and then dead-lettered, and dead letters survive a restart
because they are rows. What is missing is the queue in front, and with it
at-least-once delivery for the request itself.

This is the one requirement where the implementation knowingly does something
else. It should be revisited if the directory ever becomes slow enough that the
SIS notices.

### They presuppose an interface this broker does not have

**NFR-UX-01** (WCAG 2.1 AA on login, MFA, consent and error pages) and **NFR-UX-03**
(MFA enrolment in four screens or fewer).

The broker serves JSON and one error page. The login form belongs to the upstream
identity provider; there is no consent screen, because release is decided by
policy rather than by asking; MFA enrolment is an API that a relying application
would build a screen for. An accessibility audit needs pages to audit.

**NFR-UX-02** — errors that say nothing useful to an attacker and carry a
correlation id a person can quote — is met, because it is about the one page that
exists.

### They presuppose infrastructure the development stack does not have

**NFR-SEC-04** (TLS 1.2 minimum, no RSA key exchange, no CBC ciphers, no
compression, verified by scanning the stack).

The development stack is plaintext on localhost by design: `__Host-` cookies
require `Secure`, which Chrome and Firefox honour on `http://localhost`, and a TLS
proxy in the compose file would be ceremony around a certificate nobody trusts.
There is no TLS endpoint to scan, so the scan would pass by measuring nothing.

The application-layer half of the requirement is enforced: HSTS is set on every
response, and the cookie attributes are asserted exactly.

**NFR-AVAIL-01** has two halves. The design for a production deployment is now
written — see [the HA design](ha-design.md), which is derived from what the code
does rather than from a template, and names the four places this broker is not
stateless. The other half asks for 99.5% availability measured over the demo
period, and there is no uptime monitor against a stack that runs on a laptop when
somebody is working on it. That number would be a fiction, so it is not claimed.

### Not measured

**NFR-PERF-02** (SSO round trip p95 < 800 ms) and **NFR-PERF-04** (SCIM filter
over 10,000 users p95 < 300 ms) are measured in part and neither figure answers
its requirement. Both are in the
[latency budgets report](perf/latency-budgets-2026-09-15.md).

NFR-PERF-02 asks for the round trip excluding upstream think time. Only the
outbound leg is timed — resolving the IdP, building the `AuthnRequest`, deflating
and signing it — at 0.329s against a 0.8s budget. The consuming half, the
fifteen-check gate, is not, because driving it once per sample means completing a
real login and a login contains the upstream the requirement excludes.

NFR-PERF-04 was measured against a directory holding five people rather than
10,000. A filter over five rows is an index lookup that never reaches the
behaviour the requirement is about. Seeding 10,000 through SCIM takes roughly
half an hour at the measured provisioning latency and was not done.

**NFR-PERF-03** (token endpoint, 0.035s against 0.15s) and **NFR-PERF-05**
(authorization decision, 6 microseconds against 50 ms) are measured and met.

**NFR-PROV-03** (100 provisioning events a minute for ten minutes, no loss, no
dead-letter growth). The harness exists — `perf/provisioning_soak.py` — and has
never run to completion. Two attempts were killed part way by host memory
pressure from work outside this project, the second with Keycloak and OpenLDAP
stopped to free half a gigabyte. Blocked by the machine rather than by the code,
which is a different thing from unwritten and is recorded as such. See
[`perf/README.md`](../perf/README.md).

**NFR-OBS-04** (audit query for one subject over 90 days under 2 s at 5 million
events). The index the requirement names exists and is exercised; the five
million rows are not. Seeding them is a machine-hours exercise and was not run.

---

## Gaps inside things that are built

Stated in the runbook that needs them rather than left to be found at three in
the morning:

- **No admin endpoint for OIDC client registration.** Clients are registered with
  a snippet against the registry. See [SP onboarding](runbooks/sp-onboarding.md).
- **No admin endpoint for listing or replaying dead letters.** FR-LC-09 asks that
  they be visible and replayable; they are both, through the store rather than
  through an API. See [provisioning backlog](runbooks/provisioning-backlog.md).
- **No admin endpoint for removing somebody else's second factor.** During an
  incident the practical answer is to deprovision. See
  [compromised account](runbooks/compromised-account.md).

## Not met, in one list

The reasons are above; this is the same set in a form a test can check, so the
prose and the claim cannot drift apart.

```text
FR-FED-04
FR-FED-06
FR-FED-07
NFR-AVAIL-01
NFR-AVAIL-05
NFR-OBS-04
NFR-PERF-02
NFR-PERF-04
NFR-PROV-03
NFR-SEC-04
NFR-UX-01
NFR-UX-03
```

Twelve of 148. Every other requirement is referenced by the work, which is a
weaker statement than "met" — see below.

## Cited but worth re-reading

Some requirements are referenced in code comments and have no test that names
them. That is a weaker claim than it looks, and the two completeness tests —
`test_negative_suite_completeness.py` for reason codes and
`test_audit_coverage.py` for event types — exist because the same gap in those
two vocabularies would be invisible.
