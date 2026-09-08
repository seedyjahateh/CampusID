# ADR-001: Build the broker in Python with FastAPI

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Milestone | M0 |
| Affects | All of §5; NFR-PERF-01…05, NFR-OPS-01 |

## Context

The broker must speak four protocol roles (SAML SP, OIDC RP, OIDC OP, SCIM
SP/client) and talk to LDAP, inside a five-week solo build window. The two
capabilities that dominate the choice are XML signature/encryption handling and
a usable OAuth 2.0 provider foundation — writing either from scratch is the
project.

The developer knows OAuth 2.0 and JWT already and has not implemented SAML
before, so the language should minimise time spent fighting the toolchain and
maximise time spent on the identity registry, which is where the portfolio
value sits.

## Decision

Python 3.12 with FastAPI, using `pysaml2` (over `xmlsec1`) for SAML, Authlib
for the OAuth/OIDC provider, `ldap3` for the directory, SQLAlchemy 2 with
asyncpg for Postgres, and `redis-py` for sessions and the replay cache.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Python + FastAPI** | Mature SAML and OIDC libraries; async throughout; fastest path to the registry logic; test tooling is excellent | XML signature handling depends on the native `xmlsec1` library, which is a build-environment risk | **Chosen** |
| Java + Spring Security SAML, or a real Shibboleth SP | Closest to what a university actually runs; strongest signal to an IAM hiring manager | Configuration alone would consume the build window; Shibboleth SP is a native Apache/NGINX module, so the broker would be split across two runtimes | Rejected — cost is the entire schedule |
| Node.js + `node-saml`/`oidc-provider` | `oidc-provider` is the best OIDC OP implementation in any ecosystem | `node-saml`'s validation surface is thinner, and SAML validation is the part being demonstrated | Rejected — weak where the project needs strength |
| Go | Single static binary, excellent operational story | SAML and SCIM library ecosystem is immature; more code written per feature | Rejected — no time budget for it |

## Consequences

**Accepted costs.** Native `xmlsec1` bindings must be present in the image, so
the container is heavier than a Go binary and the build is platform-sensitive.
`pysaml2`'s API is dated and its documentation is thin; expect to read its
source. Python's throughput is lower than the JVM's, which the NFR-PERF budgets
already account for.

**Reversal cost.** Expensive after M2. The registry schema and the policy
engines would port, but every protocol edge would be rewritten.

**Follow-ups.**
- Pin the `xmlsec1` system package version in the Dockerfile when SAML lands
  (M1); an unpinned upgrade has broken signature verification before.
- Verify the image builds on arm64 as well as amd64 (risk R9).

## Verification

`docker compose up` producing a healthy broker (`scripts/smoke.sh`) proves the
stack assembles. The SAML validation matrix in M1 proves the library choice
carries the security requirements; if it does not, ADR-002 records the switch.
