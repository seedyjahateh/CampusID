# ADR-003: Own the SAML validation gate on signxml, not pysaml2

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Milestone | M1 |
| Affects | FR-SAML-01…11, NFR-SEC-02, NFR-OPS-01, NFR-OPS-05 |
| Supersedes | ADR-001's SAML line (`pysaml2` over `xmlsec1`) |

## Context

ADR-001 chose `pysaml2` on the reasonable argument that nobody should write a
SAML stack in a five-week window. Building M1 changed two facts behind that.

**The deliverable is the rejection path, not the login.** PRD §12.2 makes the
negative matrix the primary artefact for the security reviewer, and §14.1 gates
CI on it. A library that accepts or rejects an assertion is exactly what is
needed for a working login and exactly not what is needed for a test that says
*which* of fifteen checks refused it and why. `pysaml2` raises a handful of
exception types across a validation path it owns; mapping those onto
per-check reason codes means matching on exception messages, which is a string
comparison one upstream release away from breaking silently.

**`xmlsec1` is a native build.** `pysaml2` needs `python-xmlsec`, which needs
`libxmlsec1` and its headers. That is PRD risk R1 (a canonicalisation and build
tar pit) and risk R9 (a reviewer on an arm64 laptop cannot run the project).
Neither risk is about correctness and both are about whether the work is
*seen*.

## Decision

Build the assertion gate in this repository on top of `signxml` 5.1.0, which is
pure `lxml` plus `cryptography`. The gate is an ordered tuple of named checks in
`campusid/saml/gate.py`; each raises `SamlRejected(ReasonCode.X)` with a reason
code from a single registry in `campusid/errors.py`.

`signxml` is used for one thing: verifying an XML digital signature against a
certificate we supply. Everything else — parsing, structural checks, audience,
conditions, subject confirmation, replay — is ours.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **signxml + our own gate** (chosen) | Per-check reason codes are possible; no native build, so the image is multi-arch and a reviewer can run it; the security argument is legible in the repository | We own every check, including the ones a library would have got right for free; a mistake is ours | **Chosen** |
| `pysaml2` with `xmlsec1` | A mature stack that has seen real federations; far less code | Native build (R1, R9); reason codes become exception-message matching; the reviewer sees a configuration, not an argument | Rejected — it optimises for the login, and the login is not the deliverable |
| `python3-saml` | Simpler API than `pysaml2` | Also `xmlsec1`; and it is the stack that carried CVE-2017-11427, the comment-truncation bug this project tests for by name | Rejected |
| Verify signatures by hand with `cryptography` | No dependency at all | Canonicalisation is the part nobody should write twice, and getting exclusive c14n wrong fails open | Rejected |

## Consequences

**What this buys.** Fifteen checks with fifteen reason codes, each independently
forgeable by the test IdP in `tests/support/saml_forge.py` and independently
asserted. Eight XSW variants rejected by named structural predicates rather than
rendered harmless by accident. A build with no compiler in it.

**What it costs, honestly.** Every check is ours to get wrong, and some of them
are subtle — the `signed_xml` rule below is a bug this project would have had if
it had not been written down. A library would have covered them without being
asked. The trade is defensible only because the checks are visible and tested;
it would be indefensible in a codebase where they were not.

**`require_x509=True` does no PKIX validation.** `signxml` will verify against
the certificate we hand it and will not build or check a chain. That is correct
for SAML — trust comes from metadata, not from a public CA — and is recorded
here so a reviewer does not read its absence as an oversight.

**Reversal cost.** Moderate. The gate's checks are independent of the signature
library; swapping `signxml` for `xmlsec` bindings would touch
`campusid/saml/signature.py` and nothing else. The risk register names that as
the fallback if a real Keycloak assertion had failed to verify.

## Verification

- `tests/security/test_saml_validation_matrix.py` — every check, accepted and
  rejected, with its reason code.
- `tests/security/test_xsw_attacks.py` — eight wrapping variants, each rejected
  as `signature_wrapping_detected` rather than merely ignored.
- `tests/security/test_algorithm_allowlist.py` — SHA-1 and MD5 refused as
  `weak_algorithm`, not as `signature_invalid`, which is the whole reason the
  algorithm allowlist is pre-flighted before `signxml` sees the document.
- `tests/security/test_negative_suite_completeness.py` — every reason code in the
  registry is exercised by at least one test, so a check cannot be added without
  a test that reaches it.
- `tests/integration/test_keycloak_sso.py` — a real assertion from a real IdP
  verifies, which is the claim the fallback existed for.
