# ADR-004: Check order is a security property, and the session needs two cookies

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-09 |
| Milestone | M1 |
| Affects | FR-SAML-04…10, FR-SES-01/02/03/06, NFR-SEC-01, NFR-SEC-02 |

## Context

Two decisions in M1 look like implementation detail and are not. Both are the
kind of thing that works in testing either way and fails in production only one
way, so both are written down.

## Decision 1: the gate's checks run in a fixed order, and the order is tested

`campusid/saml/gate.py` holds an ordered tuple. Three positions in it are load-
bearing.

**Replay comes after signature verification.** Writing the assertion id into the
replay cache before checking the signature lets an unauthenticated attacker POST
forged responses carrying observed assertion ids. The cache fills with entries
the legitimate assertion will later collide with, and the victim's login fails as
a replay. That is a denial of service on authentication, mounted with no
credentials at all.

**Algorithms are pre-flighted before `signxml` sees the document.** `signxml`
raises `InvalidInput` for a disallowed method and `InvalidSignature` otherwise.
Distinguishing "SHA-1" from "wrong key" by exception message is a string match
one release away from breaking, and the reason code matters: an operator who is
told `signature_invalid` goes looking for a key rollover, and an operator told
`weak_algorithm` goes looking for a misconfigured IdP. Our own allowlist runs
first; `signxml` refuses it again as defence in depth.

**Decryption precedes assertion-signature verification.** PRD §7.3's diagram had
verify before decrypt, which is wrong whenever the assertion is both signed and
encrypted: there is nothing to verify until it is decrypted. The PRD is amended.

## Decision 2: after verification, only `signed_xml` is read

`signxml` verifies against an internal deep copy and returns it. The original
parse tree is dropped, and nothing downstream can reach it.

This is the single most important line in the milestone, and the reason it is an
ADR rather than a comment is that the obvious way to assert it does not work:
`verify_result.signed_xml is original_element` is *always* False, because the
copy is always a different object. A test written the natural way passes whether
or not the rule holds. `tests/security/test_saml_signature.py` asserts the
property by construction instead — the verifier returns the verified tree and
downstream code is given no path to the other one.

Without this rule, XSW3 through XSW8 still verify a real signature over a real
assertion and then hand the *attacker's* assertion to the identity layer. The
structural predicates in `campusid/saml/xsw.py` reject those documents outright
and run first, because PRD acceptance criterion 4 asks for rejection rather than
neutralisation. This rule is the net behind them, not the mechanism.

## Decision 3: the session uses two cookies, with different `SameSite` values

| Cookie | Attributes | Purpose |
|---|---|---|
| `__Host-campusid_session` | `Secure; HttpOnly; SameSite=Lax; Path=/` | The session (NFR-SEC-01) |
| `__Host-campusid_req` | `Secure; HttpOnly; SameSite=None; Path=/`, ~5 min | Binds one in-flight `AuthnRequest` |

Keying request state solely off `RelayState` allows login-CSRF: an attacker hands
the victim a valid `RelayState` and the victim is silently signed in as the
attacker. The fix is a nonce the attacker cannot supply — but a `Lax` cookie is
**not** sent on the cross-site POST that a genuine IdP makes to the ACS endpoint,
so the binding nonce has to be `SameSite=None`. The ACS requires the stored
`RelayState` record's nonce to equal the cookie's, and deletes both on consume.

**The development stack hides this bug.** `http://localhost:8000` and
`http://localhost:8080` are the same *site* — site is registrable-domain based
and ports are irrelevant — so the IdP-to-ACS POST is same-site locally and a
`Lax`-only design appears to work perfectly, then breaks against a real
federation partner. That is why the attribute is asserted in a unit test rather
than discovered in staging.

This amends NFR-SEC-01, which described one cookie.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Ordered tuple, tested** (chosen) | The order is visible, and a reordering fails a test that says why | A test that pins an order is a test somebody will want to "fix" | **Chosen** — the docstring says why it is there |
| Checks in whatever order reads well | Simpler | The replay-cache poisoning above is invisible until somebody mounts it | Rejected |
| One cookie, `SameSite=Lax` | Simpler; works in development | Fails against a real IdP, and the failure is a login that silently does not bind | Rejected |
| One cookie, `SameSite=None` | Works everywhere | Gives up CSRF protection on the session itself to solve a problem specific to the in-flight request | Rejected |
| `RelayState` alone | No second cookie | Login-CSRF: the value is attacker-suppliable by construction | Rejected |

## Consequences

**Accepted costs.** The gate's order is a thing to maintain: a new check has to
be placed deliberately, and `tests/security/test_gate_check_order.py` will fail
if it is not. The second cookie is a second thing to set, clear and reason about
on every ACS path.

**`__Host-` requires `Secure`,** which Chrome and Firefox honour on
`http://localhost` and Safari does not. That is an accepted development-only
exception; a TLS proxy for the dev stack is deferred rather than pretended.

**Reversal cost.** Low for the ordering — it is a tuple. High for the cookies:
removing the binding cookie reintroduces login-CSRF, so it is not a change
anybody should make without reading this.

## Verification

- `tests/security/test_gate_check_order.py` — pins the order and states the
  denial-of-service rationale in the test itself, so somebody reordering the
  tuple reads the argument before overriding it.
- `tests/security/test_saml_signature.py` — verification returns the signed copy,
  and downstream code cannot reach the unverified tree.
- `tests/security/test_xsw_attacks.py` — all eight variants rejected structurally.
- `tests/security/test_cookie_attributes.py` — the exact `Set-Cookie` for both
  cookies, including the `SameSite=None` the development stack would never have
  forced.
- `tests/unit/test_session_store.py` — the identifier rotates on authentication
  (`test_rotation_issues_a_new_identifier_and_kills_the_old`) and on elevation
  (`test_elevation_raises_assurance_and_rotates`), which is FR-SES-03.
