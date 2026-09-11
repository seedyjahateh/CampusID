# CampusID

> A standards-native SAML/OIDC identity broker with SCIM 2.0 provisioning,
> LDAP/AD integration, and campus attribute-release policy.

CampusID federates a sample campus application against a SAML 2.0 IdP **and** an
OIDC provider, provisions and deprovisions accounts from a mock SIS over SCIM
2.0, resolves group membership from LDAP/Active Directory, and enforces
RBAC/ABAC with step-up MFA — logging every authentication, authorization, and
attribute-release decision.

**Status: M1 complete.** A browser picks an institution, signs in against one of
two real Keycloak IdPs, and lands in a broker session — through a validation
gate that rejects expired, misaddressed, replayed, wrapped and
comment-spliced assertions, and decrypts encrypted ones. Full specification:
[`docs/PRD.md`](docs/PRD.md).

## Quickstart

```sh
git clone <repo> && cd CampusID
cp .env.example .env
docker compose up -d --wait

curl http://localhost:8000/healthz        # liveness  -> 200
curl http://localhost:8000/saml/metadata  # our SP descriptor
```

### With a real IdP

```sh
docker compose --profile federation up -d
docker compose --profile federation run --rm federation-init
```

`federation-init` performs the metadata exchange in both directions: it hands
the broker's descriptor to Keycloak (creating the SAML client, pinning the
attributes Keycloak gets wrong by default, and installing the eduPerson
mappers) and registers Keycloak's descriptor with the broker.

Then open <http://localhost:8000/disco>, pick an institution, and sign in:

| Institution | User | Password |
|---|---|---|
| Campus University | `sam.obrien` | `campus-dev-password` |
| Partner College | `priya.nair` | `partner-dev-password` |

You land on `/me` with the released eduPerson attributes. Two Keycloak realms
stand in for two federation partners: each is its own SAML entity with its own
entityID and signing key, so the broker really does have to choose a
certificate by issuer.

The exchange is automated rather than pre-baked because the Keycloak client
must carry the broker's signing certificate, and the broker generates its
keypair on first start — so the certificate does not exist until it has run.
The alternative, a committed development key, is not something a project about
credential handling should ship.

| Service | Address | Purpose |
|---|---|---|
| `broker` | http://localhost:8000 | The identity broker |
| `broker` API docs | http://localhost:8000/docs | Non-production only |
| `postgres` | 127.0.0.1:55432 | Identity registry and audit store |
| `redis` | 127.0.0.1:56379 | Sessions, replay cache, rate limits, job queue |

Data-tier host ports are deliberately off-standard so the stack starts on a
machine that already runs Postgres or Redis; override them in `.env`.

### Second factors

TOTP and WebAuthn need nothing beyond the base stack. Push approval needs the
simulator:

```sh
docker compose --profile mfa up -d
CAMPUSID_PUSH_URL=http://push-sim:8100 docker compose up -d broker
```

| Service | Address | Purpose |
|---|---|---|
| `push-sim` | http://localhost:8100 | Approve or deny pending push requests |

**The push service is a simulator, and that boundary is real.** It stands in for
Duo or Okta Verify so the broker's push flow can be built and demonstrated end to
end, and it makes none of the guarantees a real one does: there is no device
registration, no cryptographic binding to a phone, and no channel an attacker
cannot open a browser tab onto. Anybody who can reach it can approve anybody's
request. Its approval page says so in a banner, because a reviewer clicking
Approve should not have to read the source to know what they are looking at.

What *is* real is the shape around it — a request raised, waited on, and resolved
as approved, denied or timed out, bound to the person who raised it, spendable
once, and expiring on the broker's own clock as well as the service's. That half
transfers to a genuine provider unchanged. The trust does not.

TOTP, WebAuthn and recovery codes carry no such caveat: those are real
implementations of RFC 6238, the WebAuthn assertion ceremony, and Argon2id-hashed
single-use codes respectively.

### The audit trail

Every audit event carries the hash of the one before it, so the trail is a chain
rather than a pile. Verify it, and print the head:

```sh
docker compose exec broker python scripts/verify_audit_chain.py
```

The chain makes *partial* tampering impossible to hide: an edited field, a
deleted row, an inserted event. It does not stop somebody who can rewrite the
whole table from the tamper point forward — publishing the head hash somewhere
they do not control is what closes that, and it is an operational practice rather
than code.

The broker connects as `campusid_app`, a role with no DDL rights and only SELECT
and INSERT on `audit_event`. An UPDATE against the trail from the application's
connection is refused by Postgres, not merely absent from the code. Migrations
connect as the schema owner, because they have to own it and the application must
not.

### Administration

The admin API lives under `/admin` and is protected by the broker it
administers: no separate password, no bypass, no token in the environment.
Reaching it needs a session, the `iam-admin` role and AAL2. Somebody without the
role gets a 404 rather than a 403, so the console's existence is not something an
ordinary account can confirm.

`POST /admin/impersonate` lets an administrator act as a fixture account to test
an SP integration. **It does not exist in production** — absent, not disabled —
and it will only assume accounts named in `CAMPUSID_IMPERSONATION_FIXTURES`.
Every action the resulting session takes is recorded against the administrator
who started it with `impersonation: true`.

## Tests

```sh
docker compose run --rm tests pytest tests/unit -v   # no containers needed
docker compose run --rm tests                        # integration, needs the stack
```

CI runs lint (`ruff`), type-check (`mypy --strict`), unit tests with an 85%
coverage gate, a secret scan over the full history, and a compose smoke test
that reproduces the quickstart on a clean runner.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Repo scaffold, data tier, migrations, CI | ✅ Complete |
| M1 | SAML SP with the full assertion validation gate, two IdPs, discovery, federation registry, sessions, encrypted assertions | ✅ Complete |
| M2 | Attribute release policy, OIDC provider, dual-protocol sample app | ✅ Complete |
| M3 | SCIM 2.0 provisioning, joiner/mover/leaver lifecycle | ✅ Complete |
| M4 | LDAP/AD, RBAC/ABAC, TOTP + WebAuthn + step-up MFA, admin API | ✅ Complete |
| M5 | Audit hash chain, dashboard, hardening, documentation | |

## Layout

```
campusid/      broker application (saml/ oidc/ scim/ directory/ policy/ mfa/ audit/ arrive per milestone)
migrations/    Alembic revisions; forward-only, advisory-locked (ADR-002)
tests/         unit/ (no containers) · integration/ (live stack) · security/ · e2e/
scripts/       entrypoint.sh · smoke.sh
docs/          PRD.md · decisions/ (ADRs)
```

## Design decisions

| ADR | Decision |
|---|---|
| [001](docs/decisions/ADR-001-language-and-stack.md) | Python + FastAPI over Java/Shibboleth and Node — and what that costs |
| [002](docs/decisions/ADR-002-forward-only-migrations.md) | Forward-only migrations behind a Postgres advisory lock |

## Data statement

All identity data in this project is synthetic. Nothing here is legal advice; a
real deployment handling student records requires review by the institution's
registrar and counsel. See the FERPA analysis in
[`docs/PRD.md` §10.4](docs/PRD.md).

## License

MIT — see [LICENSE](LICENSE).
