# CampusID

> A standards-native SAML/OIDC identity broker with SCIM 2.0 provisioning,
> LDAP/AD integration, and campus attribute-release policy.

CampusID federates a sample campus application against a SAML 2.0 IdP **and** an
OIDC provider, provisions and deprovisions accounts from a mock SIS over SCIM
2.0, resolves group membership from LDAP/Active Directory, and enforces
RBAC/ABAC with step-up MFA — logging every authentication, authorization, and
attribute-release decision.

**Status: M1a complete.** A browser can sign in against a real Keycloak IdP and
land in a broker session, through a validation gate that rejects expired,
misaddressed, replayed and signature-wrapped assertions. Full specification:
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

Then open <http://localhost:8000/saml/sso> and sign in as `sam.obrien` /
`campus-dev-password`. You land on `/me` with the released attributes.

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
| M1a | Keycloak IdP, SAML SP with the full assertion validation gate, federation registry, sessions | ✅ Complete |
| M1b | SimpleSAMLphp second IdP, discovery service, encrypted assertions | Next |
| M2 | Attribute release policy, OIDC provider, dual-protocol sample app | |
| M3 | SCIM 2.0 provisioning, joiner/mover/leaver lifecycle | |
| M4 | LDAP/AD, RBAC/ABAC, TOTP + WebAuthn + step-up MFA | |
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
