# Performance runs

Measured runs against a live development stack, producing reports committed to
[`docs/perf/`](../docs/perf). Not tests: a test asserts a property and fails,
while these produce a distribution somebody has to read.

| Run | Requirement | Target |
|---|---|---|
| `perf.provisioning_latency` | NFR-PROV-01 | p95 < 30s, p99 < 60s |
| `perf.deprovisioning_latency` | NFR-PROV-02 | p95 < 15s, p99 < 60s |

## Running them

The directory has to be in the broker's path, or the figures omit the downstream
write that both requirements name. The reports say which case they are, so a run
without it is honest rather than wrong — but it is not the measurement asked for.

Set these in `.env` and recreate the broker:

```
CAMPUSID_LDAP_URL=ldap://openldap:389
CAMPUSID_LDAP_BIND_DN=cn=admin,dc=campus,dc=test
CAMPUSID_LDAP_BIND_PASSWORD=change-me-local-only
CAMPUSID_LDAP_ALLOW_PLAINTEXT=true
```

```sh
docker compose --profile directory up -d --force-recreate --wait broker openldap
docker compose --profile directory run --rm directory-init   # first time only
curl -s http://localhost:8000/readyz | jq '.checks.directory'
```

Then:

```sh
docker compose run --rm --entrypoint python tests -m perf.provisioning_latency
docker compose run --rm --entrypoint python tests -m perf.deprovisioning_latency
```

Each writes a dated report and exits non-zero if it missed its target.

**Put `.env` back afterwards.** Leaving the directory wired changes what the
integration suite exercises, and leaving `ALLOW_PLAINTEXT` set is a setting the
broker refuses to start with in production for a reason.

## Cleaning up afterwards

Each run deletes its subjects through the SCIM API, and **a SCIM delete is soft by
design**: the person is deactivated and their identifiers tombstoned so nobody is
ever issued their ePPN again. That is the right behaviour for a broker and the
wrong behaviour for a measurement harness, because the rows accumulate and every
later run searches past them.

So the rows need removing directly, which is a development-stack operation and
has no API by design:

```sh
docker compose exec -T postgres psql -U campusid -d campusid <<'SQL'
BEGIN;
CREATE TEMP TABLE subjects AS
  SELECT DISTINCT p.person_uuid
  FROM person p JOIN identifier i USING (person_uuid)
  WHERE i.value LIKE 'perf.%@campus.test' OR i.value LIKE 'leaver.%@campus.test';
DELETE FROM lifecycle_event      WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM entitlement_grant    WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM provisioning_dead_letter WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM scim_source_record   WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM account              WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM identifier           WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM affiliation          WHERE person_uuid IN (SELECT person_uuid FROM subjects);
DELETE FROM person               WHERE person_uuid IN (SELECT person_uuid FROM subjects);
COMMIT;
SQL
```

And the directory entries, which a disable leaves in place:

```sh
docker compose exec -T openldap sh -c '
  ldapsearch -x -D "cn=admin,dc=campus,dc=test" -w change-me-local-only \
    -b "ou=people,dc=campus,dc=test" "(|(uid=perf.*)(uid=leaver.*))" dn \
  | sed -n "s/^dn: //p" \
  | xargs -r -n1 ldapdelete -x -D "cn=admin,dc=campus,dc=test" -w change-me-local-only'
```

The audit events are deliberately **not** cleaned. They are append-only and
hash-chained; deleting them by hand is the thing the whole design exists to
prevent, and a retention pass is how they go.

## What these numbers are and are not

They are a regression signal against a previous run on the same hardware. They
are not a capacity statement: the data tier, the broker, the directory and the
process driving the load all share one host, so the figures say what this stack
does when nothing else is happening to it.

The reports print the rank each percentile came from, because a p99 of 200
samples is the second-worst observation rather than a property of the system.
Where the p99 and the maximum disagree by much, the maximum is the number to ask
about.

## Not run

**NFR-PROV-03** — 100 events/minute for ten minutes with no dead-letter growth —
has no harness here. It is a soak rather than a latency measurement, it needs a
host that will not be doing anything else for ten minutes, and the figures above
suggest the interesting number is throughput under concurrency rather than the
sequential latency these runs measure. That is a real gap and it is stated rather
than implied.
