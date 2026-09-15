# Runbook: drift remediation

**Verified on:** 2026-09-15
**Covers:** FR-LC-07, FR-DIR-08

Reconciliation asks the directory about every person the broker knows and reports
where the two disagree. Run it on a schedule you choose rather than on a timer
the broker owns: it walks every person and asks the directory about each, which
is a job for a quiet hour and not something the broker should decide to do to
itself while serving logins.

```sh
docker compose run --rm tests python scripts/reconcile.py
```

Dry run unless `--apply` is given. The flag is spelled out rather than
abbreviated because the difference between the two is the difference between a
report and a change to every account the report names.

---

## Reading the report

Four kinds, and what you do about each is different. That is why they are
separate values rather than one message with prose in it.

### `should_be_disabled` — the security finding

The broker says this person has left; the directory still lets them in. Somebody
who has been deprovisioned here can still authenticate there.

**This is the only kind the job will fix on its own**, and the only one worth
running with `--apply` unattended:

```sh
docker compose run --rm tests python scripts/reconcile.py --apply
```

If the count is not zero on a routine run, the interesting question is not the
accounts — it is why deprovisioning did not reach the directory. Check
[provisioning backlog](provisioning-backlog.md) before closing the finding, or
you will be closing it again next month.

### `missing_downstream` — a gap, not a hazard

An active person with no directory account. Usually somebody created
just-in-time by a federated login who was never provisioned from the SIS.

Reported rather than fixed, deliberately. Creating a directory account is a
decision with a password policy and a naming convention attached, and neither
belongs to a reconciliation job.

A handful is normal on a campus with federated guests. A hundred means the SIS
feed has stopped and nobody noticed, which is a different investigation.

### `orphaned` — reported and never touched

A directory account the broker has never heard of. It might be a service
account, a contractor somebody else provisioned, or the only administrator
account on the box.

**The job will not touch these and neither should a script you write.** Work
through them by hand, and expect most to be legitimate. The value of the list is
that it stops being a surprise, not that it shrinks.

### `unreachable` — not drift

The directory could not be asked about this person. An absence of evidence,
recorded as such so a run during an outage does not read as a clean bill of
health.

**If this count is non-zero, the run is incomplete and the totals below it mean
nothing.** Fix the directory and run again rather than acting on a partial
answer. This is the single most important line in the report and the easiest to
scroll past.

---

## When the report is large

A first run against a directory nobody has reconciled before will be. Triage in
this order:

1. **`unreachable` first.** If it is large, everything else is unreliable.
2. **`should_be_disabled` second.** People who left and can still log in.
3. **`missing_downstream` third**, as a provisioning question rather than a list
   of accounts to create.
4. **`orphaned` last**, as an inventory exercise.

Do not `--apply` a first run without reading it. The job only disables, and
disabling somebody who should not have been in the report is an outage for a real
person.

## What it cannot tell you

Reconciliation compares existence and enabled-ness. It does not compare
attributes, group membership, or entitlements. A person who exists in both places
with the wrong affiliation is not drift by this definition, and the lifecycle
timeline is where that question is answered:

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/audit/subject/$PERSON_UUID"
```

---

## Cadence

Weekly is a reasonable default for a campus. Two considerations pull against each
other: a reconciliation run costs one directory search per person, so a daily run
on a large campus is a load decision rather than a free safety net — and a
`should_be_disabled` finding is a person who can still log in for however long the
interval is.

If the deprovisioning SLO matters more than the load, the answer is to fix why
deprovisioning is not reaching the directory, not to reconcile more often.
Reconciliation is a safety net, and a safety net you rely on is a design.
