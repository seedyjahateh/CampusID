# Runbook: a compromised account

**Verified on:** 2026-09-15
**Covers:** FR-ADM-06, FR-LC-03, NFR-SEC-10
**Prerequisites:** an admin session at AAL2 — see [the README](README.md)

Somebody else is using an account. The order below is not arbitrary: each step
closes a way back in that the previous one does not, and doing them in a
different order leaves a window open that the attacker is already inside.

**Contain first, investigate second.** The trail is append-only and is not going
anywhere. Access is.

---

## 1. Find out what you are dealing with

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/people/$PERSON_UUID" | jq
```

That is one read composed from the stores that own each fact — sessions,
factors, roles, group memberships, recent releases. If you do not have the
person's UUID, the audit search takes a subject key or an ePPN.

Note their **live sessions** and **which applications hold grants**. Both matter
in step 3.

## 2. Close the sessions

```sh
curl -s -X POST "https://broker.campus.test/admin/people/$PERSON_UUID/sessions/terminate" \
  -b "__Host-campusid_session=$SID" \
  -H 'Content-Type: application/json' \
  -d '{"reason": "INC-4471 credential compromise"}'
```

Omitting a session handle ends all of them. Sessions are keyed by person rather
than by identifier precisely so this means *every* session: somebody who logged
in through two identity providers has two subject keys, and ending half of them
is the failure this design exists to prevent.

This is recorded as a session termination by an administrator rather than as a
logout, because the actor is different and an investigation reads the two very
differently.

## 3. Revoke the tokens

**Ending a session does not stop a refresh token.** A destroyed session stops
`/userinfo`; it does not stop a refresh token rotating happily against a session
that no longer exists. That is the gap this step closes, and it is the one most
often missed.

For each client from step 1:

```sh
curl -s -X POST https://broker.campus.test/oauth2/revoke \
  -d "token=$REFRESH_TOKEN&client_id=$CLIENT&client_secret=$CLIENT_SECRET"
```

If you cannot enumerate the tokens — the usual case — deprovision instead. The
leaver sequence revokes every grant family belonging to every session of that
person, in the right order, and records each step as it completes:

```sh
curl -s -X DELETE "https://broker.campus.test/scim/v2/Users/$PERSON_UUID" \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

That is a soft delete. The person is deactivated, their identifiers are
tombstoned so nobody is ever issued their ePPN, and the audit trail keeps naming
them. It is reversible by a re-provision from the SIS; it is not a deletion.

## 4. Deal with the credential itself

The broker does not hold the primary credential — the upstream identity provider
does. **Password resets happen there, and this step is a phone call, not a
command.** Until it happens, the attacker can start a fresh login and everything
above buys you only the time that call takes.

What the broker does hold is second factors. If a factor may also be compromised
— a stolen phone, a shared recovery code — remove it:

```sh
curl -s -X DELETE "https://broker.campus.test/mfa/factors/$FACTOR_ID" \
  -b "__Host-campusid_session=$PERSONS_SESSION"
```

This is the person's own endpoint and needs their session, which during an
incident you will not have. Removing a factor on somebody's behalf has no admin
endpoint today — the practical answer is to deprovision as in step 3 and let
re-enrolment happen on the next login, which is also the answer that does not
require you to be able to act as somebody else.

**Leave at least one factor if you can.** An account with every factor removed
falls back to single-factor authentication, which is the direction you are trying
to move away from.

## 5. Now investigate

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/audit/subject/$PERSON_UUID" | jq
```

Oldest first, which is how you read a compromise: find where it starts, not where
you noticed. Questions the timeline answers directly:

- **Which identity provider authenticated them, and from what address.** A login
  from an unexpected provider is a different incident from a stolen password.
- **Did a second factor succeed, and which kind.** A successful `hwk` step-up is
  very hard to fake and suggests the incident is somewhere else.
- **Lockouts before the success.** Five failures then a success is a guess that
  landed.
- **What was released, and to whom.** This is the disclosure question somebody
  will ask, and it is the record that answers it.

Take a copy for the incident file. The export is itself audited, which is the
point:

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/audit/export?subject=$PERSON_UUID" \
  -o "INC-4471-$PERSON_UUID.ndjson"
```

## 6. Confirm the trail is intact

If you suspect the attacker reached the database rather than only the account:

```sh
docker compose exec broker python scripts/verify_audit_chain.py
```

It names the first broken link rather than every one after it, because every link
after a tamper is broken as a consequence. Compare the head hash against whatever
you publish it to; a trail rewritten from a tamper point forward produces a head
that no longer matches.

---

## Afterwards

- **Re-enable access deliberately**, not by reversing the steps in order. A
  re-provision from the SIS is the clean path.
- **Check whether the same address tripped the rate limiter for other accounts.**
  One compromised password is an incident; one address failing against forty
  accounts is a campaign, and the trail distinguishes them.
- **If an identity provider was the source**, disable it and work the
  [IdP onboarding](idp-onboarding.md) runbook backwards.
