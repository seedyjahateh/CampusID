# Runbooks

What to do, written for whoever is on call rather than for whoever wrote the
code. No prior knowledge of the codebase is assumed, and every command is one
that has been run.

| Runbook | When you need it |
|---|---|
| [Key rotation](key-rotation.md) | Replacing SAML signing, SAML encryption, OIDC signing keys, or the pairwise salt |
| [IdP onboarding](idp-onboarding.md) | A new identity provider wants to federate with us |
| [SP onboarding](sp-onboarding.md) | A new application wants to authenticate people through us |
| [Compromised account](compromised-account.md) | Somebody's credentials are in the wrong hands |
| [Provisioning backlog](provisioning-backlog.md) | Writes to a downstream system are failing or piling up |
| [Drift remediation](drift-remediation.md) | The directory and the broker disagree about who exists |

## How to authenticate to the admin API

Every `/admin` endpoint needs three things, checked in this order: a session, a
role, and AAL2. The order decides what you are told when it refuses.

| Response | Meaning |
|---|---|
| 401 | No session, or one that has expired. Log in again. |
| 404 | You have a session but not the role. It is a 404 rather than a 403 because a 403 confirms the console exists to somebody who should not know. |
| 403 `step_up_required` | You have the role and a single-factor session. Complete a second factor and retry; this is the one refusal that tells you how to fix it. |

Commands in these runbooks use a session cookie:

```sh
curl -s -b "__Host-campusid_session=$SID" https://broker.campus.test/admin/entities
```

Obtain `$SID` by logging in through a browser and copying the cookie, or by
completing an SSO round trip with a scripted client. There is deliberately no
API token for the admin surface: every administrative action is recorded against
a person, and a token is not a person.

## Conventions

Each runbook carries a **verified on** date at the top. That is the date somebody
last ran the steps, not the date the file was edited. A runbook nobody has
executed in a year is a document, not a procedure, and the date is what makes the
difference visible.

`tests/unit/test_docs_links.py` checks that every runbook exists, carries that
date, and contains no link to a file that is not there.
