# Runbook: key rotation

**Verified on:** 2026-09-15
**Covers:** NFR-SEC-06, FR-FED-05
**Audience:** whoever is on call for the broker. No prior knowledge of the code is assumed.

CampusID holds four kinds of key material and none of them can be swapped in one
step, because in every case somebody else is holding something derived from the
old value. What differs is *who* holds it and *which direction* the overlap has
to run. Getting that direction wrong is the way a routine rotation becomes an
outage, so each procedure below leads with it.

| Material | Who else holds something | Overlap runs | Routine cadence |
|---|---|---|---|
| SAML signing key | Peers, pinned in our metadata | Publish, wait, then use | Annually |
| SAML encryption key | Peers, pinned in our metadata | Use, wait, then unpublish | Annually |
| OIDC signing key | Relying parties, cached JWKS | Use immediately, retire later | Quarterly |
| Pairwise-ID salt | Every SP, stored per user | **No overlap exists** | Never, except under compromise |

Everything lives in the `saml-keys` volume, mounted at `/var/lib/campusid/saml`.
It is the one piece of broker state that cannot be rebuilt: losing it means
re-doing the metadata exchange with every peer and invalidating every token.

---

## Before you start

Confirm which keys are live. This is also the check you repeat after each step.

```sh
docker compose exec broker python - <<'EOF'
from pathlib import Path
from campusid.keys import fingerprint, load_or_create_set
from campusid.config import get_settings

directory = Path(get_settings().saml_key_dir)
for role in ("sp-signing", "sp-encryption"):
    keys = load_or_create_set(directory, role, get_settings().base_url)
    print(role)
    for certificate in keys.certificates:
        marker = "active " if certificate == keys.active.certificate_pem else "published"
        print(f"  {marker}  {fingerprint(certificate)}")
EOF
```

Then fetch the metadata a peer actually sees, so you are comparing against what
is published rather than what is on disk:

```sh
curl -s http://localhost:8000/saml/metadata | grep -c X509Certificate
```

---

## 1. SAML signing key

**Direction: publish first, use second.** We sign our `AuthnRequest`; the peer
verifies it against a certificate they loaded from our metadata. A peer that has
not refreshed since we staged the new key has never seen the new certificate and
will reject anything signed with it. So the new key must be visible in our
metadata, and the peer must have picked it up, *before* it signs anything.

The waiting period is the slowest peer's metadata refresh interval, not ours.
For a federation that is typically 24 hours; for a bilateral partner it may be
whenever somebody runs a script. **Find out rather than assume** — this number is
the whole procedure, and the InCommon default of 24h is a reasonable floor but
not an answer for a partner who refreshes manually.

### Step 1 — stage the successor

```sh
docker compose exec broker python -c "
from pathlib import Path
from campusid import keys
from campusid.config import get_settings
settings = get_settings()
material = keys.stage(Path(settings.saml_key_dir), 'sp-signing', settings.base_url)
print(keys.fingerprint(material.certificate_pem))
"
docker compose restart broker
```

Record the fingerprint it prints; the next step needs it. The restart is required
because metadata is rendered once at startup: a document that varied between
fetches would give two peers different ideas of who we are.

Confirm the metadata now carries two signing certificates, and tell every peer to
refresh. Nothing has changed about what signs, so this step is safe to leave in
place indefinitely.

### Step 2 — wait

One full refresh interval of the slowest peer, plus a margin. Do not shorten this
because the change looks harmless; the change *is* harmless, and the waiting is
the part that does the work.

### Step 3 — promote

```sh
docker compose exec broker python -c "
from pathlib import Path
from campusid import keys
from campusid.config import get_settings
settings = get_settings()
keys.promote(Path(settings.saml_key_dir), 'sp-signing', '<fingerprint from step 1>')
"
docker compose restart broker
```

The old certificate stays published. Log in through one peer before continuing.

### Step 4 — retire, after a second wait

```sh
docker compose exec broker python -c "
from pathlib import Path
from campusid import keys
from campusid.config import get_settings
settings = get_settings()
keys.retire(Path(settings.saml_key_dir), 'sp-signing', '<old fingerprint>')
"
docker compose restart broker
```

`retire` refuses to remove the active key. That guard exists because this command
takes a fingerprint and the mistake is a copy-paste away.

### If a peer breaks mid-rotation

Roll back by promoting the old fingerprint again. Both keys are still published
and both are still on disk, which is the entire reason for the overlap. Do not
retire anything while investigating.

---

## 2. SAML encryption key

**Direction: use first, unpublish second — the opposite of signing.** The peer
encrypts to a certificate from our metadata and we decrypt. A peer that has not
refreshed is still encrypting to the *old* certificate, so the old private key
has to stay loaded until every peer has moved on.

The broker holds every key in the set and tries each in turn, so both work for as
long as both are present. The steps are the same three commands with
`sp-encryption` in place of `sp-signing`, and the difference is only in what you
may safely do early:

1. **Stage** the successor and restart. Both certificates are now published.
2. **Promote** immediately if you wish — which certificate we prefer does not
   matter, because the peer chooses and we accept either.
3. **Wait** one full refresh interval of the slowest peer.
4. **Retire** the old one. This is the step that can break a peer, and it is the
   last one rather than the first.

If a peer reports `decryption_failed` after step 4, they are still encrypting to
the retired certificate: their metadata refresh did not happen. The old key is
gone from the volume, so recovery is a re-stage plus a real conversation about
their refresh interval.

---

## 3. OIDC signing key

**Direction: use immediately, retire later.** A relying party refetches our JWKS
when it meets a `kid` it does not recognise, which is why this one needs no
advance-notice step. What it does need is for tokens already issued to keep
verifying, so the outgoing key stays published.

```sh
docker compose exec broker python -c "
from pathlib import Path
from campusid.oidc import keys
from campusid.config import get_settings
after = keys.rotate(Path(get_settings().saml_key_dir))
print('active  ', after.active.kid)
print('retiring', [key.kid for key in after.retiring])
"
docker compose restart broker
```

New tokens are signed with the new key from the restart. Both `kid`s appear in
`/.well-known/jwks.json`.

**Wait for the longest-lived token that could bear the old `kid` to expire.** That
is the refresh-token lifetime, not the access-token lifetime — check
`campusid/oidc/tokens.py` for the current values rather than trusting memory.
Then:

```sh
docker compose exec broker python -c "
from pathlib import Path
from campusid.oidc import keys
from campusid.config import get_settings
keys.retire(Path(get_settings().saml_key_dir), '<old kid>')
"
docker compose restart broker
```

Retirement is deliberately manual. On a timer, a clock problem or one unusually
long-lived refresh token turns into every session failing at once.

A relying party that caches the JWKS without honouring `kid` will break at the
rotation rather than at the retirement. That is their bug, and it is worth
knowing which of your relying parties have it *before* a compromise forces an
unplanned rotation.

---

## 4. Pairwise-ID salt

**There is no overlap, and this is not a rotation.** Every SP's identifier for
every person is derived from this salt. An SP stores the identifier it was given
and has no mechanism to be told that a different string now means the same
person. Changing the salt replaces each SP's entire user base with strangers,
simultaneously, everywhere.

Treat the value as restore-critical and back it up with the database. The broker
refuses to start in production while it still holds the development default.

**If it has to change** — which in practice means it was disclosed — this is a
migration with a project plan, not an operation:

1. Freeze provisioning.
2. For every SP, export the mapping from person to current identifier.
3. Generate the new salt and compute the new identifier for every person at every
   SP.
4. Hand each SP a mapping of old identifier to new, and have them apply it to
   their own user table. **Every SP has to do this**, and an SP that cannot is an
   SP whose users lose their accounts.
5. Deploy the new salt only once every SP has confirmed.
6. Unfreeze.

A disclosed salt does not immediately let anybody correlate users across SPs —
they would also need the person keys — but it removes the property the pairwise
scheme exists to provide, so the decision to migrate is a real one rather than a
formality.

---

## What is exercised automatically

`tests/unit/test_key_rotation_all.py` covers the mechanics of all four: that
staging does not change what signs, that promotion keeps both published, that
retirement refuses the active key, that an interrupted rotation survives a
restart, that both private keys are held during an encryption overlap, that the
outgoing OIDC key stays in the published JWKS, and that a new salt changes every
identifier.

What it cannot cover is the waiting. No test knows your slowest peer's refresh
interval, and that number is what makes each procedure above correct.
