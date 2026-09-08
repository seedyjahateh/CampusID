# Keycloak realm

`realm-campus.json` is imported at container start (`--import-realm`). It
carries the realm and its fixture users, and deliberately **no SAML client**.

Keycloak's realm importer rejects any field it does not recognise — including
comment keys — so the reasoning lives here rather than inline.

## Why the SAML client is not in this file

The client must carry the broker's signing certificate, and that certificate
does not exist until the broker has started once and generated its keypair. A
static import cannot contain it.

The alternative would be committing a fixed development key, which a repository
about credential handling should not do, and which gitleaks would fail the
build for. So `scripts/federation_init.py` creates the client after both
services are up, from the broker's own published metadata — the same path a
Keycloak administrator uses when they upload an SP descriptor by hand.

## Fixture users

From PRD NFR-OPS-04. Password for all of them is `campus-dev-password`.

| Username | Purpose |
|---|---|
| `sam.obrien` | Baseline student. Name carries an apostrophe and combining diacritics — XML canonicalisation and LDAP DN escaping both break on those, and an all-ASCII fixture set would never reveal it. |
| `dana.wu` | Dual affiliation (staff **and** student), so entitlement union is exercised. |
| `marcus.reed` | FERPA directory-suppressed; the attribute-release policy in M2 must refuse to release directory attributes for them. |
| `terminated.tim` | Disabled in Keycloak. Authentication fails upstream, which is a different path from the broker's own `subject_deactivated`. |

## Ports

Keycloak publishes on **18080**, not 8080, so the stack starts on a machine
already running something there.

`KC_HOSTNAME` must be the URL a *browser* can reach, because Keycloak generates
the URLs in its SAML descriptor from it. The broker fetches that same
descriptor over the internal compose network and still receives browser-usable
URLs — which is what lets the whole arrangement work with no hosts-file entry.
An `entityID` is an identifier, not a fetch address.

Change `KEYCLOAK_PORT` and you must change `KEYCLOAK_PUBLIC_URL` and
`CAMPUSID_SAML_DEFAULT_IDP` with it: the realm URL *is* the entityID.
