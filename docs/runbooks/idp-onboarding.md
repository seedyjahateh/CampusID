# Runbook: onboarding an identity provider

**Verified on:** 2026-09-15
**Covers:** FR-FED-01, FR-FED-02, FR-ADM-02
**Prerequisites:** an admin session at AAL2 — see [the README](README.md)

A new IdP means a new source of assertions this broker will believe. Everything
below is in service of one question: **what exactly are we agreeing to trust, and
can we stop trusting it without losing the record?**

---

## 1. Get their metadata, and read it before registering it

Ask for a metadata URL rather than a file. A URL can be refreshed; a file has to
be re-sent by somebody who has left.

```sh
curl -s https://idp.partner.edu/metadata | head -40
```

Three things to check by eye before anything else:

- **The entityID.** It is an identifier, not an address, and it is what every
  audit record will name. If it changes later, that is a different IdP as far as
  this broker and its trail are concerned.
- **`validUntil`.** Metadata past its expiry is refused, deliberately. If theirs
  is short, find out how they refresh it before you depend on it.
- **The signing certificate.** This is the whole of the trust decision. Confirm
  its fingerprint out of band — a phone call to somebody you know — because a
  metadata document fetched over TLS proves only that somebody controls the
  hostname.

## 2. Register it

```sh
curl -s -X POST https://broker.campus.test/admin/entities \
  -b "__Host-campusid_session=$SID" \
  -H 'Content-Type: application/json' \
  -d '{"metadata_url": "https://idp.partner.edu/metadata", "reason": "TICKET-1234 partner federation"}'
```

The reason is required and goes in its own column, so "every federation change
and why" is a query rather than a search through JSON.

The endpoint fetches the document server-side and **does not follow redirects**.
A fetch of an operator-supplied URL that chased redirects is how an allowlisted
address becomes an arbitrary one. If the partner's URL redirects, ask them for
the final one.

Confirm what the parser made of it — this is what the gate will actually use, not
what the document appears to say:

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/entities/$(printf %s 'https://idp.partner.edu/idp' | jq -sRr @uri)"
```

Check the certificate fingerprint here against the one you confirmed by phone.

## 3. Send them ours

```sh
curl -s https://broker.campus.test/saml/metadata -o campusid-metadata.xml
```

Tell them to load it by URL, for the same reason we asked them to. If they load a
file, they will not pick up a key rotation and the first they will know of it is
a failed login — see [key rotation](key-rotation.md) for why the overlap window
exists and what it assumes about their refresh interval.

## 4. Test a login before anybody depends on it

Start an authentication against the new entityID directly:

```
https://broker.campus.test/saml/sso?idp=https%3A%2F%2Fidp.partner.edu%2Fidp
```

If it fails, the browser is told nothing useful on purpose. The reason code is in
the trail, against the correlation id shown on the error page:

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/audit?correlation_id=$REFERENCE"
```

The four failures that account for most first logins:

| Reason code | What it usually means |
|---|---|
| `signature_missing` | They are signing the Response and not the Assertion. Most products default to this. |
| `audience_mismatch` | Their `Audience` is not our entityID. Usually a copy of another SP's config. |
| `destination_mismatch` | They are posting to a different ACS URL than the one in our metadata. |
| `assertion_expired` | Clock skew. Check both ends against NTP before adjusting tolerance. |

Do not widen the clock-skew setting to make a login work. It is bounded at 300
seconds by the configuration schema for the reason that widening it is the quiet
way a replay window becomes exploitable.

## 5. Decide what they may assert

Registration establishes trust in the signature. It does not decide what the
assertion may *say*. Identifiers this broker issues and entitlements it derives
override anything asserted under those names, which is what stops an upstream
granting itself access — but confirm the release policy for the applications
those users will reach before announcing the integration.

---

## Turning it off

Disabling is not deletion, and that is the point:

```sh
curl -s -X POST "https://broker.campus.test/admin/entities/$ENTITY/enabled" \
  -b "__Host-campusid_session=$SID" \
  -H 'Content-Type: application/json' \
  -d '{"enabled": false, "reason": "TICKET-5678 suspected compromise"}'
```

Logins stop immediately. The entity, its metadata history and every audit record
naming it remain, which is what an investigation needs. Re-enabling is the same
call with `true`.

**Disable before you investigate, not after.** A suspected IdP compromise means
every assertion it sends is suspect, and the cost of a wrong disable is an
outage for one partner while the cost of a wrong delay is sessions you did not
authorise.
