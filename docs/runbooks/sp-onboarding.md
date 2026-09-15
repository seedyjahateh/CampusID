# Runbook: onboarding a relying application

**Verified on:** 2026-09-15
**Covers:** FR-OP-01, FR-ARP-01, FR-SCIM-13

An application that authenticates people through this broker is an OIDC client
here. Registering one is two decisions — what it may ask for, and what it may be
told — and they are made in different places on purpose.

> **Gap, stated rather than hidden.** There is no admin endpoint for client
> registration today. `/admin/entities` covers SAML identity providers only, and
> dynamic client registration (RFC 7591) is not implemented. Clients are
> registered with the snippet in step 2 below, run against the broker. This is
> the one procedure here that is not an API call, and it is the first thing to
> fix if client onboarding stops being occasional.

---

## 1. Collect four things from them

| What | Why it matters |
|---|---|
| A client id | Yours to choose. It appears in every audit record and every token, so make it readable: `library-catalogue`, not `app3`. |
| Every redirect URI, exactly | Matched exactly, not by prefix. A prefix match is an open redirect waiting for somebody to append a path. |
| The scopes they need | Not the scopes they ask for. `openid` plus what the integration actually reads. |
| Whether they can keep a secret | A server-side application can. A single-page app or a mobile app cannot, and must be registered public with PKCE. |

The fourth is the one people get wrong. A public client with a secret in its
JavaScript bundle is a confidential client with a published password.

## 2. Register it

```sh
docker compose exec broker python - <<'EOF'
import asyncio, secrets
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.oidc.clients import ClientType
from campusid.oidc.registry import ClientRegistry

SECRET = secrets.token_urlsafe(32)

async def main() -> None:
    engine = create_engine(get_settings())
    try:
        registry = ClientRegistry(create_session_factory(engine))
        await registry.register(
            client_id="library-catalogue",
            client_type=ClientType.CONFIDENTIAL,
            display_name="Library catalogue",
            redirect_uris=("https://library.campus.test/oidc/callback",),
            allowed_scopes=frozenset({"openid", "profile", "email"}),
            secret=SECRET,
        )
    finally:
        await engine.dispose()
    print("client_secret:", SECRET)

asyncio.run(main())
EOF
```

**Hand the secret over once, out of band, and do not keep a copy.** Only its hash
is stored, so a lost secret is re-issued by registering again — which is the
behaviour you want, because it means nobody can read it back out of the
database.

For a public client, pass `ClientType.PUBLIC` and omit `secret`. PKCE is required
of every client regardless, so a public one is not weaker in the dimension that
matters for an authorization code.

For a provisioning client — an SIS pushing people over SCIM rather than logging
anybody in — the scopes are `scim:read` and `scim:write`, and the redirect URI is
one that cannot be reached. A client-credentials client never redirects anybody,
and a plausible-looking URI is one somebody later mistakes for a real integration.

`scim:write` does not imply `scim:read`. Give whichever the integration needs; a
reporting job with write access is how a read-only integration ends up able to
deprovision the campus.

## 3. Decide what it may be told

Registration says which scopes may be requested. The release policy says which
attributes are actually released, and default-deny means a client with no policy
file receives nothing.

Add `policies/library-catalogue.yaml`. One file per application, so adding an
application is adding a file and a review diff shows one application's policy
rather than everybody's. Policies reload without a restart.

Release the minimum that makes the integration work. "They asked for it" is not a
justification that survives a FERPA conversation, and every release is recorded
with the rule that decided it — including the ones you will be asked about.

## 4. Test before announcing

Check the client can reach the discovery document and our keys:

```sh
curl -s https://broker.campus.test/.well-known/openid-configuration | jq .issuer
curl -s https://broker.campus.test/.well-known/jwks.json | jq '.keys[].kid'
```

Then do a real authorization code round trip from their application and inspect
what was released:

```sh
curl -s -b "__Host-campusid_session=$SID" \
  "https://broker.campus.test/admin/audit?event_type=attribute.release&target=library-catalogue"
```

Compare that against what you intended. It is the same record a person sees about
themselves, and it is the one an auditor will read.

## 5. Tell them two things they will otherwise learn the hard way

**Honour `kid`.** A client that caches our JWKS without checking the key id
breaks at the next key rotation rather than at the retirement, and the rotation
is routine. See [key rotation](key-rotation.md).

**The subject is pairwise by default.** Their identifier for a person is not the
same string another application receives, deliberately. If they need a shared
identifier there is a policy setting for it, and it is a decision with a reason
attached rather than a default.

---

## Removing an application

Delete its policy file and its registration. The audit records naming it stay,
which is what an access review needs a year later.

Sessions already issued outlive the registration, so revoke the grant families
too if the removal is urgent rather than tidy:

```sh
curl -s -X POST https://broker.campus.test/oauth2/revoke \
  -d "token=$REFRESH_TOKEN&client_id=library-catalogue&client_secret=$SECRET"
```

If the removal is a response to a compromise rather than a decommissioning, go to
[compromised account](compromised-account.md) instead — an application's
credentials in the wrong hands is the same problem as a person's, with a wider
blast radius.
