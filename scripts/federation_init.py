"""Automated metadata exchange between the broker and Keycloak (FR-FED-02).

Runs once, after both are up, and makes them trust each other. For each realm:

1. Fetch the broker's SP metadata.
2. Hand it to Keycloak's ``client-description-converter``, which turns a SAML
   descriptor into a client - the same path a Keycloak administrator uses when
   they upload an SP's metadata by hand.
3. Patch the client attributes Keycloak gets wrong by default (see below).
4. Add protocol mappers so eduPerson attributes are actually released.
5. Fetch that realm's IdP descriptor and register it with the broker.

This exists because a static realm import cannot contain the broker's signing
certificate: the broker generates its keypair on first start, so the
certificate is not knowable until it has run. Committing a fixed key instead
would put a private key in a repository about credential handling.

It writes the IdP registration **straight to the database** through the same
`FederationRegistry` the broker uses, rather than calling an HTTP endpoint. An
unauthenticated registration endpoint would be a hole in exactly the thing this
project is about, and the admin API that would secure it is M4 work.

Two Keycloak defaults are actively wrong for us, and both fail confusingly:

``saml.assertion.signature`` defaults to **false**, so Keycloak signs the
Response but not the Assertion and a correct SP that requires a signed
assertion rejects every login with `signature_missing`.

``saml.client.signature`` defaults to **true**, so Keycloak expects our
`AuthnRequest` to be signed and needs our certificate to check it. Import the
client without that certificate and every login fails before it starts.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import httpx

from campusid.config import Settings
from campusid.db import create_engine, create_session_factory
from campusid.federation.registry import FederationRegistry

BROKER = os.environ.get("FEDERATION_BROKER_URL", "http://broker:8000")
KEYCLOAK = os.environ.get("FEDERATION_KEYCLOAK_URL", "http://keycloak:8080")

REALMS = [
    realm.strip()
    for realm in os.environ.get("FEDERATION_KEYCLOAK_REALMS", "campus,partner").split(",")
    if realm.strip()
]
"""Each Keycloak realm is a separate SAML entity with its own entityID and its
own signing key, so two realms give the broker two genuinely distinct IdPs to
discover between - which is what FR-SAML-10 needs in order to be worth testing.

A second *implementation* such as SimpleSAMLphp would additionally prove
cross-vendor interoperability. That is a different property and it is deferred:
the honest summary is that this exercises our multi-IdP handling, not our
interoperability with a second product."""

ADMIN_USER = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")

READY_ATTEMPTS = 60
READY_DELAY = 2.0

# Every one of these is pinned rather than left to Keycloak's default, so a
# Keycloak upgrade cannot silently change what our peer promises to do.
CLIENT_ATTRIBUTES: dict[str, str] = {
    "saml.assertion.signature": "true",
    "saml.server.signature": "true",
    "saml.client.signature": "true",
    "saml.signature.algorithm": "RSA_SHA256",
    "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
    "saml.force.post.binding": "true",
    "saml.authnstatement": "true",
    "saml_name_id_format": "persistent",
    "saml.encrypt": "false",
}

ATTRIBUTE_MAPPERS: list[tuple[str, str, str]] = [
    # (mapper name, Keycloak user attribute, SAML attribute name)
    #
    # The SAML names are the eduPerson OIDs, with NameFormat "URI Reference".
    # Shibboleth and Keycloak both key their mappers on the URI form; the basic
    # form silently releases nothing, which from the SP side looks identical to
    # a release-policy problem.
    ("eppn", "eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
    ("scoped-affiliation", "eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"),
    ("primary-affiliation", "eduPersonPrimaryAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"),
    ("entitlement", "eduPersonEntitlement", "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"),
    ("display-name", "displayName", "urn:oid:2.16.840.1.113730.3.1.241"),
    ("org-unit", "ou", "urn:oid:2.5.4.11"),
]


def log(message: str) -> None:
    print(f"federation-init: {message}", flush=True)


async def wait_for(client: httpx.AsyncClient, url: str, what: str) -> None:
    """Poll until ``url`` answers, or give up loudly.

    Keycloak's image is distroless, with no shell for a compose healthcheck to
    use, so readiness is polled from here instead.
    """
    for attempt in range(1, READY_ATTEMPTS + 1):
        try:
            response = await client.get(url, timeout=5.0)
        except httpx.HTTPError:
            pass
        else:
            if response.status_code < 500:
                log(f"{what} is up")
                return
        if attempt % 5 == 0:
            log(f"waiting for {what} ({attempt}/{READY_ATTEMPTS})")
        await asyncio.sleep(READY_DELAY)
    raise SystemExit(f"federation-init: {what} never became ready at {url}")


async def admin_token(client: httpx.AsyncClient) -> str:
    response = await client.post(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


async def upsert_saml_client(
    client: httpx.AsyncClient, token: str, realm: str, sp_metadata: bytes
) -> str:
    """Create or update the broker's client in one realm, from its metadata."""
    headers = {"Authorization": f"Bearer {token}"}

    converted = await client.post(
        f"{KEYCLOAK}/admin/realms/{realm}/client-description-converter",
        content=sp_metadata,
        headers={**headers, "Content-Type": "application/xml"},
    )
    converted.raise_for_status()
    representation: dict[str, Any] = converted.json()

    representation["attributes"] = {
        **representation.get("attributes", {}),
        **CLIENT_ATTRIBUTES,
    }
    representation["enabled"] = True
    client_id = str(representation["clientId"])

    existing = await client.get(
        f"{KEYCLOAK}/admin/realms/{realm}/clients",
        params={"clientId": client_id},
        headers=headers,
    )
    existing.raise_for_status()
    found = existing.json()

    if found:
        internal_id = found[0]["id"]
        representation["id"] = internal_id
        updated = await client.put(
            f"{KEYCLOAK}/admin/realms/{realm}/clients/{internal_id}",
            json=representation,
            headers=headers,
        )
        updated.raise_for_status()
        log(f"[{realm}] updated SAML client {client_id}")
    else:
        created = await client.post(
            f"{KEYCLOAK}/admin/realms/{realm}/clients",
            json=representation,
            headers=headers,
        )
        created.raise_for_status()
        internal_id = created.headers["location"].rsplit("/", 1)[-1]
        log(f"[{realm}] created SAML client {client_id}")

    await add_attribute_mappers(client, token, realm, internal_id)
    return client_id


async def add_attribute_mappers(
    client: httpx.AsyncClient, token: str, realm: str, internal_id: str
) -> None:
    """Release the eduPerson attributes the broker asks for."""
    headers = {"Authorization": f"Bearer {token}"}
    base = f"{KEYCLOAK}/admin/realms/{realm}/clients/{internal_id}/protocol-mappers/models"

    current = await client.get(base, headers=headers)
    current.raise_for_status()
    existing = {mapper["name"] for mapper in current.json()}

    for name, user_attribute, saml_name in ATTRIBUTE_MAPPERS:
        if name in existing:
            continue
        response = await client.post(
            base,
            headers=headers,
            json={
                "name": name,
                "protocol": "saml",
                "protocolMapper": "saml-user-attribute-mapper",
                "config": {
                    "user.attribute": user_attribute,
                    "attribute.name": saml_name,
                    "attribute.nameformat": "URI Reference",
                    "friendly.name": user_attribute,
                },
            },
        )
        response.raise_for_status()
    log(f"[{realm}] attribute mappers present ({len(ATTRIBUTE_MAPPERS)})")


async def register_idps_with_broker(realms: list[str]) -> list[str]:
    """Load each realm's descriptor into the broker's registry."""
    documents: list[tuple[str, str, bytes]] = []
    async with httpx.AsyncClient() as client:
        for realm in realms:
            url = f"{KEYCLOAK}/realms/{realm}/protocol/saml/descriptor"
            response = await client.get(url)
            response.raise_for_status()
            documents.append((realm, url, response.content))

    engine = create_engine(Settings())
    entity_ids: list[str] = []
    try:
        registry = FederationRegistry(create_session_factory(engine))
        for realm, url, document in documents:
            descriptor = await registry.register_idp(
                document, metadata_url=url, display_name=_display_name(realm)
            )
            entity_ids.append(descriptor.entity_id)
            log(f"[{realm}] registered IdP {descriptor.entity_id}")
    finally:
        await engine.dispose()

    return entity_ids


def _display_name(realm: str) -> str:
    """What the discovery chooser shows. Names, not entityIDs: a user picking
    their institution should not have to read a URL."""
    return {"campus": "Campus University", "partner": "Partner College"}.get(realm, realm.title())


SIS_CLIENT_ID = "campus-sis"
SIS_SECRET = "dev-only-provisioning-secret-not-for-production"  # noqa: S105
"""A fixed development secret, and it is fixed on purpose.

Everywhere else this project refuses to commit a credential — the SAML keypair
is generated on first boot precisely so no private key is in the repository. The
difference is that this one is *only* usable against a broker whose own
`CAMPUSID_ENVIRONMENT` is `dev`, it grants nothing but SCIM scopes on a database
full of fixture people, and the alternative is a generated secret that the
integration tests would then have to read out of the container.

A real deployment registers its SIS through the admin API and gets a generated
secret once. This script runs only under the `federation` compose profile.
"""


async def register_provisioning_client() -> None:
    """Register the SIS as a confidential client with the SCIM scopes.

    FR-SCIM-13's other half. The SCIM API takes a bearer token from this
    broker's own token endpoint, so there has to *be* a client that can get one
    — and a provisioning client uses the client-credentials grant, because an
    SIS runs at three in the morning and there is nobody to authenticate.
    """
    from campusid.oidc.claims import SCOPE_SCIM_READ, SCOPE_SCIM_WRITE
    from campusid.oidc.clients import ClientType
    from campusid.oidc.registry import ClientRegistry

    engine = create_engine(Settings())
    try:
        registry = ClientRegistry(create_session_factory(engine))
        await registry.register(
            client_id=SIS_CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            display_name="Campus SIS (development fixture)",
            # A client-credentials client never redirects anybody, but a
            # registration must carry a redirect URI — so it gets one that
            # cannot be reached, rather than a plausible one somebody might
            # later mistake for a real integration.
            redirect_uris=("https://sis.campus.test/unused",),
            allowed_scopes=frozenset({"openid", SCOPE_SCIM_READ, SCOPE_SCIM_WRITE}),
            secret=SIS_SECRET,
        )
        log(f"registered provisioning client {SIS_CLIENT_ID}")
    finally:
        await engine.dispose()


async def main() -> int:
    async with httpx.AsyncClient(follow_redirects=True) as client:
        await wait_for(client, f"{BROKER}/healthz", "broker")
        await wait_for(client, f"{KEYCLOAK}/realms/{REALMS[0]}", "keycloak")

        metadata = await client.get(f"{BROKER}/saml/metadata")
        metadata.raise_for_status()
        log(f"fetched SP metadata ({len(metadata.content)} bytes)")

        token = await admin_token(client)
        for realm in REALMS:
            await upsert_saml_client(client, token, realm, metadata.content)

    entity_ids = await register_idps_with_broker(REALMS)
    await register_provisioning_client()

    log("metadata exchange complete")
    for entity_id in entity_ids:
        log(f"  idp entityID : {entity_id}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
