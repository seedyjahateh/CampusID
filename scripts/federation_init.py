"""Automated metadata exchange between the broker and Keycloak (FR-FED-02).

Runs once, after both are up, and makes them trust each other:

1. Fetch the broker's SP metadata.
2. Hand it to Keycloak's ``client-description-converter``, which turns a SAML
   descriptor into a client — the same path a Keycloak administrator uses when
   they upload an SP's metadata by hand.
3. Patch the client attributes Keycloak gets wrong by default (see below).
4. Add protocol mappers so eduPerson attributes are actually released.
5. Fetch Keycloak's IdP descriptor and register it with the broker.

This exists because a static realm import cannot contain the broker's signing
certificate: the broker generates its keypair on first start, so the
certificate is not knowable until it has run. Committing a fixed key instead
would put a private key in a repository about credential handling.

It writes the IdP registration **straight to the database** through the same
`FederationRegistry` the broker uses, rather than calling an HTTP endpoint. An
unauthenticated registration endpoint would be a hole in exactly the thing this
project is about, and the admin API that would secure it is M4 work.

Two Keycloak defaults are actively wrong for us, and both fail confusingly:

``saml.assertion.signature`` defaults to **false** — Keycloak signs the
Response but not the Assertion, so a correct SP that requires a signed
assertion rejects every login with `signature_missing`.

``saml.client.signature`` defaults to **true**, meaning Keycloak expects our
`AuthnRequest` to be signed and needs our certificate to check it. Import the
client without that certificate and every login fails before it starts.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import httpx

from campusid.db import create_engine, create_session_factory
from campusid.federation.registry import FederationRegistry

BROKER = os.environ.get("FEDERATION_BROKER_URL", "http://broker:8000")
KEYCLOAK = os.environ.get("FEDERATION_KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.environ.get("FEDERATION_KEYCLOAK_REALM", "campus")
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
    # form silently releases nothing, which looks identical to a release-policy
    # problem from the SP side.
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
    """Poll until ``url`` answers, or give up loudly."""
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


async def upsert_saml_client(client: httpx.AsyncClient, token: str, sp_metadata: bytes) -> str:
    """Create or update the broker's client in Keycloak from its metadata."""
    headers = {"Authorization": f"Bearer {token}"}

    converted = await client.post(
        f"{KEYCLOAK}/admin/realms/{REALM}/client-description-converter",
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
        f"{KEYCLOAK}/admin/realms/{REALM}/clients",
        params={"clientId": client_id},
        headers=headers,
    )
    existing.raise_for_status()
    found = existing.json()

    if found:
        internal_id = found[0]["id"]
        representation["id"] = internal_id
        updated = await client.put(
            f"{KEYCLOAK}/admin/realms/{REALM}/clients/{internal_id}",
            json=representation,
            headers=headers,
        )
        updated.raise_for_status()
        log(f"updated SAML client {client_id}")
    else:
        created = await client.post(
            f"{KEYCLOAK}/admin/realms/{REALM}/clients",
            json=representation,
            headers=headers,
        )
        created.raise_for_status()
        internal_id = created.headers["location"].rsplit("/", 1)[-1]
        log(f"created SAML client {client_id}")

    await add_attribute_mappers(client, token, internal_id)
    return client_id


async def add_attribute_mappers(client: httpx.AsyncClient, token: str, internal_id: str) -> None:
    """Release the eduPerson attributes the broker asks for."""
    headers = {"Authorization": f"Bearer {token}"}
    base = f"{KEYCLOAK}/admin/realms/{REALM}/clients/{internal_id}/protocol-mappers/models"

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
    log(f"attribute mappers present ({len(ATTRIBUTE_MAPPERS)})")


async def register_idp_with_broker() -> str:
    """Load Keycloak's descriptor into the broker's registry."""
    async with httpx.AsyncClient() as client:
        descriptor_url = f"{KEYCLOAK}/realms/{REALM}/protocol/saml/descriptor"
        response = await client.get(descriptor_url)
        response.raise_for_status()
        document = response.content

    engine = create_engine_from_environment()
    try:
        registry = FederationRegistry(create_session_factory(engine))
        descriptor = await registry.register_idp(
            document, metadata_url=descriptor_url, display_name="Campus Keycloak"
        )
    finally:
        await engine.dispose()

    log(f"registered IdP {descriptor.entity_id}")
    return descriptor.entity_id


def create_engine_from_environment() -> Any:
    from campusid.config import Settings

    return create_engine(Settings())


async def main() -> int:
    async with httpx.AsyncClient(follow_redirects=True) as client:
        await wait_for(client, f"{BROKER}/healthz", "broker")
        await wait_for(client, f"{KEYCLOAK}/realms/{REALM}", "keycloak")

        metadata = await client.get(f"{BROKER}/saml/metadata")
        metadata.raise_for_status()
        log(f"fetched SP metadata ({len(metadata.content)} bytes)")

        token = await admin_token(client)
        client_id = await upsert_saml_client(client, token, metadata.content)

    entity_id = await register_idp_with_broker()

    log("metadata exchange complete")
    log(f"  broker entityID : {client_id}")
    log(f"  idp entityID    : {entity_id}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
