"""The two public OIDC metadata endpoints (FR-OP-01, FR-OP-02).

They are the only OIDC routes that need no authentication, which makes what they
do *not* contain the thing worth asserting.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from campusid.oidc import keys as oidc_keys
from campusid.oidc.keys import KeySet
from campusid.routes.oidc import METADATA_CACHE_CONTROL


async def test_the_discovery_document_is_served(client: AsyncClient) -> None:
    response = await client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    assert response.json()["issuer"] == "https://broker.test"


async def test_the_discovery_document_advertises_this_deployments_urls(
    client: AsyncClient,
) -> None:
    """Derived from the configured base URL, so a deployment behind a different
    hostname advertises itself rather than the developer's laptop."""
    document = (await client.get("/.well-known/openid-configuration")).json()

    assert document["token_endpoint"] == "https://broker.test/oauth2/token"
    assert document["jwks_uri"] == "https://broker.test/.well-known/jwks.json"


async def test_the_jwks_is_served(client: AsyncClient, oidc_key_set: KeySet) -> None:
    response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert [entry["kid"] for entry in response.json()["keys"]] == [oidc_key_set.active.kid]


async def test_the_jwks_carries_no_private_material(client: AsyncClient) -> None:
    """The document that would be catastrophic to get wrong, asserted against
    the serialised bytes rather than the object — a leak would arrive as an
    extra key in the JSON, not as a changed type."""
    body = (await client.get("/.well-known/jwks.json")).text

    for private_parameter in ('"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"'):
        assert private_parameter not in body


async def test_the_jwks_entry_carries_what_a_verifier_needs(client: AsyncClient) -> None:
    entry = (await client.get("/.well-known/jwks.json")).json()["keys"][0]

    assert entry.keys() == {"kty", "use", "alg", "kid", "n", "e"}
    assert entry["use"] == "sig"
    assert entry["alg"] == "RS256"


async def test_both_documents_are_briefly_cacheable(client: AsyncClient) -> None:
    """Long caching of the JWKS is the classic way a rotation breaks a
    federation — a client holding yesterday's document refuses today's tokens —
    while no caching puts every relying party's verification on our
    availability."""
    for path in ("/.well-known/openid-configuration", "/.well-known/jwks.json"):
        response = await client.get(path)
        assert response.headers["cache-control"] == METADATA_CACHE_CONTROL


async def test_the_jwks_publishes_both_keys_during_a_rotation(
    app: FastAPI, client: AsyncClient, oidc_key_set: KeySet
) -> None:
    """What a client fetching mid-rotation has to see: both, so a token signed
    a second before the rotation still verifies."""
    incoming = oidc_keys.generate(key_size=2048)
    app.state.oidc_keys = KeySet(active=incoming, retiring=(oidc_key_set.active,))

    published = {
        entry["kid"] for entry in (await client.get("/.well-known/jwks.json")).json()["keys"]
    }

    assert published == {incoming.kid, oidc_key_set.active.kid}


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration", "/.well-known/jwks.json"])
async def test_neither_document_needs_a_session(client: AsyncClient, path: str) -> None:
    """A client configures itself before anybody has logged in. Requiring
    authentication here would make the provider undiscoverable."""
    response = await client.get(path)

    assert response.status_code == 200


async def test_the_security_headers_still_apply(client: AsyncClient) -> None:
    """These are JSON documents served from the same origin as the login flow,
    so the middleware's headers matter here too."""
    response: Any = await client.get("/.well-known/jwks.json")

    assert "x-content-type-options" in response.headers
