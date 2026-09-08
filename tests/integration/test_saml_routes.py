"""A complete SSO round trip over HTTP (PRD acceptance criterion 1, in part).

Drives the running broker exactly as a browser would — start at `/saml/sso`,
follow the redirect, answer it at `/saml/acs`, land on `/me` — with the forge
standing in for the IdP. Keycloak replaces the forge in the federation profile;
everything on the broker's side of the exchange is the same code path.

This is the first test that exercises the routes, the registry, both Redis
stores, the gate, the session store and the cookie policy together. Each has
its own unit tests; none of them proves they are wired to each other.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from lxml import etree
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.federation.models import FederationEntity
from campusid.federation.registry import FederationRegistry
from campusid.saml.authn_request import decode_saml_request
from campusid.saml.namespaces import SAMLP, qn
from campusid.session.cookies import REQUEST_BINDING_COOKIE, SESSION_COOKIE
from tests.support.saml_forge import ForgedIdP

pytestmark = pytest.mark.integration

BROKER = "http://broker:8000"
"""Reached over the compose network. The broker's own view of itself is
`https://broker.test` in tests, which is what its Destination and Audience are
built from — see `_forge_response`."""


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def registered_idp(engine: AsyncEngine) -> AsyncIterator[ForgedIdP]:
    """An IdP the broker trusts, registered directly into its database."""
    sessions: async_sessionmaker[AsyncSession] = create_session_factory(engine)
    idp = ForgedIdP(entity_id="https://forge.test/saml")
    # The broker builds Destination and Audience from its own base_url.
    settings = get_settings()
    idp.default_audience = f"{settings.base_url}/saml/metadata"
    idp.default_destination = f"{settings.base_url}/saml/acs"

    await FederationRegistry(sessions).register_idp(idp.metadata())
    yield idp

    async with sessions() as session, session.begin():
        await session.execute(
            delete(FederationEntity).where(FederationEntity.entity_id == idp.entity_id)
        )


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BROKER, follow_redirects=False) as http:
        yield http


# --- metadata --------------------------------------------------------------


async def test_metadata_is_published_and_valid(client: httpx.AsyncClient) -> None:
    from campusid.saml.metadata_sp import validate_metadata

    response = await client.get("/saml/metadata")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/samlmetadata+xml")
    validate_metadata(response.content)


async def test_metadata_is_byte_stable_across_requests(client: httpx.AsyncClient) -> None:
    """Two peers fetching our descriptor must get the same document, or they
    end up with different ideas of who we are."""
    first = await client.get("/saml/metadata")
    second = await client.get("/saml/metadata")

    assert first.content == second.content


# --- starting a login ------------------------------------------------------


async def test_sso_redirects_to_the_idp_with_a_signed_request(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    response = await client.get("/saml/sso", params={"idp": registered_idp.entity_id})

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(f"{registered_idp.entity_id}/sso?")

    query = parse_qs(urlsplit(location).query)
    assert {"SAMLRequest", "RelayState", "SigAlg", "Signature"} <= query.keys()

    request = etree.fromstring(decode_saml_request(query["SAMLRequest"][0]))
    assert request.tag == qn(SAMLP, "AuthnRequest")


async def test_sso_sets_the_request_binding_cookie(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    """`SameSite=None`, because the IdP's POST back to our ACS is cross-site."""
    response = await client.get("/saml/sso", params={"idp": registered_idp.entity_id})

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{REQUEST_BINDING_COOKIE}=")
    assert "SameSite=none" in cookie
    assert "HttpOnly" in cookie


async def test_sso_against_an_unregistered_idp_is_refused(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/saml/sso", params={"idp": "https://stranger.test/saml"})

    assert response.status_code == 400
    assert "stranger.test" not in response.text  # the reason is audited, not rendered


# --- the full round trip ---------------------------------------------------


def _unique_assertion_id() -> str:
    """A fresh assertion ID per test.

    The broker's replay cache is real Redis and outlives an individual test, so
    reusing the forge's default would have one test's assertion rejected as a
    replay of another's — which is the cache working correctly, and exactly why
    real IdPs mint a new ID for every assertion.
    """
    return f"_{secrets.token_hex(12)}"


async def _begin_login(client: httpx.AsyncClient, idp: ForgedIdP) -> tuple[str, str]:
    """Start SSO, arm the client's binding cookie, and return the request id
    and relay state the IdP would echo back."""
    response = await client.get("/saml/sso", params={"idp": idp.entity_id})
    query = parse_qs(urlsplit(response.headers["location"]).query)
    request = etree.fromstring(decode_saml_request(query["SAMLRequest"][0]))
    client.cookies.set(REQUEST_BINDING_COOKIE, response.cookies[REQUEST_BINDING_COOKIE])
    return request.get("ID") or "", query["RelayState"][0]


async def test_a_full_sso_round_trip_establishes_a_session(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    """The acceptance criterion, with the forge standing in for Keycloak."""
    request_id, relay_state = await _begin_login(client, registered_idp)

    document = registered_idp.response(
        assertion_id=_unique_assertion_id(),
        in_response_to=request_id,
        attributes={"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": ["student@campus.edu"]},
    )
    acs = await client.post(
        "/saml/acs",
        data={
            "SAMLResponse": base64.b64encode(document).decode(),
            "RelayState": relay_state,
        },
    )

    assert acs.status_code == 303
    assert acs.headers["location"] == "/me"

    # Sent explicitly rather than from the cookie jar. The session cookie is
    # `Secure`, and a conforming client will not store it for a plain-http
    # origin like `broker:8000` — the `__Host-` requirement working as
    # specified. A browser on `http://localhost` accepts it because localhost
    # is a trustworthy origin; the compose network hostname is not. The
    # attributes themselves are pinned in test_cookie_attributes.py.
    session_cookie = acs.cookies[SESSION_COOKIE]
    me = await client.get("/me", headers={"Cookie": f"{SESSION_COOKIE}={session_cookie}"})

    assert me.status_code == 200
    body = me.json()
    assert body["authenticated"] is True
    assert body["subject"] == f"{registered_idp.entity_id}|sam.obrien@campus.edu"
    assert body["attributes"]["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"] == ["student@campus.edu"]


async def test_me_is_unauthenticated_without_a_session(client: httpx.AsyncClient) -> None:
    response = await client.get("/me")

    assert response.status_code == 401
    assert response.json() == {"authenticated": False}


# --- the rejections, over HTTP --------------------------------------------


async def test_a_response_without_the_binding_cookie_is_refused(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    """Login CSRF: an attacker hands the victim a valid RelayState.

    Without the binding cookie the ACS cannot tell that this browser started
    the flow, so it must refuse rather than sign someone in as whoever the
    assertion names.
    """
    request_id, relay_state = await _begin_login(client, registered_idp)
    client.cookies.delete(REQUEST_BINDING_COOKIE)  # the attacker cannot set it

    response = await client.post(
        "/saml/acs",
        data={
            "SAMLResponse": base64.b64encode(
                registered_idp.response(
                    assertion_id=_unique_assertion_id(), in_response_to=request_id
                )
            ).decode(),
            "RelayState": relay_state,
        },
    )

    assert response.status_code == 400
    assert SESSION_COOKIE not in response.cookies


async def test_a_replayed_response_is_refused(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    request_id, relay_state = await _begin_login(client, registered_idp)
    payload = {
        "SAMLResponse": base64.b64encode(
            registered_idp.response(assertion_id=_unique_assertion_id(), in_response_to=request_id)
        ).decode(),
        "RelayState": relay_state,
    }

    first = await client.post("/saml/acs", data=payload)
    second = await client.post("/saml/acs", data=payload)

    assert first.status_code == 303
    assert second.status_code == 400


async def test_a_forged_signature_is_refused(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    request_id, relay_state = await _begin_login(client, registered_idp)

    response = await client.post(
        "/saml/acs",
        data={
            "SAMLResponse": base64.b64encode(
                registered_idp.response(
                    assertion_id=_unique_assertion_id(),
                    in_response_to=request_id,
                    sign_with=ForgedIdP().key,
                )
            ).decode(),
            "RelayState": relay_state,
        },
    )

    assert response.status_code == 400
    assert SESSION_COOKIE not in response.cookies


async def test_every_rejection_looks_identical(
    client: httpx.AsyncClient, registered_idp: ForgedIdP
) -> None:
    """Uniform errors (NFR-UX-02).

    Varying the response by reason would let an attacker enumerate the gate's
    fifteen checks by observation. Only the correlation id differs.
    """
    request_id, relay_state = await _begin_login(client, registered_idp)

    bad_signature = await client.post(
        "/saml/acs",
        data={
            "SAMLResponse": base64.b64encode(
                registered_idp.response(
                    assertion_id=_unique_assertion_id(),
                    in_response_to=request_id,
                    sign_with=ForgedIdP().key,
                )
            ).decode(),
            "RelayState": relay_state,
        },
    )
    _, second_relay_state = await _begin_login(client, registered_idp)
    not_base64 = await client.post(
        "/saml/acs",
        data={"SAMLResponse": "not base64 at all", "RelayState": second_relay_state},
    )

    assert bad_signature.status_code == not_base64.status_code == 400
    assert len(bad_signature.text) == len(not_base64.text)
    assert "signature" not in bad_signature.text.lower()


async def test_an_oversized_body_is_refused_before_parsing(
    client: httpx.AsyncClient,
) -> None:
    """The ASGI body cap. `Content-Length` alone would not do: it is absent
    under chunked encoding and exactly as trustworthy as the body it
    describes."""
    response = await client.post("/saml/acs", data={"SAMLResponse": "A" * (600 * 1024)})

    assert response.status_code == 413
