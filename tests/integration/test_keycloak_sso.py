"""A real login against Keycloak (PRD acceptance criterion 1).

Everything before this used the forge, which signs whatever we ask it to. This
drives an actual IdP: Keycloak mints the assertion, chooses its own signing
key, formats its own timestamps, and orders its own elements. It is the test
that catches the difference between "our SP agrees with our forge" and "our SP
interoperates".

Requires the federation profile:

    docker compose --profile federation up -d
    docker compose --profile federation run --rm federation-init
    docker compose run --rm tests tests/integration -m federation
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from html import unescape
from urllib.parse import urlsplit

import httpx
import pytest

from campusid.session.cookies import REQUEST_BINDING_COOKIE, SESSION_COOKIE

pytestmark = [pytest.mark.integration, pytest.mark.federation]

BROKER = "http://broker:8000"
KEYCLOAK_INTERNAL = "http://keycloak:8080"
KEYCLOAK_PUBLIC = "http://localhost:18080"
IDP_ENTITY_ID = f"{KEYCLOAK_PUBLIC}/realms/campus"

USERNAME = "sam.obrien"
PASSWORD = "campus-dev-password"

LOGIN_FORM_ACTION = re.compile(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"')
POST_FORM_ACTION = re.compile(r'<form[^>]*action="([^"]+)"', re.IGNORECASE)
SAML_RESPONSE_FIELD = re.compile(
    r'<input[^>]+name="SAMLResponse"[^>]+value="([^"]*)"', re.IGNORECASE
)
RELAY_STATE_FIELD = re.compile(r'<input[^>]+name="RelayState"[^>]+value="([^"]*)"', re.IGNORECASE)


def _internal(url: str) -> str:
    """Rewrite a browser-facing Keycloak URL to one this container can reach.

    Keycloak advertises `localhost:18080` because that is where the *browser*
    finds it; from inside the compose network it is `keycloak:8080`. A real
    browser needs no such rewrite — this is the price of driving the flow from
    a container, and it is only ever applied to the transport, never to the
    entityID or to anything the signature covers.
    """
    return url.replace(KEYCLOAK_PUBLIC, KEYCLOAK_INTERNAL)


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as http:
        yield http


async def _authenticate(client: httpx.AsyncClient) -> httpx.Response:
    """Walk the whole browser flow and return the broker's ACS response."""
    start = await client.get(f"{BROKER}/saml/sso", params={"idp": IDP_ENTITY_ID})
    assert start.status_code == 303, start.text
    binding_cookie = start.cookies[REQUEST_BINDING_COOKIE]

    # Keycloak checks the AuthnRequest signature and its Destination before it
    # will show a login page at all, so reaching this page already proves the
    # redirect binding, the raw-DEFLATE encoding and the query-string signature
    # are all correct.
    login_page = await client.get(_internal(start.headers["location"]))
    assert login_page.status_code == 200, login_page.text
    match = LOGIN_FORM_ACTION.search(login_page.text)
    assert match, "Keycloak did not render a login form"

    submitted = await client.post(
        _internal(unescape(match.group(1))),
        data={"username": USERNAME, "password": PASSWORD},
        cookies=login_page.cookies,
    )
    # Keycloak answers with an auto-submitting form carrying the assertion.
    assert submitted.status_code == 200, submitted.text
    response_field = SAML_RESPONSE_FIELD.search(submitted.text)
    assert response_field, f"no SAMLResponse in Keycloak's reply: {submitted.text[:400]}"

    relay_field = RELAY_STATE_FIELD.search(submitted.text)
    form = {"SAMLResponse": unescape(response_field.group(1))}
    if relay_field:
        form["RelayState"] = unescape(relay_field.group(1))

    acs_action = POST_FORM_ACTION.search(submitted.text)
    assert acs_action
    acs_url = unescape(acs_action.group(1))
    assert urlsplit(acs_url).path == "/saml/acs"

    return await client.post(
        f"{BROKER}/saml/acs",
        data=form,
        cookies={REQUEST_BINDING_COOKIE: binding_cookie},
    )


async def test_a_real_keycloak_login_establishes_a_session(
    client: httpx.AsyncClient,
) -> None:
    """The milestone acceptance criterion.

    A browser starts at the broker, authenticates at Keycloak, and comes back
    with an assertion the gate accepts — signed by Keycloak's key, validated
    against a certificate the broker learned from Keycloak's metadata, which it
    was handed by federation-init and has never seen written down anywhere.
    """
    acs = await _authenticate(client)

    assert acs.status_code == 303, acs.text
    assert acs.headers["location"] == "/me"

    session_cookie = acs.cookies[SESSION_COOKIE]
    me = await client.get(f"{BROKER}/me", headers={"Cookie": f"{SESSION_COOKIE}={session_cookie}"})

    assert me.status_code == 200
    body = me.json()
    assert body["authenticated"] is True
    assert body["idp"] == IDP_ENTITY_ID


async def test_keycloak_releases_the_edu_person_attributes(
    client: httpx.AsyncClient,
) -> None:
    """The protocol mappers federation-init installed, proved end to end.

    Attribute release is the part of a SAML integration that silently does
    nothing when misconfigured: the login succeeds and the SP simply learns
    less than it asked for. Naming the OIDs here means a mapper that stops
    working fails a test rather than degrading a downstream feature.
    """
    acs = await _authenticate(client)
    me = await client.get(
        f"{BROKER}/me",
        headers={"Cookie": f"{SESSION_COOKIE}={acs.cookies[SESSION_COOKIE]}"},
    )

    attributes = me.json()["attributes"]

    assert attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"] == ["sam.obrien@campus.edu"]
    assert set(attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"]) == {
        "student@campus.edu",
        "member@campus.edu",
    }
    assert attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.7"] == [
        "urn:mace:campus.edu:entitlement:lms:access"
    ]


async def test_keycloak_signs_the_assertion_not_only_the_response(
    client: httpx.AsyncClient,
) -> None:
    """Keycloak's `saml.assertion.signature` defaults to **false**.

    With that default it signs the Response and leaves the Assertion unsigned,
    and our gate — correctly requiring a signed assertion — rejects every
    login with `signature_missing`. That is an afternoon of debugging correct
    code, so federation-init pins the attribute and this asserts it took.

    Proved by the login succeeding at all: the gate would refuse it otherwise.
    """
    acs = await _authenticate(client)

    assert acs.status_code == 303


async def test_the_broker_is_registered_as_a_keycloak_client() -> None:
    """federation-init created the client from our published metadata.

    Fetching Keycloak's descriptor is not enough on its own — the exchange has
    to work in both directions, and the half that needs our certificate is the
    half a static realm import cannot do.
    """
    async with httpx.AsyncClient(timeout=30.0) as http:
        descriptor = await http.get(f"{KEYCLOAK_INTERNAL}/realms/campus/protocol/saml/descriptor")

    assert descriptor.status_code == 200
    assert b"IDPSSODescriptor" in descriptor.content
