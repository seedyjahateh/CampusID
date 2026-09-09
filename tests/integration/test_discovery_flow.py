"""Discovery against two real IdPs (PRD acceptance criterion 2).

Two Keycloak realms, each its own SAML entity with its own entityID and its own
signing key. The point is not that Keycloak runs twice; it is that the broker
holds two sets of trusted certificates at once and must pick the right one by
issuer — the failure mode where any registered peer can sign for any other.

What this does *not* prove is interoperability with a second SAML
implementation. SimpleSAMLphp would add that, and is deferred.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from html import unescape
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from campusid.routes.disco import LAST_IDP_COOKIE
from campusid.session.cookies import REQUEST_BINDING_COOKIE, SESSION_COOKIE

pytestmark = [pytest.mark.integration, pytest.mark.federation]

BROKER = "http://broker:8000"
"""Where this container reaches the broker."""

BROKER_PUBLIC = "http://localhost:8000"
"""The broker's own view of itself, which is what its `return` URL check
compares against. Reaching it at `broker:8000` and handing it a `return` of
`broker:8000` is refused, correctly: that host is not the origin it publishes."""

KEYCLOAK_INTERNAL = "http://keycloak:8080"
KEYCLOAK_PUBLIC = "http://localhost:18080"

CAMPUS = f"{KEYCLOAK_PUBLIC}/realms/campus"
PARTNER = f"{KEYCLOAK_PUBLIC}/realms/partner"

LOGIN_FORM_ACTION = re.compile(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"')
SAML_RESPONSE_FIELD = re.compile(r'<input[^>]+name="SAMLResponse"[^>]+value="([^"]*)"')
RELAY_STATE_FIELD = re.compile(r'<input[^>]+name="RelayState"[^>]+value="([^"]*)"')


def _internal(url: str) -> str:
    return url.replace(KEYCLOAK_PUBLIC, KEYCLOAK_INTERNAL)


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as http:
        yield http


# --- the chooser -----------------------------------------------------------


async def test_the_chooser_lists_both_registered_idps(client: httpx.AsyncClient) -> None:
    response = await client.get(f"{BROKER}/disco")

    assert response.status_code == 200
    assert "Campus University" in response.text
    assert "Partner College" in response.text


async def test_sso_without_an_idp_falls_through_to_discovery(
    client: httpx.AsyncClient,
) -> None:
    """A default IdP is configured in `.env`, so this asks for discovery
    explicitly — the path a deployment with no default takes."""
    response = await client.get(
        f"{BROKER}/disco", params={"return": f"{BROKER_PUBLIC}/saml/sso", "returnIDParam": "idp"}
    )

    assert response.status_code in (200, 303)


async def test_choosing_an_idp_returns_to_sso_with_it_named(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(
        f"{BROKER}/disco",
        params={
            "return": f"{BROKER_PUBLIC}/saml/sso",
            "returnIDParam": "idp",
            "idpEntityID": PARTNER,
        },
    )

    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["idp"] == [PARTNER]
    assert LAST_IDP_COOKIE in response.cookies


# --- logging in through each of them ---------------------------------------


async def _login(client: httpx.AsyncClient, idp: str, username: str, password: str) -> str:
    """Complete a login against ``idp`` and return the session cookie."""
    start = await client.get(f"{BROKER}/saml/sso", params={"idp": idp})
    assert start.status_code == 303, start.text
    binding = start.cookies[REQUEST_BINDING_COOKIE]

    page = await client.get(_internal(start.headers["location"]))

    # On a second login the browser already holds a Keycloak session, so the
    # IdP answers with the assertion directly and never renders a form. That is
    # SSO doing its job; a helper that insisted on a form would make every
    # repeat login look like a failure.
    form = LOGIN_FORM_ACTION.search(page.text)
    if form is not None:
        page = await client.post(
            _internal(unescape(form.group(1))),
            data={"username": username, "password": password},
            cookies=page.cookies,
        )

    response_field = SAML_RESPONSE_FIELD.search(page.text)
    assert response_field, f"no SAMLResponse from {idp}: {page.text[:300]}"
    submitted = page

    payload = {"SAMLResponse": unescape(response_field.group(1))}
    relay = RELAY_STATE_FIELD.search(submitted.text)
    if relay:
        payload["RelayState"] = unescape(relay.group(1))

    acs = await client.post(
        f"{BROKER}/saml/acs", data=payload, cookies={REQUEST_BINDING_COOKIE: binding}
    )
    assert acs.status_code == 303, acs.text
    return acs.cookies[SESSION_COOKIE]


async def _whoami(client: httpx.AsyncClient, session_cookie: str) -> dict[str, object]:
    response = await client.get(
        f"{BROKER}/me", headers={"Cookie": f"{SESSION_COOKIE}={session_cookie}"}
    )
    assert response.status_code == 200
    return dict(response.json())


async def test_login_through_the_campus_idp(client: httpx.AsyncClient) -> None:
    body = await _whoami(client, await _login(client, CAMPUS, "sam.obrien", "campus-dev-password"))

    assert body["idp"] == CAMPUS
    # The subject is the person the registry resolved, not the IdP's name for
    # them. Somebody who logs in through both realms is one subject.
    uuid.UUID(str(body["subject"]))
    assert body["attributes"]["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"] == [  # type: ignore[index]
        "sam.obrien@campus.edu"
    ]


async def test_login_through_the_partner_idp(client: httpx.AsyncClient) -> None:
    """The second IdP, with a different signing key.

    The broker holds both realms' certificates and must choose by issuer. A
    verifier that tried every registered certificate would pass this test and
    still be broken — `test_gate_check_order` covers that directly.
    """
    body = await _whoami(
        client, await _login(client, PARTNER, "priya.nair", "partner-dev-password")
    )

    assert body["idp"] == PARTNER
    uuid.UUID(str(body["subject"]))


async def test_the_persistent_name_id_is_opaque(client: httpx.AsyncClient) -> None:
    """We ask for `persistent`, and Keycloak honours it by minting an opaque
    per-client identifier rather than echoing the username.

    That is the privacy-preserving behaviour a broker wants: the SAML ancestor
    of a pairwise identifier. A test expecting the email address here would
    have been asserting that the NameID policy was being *ignored*.
    """
    body = await _whoami(client, await _login(client, CAMPUS, "sam.obrien", "campus-dev-password"))

    name_id = str(body["name_id"])

    assert "sam.obrien" not in name_id
    assert "@campus.edu" not in name_id
    assert len(name_id) >= 16


async def test_the_persistent_name_id_is_stable_across_logins(
    client: httpx.AsyncClient,
) -> None:
    """Persistent means persistent. An identifier that changed per login would
    make every returning user look like a new person to the registry."""
    first = await _whoami(client, await _login(client, CAMPUS, "sam.obrien", "campus-dev-password"))
    second = await _whoami(
        client, await _login(client, CAMPUS, "sam.obrien", "campus-dev-password")
    )

    assert first["subject"] == second["subject"]


async def test_the_two_idps_produce_distinct_people(client: httpx.AsyncClient) -> None:
    """A `NameID` only means something within the IdP that minted it, so the
    registry matches on the pair — and two different humans at two different
    realms resolve to two different people.

    The interesting failure would be the other way round: an opaque `NameID`
    that happened to collide, or a registry that matched on the subject alone,
    would merge two strangers into one account.
    """
    campus = await _whoami(
        client, await _login(client, CAMPUS, "sam.obrien", "campus-dev-password")
    )
    partner = await _whoami(
        client, await _login(client, PARTNER, "priya.nair", "partner-dev-password")
    )

    assert campus["subject"] != partner["subject"]
    assert campus["name_id"] != partner["name_id"]
    assert campus["idp"] != partner["idp"]


async def test_each_idp_releases_its_own_attributes(client: httpx.AsyncClient) -> None:
    partner = await _whoami(
        client, await _login(client, PARTNER, "priya.nair", "partner-dev-password")
    )

    attributes = partner["attributes"]
    assert isinstance(attributes, dict)
    assert attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"] == ["priya.nair@partner.edu"]
    assert attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"] == [
        "faculty@partner.edu",
        "member@partner.edu",
    ]
