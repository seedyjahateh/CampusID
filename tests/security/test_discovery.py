"""The discovery service, and its open redirect (FR-SAML-10).

A discovery service exists to redirect somewhere it was told to go, which is
the exact shape of an open-redirect vulnerability. Most of this file is about
the `return` parameter for that reason.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.errors import BrokerError, ReasonCode
from campusid.routes.disco import LAST_IDP_COOKIE, validated_return

pytestmark = pytest.mark.security

BASE = "https://broker.test"


class _Entity:
    def __init__(self, entity_id: str, display_name: str | None = None, enabled: bool = True):
        self.entity_id = entity_id
        self.display_name = display_name
        self.enabled = enabled


class _Registry:
    def __init__(self, *entities: _Entity) -> None:
        self._entities = list(entities)

    async def list_idps(self) -> list[_Entity]:
        return self._entities


@pytest.fixture
def registered(app: FastAPI) -> None:
    app.state.registry = _Registry(
        _Entity("https://idp.test/saml", "Campus IdP"),
        _Entity("https://other-idp.test/saml", "Partner IdP"),
        _Entity("https://retired.test/saml", "Retired IdP", enabled=False),
    )


@pytest.fixture
async def client(app: FastAPI, registered: None) -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as http:
        yield http


# --- the open redirect -----------------------------------------------------


@pytest.mark.parametrize(
    ("label", "return_to"),
    [
        ("different_host", "https://attacker.test/steal"),
        ("prefix_of_our_host", "https://broker.test.attacker.test/steal"),
        ("downgraded_scheme", "http://broker.test/saml/sso"),
        ("different_port", "https://broker.test:8443/saml/sso"),
        ("scheme_relative", "//attacker.test/steal"),
        ("javascript_url", "javascript:alert(1)"),
    ],
)
def test_a_foreign_return_url_is_refused(label: str, return_to: str) -> None:
    """Each of these shares *something* with our origin, which is why the check
    compares scheme, host and port together rather than a string prefix."""
    with pytest.raises(BrokerError) as exc:
        validated_return(return_to, BASE)

    assert exc.value.reason is ReasonCode.INVALID_RETURN_URL, label


@pytest.mark.parametrize(
    ("label", "return_to"),
    [
        ("different_host", "https://attacker.test/steal"),
        ("prefix_of_our_host", "https://broker.test.attacker.test/steal"),
        ("scheme_relative", "//attacker.test/steal"),
    ],
)
async def test_a_foreign_return_url_is_never_redirected_to(
    client: AsyncClient, label: str, return_to: str
) -> None:
    """Refused rather than redirected to a safe default: silently rewriting a
    bad `return` teaches callers that anything works, and hides the attempt.
    The response must carry no `Location` at all."""
    response = await client.get("/disco", params={"return": return_to})

    assert response.status_code == 400, label
    assert "location" not in response.headers, label


async def test_our_own_return_url_is_accepted(client: AsyncClient) -> None:
    response = await client.get(
        "/disco",
        params={"return": f"{BASE}/saml/sso", "returnIDParam": "idp"},
    )

    assert response.status_code == 200  # the chooser


# --- choosing --------------------------------------------------------------


async def test_choosing_an_idp_returns_it_to_the_caller(client: AsyncClient) -> None:
    response = await client.get(
        "/disco",
        params={
            "return": f"{BASE}/saml/sso",
            "returnIDParam": "idp",
            "idpEntityID": "https://idp.test/saml",
        },
    )

    assert response.status_code == 303
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["idp"] == ["https://idp.test/saml"]


async def test_the_return_id_param_is_honoured(client: AsyncClient) -> None:
    """The protocol lets the caller name the parameter; defaulting to
    `entityID` while ignoring what they asked for sends the answer to a
    parameter they never read."""
    response = await client.get(
        "/disco",
        params={
            "return": f"{BASE}/saml/sso",
            "returnIDParam": "chosen",
            "idpEntityID": "https://idp.test/saml",
        },
    )

    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["chosen"] == ["https://idp.test/saml"]


async def test_a_choice_is_remembered(client: AsyncClient) -> None:
    """A federation with two hundred IdPs lives or dies on this cookie."""
    response = await client.get(
        "/disco",
        params={"return": f"{BASE}/saml/sso", "idpEntityID": "https://idp.test/saml"},
    )

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{LAST_IDP_COOKIE}=")
    assert "; Secure" in cookie
    assert "HttpOnly" in cookie


async def test_a_remembered_choice_skips_the_chooser(client: AsyncClient) -> None:
    response = await client.get(
        "/disco",
        params={"return": f"{BASE}/saml/sso", "returnIDParam": "idp"},
        headers={"Cookie": f"{LAST_IDP_COOKIE}=https://other-idp.test/saml"},
    )

    assert response.status_code == 303
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["idp"] == ["https://other-idp.test/saml"]


async def test_passive_discovery_with_nothing_remembered_returns_no_selection(
    client: AsyncClient,
) -> None:
    """`isPassive` means answer without interacting. With no remembered choice
    the honest answer is an empty one, not a guess."""
    response = await client.get(
        "/disco", params={"return": f"{BASE}/saml/sso", "isPassive": "true"}
    )

    assert response.status_code == 303
    assert "entityID=" not in response.headers["location"]
    assert "idp=" not in response.headers["location"]


# --- the chooser page ------------------------------------------------------


async def test_the_chooser_lists_only_enabled_idps(client: AsyncClient) -> None:
    response = await client.get("/disco")

    assert "Campus IdP" in response.text
    assert "Partner IdP" in response.text
    assert "Retired IdP" not in response.text


async def test_entity_names_are_escaped(app: FastAPI) -> None:
    """An entityID and display name come from metadata a *peer* supplied, so
    they are untrusted text rendered on our page."""
    app.state.registry = _Registry(
        _Entity("https://evil.test/saml", '<script>alert("xss")</script>')
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE) as http:
        response = await http.get("/disco")

    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text


async def test_an_empty_federation_says_so(app: FastAPI) -> None:
    app.state.registry = _Registry()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE) as http:
        response = await http.get("/disco")

    assert response.status_code == 200
    assert "No identity providers are registered" in response.text


async def test_the_chooser_is_not_cached(client: AsyncClient) -> None:
    """It reflects the current federation and a per-user cookie decision."""
    response = await client.get("/disco")

    assert response.headers["cache-control"] == "no-store"
