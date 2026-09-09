"""The provider metadata document (FR-OP-01).

A discovery document is a set of promises. Most of these tests are about the two
it deliberately does *not* make.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from campusid.oidc.claims import SUPPORTED_CLAIMS, SUPPORTED_SCOPES
from campusid.oidc.discovery import (
    PROTOCOL_CLAIMS,
    TOKEN_ENDPOINT_AUTH_METHODS,
    discovery_document,
)

ISSUER = "https://broker.campus.test"

REQUIRED_BY_THE_SPECIFICATION = {
    "issuer",
    "authorization_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
}

ENDPOINTS = [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "end_session_endpoint",
    "pushed_authorization_request_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
]


@pytest.fixture(scope="module")
def document() -> dict[str, object]:
    return discovery_document(ISSUER)


def test_every_field_openid_discovery_requires_is_present(document: dict[str, object]) -> None:
    assert set(document) >= REQUIRED_BY_THE_SPECIFICATION


@pytest.mark.parametrize("field", ENDPOINTS)
def test_every_advertised_endpoint_is_present(document: dict[str, object], field: str) -> None:
    """FR-OP-01 names all eight. A client configures itself from this document
    and cannot discover an endpoint that is missing from it."""
    assert field in document


@pytest.mark.parametrize("field", ENDPOINTS)
def test_every_endpoint_is_under_the_issuer(document: dict[str, object], field: str) -> None:
    """Everything derives from one base URL, so an endpoint cannot drift from
    the route that serves it — the same argument `saml_entity_id` makes."""
    value = document[field]
    assert isinstance(value, str)
    assert value.startswith(f"{ISSUER}/")


def test_the_issuer_has_no_path(document: dict[str, object]) -> None:
    """An issuer that is a prefix of another issuer invites the mistake where a
    client validating by `startswith` accepts tokens from the wrong one."""
    assert urlsplit(ISSUER).path == ""
    assert document["issuer"] == ISSUER


# --- the promises it declines to make --------------------------------------


def test_only_s256_is_advertised(document: dict[str, object]) -> None:
    """A provider that also advertises `plain` is telling every client the weak
    option is acceptable, and some library will take it."""
    assert document["code_challenge_methods_supported"] == ["S256"]


def test_only_the_code_flow_is_advertised(document: dict[str, object]) -> None:
    """Implicit and hybrid put tokens in a URL fragment, where they reach
    browser history, referrer headers and any script on the page. Deprecated in
    OAuth 2.1, and there is no reason for a new provider to carry them."""
    assert document["response_types_supported"] == ["code"]
    assert "token" not in str(document["response_types_supported"])


def test_only_rs256_is_advertised(document: dict[str, object]) -> None:
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]


def test_no_algorithm_the_verifier_would_refuse_is_advertised(
    document: dict[str, object],
) -> None:
    """Advertising less than you support is harmless. Advertising more is a
    promise the first client to rely on it discovers you cannot keep."""
    advertised = document["id_token_signing_alg_values_supported"]
    assert isinstance(advertised, list)
    assert "none" not in advertised
    assert not any(alg.startswith("HS") for alg in advertised)


def test_the_request_parameter_is_not_supported(document: dict[str, object]) -> None:
    """A `request` object is a signed JWT of authorization parameters, and
    supporting it means accepting and verifying attacker-supplied JWTs on an
    unauthenticated endpoint. PAR achieves the same thing — keeping the request
    off the front channel — with none of that surface."""
    assert document["request_parameter_supported"] is False
    assert document["request_uri_parameter_supported"] is True


def test_the_claims_parameter_is_not_supported(document: dict[str, object]) -> None:
    """Per-request claim selection would be a second release mechanism beside
    the policy engine, and two mechanisms deciding disclosure is one too many."""
    assert document["claims_parameter_supported"] is False


# --- what it advertises ----------------------------------------------------


def test_advertised_scopes_match_the_mapping(document: dict[str, object]) -> None:
    """A scope here that the claim mapping does not know is a scope a client can
    request and receive nothing for."""
    assert document["scopes_supported"] == list(SUPPORTED_SCOPES)


def test_advertised_claims_cover_the_protocol_and_identity_sets(
    document: dict[str, object],
) -> None:
    assert document["claims_supported"] == [*PROTOCOL_CLAIMS, *SUPPORTED_CLAIMS]


def test_the_protocol_claims_are_what_the_id_token_carries(
    document: dict[str, object],
) -> None:
    """These are advertised alongside the identity claims so a client can see
    the whole set it may receive, not just the configurable half."""
    assert set(PROTOCOL_CLAIMS) == {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "sid",
    }


def test_no_restricted_attribute_is_advertised_as_a_claim(
    document: dict[str, object],
) -> None:
    """The document is public. Advertising a claim the broker will never release
    tells the world what it holds about people."""
    claims = document["claims_supported"]
    assert isinstance(claims, list)
    assert not any("student" in claim or "employee" in claim for claim in claims)


def test_public_clients_may_authenticate_with_nothing(document: dict[str, object]) -> None:
    """`none` is for clients that hold no secret. It is not a weaker option a
    confidential client may choose — the registration decides, and
    `authenticate` refuses a confidential client that presents nothing."""
    assert "none" in TOKEN_ENDPOINT_AUTH_METHODS
    assert document["token_endpoint_auth_methods_supported"] == list(TOKEN_ENDPOINT_AUTH_METHODS)


def test_back_channel_logout_advertises_session_support(
    document: dict[str, object],
) -> None:
    """FR-OP-12. `session_supported` says our logout token carries `sid`, so a
    client can end one session rather than every session that person has."""
    assert document["backchannel_logout_supported"] is True
    assert document["backchannel_logout_session_supported"] is True


def test_the_document_is_a_pure_function_of_the_issuer() -> None:
    """Two brokers configured identically must describe themselves identically,
    and the same broker must not describe itself differently between requests."""
    assert discovery_document(ISSUER) == discovery_document(ISSUER)
    assert discovery_document("https://other.test") != discovery_document(ISSUER)
