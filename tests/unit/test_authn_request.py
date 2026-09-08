"""AuthnRequest generation and redirect-binding signing (FR-SAML-01).

The round-trip test is the important one. The redirect signature covers the
query string exactly as it appears in the URL, so the two classic failures —
signing a differently-encoded string than the one sent, and using zlib instead
of raw DEFLATE — both produce a URL that looks perfectly correct and that no
IdP will accept.
"""

from __future__ import annotations

import base64
import datetime as dt
import zlib
from urllib.parse import parse_qs, quote, unquote, urlsplit

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.authn_request import (
    PASSWORD_PROTECTED_TRANSPORT,
    RSA_SHA256_SIG_ALG,
    AuthnRequestPolicy,
    build_authn_request,
    decode_saml_request,
    deflate,
    inflate,
    new_id,
    prepare_redirect,
    validate_protocol_document,
    verify_redirect_signature,
)
from campusid.saml.namespaces import SAML, SAMLP, qn
from tests.support.saml_forge import SigningKey, generate_signing_key

DESTINATION = "https://idp.test/saml/sso"


@pytest.fixture(scope="module")
def sp_key() -> SigningKey:
    return generate_signing_key("broker.test")


@pytest.fixture
def policy() -> AuthnRequestPolicy:
    return AuthnRequestPolicy(
        entity_id="https://broker.test/saml/metadata",
        acs_url="https://broker.test/saml/acs",
    )


def _query(url: str) -> str:
    return urlsplit(url).query


# --- the document ---------------------------------------------------------


def test_the_request_validates_against_the_protocol_schema(
    policy: AuthnRequestPolicy,
) -> None:
    """Child order in `AuthnRequest` is schema-significant, exactly as in
    metadata: Issuer, NameIDPolicy, RequestedAuthnContext."""
    validate_protocol_document(
        build_authn_request(policy, DESTINATION, request_id=new_id(), now=dt.datetime.now(dt.UTC))
    )


def test_the_request_carries_the_expected_attributes(policy: AuthnRequestPolicy) -> None:
    request = etree.fromstring(
        build_authn_request(
            policy, DESTINATION, request_id="_abc", now=dt.datetime(2026, 9, 8, 12, tzinfo=dt.UTC)
        )
    )

    assert request.tag == qn(SAMLP, "AuthnRequest")
    assert request.get("ID") == "_abc"
    assert request.get("Version") == "2.0"
    assert request.get("IssueInstant") == "2026-09-08T12:00:00Z"
    assert request.get("Destination") == DESTINATION
    assert request.get("AssertionConsumerServiceURL") == policy.acs_url
    assert request.findtext(qn(SAML, "Issuer")) == policy.entity_id


def test_m1_requests_password_protected_transport(policy: AuthnRequestPolicy) -> None:
    """Not REFEDS MFA: Keycloak does not satisfy it and answers `unspecified`,
    so `Comparison="exact"` would fail every login. Step-up is M4."""
    request = etree.fromstring(
        build_authn_request(policy, DESTINATION, request_id="_a", now=dt.datetime.now(dt.UTC))
    )

    context = request.find(qn(SAMLP, "RequestedAuthnContext"))
    assert context is not None
    assert context.get("Comparison") == "exact"
    assert context.findtext(qn(SAML, "AuthnContextClassRef")) == PASSWORD_PROTECTED_TRANSPORT


def test_the_authn_context_can_be_omitted(policy: AuthnRequestPolicy) -> None:
    """Some IdPs reject a `RequestedAuthnContext` they cannot satisfy, so
    omitting it has to remain possible."""
    request = etree.fromstring(
        build_authn_request(
            AuthnRequestPolicy(
                entity_id=policy.entity_id,
                acs_url=policy.acs_url,
                authn_context_class_ref=None,
            ),
            DESTINATION,
            request_id="_a",
            now=dt.datetime.now(dt.UTC),
        )
    )

    assert request.find(qn(SAMLP, "RequestedAuthnContext")) is None


def test_ids_start_with_an_underscore() -> None:
    """`ID` is `xs:ID`, an NCName, so it may not begin with a digit."""
    assert all(new_id()[0] == "_" for _ in range(50))
    assert len({new_id() for _ in range(100)}) == 100


# --- transport encoding ---------------------------------------------------


def test_deflate_is_raw_not_zlib_wrapped() -> None:
    """`zlib.compress` prepends a header and appends a checksum, both of which
    make the request undecodable to a peer. The binding wants the bare stream.
    """
    payload = b"<samlp:AuthnRequest/>" * 10

    raw = deflate(payload)

    assert inflate(raw) == payload
    assert raw[:2] != zlib.compress(payload)[:2]
    with pytest.raises(zlib.error):
        zlib.decompress(raw)  # would succeed if we had emitted a zlib stream


def test_the_encoded_request_round_trips(policy: AuthnRequestPolicy, sp_key: SigningKey) -> None:
    prepared = prepare_redirect(policy, DESTINATION, sp_key.private_pem)
    encoded = parse_qs(_query(prepared.redirect_url))["SAMLRequest"][0]

    assert decode_saml_request(encoded) == prepared.xml


def test_a_corrupt_payload_is_refused() -> None:
    with pytest.raises(SamlRejected) as exc:
        decode_saml_request("bm90LWRlZmxhdGVk")

    assert exc.value.reason is ReasonCode.MALFORMED_RESPONSE


# --- the signature --------------------------------------------------------


def test_a_generated_url_verifies_as_a_peer_would(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """Verification reconstructs the signed octets from the raw query string,
    not from anything the signer kept. That is what makes this a test of
    interoperability rather than of self-consistency."""
    prepared = prepare_redirect(policy, DESTINATION, sp_key.private_pem)

    verify_redirect_signature(_query(prepared.redirect_url), (sp_key.certificate_pem,))


def test_the_signed_parameters_appear_in_binding_order(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """SAML Bindings 3.4.4.1 fixes the order: SAMLRequest, RelayState, SigAlg.
    Not alphabetical, not insertion order — and a peer rebuilds the string from
    that order regardless of how ours is laid out."""
    query = _query(prepare_redirect(policy, DESTINATION, sp_key.private_pem).redirect_url)

    names = [pair.partition("=")[0] for pair in query.split("&")]

    assert names == ["SAMLRequest", "RelayState", "SigAlg", "Signature"]


def test_the_signature_algorithm_is_advertised(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    query = parse_qs(_query(prepare_redirect(policy, DESTINATION, sp_key.private_pem).redirect_url))

    assert query["SigAlg"][0] == RSA_SHA256_SIG_ALG


def test_a_tampered_request_fails_verification(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """The whole point of signing the request: an IdP must be able to tell that
    the ACS URL or the requested context was altered in transit."""
    prepared = prepare_redirect(policy, DESTINATION, sp_key.private_pem)
    tampered = build_authn_request(
        AuthnRequestPolicy(entity_id=policy.entity_id, acs_url="https://attacker.test/steal"),
        DESTINATION,
        request_id=prepared.request_id,
        now=dt.datetime.now(dt.UTC),
    )

    # Substituted in the *raw* query. Using the value `parse_qs` returns would
    # splice a decoded string into an encoded query, match nothing, and leave
    # the URL untouched — a test that passes while proving nothing.
    raw_query = _query(prepared.redirect_url)
    original = raw_query.partition("SAMLRequest=")[2].partition("&")[0]
    swapped = raw_query.replace(
        original, quote(base64.b64encode(deflate(tampered)).decode(), safe=""), 1
    )
    assert swapped != raw_query, "the substitution did not take effect"

    with pytest.raises(SamlRejected) as exc:
        verify_redirect_signature(swapped, (sp_key.certificate_pem,))

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


def test_a_signature_from_another_key_is_refused(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    prepared = prepare_redirect(policy, DESTINATION, sp_key.private_pem)

    with pytest.raises(SamlRejected) as exc:
        verify_redirect_signature(
            _query(prepared.redirect_url), (generate_signing_key().certificate_pem,)
        )

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


def test_an_unsigned_query_is_refused() -> None:
    with pytest.raises(SamlRejected) as exc:
        verify_redirect_signature("SAMLRequest=abc&SigAlg=x", ())

    assert exc.value.reason is ReasonCode.SIGNATURE_MISSING


def test_verification_tries_every_published_certificate(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """Key rollover again: during the overlap either key may have signed."""
    prepared = prepare_redirect(policy, DESTINATION, sp_key.private_pem)

    verify_redirect_signature(
        _query(prepared.redirect_url),
        (generate_signing_key().certificate_pem, sp_key.certificate_pem),
    )


# --- correlation state ----------------------------------------------------


def test_relay_state_is_unguessable(policy: AuthnRequestPolicy, sp_key: SigningKey) -> None:
    """RelayState correlates the response to the browser that started the
    flow, so a predictable value would let an attacker forge that link."""
    states = {
        prepare_redirect(policy, DESTINATION, sp_key.private_pem).relay_state for _ in range(25)
    }

    assert len(states) == 25
    assert all(len(state) >= 32 for state in states)


def test_an_explicit_request_id_and_relay_state_are_honoured(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """The caller records these in the outstanding-request store, so it has to
    be able to fix them rather than discover them afterwards."""
    prepared = prepare_redirect(
        policy,
        DESTINATION,
        sp_key.private_pem,
        request_id="_fixed",
        relay_state="relay-token",
    )

    assert prepared.request_id == "_fixed"
    assert prepared.relay_state == "relay-token"
    assert unquote(parse_qs(_query(prepared.redirect_url))["RelayState"][0]) == "relay-token"


def test_a_destination_with_an_existing_query_is_appended_to(
    policy: AuthnRequestPolicy, sp_key: SigningKey
) -> None:
    """Some IdP SSO endpoints already carry a query parameter. Starting a
    second `?` would silently corrupt the request."""
    prepared = prepare_redirect(policy, "https://idp.test/sso?realm=campus", sp_key.private_pem)

    assert "?realm=campus&SAMLRequest=" in prepared.redirect_url
    verify_redirect_signature(_query(prepared.redirect_url), (sp_key.certificate_pem,))
