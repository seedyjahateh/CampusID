"""XML-DSig verification against real signatures (PRD FR-SAML-02)."""

from __future__ import annotations

from typing import Any

import pytest
from signxml import SignatureConfiguration

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml import algorithms, signature
from campusid.saml.namespaces import Q_ASSERTION
from campusid.saml.parser import parse_saml
from campusid.saml.signature import (
    ASSERTION_SIGNATURE_LOCATION,
    RESPONSE_SIGNATURE_LOCATION,
    VerifiedSignature,
    verify_signature,
)
from tests.support.saml_forge import ForgedIdP, generate_signing_key
from tests.support.xmlbuild import RSA_SHA1, SHA1


def _verify_assertion(document: bytes, certificates: list[str]) -> VerifiedSignature:
    root = parse_saml(document)
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None
    return verify_signature(
        root,
        assertion,
        location=ASSERTION_SIGNATURE_LOCATION,
        certificates=certificates,
    )


def test_a_valid_assertion_signature_verifies(idp: ForgedIdP) -> None:
    result = _verify_assertion(idp.response(), [idp.key.certificate_pem])

    assert result.element.get("ID") == "_assertion1"


def test_a_valid_response_signature_verifies(idp: ForgedIdP) -> None:
    document = idp.response(sign="response")
    root = parse_saml(document)

    result = verify_signature(
        root,
        root,
        location=RESPONSE_SIGNATURE_LOCATION,
        certificates=[idp.key.certificate_pem],
    )

    assert result.element.get("ID") == "_response1"


def test_the_verified_element_is_a_copy_not_our_element(idp: ForgedIdP) -> None:
    """Pins the sharpest edge in the whole library.

    signxml verifies against an internal deep copy, so an identity check
    written the obvious way (`result.signed_xml is our_assertion`) is always
    False and therefore passes vacuously. Everything downstream must read from
    the returned element instead.
    """
    root = parse_saml(idp.response())
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None

    result = verify_signature(
        root,
        assertion,
        location=ASSERTION_SIGNATURE_LOCATION,
        certificates=[idp.key.certificate_pem],
    )

    assert result.element is not assertion
    assert result.element.get("ID") == assertion.get("ID")


def test_an_unsigned_assertion_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(SamlRejected) as exc:
        _verify_assertion(idp.response(sign=None), [idp.key.certificate_pem])

    assert exc.value.reason is ReasonCode.SIGNATURE_MISSING


def test_a_signature_from_the_wrong_key_is_refused(idp: ForgedIdP, other_idp: ForgedIdP) -> None:
    """A registered peer signing for another entity's ID is the realistic
    multi-IdP failure, and it must not verify."""
    document = idp.response(sign_with=other_idp.key)

    with pytest.raises(SamlRejected) as exc:
        _verify_assertion(document, [idp.key.certificate_pem])

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


def test_an_issuer_with_no_registered_certificate_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(SamlRejected) as exc:
        _verify_assertion(idp.response(), [])

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


def test_key_rollover_accepts_either_published_certificate(idp: ForgedIdP) -> None:
    """During a rollover an IdP publishes two signing certificates and may sign
    with either. Rejecting the one we did not try first would break every login
    for the length of the overlap window (FR-FED-05)."""
    retired = generate_signing_key("retired.idp.test")

    result = _verify_assertion(idp.response(), [retired.certificate_pem, idp.key.certificate_pem])

    assert result.element.get("ID") == "_assertion1"


@pytest.mark.parametrize(
    ("label", "override"),
    [
        ("sha1_signature", {"signature_method_uri": RSA_SHA1}),
        ("sha1_digest", {"digest_method_uri": SHA1}),
    ],
)
def test_weak_algorithms_are_refused_before_verification(
    idp: ForgedIdP, label: str, override: dict[str, Any]
) -> None:
    """`weak_algorithm`, not `signature_invalid`.

    Relabelling breaks the signature too, so a naive implementation would
    report a digest mismatch and lose the distinction. Ours checks the
    allowlist first, which is the only way the audit trail can answer "is
    anyone still offering SHA-1?".
    """
    with pytest.raises(SamlRejected) as exc:
        _verify_assertion(idp.response(**override), [idp.key.certificate_pem])

    assert exc.value.reason is ReasonCode.WEAK_ALGORITHM, label


def test_verifying_a_different_element_than_we_consume_is_refused(idp: ForgedIdP) -> None:
    """The D2 identity guard, exercised directly.

    Here the pinned location resolves the *Response* signature while the caller
    declares it will consume the *Assertion*. Verification succeeds — the
    Response signature is genuine — so nothing cryptographic objects. Only the
    identity check notices that the verified element is not the one about to be
    read, which is the exact shape of every wrapping attack.
    """
    root = parse_saml(idp.response(sign="both"))
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None

    with pytest.raises(SamlRejected) as exc:
        verify_signature(
            root,
            assertion,
            location=RESPONSE_SIGNATURE_LOCATION,
            certificates=[idp.key.certificate_pem],
        )

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_signxml_enums_agree_with_the_uri_allowlist() -> None:
    """The allowlist exists twice — as URIs for our pre-flight check and as
    signxml enums for its configuration. They must not drift apart, or one
    layer would admit something the other refuses."""
    assert {
        method.value for method in signature.PERMITTED_SIGNATURE_METHODS
    } == algorithms.PERMITTED_SIGNATURE_METHODS
    assert {
        digest.value for digest in signature.PERMITTED_DIGEST_ALGORITHMS
    } == algorithms.PERMITTED_DIGEST_METHODS


def test_signature_location_is_never_the_signxml_default() -> None:
    """signxml defaults to `.//` — a signature found *anywhere* satisfies it,
    which is exactly the condition wrapping attacks create. Reading the default
    off the library rather than hardcoding it means this test still fires if a
    future version changes it."""
    signxml_default = SignatureConfiguration().location

    assert signxml_default == ".//"
    assert signxml_default != RESPONSE_SIGNATURE_LOCATION
    assert signxml_default != ASSERTION_SIGNATURE_LOCATION
    assert ASSERTION_SIGNATURE_LOCATION.endswith("Assertion/")
