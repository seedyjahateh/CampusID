"""XSW structural predicates D1, D4 and D5 (PRD FR-SAML-08).

These run *before* verification, which is what lets a wrapped document be
rejected with `signature_wrapping_detected` rather than merely processed
harmlessly. The eight full attack variants are exercised end-to-end against real
signatures in `test_xsw_attacks.py`; here each predicate is pinned in isolation
so a failure names the defense that broke.
"""

from __future__ import annotations

from typing import Any

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import Q_SIGNATURE
from campusid.saml.xsw import (
    assert_reference_binds_to_parent,
    assert_signature_placement,
    assert_single_response_and_assertion,
)
from tests.support.xmlbuild import ENVELOPED, EXC_C14N, parse, response_xml, signature_xml

pytestmark = pytest.mark.security


# --- D1: exactly one Response and one Assertion ---------------------------


def test_d1_accepts_a_well_formed_response() -> None:
    assert_single_response_and_assertion(parse(response_xml()))


def test_d1_rejects_a_second_assertion() -> None:
    """XSW3: an evil assertion added as a sibling of the signed one."""
    evil = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil"/>'

    with pytest.raises(SamlRejected) as exc:
        assert_single_response_and_assertion(parse(response_xml(extra_assertions=evil)))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d1_rejects_an_assertion_hidden_in_extensions() -> None:
    """XSW7: `samlp:Extensions` accepts arbitrary children, so a spare copy of
    the signed assertion hides there and schema validation still passes."""
    extensions = (
        '<samlp:Extensions xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_hidden"/>'
        "</samlp:Extensions>"
    )

    with pytest.raises(SamlRejected) as exc:
        assert_single_response_and_assertion(parse(response_xml(extensions=extensions)))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d1_rejects_a_second_response() -> None:
    """XSW1/XSW2: an evil `Response` becomes the root and the genuine signed
    one is nested inside it, so the signature verifies against content the
    consumer never reads."""
    nested = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_outer">'
        + response_xml()
        + "</samlp:Response>"
    )

    with pytest.raises(SamlRejected) as exc:
        assert_single_response_and_assertion(parse(nested))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


# --- D5: signatures only in permitted positions ---------------------------


def test_d5_accepts_signatures_on_response_and_assertion() -> None:
    root = parse(
        response_xml(
            response_signature=signature_xml(reference_uri="#_r1"),
            assertion_signature=signature_xml(reference_uri="#_a1"),
        )
    )

    assert_signature_placement(root)


def test_d5_rejects_a_signature_buried_elsewhere() -> None:
    """XSW6/8 hide the original signed element, and its signature, inside a
    `ds:Object`, where the default `.//` signature lookup would still find it."""
    extensions = (
        '<samlp:Extensions xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
        + signature_xml(reference_uri="#_a1")
        + "</samlp:Extensions>"
    )

    with pytest.raises(SamlRejected) as exc:
        assert_signature_placement(parse(response_xml(extensions=extensions)))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d5_rejects_two_signatures_on_one_element() -> None:
    doubled = signature_xml(reference_uri="#_a1") * 2

    with pytest.raises(SamlRejected) as exc:
        assert_signature_placement(parse(response_xml(assertion_signature=doubled)))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d5_accepts_a_signature_on_a_bare_assertion_root() -> None:
    """A decrypted `EncryptedAssertion` is verified as its own document, with
    the `Assertion` as root rather than nested in a `Response` (M2). The
    predicate has to accept that shape now so the M2 path is not a special
    case bolted on later."""
    bare = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">'
        + signature_xml(reference_uri="#_a1")
        + "</saml:Assertion>"
    )

    assert_signature_placement(parse(bare))


# --- D4: the reference must bind to the signature's own parent ------------


def _assertion_signature(**kwargs: Any) -> etree._Element:
    root = parse(response_xml(assertion_signature=signature_xml(**kwargs)))
    signature = root.find(f".//{Q_SIGNATURE}")
    assert signature is not None
    return signature


def test_d4_accepts_a_reference_to_the_enclosing_assertion() -> None:
    assert_reference_binds_to_parent(_assertion_signature(reference_uri="#_a1"))


def test_d4_rejects_a_reference_pointing_elsewhere() -> None:
    """XSW2/5: the signature sits in the right place but digests a *different*
    element, so the consumer reads attacker content from a verified document."""
    with pytest.raises(SamlRejected) as exc:
        assert_reference_binds_to_parent(_assertion_signature(reference_uri="#_r1"))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d4_rejects_an_external_reference() -> None:
    """A non-`#` URI would have the verifier fetch attacker-chosen content."""
    with pytest.raises(SamlRejected) as exc:
        assert_reference_binds_to_parent(
            _assertion_signature(reference_uri="http://attacker.test/a.xml")
        )

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d4_rejects_multiple_references() -> None:
    """A second, satisfied reference is how an attacker gets a signature to
    'cover' content it does not actually protect."""
    with pytest.raises(SamlRejected) as exc:
        assert_reference_binds_to_parent(_assertion_signature(reference_count=2))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d4_rejects_a_missing_enveloped_signature_transform() -> None:
    """Without it the signature would purport to cover itself."""
    with pytest.raises(SamlRejected) as exc:
        assert_reference_binds_to_parent(_assertion_signature(transforms=(EXC_C14N,)))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d4_rejects_a_detached_signature() -> None:
    """A signature with no parent element covers nothing in this document."""
    with pytest.raises(SamlRejected) as exc:
        assert_reference_binds_to_parent(parse(signature_xml()))

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


def test_d4_accepts_enveloped_transform_alone() -> None:
    """Some IdPs omit the explicit c14n transform and rely on
    `CanonicalizationMethod`. That is valid; do not break those logins."""
    assert_reference_binds_to_parent(_assertion_signature(transforms=(ENVELOPED,)))
