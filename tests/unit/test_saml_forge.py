"""Tests for the forge itself.

A test harness that lies produces a suite that passes for the wrong reasons, so
the forge's own invariants are pinned here — above all that its "valid" output
really is valid.
"""

from __future__ import annotations

import pytest

from campusid.saml.namespaces import (
    Q_ASSERTION,
    Q_AUDIENCE,
    Q_ISSUER,
    Q_NAME_ID,
    Q_SIGNATURE,
)
from campusid.saml.parser import parse_saml, text_of
from campusid.saml.signature import ASSERTION_SIGNATURE_LOCATION, verify_signature
from tests.support.saml_forge import ForgedIdP, apply_xsw, generate_signing_key


def test_the_default_response_is_well_formed(idp: ForgedIdP) -> None:
    root = parse_saml(idp.response())

    assert text_of(root.find(Q_ISSUER)) == idp.entity_id
    assert root.get("Destination") == idp.default_destination
    assert root.get("InResponseTo") == "_request1"

    assertion = root.find(Q_ASSERTION)
    assert assertion is not None
    assert text_of(assertion.find(f".//{Q_NAME_ID}")) == "sam.obrien@campus.edu"
    assert text_of(assertion.find(f".//{Q_AUDIENCE}")) == idp.default_audience


def test_signature_sits_after_issuer_and_still_verifies(idp: ForgedIdP) -> None:
    """signxml appends `ds:Signature` last; the SAML schema puts it immediately
    after `saml:Issuer`, which is where real IdPs emit it.

    Moving it is safe because the enveloped-signature transform removes the
    element before digesting, so its position within the same parent does not
    change what was signed. This asserts both halves: the schema position *and*
    that the signature survived the move.
    """
    root = parse_saml(idp.response())
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None

    children = [child.tag for child in assertion]
    assert children.index(Q_SIGNATURE) == children.index(Q_ISSUER) + 1

    result = verify_signature(
        root,
        assertion,
        location=ASSERTION_SIGNATURE_LOCATION,
        certificates=[idp.key.certificate_pem],
    )
    assert result.element.get("ID") == "_assertion1"


def test_attributes_are_rendered(idp: ForgedIdP) -> None:
    document = idp.response(
        attributes={"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": ["student@campus.edu"]}
    )

    assert b"student@campus.edu" in document
    assert b"attrname-format:uri" in document


def test_each_idp_gets_a_distinct_key() -> None:
    """Otherwise the wrong-key test would be verifying against itself."""
    assert generate_signing_key().certificate_pem != generate_signing_key().certificate_pem


def test_unknown_xsw_variant_is_rejected(idp: ForgedIdP) -> None:
    """A typo in a variant number must fail loudly, not silently return an
    unwrapped document that then 'passes' the attack test."""
    root = parse_saml(idp.response())

    with pytest.raises(ValueError, match="unknown XSW variant"):
        apply_xsw(root, 99)


def test_signing_can_be_disabled(idp: ForgedIdP) -> None:
    assert Q_SIGNATURE.encode() not in idp.response(sign=None)


def test_signing_both_produces_two_signatures(idp: ForgedIdP) -> None:
    root = parse_saml(idp.response(sign="both"))

    assert root.find(Q_SIGNATURE) is not None
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None
    assert assertion.find(Q_SIGNATURE) is not None
