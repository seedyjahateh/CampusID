"""Algorithm allowlist (PRD FR-SAML-02, §11.1).

The point of pre-flighting algorithms ourselves is that `weak_algorithm` must be
distinguishable from `signature_invalid`. A reviewer asking "does this reject
SHA-1?" deserves a test that proves the SHA-1 path specifically, not one that
proves the document was rejected for some reason.
"""

from __future__ import annotations

from typing import Any

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.algorithms import (
    PERMITTED_DIGEST_METHODS,
    PERMITTED_SIGNATURE_METHODS,
    assert_algorithms_permitted,
)
from campusid.saml.namespaces import Q_SIGNATURE
from tests.support.xmlbuild import (
    ENVELOPED,
    EXC_C14N,
    EXC_C14N_WITH_COMMENTS,
    INCLUSIVE_C14N,
    RSA_SHA1,
    RSA_SHA256,
    SHA1,
    SHA256,
    parse,
    response_xml,
    signature_xml,
)

pytestmark = pytest.mark.security


def _signature(**kwargs: Any) -> etree._Element:
    """Build a Response carrying an assertion signature, and return that signature."""
    root = parse(response_xml(assertion_signature=signature_xml(**kwargs)))
    signature = root.find(f".//{Q_SIGNATURE}")
    assert signature is not None
    return signature


def test_rsa_sha256_is_accepted() -> None:
    assert_algorithms_permitted(_signature())


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("rsa_sha1_signature", {"signature_method": RSA_SHA1}),
        ("sha1_digest", {"digest_method": SHA1}),
        ("inclusive_c14n", {"c14n_method": INCLUSIVE_C14N}),
        ("unknown_transform", {"transforms": (ENVELOPED, "http://evil.test/transform")}),
        ("md5_signature", {"signature_method": "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"}),
    ],
)
def test_weak_or_unknown_algorithms_are_refused(label: str, kwargs: dict[str, Any]) -> None:
    with pytest.raises(SamlRejected) as exc:
        assert_algorithms_permitted(_signature(**kwargs))

    assert exc.value.reason is ReasonCode.WEAK_ALGORITHM, label


def test_with_comments_reports_a_hardening_violation_not_a_weak_algorithm() -> None:
    """Distinct code on purpose: `#WithComments` is refused because of the
    truncation bypass it enables, not because the algorithm is cryptographically
    weak. Collapsing the two would lose that distinction in the audit trail."""
    with pytest.raises(SamlRejected) as exc:
        assert_algorithms_permitted(_signature(c14n_method=EXC_C14N_WITH_COMMENTS))

    assert exc.value.reason is ReasonCode.XML_HARDENING_VIOLATION


def test_with_comments_in_a_transform_is_also_refused() -> None:
    """The attack works equally well from the transform list."""
    with pytest.raises(SamlRejected) as exc:
        assert_algorithms_permitted(_signature(transforms=(ENVELOPED, EXC_C14N_WITH_COMMENTS)))

    assert exc.value.reason is ReasonCode.XML_HARDENING_VIOLATION


def test_missing_signature_method_is_refused() -> None:
    """An absent algorithm must not read as an acceptable default."""
    signature = parse(
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        "<ds:SignedInfo>"
        f'<ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/>'
        "</ds:SignedInfo></ds:Signature>"
    )

    with pytest.raises(SamlRejected) as exc:
        assert_algorithms_permitted(signature)

    assert exc.value.reason is ReasonCode.WEAK_ALGORITHM


def test_allowlists_exclude_every_sha1_variant() -> None:
    """Guards the constants themselves against a careless addition."""
    assert RSA_SHA1 not in PERMITTED_SIGNATURE_METHODS
    assert SHA1 not in PERMITTED_DIGEST_METHODS
    assert all("sha1" not in a.lower() for a in PERMITTED_SIGNATURE_METHODS)
    assert all("sha1" not in a.lower() for a in PERMITTED_DIGEST_METHODS)
    assert RSA_SHA256 in PERMITTED_SIGNATURE_METHODS
    assert SHA256 in PERMITTED_DIGEST_METHODS
