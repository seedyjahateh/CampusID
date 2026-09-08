"""XML-DSig verification.

signxml does the cryptography. This module decides *what* gets verified, which
is where SAML implementations actually go wrong.

Three rules shape the code below.

**Every distinguishable failure is diagnosed before signxml runs.** signxml
raises ``InvalidInput`` when no signature sits at the expected location and
``InvalidSignature`` when the key is wrong, and telling "signed with SHA-1"
from "signed by the wrong IdP" apart would otherwise mean matching on exception
text. So a missing signature, a weak algorithm and a wrapped reference are all
caught here first, each with its own reason code, and anything reaching signxml
can only ever produce `signature_invalid`.

**The location is always pinned.** signxml's default is ``.//`` — a signature
found anywhere in the document satisfies it, which is precisely what wrapping
attacks arrange. Both call sites pass an explicit path.

**The verified element is not the element we passed in.** signxml verifies
against an internal deep copy, so ``result.signed_xml is our_element`` is
*always* False; an identity check written the natural way silently passes.
Callers must read from the returned element and drop their own parse tree.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from lxml import etree
from signxml import (
    DigestAlgorithm,
    SignatureConfiguration,
    SignatureMethod,
    XMLVerifier,
)
from signxml.exceptions import SignXMLException

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.algorithms import assert_algorithms_permitted
from campusid.saml.namespaces import Q_ASSERTION, Q_SIGNATURE
from campusid.saml.xsw import assert_reference_binds_to_parent

RESPONSE_SIGNATURE_LOCATION: Final = "./"
"""A signature that is a direct child of the document root."""

ASSERTION_SIGNATURE_LOCATION: Final = f"./{Q_ASSERTION}/"
"""A signature that is a direct child of the Response's Assertion."""

PERMITTED_SIGNATURE_METHODS: Final[frozenset[SignatureMethod]] = frozenset(
    {
        SignatureMethod.RSA_SHA256,
        SignatureMethod.RSA_SHA384,
        SignatureMethod.RSA_SHA512,
        SignatureMethod.ECDSA_SHA256,
        SignatureMethod.ECDSA_SHA384,
        SignatureMethod.ECDSA_SHA512,
    }
)
"""Narrower than signxml's default, which still admits RSA-SHA224, the
RSA-MGF1 family and HMAC. `test_signature.py` asserts this set agrees with the
URI allowlist in `algorithms.py`, so the two representations cannot drift."""

PERMITTED_DIGEST_ALGORITHMS: Final[frozenset[DigestAlgorithm]] = frozenset(
    {
        DigestAlgorithm.SHA256,
        DigestAlgorithm.SHA384,
        DigestAlgorithm.SHA512,
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedSignature:
    """The outcome of a successful verification.

    `element` is signxml's verified copy. It is the only trustworthy view of
    the signed content; the document it came from may contain anything.
    """

    element: etree._Element


def find_signature(parent: etree._Element) -> etree._Element | None:
    """Return the `ds:Signature` that is a *direct child* of ``parent``.

    Deliberately not a descendant search: a signature nested deeper belongs to
    something else, and treating it as this element's signature is the mistake
    wrapping attacks are built on.
    """
    return parent.find(Q_SIGNATURE)


def verify_signature(
    document: etree._Element,
    signed_element: etree._Element,
    *,
    location: str,
    certificates: Sequence[str],
) -> VerifiedSignature:
    """Verify the signature on ``signed_element`` within ``document``.

    ``certificates`` are the signing certificates from the issuing IdP's
    metadata, and only those — trust is metadata-pinned. Several are accepted
    so a key rollover with two published certificates keeps working
    (FR-FED-05); the first that verifies wins.
    """
    signature = find_signature(signed_element)
    if signature is None:
        raise SamlRejected(
            ReasonCode.SIGNATURE_MISSING,
            f"no ds:Signature is a direct child of {etree.QName(signed_element).localname}",
        )

    # Diagnosed here so the reason code is ours, not inferred from signxml.
    assert_algorithms_permitted(signature)
    assert_reference_binds_to_parent(signature)

    if not certificates:
        raise SamlRejected(
            ReasonCode.SIGNATURE_INVALID, "issuer has no signing certificates registered"
        )

    configuration = SignatureConfiguration(
        require_x509=True,
        location=location,
        expect_references=1,
        signature_methods=PERMITTED_SIGNATURE_METHODS,
        digest_algorithms=PERMITTED_DIGEST_ALGORITHMS,
    )

    for certificate in certificates:
        try:
            result = XMLVerifier().verify(
                document,
                x509_cert=certificate,
                expect_config=configuration,
                # SAML uses ID, not Id. signxml would try Id first and could
                # resolve a reference against a different attribute.
                id_attribute="ID",
            )
        except SignXMLException:
            continue

        # signxml returns a list when a signature covers several references.
        # `expect_references=1` should already have refused that, so reaching
        # here means the two disagree — refuse rather than pick one.
        if isinstance(result, list):
            raise SamlRejected(
                ReasonCode.SIGNATURE_WRAPPING_DETECTED,
                f"signature covers {len(result)} references, expected exactly one",
            )

        # Narrowing signxml's Optional return. Like the branch above, this is
        # unreachable given the configuration and exists so a change in the
        # library's contract fails closed rather than passing None downstream.
        verified = result.signed_xml
        if verified is None:
            raise SamlRejected(
                ReasonCode.SIGNATURE_INVALID, "verification returned no signed element"
            )

        _assert_verified_element_is_the_expected_one(verified, signed_element)
        return VerifiedSignature(element=verified)

    raise SamlRejected(
        ReasonCode.SIGNATURE_INVALID,
        f"no registered certificate ({len(certificates)} tried) verifies the signature",
    )


def _assert_verified_element_is_the_expected_one(
    verified: etree._Element, expected: etree._Element
) -> None:
    """Confirm signxml verified the element we intend to consume.

    Identity comparison is impossible — `verified` is a deep copy — so this
    matches on tag and ``ID``. That is sound only because the parser has
    already refused duplicate IDs (D0); without that guarantee an attacker
    could give two elements the same ID and make this check meaningless.
    """
    if verified.tag != expected.tag or verified.get("ID") != expected.get("ID"):
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"verified element {etree.QName(verified).localname}"
            f"#{verified.get('ID')!r} is not the element being consumed "
            f"({etree.QName(expected).localname}#{expected.get('ID')!r})",
        )
