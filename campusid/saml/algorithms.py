"""Cryptographic algorithm allowlists, checked before verification runs.

signxml also rejects weak algorithms, so this module is not what keeps SHA-1
out. It exists because *which* failure occurred has to be knowable. signxml
raises ``InvalidInput`` for a disallowed method and ``InvalidSignature`` for a
bad one, and telling "signed with SHA-1" apart from "signed with the wrong key"
by matching exception text is a string comparison waiting to break on a library
upgrade. Inspecting the algorithm URIs ourselves first makes `weak_algorithm`
deterministic; signxml then rejects the same document again, as defense in
depth.

The ``#WithComments`` refusal is a security control, not tidiness. SAML mandates
comment-free canonicalisation, and comment-preserving c14n is half of the 2018
comment-truncation bypass (see `parser.py`). Refusing it explicitly also keeps
the failure legible: our parser strips comments, so a genuinely
comment-preserving signature would otherwise fail with an opaque digest
mismatch.
"""

from __future__ import annotations

from typing import Final

from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import (
    Q_CANONICALIZATION_METHOD,
    Q_DIGEST_METHOD,
    Q_SIGNATURE_METHOD,
    Q_TRANSFORM,
)

_DSIG: Final = "http://www.w3.org/2000/09/xmldsig#"
_DSIG_MORE: Final = "http://www.w3.org/2001/04/xmldsig-more#"
_XMLENC: Final = "http://www.w3.org/2001/04/xmlenc#"
_EXC_C14N: Final = "http://www.w3.org/2001/10/xml-exc-c14n#"

PERMITTED_SIGNATURE_METHODS: Final[frozenset[str]] = frozenset(
    {
        f"{_DSIG_MORE}rsa-sha256",
        f"{_DSIG_MORE}rsa-sha384",
        f"{_DSIG_MORE}rsa-sha512",
        f"{_DSIG_MORE}ecdsa-sha256",
        f"{_DSIG_MORE}ecdsa-sha384",
        f"{_DSIG_MORE}ecdsa-sha512",
    }
)
"""RSA-SHA1 and DSA-SHA1 are deliberately absent (FR-SAML-02)."""

PERMITTED_DIGEST_METHODS: Final[frozenset[str]] = frozenset(
    {
        f"{_XMLENC}sha256",
        f"{_DSIG_MORE}sha384",
        f"{_XMLENC}sha512",
    }
)

PERMITTED_CANONICALIZATION_METHODS: Final[frozenset[str]] = frozenset({_EXC_C14N})
"""Exclusive c14n without comments. SAML 2.0 core §5.4.2 requires exclusive
canonicalisation; the comment-preserving variant is refused separately below so
it reports a hardening violation rather than a bare algorithm mismatch."""

PERMITTED_TRANSFORMS: Final[frozenset[str]] = frozenset(
    {
        f"{_DSIG}enveloped-signature",
        _EXC_C14N,
    }
)

WITH_COMMENTS_SUFFIX: Final = "#WithComments"


def assert_algorithms_permitted(signature: etree._Element) -> None:
    """Validate every algorithm URI inside a ``ds:Signature``.

    Raises `SamlRejected` with `WEAK_ALGORITHM` for a disallowed signature or
    digest algorithm, and `XML_HARDENING_VIOLATION` for comment-preserving
    canonicalisation.
    """
    _assert_no_with_comments(signature)

    method = signature.find(f".//{Q_SIGNATURE_METHOD}")
    algorithm = method.get("Algorithm") if method is not None else None
    if algorithm not in PERMITTED_SIGNATURE_METHODS:
        raise SamlRejected(
            ReasonCode.WEAK_ALGORITHM,
            f"signature method {algorithm!r} is not permitted",
        )

    for digest in signature.iter(Q_DIGEST_METHOD):
        digest_algorithm = digest.get("Algorithm")
        if digest_algorithm not in PERMITTED_DIGEST_METHODS:
            raise SamlRejected(
                ReasonCode.WEAK_ALGORITHM,
                f"digest method {digest_algorithm!r} is not permitted",
            )

    c14n = signature.find(f".//{Q_CANONICALIZATION_METHOD}")
    c14n_algorithm = c14n.get("Algorithm") if c14n is not None else None
    if c14n_algorithm not in PERMITTED_CANONICALIZATION_METHODS:
        raise SamlRejected(
            ReasonCode.WEAK_ALGORITHM,
            f"canonicalisation method {c14n_algorithm!r} is not permitted",
        )

    for transform in signature.iter(Q_TRANSFORM):
        transform_algorithm = transform.get("Algorithm")
        if transform_algorithm not in PERMITTED_TRANSFORMS:
            raise SamlRejected(
                ReasonCode.WEAK_ALGORITHM,
                f"transform {transform_algorithm!r} is not permitted",
            )


def _assert_no_with_comments(signature: etree._Element) -> None:
    """Refuse comment-preserving canonicalisation anywhere in the signature."""
    for element in signature.iter():
        algorithm = element.get("Algorithm")
        if algorithm and algorithm.endswith(WITH_COMMENTS_SUFFIX):
            raise SamlRejected(
                ReasonCode.XML_HARDENING_VIOLATION,
                f"comment-preserving canonicalisation {algorithm!r} is refused",
            )
