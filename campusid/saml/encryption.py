"""XML Encryption: decrypting an `EncryptedAssertion` (FR-SAML-03).

Hand-written against `cryptography` rather than delegated to a library,
because the only Python options are bindings to `libxmlsec1` — the native
dependency the whole stack was chosen to avoid (ADR-003).

The security shape here is unusual and worth stating plainly: **when only the
assertion is signed, decryption runs on wholly unauthenticated input.** An
attacker can send arbitrary ciphertext and we will attempt to decrypt it before
any signature has been checked, because there is nothing to check until the
plaintext exists. Four consequences follow.

**AEAD only.** GCM is required; CBC is refused. XML Encryption's CBC mode is
the target of the Jager-Somorovsky backwards-compatibility attack, and
authenticated encryption removes the padding oracle by construction rather than
by careful error handling.

**One uniform error.** Every failure — a bad OAEP unwrap, a wrong key size, a
GCM tag mismatch, malformed base64, unparseable plaintext — raises
`decryption_failed` with no distinguishing detail. Bleichenbacher's lesson is
that an attacker who can tell *which* step failed has an oracle.

That uniformity has a real cost, and it is paid by whoever debugs this: a
mistake anywhere in the chain reports as one indistinguishable failure. The
original exception is preserved on the `__cause__` chain for a traceback, which
is the only concession made — the audit record and the HTTP response stay
uniform.

**The plaintext is re-parsed with the hardened parser** and re-checked against
the size cap. Decrypted bytes are still attacker-influenced; feeding them to a
permissive parser would reopen XXE behind the encryption.

**The result is a standalone document.** The decrypted assertion is never
spliced back into the outer tree, which would reintroduce the ID collisions the
parser refuses.
"""

from __future__ import annotations

import base64
from typing import Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import (
    Q_CIPHER_DATA,
    Q_CIPHER_VALUE,
    Q_ENCRYPTED_DATA,
    Q_ENCRYPTED_KEY,
    Q_ENCRYPTION_METHOD,
    Q_MGF,
    XENC,
    XENC11,
)
from campusid.saml.parser import MAX_DOCUMENT_BYTES, parse_saml

_DSIG: Final = "http://www.w3.org/2000/09/xmldsig#"
_DSIG_MORE: Final = "http://www.w3.org/2001/04/xmldsig-more#"

RSA_OAEP_MGF1P: Final = f"{XENC}rsa-oaep-mgf1p"
"""The 2002 form. Fixed at SHA-1 for both the digest and MGF1 — not
configurable, and not a weakness here: OAEP's security does not rest on the
collision resistance of its hash."""

RSA_OAEP: Final = f"{XENC11}rsa-oaep"
"""The 2013 form, with an explicit `DigestMethod` and `xenc11:MGF`."""

PERMITTED_KEY_TRANSPORT: Final[frozenset[str]] = frozenset({RSA_OAEP_MGF1P, RSA_OAEP})
"""RSA 1.5 key transport (`xenc#rsa-1_5`) is absent deliberately: it is the
original Bleichenbacher target and has no place in a new implementation."""

PERMITTED_CONTENT_ENCRYPTION: Final[dict[str, int]] = {
    f"{XENC11}aes128-gcm": 16,
    f"{XENC11}aes192-gcm": 24,
    f"{XENC11}aes256-gcm": 32,
}
"""GCM only, mapped to key length. Every CBC variant is refused — see the
module docstring."""

_DIGESTS: Final[dict[str, hashes.HashAlgorithm]] = {
    f"{_DSIG}sha1": hashes.SHA1(),  # noqa: S303 - OAEP label hash, not a signature digest
    f"{XENC}sha256": hashes.SHA256(),
    f"{_DSIG_MORE}sha384": hashes.SHA384(),
    f"{XENC}sha512": hashes.SHA512(),
}

_MGF_HASHES: Final[dict[str, hashes.HashAlgorithm]] = {
    f"{XENC11}mgf1sha1": hashes.SHA1(),  # noqa: S303 - MGF1 hash, per XML-Enc 1.1
    f"{XENC11}mgf1sha224": hashes.SHA224(),
    f"{XENC11}mgf1sha256": hashes.SHA256(),
    f"{XENC11}mgf1sha384": hashes.SHA384(),
    f"{XENC11}mgf1sha512": hashes.SHA512(),
}

GCM_IV_BYTES: Final = 12
GCM_TAG_BYTES: Final = 16


def decrypt_assertion(
    encrypted_assertion: etree._Element, private_key_pem: bytes
) -> etree._Element:
    """Decrypt an `EncryptedAssertion` into a standalone `Assertion` element.

    Raises `SamlRejected` with `decryption_failed` for anything that goes
    wrong, or `unsupported_encryption_algorithm` when the algorithms are named
    but refused. The latter is a deliberate exception to the uniform-error
    rule: it names a *configuration* mismatch an operator must fix, is decided
    before any key material is touched, and so leaks nothing about the
    plaintext.
    """
    encrypted_data = encrypted_assertion.find(Q_ENCRYPTED_DATA)
    if encrypted_data is None:
        raise SamlRejected(ReasonCode.DECRYPTION_FAILED, "EncryptedAssertion has no EncryptedData")

    content_algorithm = _algorithm(encrypted_data)
    if content_algorithm not in PERMITTED_CONTENT_ENCRYPTION:
        raise SamlRejected(
            ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM,
            f"content encryption {content_algorithm!r} is not permitted; "
            "CampusID requires AES-GCM",
        )

    encrypted_key = _find_encrypted_key(encrypted_assertion, encrypted_data)
    key_algorithm = _algorithm(encrypted_key)
    if key_algorithm not in PERMITTED_KEY_TRANSPORT:
        raise SamlRejected(
            ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM,
            f"key transport {key_algorithm!r} is not permitted",
        )

    # From here down every failure collapses to one code and one message.
    # An attacker who can distinguish "bad padding" from "bad tag" has an
    # oracle; one who only ever sees "decryption_failed" has nothing.
    try:
        session_key = _unwrap_key(encrypted_key, key_algorithm, private_key_pem)
        expected_length = PERMITTED_CONTENT_ENCRYPTION[content_algorithm]
        if len(session_key) != expected_length:
            raise ValueError("session key length mismatch")
        plaintext = _decrypt_gcm(_cipher_value(encrypted_data), session_key)
    except SamlRejected:
        raise
    except Exception as exc:
        raise SamlRejected(ReasonCode.DECRYPTION_FAILED, "assertion decryption failed") from exc

    if len(plaintext) > MAX_DOCUMENT_BYTES:
        raise SamlRejected(
            ReasonCode.PAYLOAD_TOO_LARGE, "decrypted assertion exceeds the size ceiling"
        )

    # Hardened, and standalone. Decrypted bytes are still attacker-influenced,
    # and splicing them into the outer tree would reintroduce ID collisions.
    return parse_saml(plaintext)


def _find_encrypted_key(
    encrypted_assertion: etree._Element, encrypted_data: etree._Element
) -> etree._Element:
    """Locate the wrapped session key.

    It may sit inside `EncryptedData/KeyInfo` or as a sibling of
    `EncryptedData` referenced by `RetrievalMethod`. Keycloak and
    SimpleSAMLphp differ on this, so both are accepted.
    """
    nested = encrypted_data.find(f".//{Q_ENCRYPTED_KEY}")
    if nested is not None:
        return nested
    sibling = encrypted_assertion.find(f".//{Q_ENCRYPTED_KEY}")
    if sibling is not None:
        return sibling
    raise SamlRejected(ReasonCode.DECRYPTION_FAILED, "no EncryptedKey found")


def _algorithm(element: etree._Element) -> str:
    method = element.find(Q_ENCRYPTION_METHOD)
    algorithm = method.get("Algorithm") if method is not None else None
    if not algorithm:
        raise SamlRejected(
            ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM, "no EncryptionMethod declared"
        )
    return algorithm


def _cipher_value(element: etree._Element) -> bytes:
    """Read this element's own ciphertext.

    A direct child path, deliberately not a descendant search. `EncryptedData`
    contains the `EncryptedKey` inside its `KeyInfo`, and that key has a
    `CipherValue` of its own which comes *first* in document order — so `.//`
    would return the wrapped session key where the encrypted assertion was
    wanted, and decryption would fail with a GCM tag mismatch that says nothing
    about the real cause.
    """
    cipher_value = element.find(f"{Q_CIPHER_DATA}/{Q_CIPHER_VALUE}")
    if cipher_value is None or not cipher_value.text:
        raise SamlRejected(ReasonCode.DECRYPTION_FAILED, "no CipherValue")
    return base64.b64decode("".join(cipher_value.text.split()))


def _unwrap_key(encrypted_key: etree._Element, algorithm: str, private_key_pem: bytes) -> bytes:
    """Recover the AES session key with our RSA private key."""
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("assertion decryption needs an RSA key")

    if algorithm == RSA_OAEP_MGF1P:
        digest: hashes.HashAlgorithm = hashes.SHA1()  # noqa: S303 - fixed by the 2002 spec
        mgf_hash: hashes.HashAlgorithm = hashes.SHA1()  # noqa: S303
    else:
        method = encrypted_key.find(Q_ENCRYPTION_METHOD)
        assert method is not None  # _algorithm already proved it
        digest_element = method.find(f"{{{_DSIG}}}DigestMethod")
        digest_uri = (
            digest_element.get("Algorithm") if digest_element is not None else f"{XENC}sha256"
        )
        mgf_element = method.find(Q_MGF)
        mgf_uri = mgf_element.get("Algorithm") if mgf_element is not None else f"{XENC11}mgf1sha1"
        if digest_uri not in _DIGESTS or mgf_uri not in _MGF_HASHES:
            raise SamlRejected(
                ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM,
                f"OAEP parameters {digest_uri!r}/{mgf_uri!r} are not permitted",
            )
        digest = _DIGESTS[digest_uri]
        mgf_hash = _MGF_HASHES[mgf_uri]

    return key.decrypt(
        _cipher_value(encrypted_key),
        padding.OAEP(mgf=padding.MGF1(algorithm=mgf_hash), algorithm=digest, label=None),
    )


def _decrypt_gcm(ciphertext: bytes, session_key: bytes) -> bytes:
    """Decrypt AES-GCM as XML Encryption 1.1 frames it: IV ‖ ciphertext ‖ tag.

    The tag is not stripped and checked separately — `AESGCM.decrypt` expects
    it appended, and verifies it as part of decryption. A mismatch raises, and
    the caller collapses that to the same error as everything else.
    """
    if len(ciphertext) <= GCM_IV_BYTES + GCM_TAG_BYTES:
        raise ValueError("ciphertext too short to contain an IV and a tag")
    return AESGCM(session_key).decrypt(ciphertext[:GCM_IV_BYTES], ciphertext[GCM_IV_BYTES:], None)
