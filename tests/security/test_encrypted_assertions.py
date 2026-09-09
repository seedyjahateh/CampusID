"""Encrypted assertions (FR-SAML-03, FAL2).

Decryption runs on wholly unauthenticated input when only the assertion is
signed: an attacker can send arbitrary ciphertext and we attempt to decrypt it
before any signature has been checked, because there is nothing to check until
the plaintext exists. These tests pin the consequences of that.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.keys import SigningMaterial, generate_self_signed
from campusid.saml.encryption import decrypt_assertion
from campusid.saml.gate import AssertionGate, GatePolicy, IdPResolver
from campusid.saml.namespaces import (
    Q_ASSERTION,
    Q_CIPHER_DATA,
    Q_CIPHER_VALUE,
    Q_ENCRYPTED_ASSERTION,
    Q_ENCRYPTED_DATA,
    Q_NAME_ID,
)
from campusid.saml.parser import parse_saml, text_of
from tests.support.saml_forge import (
    AES128_GCM,
    AES256_CBC,
    RSA_1_5,
    RSA_OAEP_MGF1P,
    ForgedIdP,
)
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore

pytestmark = pytest.mark.security


@pytest.fixture
def encrypting_gate(
    gate_policy: GatePolicy,
    resolve_idp: IdPResolver,
    replay_cache: InMemoryReplayCache,
    request_store: InMemoryRequestStore,
    sp_material: SigningMaterial,
) -> AssertionGate:
    return AssertionGate(
        policy=gate_policy,
        resolve_idp=resolve_idp,
        replay_cache=replay_cache,
        request_store=request_store,
        decryption_key=sp_material.private_pem,
    )


def _encrypted(idp: ForgedIdP, sp: SigningMaterial, **kwargs: object) -> bytes:
    return idp.response(encrypt_for=sp.certificate_pem, **kwargs)  # type: ignore[arg-type]


# --- the happy path --------------------------------------------------------


async def test_an_encrypted_assertion_is_accepted(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    facts = await encrypting_gate.validate(_encrypted(idp, sp_material))

    assert facts.name_id == "sam.obrien@campus.edu"
    assert facts.assertion_id == "_assertion1"


async def test_the_response_really_was_encrypted(
    idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """Guards the fixture: a test that silently stopped encrypting would make
    every assertion below pass for the wrong reason."""
    root = parse_saml(_encrypted(idp, sp_material))

    assert root.find(Q_ENCRYPTED_ASSERTION) is not None
    assert root.find(Q_ASSERTION) is None
    assert b"sam.obrien" not in etree.tostring(root)


@pytest.mark.parametrize("algorithm", [AES128_GCM, "http://www.w3.org/2009/xmlenc11#aes256-gcm"])
async def test_the_permitted_gcm_variants_decrypt(
    encrypting_gate: AssertionGate,
    idp: ForgedIdP,
    sp_material: SigningMaterial,
    algorithm: str,
) -> None:
    facts = await encrypting_gate.validate(
        _encrypted(idp, sp_material, encryption_algorithm=algorithm)
    )

    assert facts.name_id == "sam.obrien@campus.edu"


async def test_the_legacy_oaep_form_is_accepted(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """`rsa-oaep-mgf1p` is the 2002 spelling, fixed at SHA-1 for the digest and
    MGF. Still ubiquitous, and not a weakness: OAEP's security does not rest on
    the collision resistance of its hash."""
    facts = await encrypting_gate.validate(
        _encrypted(idp, sp_material, key_transport_algorithm=RSA_OAEP_MGF1P)
    )

    assert facts.name_id == "sam.obrien@campus.edu"


async def test_the_key_may_be_a_sibling_of_the_encrypted_data(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """Keycloak and SimpleSAMLphp differ on where the `EncryptedKey` goes:
    inside `EncryptedData/KeyInfo`, or beside it. Both are real."""
    facts = await encrypting_gate.validate(_encrypted(idp, sp_material, nested_encrypted_key=False))

    assert facts.name_id == "sam.obrien@campus.edu"


# --- refused algorithms ----------------------------------------------------


async def test_cbc_content_encryption_is_refused(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """XML Encryption's CBC mode is the Jager-Somorovsky target. Requiring an
    AEAD removes the padding oracle by construction rather than by careful
    error handling — and the refusal is a better portfolio artifact than a
    careful CBC implementation would be."""
    with pytest.raises(SamlRejected) as exc:
        await encrypting_gate.validate(
            _encrypted(idp, sp_material, encryption_algorithm=AES256_CBC)
        )

    assert exc.value.reason is ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM


async def test_rsa_1_5_key_transport_is_refused(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """The original Bleichenbacher target. It has no place in a new
    implementation, so it is absent from the allowlist rather than handled."""
    document = _encrypted(idp, sp_material)
    swapped = document.replace(b"http://www.w3.org/2009/xmlenc11#rsa-oaep", RSA_1_5.encode())

    with pytest.raises(SamlRejected) as exc:
        await encrypting_gate.validate(swapped)

    assert exc.value.reason is ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM


# --- uniform failure -------------------------------------------------------


def _mangle_ciphertext(document: bytes, mangle: Callable[[bytes], bytes]) -> bytes:
    """Apply ``mangle`` to the assertion ciphertext, leaving the key intact.

    Decodes and re-encodes rather than editing the base64 text. Appending
    characters after base64 padding is silently ignored by the decoder, so a
    textual edit can leave the bytes untouched and produce a test that passes
    while changing nothing.
    """
    root = parse_saml(document)
    encrypted = root.find(Q_ENCRYPTED_ASSERTION)
    assert encrypted is not None
    # The EncryptedData's own CipherValue, not the wrapped key's — the key sits
    # earlier in document order, inside KeyInfo.
    data = encrypted.find(Q_ENCRYPTED_DATA)
    assert data is not None
    cipher = data.find(f"{Q_CIPHER_DATA}/{Q_CIPHER_VALUE}")
    assert cipher is not None and cipher.text

    original = base64.b64decode("".join(cipher.text.split()))
    mangled = mangle(original)
    assert mangled != original, "the mutation did not take effect"

    cipher.text = base64.b64encode(mangled).decode()
    return etree.tostring(root)


@pytest.mark.parametrize(
    "label",
    ["corrupt_ciphertext", "wrong_recipient_key", "truncated_ciphertext", "not_base64"],
)
async def test_every_decryption_failure_reports_the_same_thing(
    encrypting_gate: AssertionGate,
    idp: ForgedIdP,
    sp_material: SigningMaterial,
    label: str,
) -> None:
    """Bleichenbacher's lesson: an attacker who can tell *which* step failed
    has an oracle. Bad padding, a wrong key, a GCM tag mismatch and malformed
    base64 are indistinguishable from outside.
    """
    if label == "corrupt_ciphertext":
        # A flipped bit inside the GCM tag.
        document = _mangle_ciphertext(
            _encrypted(idp, sp_material), lambda raw: raw[:-1] + bytes([raw[-1] ^ 0xFF])
        )
    elif label == "wrong_recipient_key":
        stranger = generate_self_signed("stranger.test", key_size=2048)
        document = _encrypted(idp, stranger)
    elif label == "truncated_ciphertext":
        document = _mangle_ciphertext(_encrypted(idp, sp_material), lambda raw: raw[:-8])
    else:
        root = parse_saml(_encrypted(idp, sp_material))
        data = root.find(f"{Q_ENCRYPTED_ASSERTION}/{Q_ENCRYPTED_DATA}")
        assert data is not None
        cipher = data.find(f"{Q_CIPHER_DATA}/{Q_CIPHER_VALUE}")
        assert cipher is not None
        cipher.text = "!!!not base64!!!"
        document = etree.tostring(root)

    with pytest.raises(SamlRejected) as exc:
        await encrypting_gate.validate(document)

    assert exc.value.reason is ReasonCode.DECRYPTION_FAILED, label
    assert exc.value.detail == "assertion decryption failed", label


async def test_an_encrypted_response_without_a_key_configured_is_refused(
    gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """The default gate has no decryption key. Failing loudly beats silently
    treating an encrypted response as one with no assertion."""
    with pytest.raises(SamlRejected) as exc:
        await gate.validate(_encrypted(idp, sp_material))

    assert exc.value.reason is ReasonCode.DECRYPTION_FAILED


# --- the signature inside the plaintext ------------------------------------


async def test_a_forged_signature_inside_the_ciphertext_is_still_refused(
    encrypting_gate: AssertionGate,
    idp: ForgedIdP,
    other_idp: ForgedIdP,
    sp_material: SigningMaterial,
) -> None:
    """Encryption is not authentication.

    A well-formed assertion signed by the wrong key, correctly encrypted to us,
    decrypts perfectly — and must still be refused. Confidentiality says
    nothing about who wrote the plaintext.
    """
    with pytest.raises(SamlRejected) as exc:
        await encrypting_gate.validate(_encrypted(idp, sp_material, sign_with=other_idp.key))

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


async def test_an_unsigned_assertion_inside_the_ciphertext_is_refused(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    with pytest.raises(SamlRejected) as exc:
        await encrypting_gate.validate(_encrypted(idp, sp_material, sign=None))

    assert exc.value.reason is ReasonCode.SIGNATURE_MISSING


async def test_the_decrypted_fragment_is_hardened(
    idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """Decrypted bytes are still attacker-influenced.

    The plaintext goes through the same hardened parser as the outer document,
    so a DOCTYPE hidden inside the ciphertext is refused rather than parsed —
    which would otherwise reopen XXE behind the encryption.
    """
    hostile = (
        b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"/>'
    )
    encrypted = _wrap_plaintext(hostile, sp_material)

    with pytest.raises(SamlRejected) as exc:
        decrypt_assertion(encrypted, sp_material.private_pem)

    assert exc.value.reason is ReasonCode.XML_HARDENING_VIOLATION


def _wrap_plaintext(plaintext: bytes, sp: SigningMaterial) -> etree._Element:
    """Encrypt arbitrary bytes to the SP, bypassing the forge's assertion shape."""
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.x509 import load_pem_x509_certificate

    from campusid.saml.namespaces import SAML, XENC, XENC11

    session_key = os.urandom(32)
    iv = os.urandom(12)
    body = iv + AESGCM(session_key).encrypt(iv, plaintext, None)
    public_key = load_pem_x509_certificate(sp.certificate_pem.encode()).public_key()
    wrapped = public_key.encrypt(  # type: ignore[union-attr]
        session_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return etree.fromstring(
        (
            f'<saml:EncryptedAssertion xmlns:saml="{SAML}" xmlns:xenc="{XENC}">'
            f'<xenc:EncryptedData Type="{XENC}Element">'
            f'<xenc:EncryptionMethod Algorithm="{XENC11}aes256-gcm"/>'
            f'<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f'<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{XENC11}rsa-oaep">'
            f'<ds:DigestMethod Algorithm="{XENC}sha256"/>'
            f'<xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{XENC11}mgf1sha256"/>'
            f"</xenc:EncryptionMethod><xenc:CipherData>"
            f"<xenc:CipherValue>{base64.b64encode(wrapped).decode()}</xenc:CipherValue>"
            f"</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
            f"<xenc:CipherData>"
            f"<xenc:CipherValue>{base64.b64encode(body).decode()}</xenc:CipherValue>"
            f"</xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"
        ).encode()
    )


async def test_the_name_id_survives_the_round_trip(
    encrypting_gate: AssertionGate, idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """A plaintext-integrity check on the decryptor itself: the assertion that
    comes out has to be the one that went in."""
    facts = await encrypting_gate.validate(
        _encrypted(idp, sp_material, name_id="dana.wu@campus.edu")
    )

    assert facts.name_id == "dana.wu@campus.edu"


def test_decrypting_yields_a_standalone_assertion(
    idp: ForgedIdP, sp_material: SigningMaterial
) -> None:
    """Never spliced back into the Response, which would reintroduce the ID
    collisions the parser refuses."""
    root = parse_saml(_encrypted(idp, sp_material))
    encrypted = root.find(Q_ENCRYPTED_ASSERTION)
    assert encrypted is not None

    assertion = decrypt_assertion(encrypted, sp_material.private_pem)

    assert assertion.tag == Q_ASSERTION
    assert assertion.getparent() is None
    assert text_of(assertion.find(f".//{Q_NAME_ID}")) == "sam.obrien@campus.edu"
