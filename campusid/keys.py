"""SP key material.

The broker generates its own signing keypair on first start and keeps it in a
mounted volume. That is a deliberate choice over shipping a fixed development
key: a repository about credential handling that contains a private key —
however clearly labelled — is arguing against itself, and gitleaks would fail
the build for it, correctly.

The cost is that the certificate is not knowable until the broker has run once,
which is why Keycloak's client is registered by `federation-init` after the
broker is up rather than by a static realm import.

Self-signed is right here. SAML trust is metadata-pinned, not PKIX: a peer
trusts this certificate because it appeared in metadata they chose to load, not
because a CA vouched for it. A chain would add ceremony and no security.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KEY_SIZE = 3072
"""PRD section 11.2 specifies RSA 3072 for the SAML signing key. Larger than the
2048 used for throwaway test keys, because this one has a multi-year life."""

CERTIFICATE_LIFETIME = dt.timedelta(days=3650)
"""Long, and deliberately not a security control. Peers pin this certificate
through metadata, so rotation is driven by `validUntil` and the documented
overlap procedure, not by certificate expiry."""


@dataclass(frozen=True, slots=True)
class SigningMaterial:
    """A private key and its certificate.

    The private key is bytes and the certificate is text because that is what
    the consumers want: signxml and `cryptography` take key bytes, while SAML
    metadata carries certificates as base64 inside an XML element.
    """

    private_pem: bytes
    certificate_pem: str


def generate_self_signed(
    common_name: str,
    *,
    key_size: int = KEY_SIZE,
    lifetime: dt.timedelta = CERTIFICATE_LIFETIME,
    now: dt.datetime | None = None,
) -> SigningMaterial:
    """Generate a keypair and a self-signed certificate for ``common_name``."""
    now = now or dt.datetime.now(dt.UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return SigningMaterial(
        private_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
    )


def load_or_create(directory: Path, name: str, common_name: str) -> SigningMaterial:
    """Load the named keypair, generating and persisting it if absent.

    Idempotent, so restarting the broker keeps the identity a peer already
    trusts. Losing the volume means a new certificate and a metadata exchange
    that has to be redone — the same consequence a real deployment faces, which
    is why the volume is named rather than anonymous.
    """
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / f"{name}.key"
    certificate_path = directory / f"{name}.crt"

    if key_path.is_file() and certificate_path.is_file():
        return SigningMaterial(
            private_pem=key_path.read_bytes(),
            certificate_pem=certificate_path.read_text(encoding="ascii"),
        )

    material = generate_self_signed(common_name)
    # Written before the certificate, and with the mode set at creation rather
    # than after, so the key is never briefly world-readable.
    key_path.touch(mode=0o600, exist_ok=True)
    key_path.write_bytes(material.private_pem)
    certificate_path.write_text(material.certificate_pem, encoding="ascii")
    return material
