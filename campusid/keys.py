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
from typing import Final

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
    _write(key_path, certificate_path, material)
    return material


def _write(key_path: Path, certificate_path: Path, material: SigningMaterial) -> None:
    # The key is written before the certificate, and with the mode set at
    # creation rather than after, so it is never briefly world-readable.
    key_path.touch(mode=0o600, exist_ok=True)
    key_path.write_bytes(material.private_pem)
    certificate_path.write_text(material.certificate_pem, encoding="ascii")


# --- rotation ---------------------------------------------------------------
#
# A key a peer has pinned cannot be replaced in one step, so this models the
# overlap rather than the swap (NFR-SEC-06, FR-FED-05). The set holds one key we
# *use* and any number we *publish*, and the two move independently — which is
# what lets a rotation be safe in both directions:
#
# **A signing key is published before it is used.** We sign and the peer
# verifies, so a peer that has not yet refreshed our metadata would reject
# anything signed with a certificate it has never seen. Stage the new key, wait
# out the peer's refresh interval, then promote it.
#
# **An encryption key is used before it is unpublished.** The peer encrypts and
# we decrypt, so the risk runs the other way: a peer that is still using the old
# certificate sends ciphertext only the old private key opens. Publish the new
# one, keep accepting the old, and retire it once the window has passed.
#
# Both are the same three verbs in a different order, which is why this does not
# try to encode a direction. Getting the order right is the runbook's job and it
# is what the runbook is mostly about.

ADDITIONAL: Final = "-additional"
"""Suffix of the directory holding every published key that is not the active
one. Beside the active pair rather than replacing it, so a volume written by a
version of this broker that knew nothing about rotation still loads."""


@dataclass(frozen=True, slots=True)
class KeySet:
    """The keys of one role: the one in use, and everything published."""

    active: SigningMaterial
    """What we sign with, or prefer to be encrypted to."""

    additional: tuple[SigningMaterial, ...] = ()
    """Published alongside it. A staged successor, an outgoing predecessor, or
    both — this does not distinguish them, because the difference is in the
    operator's intent rather than in the key."""

    @property
    def certificates(self) -> tuple[str, ...]:
        """Every certificate to publish, active first.

        Order is not load-bearing for a conformant peer, which reads all of
        them, but it is what a human comparing two metadata documents reads
        first.
        """
        return (self.active.certificate_pem, *(each.certificate_pem for each in self.additional))

    @property
    def private_keys(self) -> tuple[bytes, ...]:
        """Every private key, for a decryption that must try each in turn."""
        return (self.active.private_pem, *(each.private_pem for each in self.additional))


def fingerprint(certificate_pem: str) -> str:
    """The SHA-256 fingerprint, lowercase hex and no colons.

    How a peer refers to our certificate and therefore how an operator does,
    which is the only reason to prefer it to a serial number. It is also derived
    from the material rather than assigned, so it cannot name the wrong key.
    """
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    return certificate.fingerprint(hashes.SHA256()).hex()


def load_or_create_set(directory: Path, name: str, common_name: str) -> KeySet:
    """Load every key of one role, generating the active one if it is absent."""
    active = load_or_create(directory, name, common_name)
    return KeySet(active=active, additional=_load_additional(directory, name))


def stage(directory: Path, name: str, common_name: str) -> SigningMaterial:
    """Mint a successor and publish it without using it.

    The first half of a rotation, and on its own it changes nothing a peer can
    observe except the metadata document. Returning the new material rather than
    the set, because the next thing an operator does is read its fingerprint to
    quote in `promote`.
    """
    material = generate_self_signed(common_name)
    _write(*_additional_paths(directory, name, material), material)
    return material


def promote(directory: Path, name: str, certificate_fingerprint: str) -> KeySet:
    """Start using a published key, demoting the current one beside it.

    A swap rather than a replacement: the outgoing key stays published, because
    a peer mid-refresh may still be verifying against it and dropping it here
    would make this step the outage the overlap exists to prevent.
    """
    current = load_or_create_set(directory, name, _subject_of(directory, name))
    incoming = _find(current.additional, certificate_fingerprint)
    if incoming is None:
        raise KeyError(f"no published key with fingerprint {certificate_fingerprint}")

    # The outgoing key moves into the additional directory before the incoming
    # one is removed from it, so a crash between the two leaves the key
    # published twice rather than not at all.
    _write(*_additional_paths(directory, name, current.active), current.active)
    _unlink(*_additional_paths(directory, name, incoming))
    _write(directory / f"{name}.key", directory / f"{name}.crt", incoming)

    return load_or_create_set(directory, name, _subject_of(directory, name))


def retire(directory: Path, name: str, certificate_fingerprint: str) -> KeySet:
    """Stop publishing a key, ending its overlap.

    Refuses to touch the active one. Deleting the key we are signing with would
    not be a rotation that went wrong; it would be a broker that cannot sign,
    and the mistake is one fingerprint away from the operation above.
    """
    current = load_or_create_set(directory, name, _subject_of(directory, name))
    if fingerprint(current.active.certificate_pem) == certificate_fingerprint:
        raise ValueError(f"{certificate_fingerprint} is the active key; promote another one first")

    material = _find(current.additional, certificate_fingerprint)
    if material is None:
        raise KeyError(f"no published key with fingerprint {certificate_fingerprint}")

    _unlink(*_additional_paths(directory, name, material))
    return load_or_create_set(directory, name, _subject_of(directory, name))


def _find(
    materials: tuple[SigningMaterial, ...], certificate_fingerprint: str
) -> SigningMaterial | None:
    for material in materials:
        if fingerprint(material.certificate_pem) == certificate_fingerprint:
            return material
    return None


def _additional_paths(directory: Path, name: str, material: SigningMaterial) -> tuple[Path, Path]:
    """Where one published-but-not-active pair lives.

    Named by fingerprint, which is hex and therefore already a safe filename —
    asserted in `_safe` rather than assumed, because a name that reached the
    filesystem with a separator in it would be a path traversal carrying our own
    key material.
    """
    stem = _safe(fingerprint(material.certificate_pem))
    folder = directory / f"{name}{ADDITIONAL}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{stem}.key", folder / f"{stem}.crt"


def _load_additional(directory: Path, name: str) -> tuple[SigningMaterial, ...]:
    folder = directory / f"{name}{ADDITIONAL}"
    if not folder.is_dir():
        return ()
    materials = []
    for key_path in sorted(folder.glob("*.key")):
        certificate_path = key_path.with_suffix(".crt")
        if not certificate_path.is_file():
            # A key with no certificate cannot be published and cannot be named,
            # so it is skipped rather than raised on: a half-written pair must
            # not stop the broker starting.
            continue
        materials.append(
            SigningMaterial(
                private_pem=key_path.read_bytes(),
                certificate_pem=certificate_path.read_text(encoding="ascii"),
            )
        )
    return tuple(materials)


def _subject_of(directory: Path, name: str) -> str:
    """The common name already on the active certificate.

    Read rather than passed in, so `promote` and `retire` cannot accidentally
    mint a key for a different subject when the active pair happens to be
    missing. They never should be; this is what makes that true rather than
    assumed.
    """
    certificate_path = directory / f"{name}.crt"
    if not certificate_path.is_file():
        raise FileNotFoundError(f"{certificate_path} does not exist; there is nothing to rotate")
    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    value = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    # `value` is `str | bytes`: X.509 attributes are typed by their encoding and
    # a name that arrived as an unrecognised string type comes back as raw bytes.
    return value if isinstance(value, str) else value.decode("utf-8")


def _safe(stem: str) -> str:
    if "/" in stem or "\\" in stem or stem in {"", ".", ".."}:
        raise ValueError(f"refusing to use {stem!r} as a filename")
    return stem


def _unlink(*paths: Path) -> None:
    for path in paths:
        path.unlink(missing_ok=True)
