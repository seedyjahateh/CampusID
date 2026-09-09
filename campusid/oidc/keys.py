"""Signing keys and the published JWKS (FR-OP-02).

A key set rather than a key, because rotation is the whole reason this is not
just "the signing key". Tokens already issued must keep verifying until they
expire, so during a rotation the JWKS advertises both the new key and the
outgoing one, we sign with the new one, and the old `kid` is dropped only after
the longest-lived token that could bear it has expired.

Getting that wrong is not subtle: retire a key too early and every session
holding a token signed with it breaks at once.

`kid` is derived from the key material (RFC 7638's JWK thumbprint) rather than
assigned. Two brokers given the same key compute the same `kid`, a key cannot
be silently swapped underneath a name, and there is no counter to keep.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from campusid.oidc.jwt import RS256, SigningKey, b64url

KEY_SIZE: Final = 2048
"""RSA 2048 for token signing.

Smaller than the 3072 used for SAML, deliberately. An ID token lives five
minutes and a JWKS key rotates quarterly, where a SAML certificate is pinned in
a peer's metadata for years; the exposure windows are not comparable, and 2048
keeps token verification cheap for every relying party.
"""


@dataclass(frozen=True, slots=True)
class KeySet:
    """The keys this broker signs with and publishes."""

    active: SigningKey
    """Signs every new token."""

    retiring: tuple[SigningKey, ...] = ()
    """Published and still accepted, but no longer used for new tokens. Empty
    outside a rotation."""

    @property
    def verification_keys(self) -> dict[str, rsa.RSAPublicKey]:
        """Every key a token may legitimately have been signed with."""
        return {key.kid: key.private_key.public_key() for key in (self.active, *self.retiring)}

    def as_jwks(self) -> dict[str, list[dict[str, Any]]]:
        """The document served at `/.well-known/jwks.json`.

        Public parameters only. A private component here would be catastrophic
        and silent, so `public_jwk` builds the dictionary from an explicit list
        of fields rather than filtering a larger one.
        """
        return {"keys": [public_jwk(key) for key in (self.active, *self.retiring)]}


def generate(key_size: int = KEY_SIZE) -> SigningKey:
    """Mint a new signing key, naming it by its own thumbprint."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return SigningKey(kid=thumbprint(private_key.public_key()), private_key=private_key)


def public_jwk(key: SigningKey) -> dict[str, Any]:
    """One entry in the published key set.

    Built field by field. Serialising a key object and removing the private
    parts would put the burden on the removal being complete, which is the
    wrong way round for a document served to the internet.
    """
    numbers = key.private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": RS256,
        "kid": key.kid,
        "n": b64url(_to_bytes(numbers.n)),
        "e": b64url(_to_bytes(numbers.e)),
    }


def thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """RFC 7638 JWK thumbprint: the SHA-256 of the canonical public JWK.

    The canonical form is exactly the required members, lexicographically
    ordered, with no whitespace. Any deviation changes the thumbprint, which is
    why it is constructed here rather than reusing `public_jwk` — that carries
    `use`, `alg` and `kid`, none of which belong in the hash input.
    """
    numbers = public_key.public_numbers()
    canonical = json.dumps(
        {"e": b64url(_to_bytes(numbers.e)), "kty": "RSA", "n": b64url(_to_bytes(numbers.n))},
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )


def _to_bytes(value: int) -> bytes:
    """Big-endian, minimum length, as JWA requires for `n` and `e`."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# --- persistence -----------------------------------------------------------
#
# The key set lives in the same mounted volume as the SAML keypair, for the
# reason a restart makes obvious: an ephemeral signing key invalidates every
# outstanding ID token and access token the moment the process comes back, and
# every client that cached the JWKS starts refusing tokens it should honour.

ACTIVE_KEY_FILE: Final = "oidc-active.key"
RETIRING_DIR: Final = "oidc-retiring"


def load_or_create_key_set(directory: Path, *, key_size: int = KEY_SIZE) -> KeySet:
    """Load the signing key set, generating the active key if it is absent.

    Idempotent, so restarting keeps the identity clients have cached. Every
    private key in `oidc-retiring/` is published and accepted but never used to
    sign, which is what makes a rotation invisible to a client holding a token
    minted a minute before it.
    """
    directory.mkdir(parents=True, exist_ok=True)
    active_path = directory / ACTIVE_KEY_FILE

    if active_path.is_file():
        active = _read_key(active_path)
    else:
        active = generate(key_size)
        _write_key(active_path, active)

    retiring_dir = directory / RETIRING_DIR
    retiring = (
        tuple(_read_key(path) for path in sorted(retiring_dir.glob("*.key")))
        if retiring_dir.is_dir()
        else ()
    )
    return KeySet(active=active, retiring=retiring)


def rotate(directory: Path, *, key_size: int = KEY_SIZE) -> KeySet:
    """Mint a new active key, moving the outgoing one to `retiring/`.

    Rotation is two steps, not one, and this is the first: from here the new key
    signs and both verify. The second step — deleting the retired key once the
    longest-lived token bearing it has expired — is deliberately *not* automatic.
    Doing it on a timer means a clock problem or a long-lived refresh token
    turns into every session breaking at once, so it is a decision an operator
    makes with `retire`.
    """
    current = load_or_create_key_set(directory, key_size=key_size)

    retiring_dir = directory / RETIRING_DIR
    retiring_dir.mkdir(parents=True, exist_ok=True)
    _write_key(retiring_dir / f"{_filename(current.active.kid)}.key", current.active)

    fresh = generate(key_size)
    _write_key(directory / ACTIVE_KEY_FILE, fresh)
    return KeySet(active=fresh, retiring=(*current.retiring, current.active))


def retire(directory: Path, kid: str) -> KeySet:
    """Drop a retiring key, ending its rotation.

    Every token still bearing this `kid` stops verifying at once, which is why
    it is a separate act from `rotate`.
    """
    path = directory / RETIRING_DIR / f"{_filename(kid)}.key"
    path.unlink(missing_ok=True)
    return load_or_create_key_set(directory)


def _filename(kid: str) -> str:
    """A thumbprint is base64url, which contains `-` and `_` but never `/`, so
    it is already a safe filename. Asserted rather than assumed, because a `kid`
    that reached the filesystem with a separator in it would be a path
    traversal with our own key material as the payload."""
    if "/" in kid or "\\" in kid or kid in {"", ".", ".."}:
        raise ValueError(f"refusing to use {kid!r} as a filename")
    return kid


def _read_key(path: Path) -> SigningKey:
    private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(f"{path.name} is not an RSA private key")
    return SigningKey(kid=thumbprint(private_key.public_key()), private_key=private_key)


def _write_key(path: Path, key: SigningKey) -> None:
    # Mode set at creation rather than afterwards, so the key is never briefly
    # world-readable — the same reasoning as the SAML keypair.
    path.touch(mode=0o600, exist_ok=True)
    path.write_bytes(
        key.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
