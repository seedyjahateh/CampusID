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
from typing import Any, Final

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
