"""A virtual authenticator, for testing WebAuthn (FR-MFA-02).

The same idea as the SAML forge: a cooperative attacker. Every negative case —
a credential relayed from a lookalike origin, a registration response replayed
into the login endpoint, a cloned key whose counter went backwards — is one
keyword argument rather than a pasted blob nobody can read.

It signs with real keys, so a test that passes proves the broker verified a real
signature rather than that a stub returned `True`.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from campusid.mfa.webauthn import AT, ED, ES256, RS256, UP, UV, b64url

AAGUID = b"\x00" * 16


# --- a canonical CBOR encoder, only as much as the authenticator needs -------


def encode(value: Any) -> bytes:
    """Encode one item in the shortest form, which is what the decoder insists
    on. Deliberately separate from the decoder so a bug in one does not hide a
    bug in the other."""
    if isinstance(value, bool):
        return bytes([0xE0 | (21 if value else 20)])
    if value is None:
        return bytes([0xE0 | 22])
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        body = b"".join(encode(k) + encode(v) for k, v in value.items())
        return _head(5, len(value)) + body
    raise TypeError(f"cannot encode {type(value).__name__}")


def _head(major: int, argument: int) -> bytes:
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    if argument < 1 << 8:
        return bytes([prefix | 24, argument])
    if argument < 1 << 16:
        return bytes([prefix | 25]) + struct.pack(">H", argument)
    if argument < 1 << 32:
        return bytes([prefix | 26]) + struct.pack(">I", argument)
    return bytes([prefix | 27]) + struct.pack(">Q", argument)


# --- the authenticator ------------------------------------------------------


class VirtualAuthenticator:
    """One credential, with a real key and a counter that behaves."""

    def __init__(self, *, algorithm: int = ES256, credential_id: bytes | None = None) -> None:
        self.algorithm = algorithm
        self.credential_id = credential_id or os.urandom(32)
        self.sign_count = 0
        if algorithm == ES256:
            self._key: Any = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == RS256:
            self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self._key = ed25519.Ed25519PrivateKey.generate()

    # --- the public key, as COSE ------------------------------------------

    def cose_key(self) -> bytes:
        public = self._key.public_key()
        if self.algorithm == ES256:
            numbers = public.public_numbers()
            return encode(
                {
                    1: 2,
                    3: ES256,
                    -1: 1,
                    -2: numbers.x.to_bytes(32, "big"),
                    -3: numbers.y.to_bytes(32, "big"),
                }
            )
        if self.algorithm == RS256:
            numbers = public.public_numbers()
            return encode(
                {
                    1: 3,
                    3: RS256,
                    -1: numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"),
                    -2: numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"),
                }
            )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return encode({1: 1, 3: -8, -1: 6, -2: raw})

    # --- ceremonies --------------------------------------------------------

    def register(
        self,
        *,
        challenge: bytes,
        origin: str,
        rp_id: str,
        user_present: bool = True,
        user_verified: bool = True,
        fmt: str = "none",
        client_type: str = "webauthn.create",
        sign_count: int | None = None,
        credential_id: bytes | None = None,
        cose_key: bytes | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> tuple[bytes, bytes]:
        """Mint a `navigator.credentials.create()` result."""
        client_data = self.client_data(client_type, challenge, origin)
        authenticator = self.authenticator_data(
            rp_id=rp_id,
            user_present=user_present,
            user_verified=user_verified,
            sign_count=self.sign_count if sign_count is None else sign_count,
            credential_id=credential_id if credential_id is not None else self.credential_id,
            cose_key=cose_key if cose_key is not None else self.cose_key(),
            extensions=extensions,
        )
        attestation = encode({"fmt": fmt, "attStmt": {}, "authData": authenticator})
        return client_data, attestation

    def assert_(
        self,
        *,
        challenge: bytes,
        origin: str,
        rp_id: str,
        user_present: bool = True,
        user_verified: bool = True,
        sign_count: int | None = None,
        client_type: str = "webauthn.get",
        sign_with: VirtualAuthenticator | None = None,
        tamper: bool = False,
    ) -> tuple[bytes, bytes, bytes]:
        """Mint a `navigator.credentials.get()` result.

        `sign_with` is the wrong-key case and `tamper` is the altered-message
        case, which are different failures: one is somebody else's credential,
        the other is this credential's response modified in flight.
        """
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count

        client_data = self.client_data(client_type, challenge, origin)
        authenticator = self.authenticator_data(
            rp_id=rp_id,
            user_present=user_present,
            user_verified=user_verified,
            sign_count=sign_count,
            credential_id=None,
            cose_key=None,
            extensions=None,
        )
        message = authenticator + hashlib.sha256(client_data).digest()
        signer = sign_with or self
        signature = signer._sign(message[:-1] if tamper else message)
        return client_data, authenticator, signature

    # --- the pieces --------------------------------------------------------

    def client_data(self, ceremony: str, challenge: bytes, origin: str) -> bytes:
        """Serialised once, here, because the hash is of these exact bytes."""
        return json.dumps(
            {"type": ceremony, "challenge": b64url(challenge), "origin": origin}
        ).encode("utf-8")

    def authenticator_data(
        self,
        *,
        rp_id: str,
        user_present: bool,
        user_verified: bool,
        sign_count: int,
        credential_id: bytes | None,
        cose_key: bytes | None,
        extensions: dict[str, Any] | None,
    ) -> bytes:
        flags = 0
        if user_present:
            flags |= UP
        if user_verified:
            flags |= UV
        if credential_id is not None:
            flags |= AT
        if extensions is not None:
            flags |= ED

        data = hashlib.sha256(rp_id.encode("utf-8")).digest()
        data += bytes([flags]) + struct.pack(">I", sign_count)
        if credential_id is not None:
            data += AAGUID + struct.pack(">H", len(credential_id)) + credential_id
            data += cose_key or b""
        if extensions is not None:
            data += encode(extensions)
        return data

    def _sign(self, message: bytes) -> bytes:
        if self.algorithm == ES256:
            return bytes(self._key.sign(message, ec.ECDSA(hashes.SHA256())))
        if self.algorithm == RS256:
            return bytes(self._key.sign(message, padding.PKCS1v15(), hashes.SHA256()))
        return bytes(self._key.sign(message))
