"""WebAuthn registration and assertion (FR-MFA-02).

The parts of WebAuthn that are a security boundary, implemented against the
specification rather than delegated: what the authenticator signs, what the
browser puts in `clientDataJSON`, and which of those fields the server is
required to check. Delegating those would mean a portfolio that claims to
understand phishing resistance and points at a library for the reason it works.

**Phishing resistance is one comparison.** The authenticator scopes every
credential to an RP ID and the browser refuses to use it from another origin, so
the property the server has to preserve is simply that the origin in
`clientDataJSON` is ours and the RP ID hash in the authenticator data is ours. A
server that skips either has a second factor that a proxy in front of a lookalike
domain can relay, which is the attack every other second factor loses to.

**Attestation is `none`, and that is a decision.** Anything stronger means
deciding which authenticator models are acceptable, maintaining the metadata to
answer that, and turning a self-service enrolment into a procurement policy. A
campus that wants to bar a vendor wants an inventory, not a signature. The format
is checked and anything else is refused by name, because silently accepting an
attestation statement we do not verify is worse than not asking for one.

**User verification is recorded, not required, at the credential level.** A
passkey with a PIN and a security key with a touch are both second factors; only
the first is a *second* factor on its own. Which one this is decides whether an
assertion can satisfy a step-up by itself, so the flag is carried out of here
rather than collapsed into a boolean pass.

**A sign counter that goes backwards means two authenticators.** Counters are
per-credential and monotonic, so a value at or below the stored one is a copy of
the private key in use somewhere — the one signal WebAuthn gives that a
credential has been cloned. Reported by name rather than as a generic failure,
because the response to it is to revoke the credential rather than to retry.
Authenticators that do not implement counters report zero forever, and that case
is allowed explicitly rather than by accident.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from campusid.mfa import cbor

# --- reason codes -----------------------------------------------------------

MALFORMED: Final = "mfa.webauthn_malformed"
WRONG_TYPE: Final = "mfa.webauthn_wrong_type"
CHALLENGE_MISMATCH: Final = "mfa.webauthn_challenge_mismatch"
ORIGIN_MISMATCH: Final = "mfa.webauthn_origin_mismatch"
RP_MISMATCH: Final = "mfa.webauthn_rp_mismatch"
USER_NOT_PRESENT: Final = "mfa.webauthn_user_not_present"
UNSUPPORTED_ATTESTATION: Final = "mfa.webauthn_unsupported_attestation"
UNSUPPORTED_ALGORITHM: Final = "mfa.webauthn_unsupported_algorithm"
SIGNATURE_INVALID: Final = "mfa.webauthn_signature_invalid"
CLONED: Final = "mfa.cloned_credential_suspected"


class WebAuthnRejected(Exception):
    """A registration or assertion that did not hold, and why.

    Named reasons for the same argument the SAML gate makes: "it failed" tells an
    operator nothing, and a reviewer cannot tell a check that runs from a check
    that was forgotten.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --- what the authenticator says --------------------------------------------

UP: Final = 0x01
"""User was present — a touch. Required for every ceremony."""

UV: Final = 0x04
"""User was verified — a PIN, a fingerprint, a face. Recorded, not required."""

AT: Final = 0x40
"""Attested credential data follows. Present at registration, absent afterwards."""

ED: Final = 0x80
"""Extension data follows."""

ES256: Final = -7
RS256: Final = -257
EDDSA: Final = -8

SUPPORTED_ALGORITHMS: Final = (ES256, RS256, EDDSA)
"""The COSE algorithms this broker will register.

An allowlist rather than "whatever the key says", because the algorithm
identifier arrives with the credential and a server that honoured it blindly
would let the enrolling party choose the verification path.
"""

COSE_KTY: Final = 1
COSE_ALG: Final = 3
COSE_CRV: Final = -1
COSE_X: Final = -2
COSE_Y: Final = -3
COSE_RSA_N: Final = -1
COSE_RSA_E: Final = -2

KTY_OKP: Final = 1
KTY_EC2: Final = 2
KTY_RSA: Final = 3

CRV_P256: Final = 1
CRV_ED25519: Final = 6


@dataclass(frozen=True, slots=True)
class AuthenticatorData:
    """The authenticator's half of the signed message."""

    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None
    public_key: bytes | None
    """The COSE key, as the exact bytes it arrived in.

    Kept encoded rather than as parsed parameters so that what is stored is what
    was signed for, and so a later change to the parser cannot change what an
    existing credential means.
    """

    @property
    def user_present(self) -> bool:
        return bool(self.flags & UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & UV)


@dataclass(frozen=True, slots=True)
class Registration:
    """A credential the broker is willing to store."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    user_verified: bool
    algorithm: int


@dataclass(frozen=True, slots=True)
class Assertion:
    """A use of a credential the broker is willing to believe."""

    credential_id: bytes
    sign_count: int
    user_verified: bool


# --- registration -----------------------------------------------------------


def register(
    *,
    client_data: bytes,
    attestation_object: bytes,
    challenge: bytes,
    origin: str,
    rp_id: str,
) -> Registration:
    """Check a `navigator.credentials.create()` result (FR-MFA-02)."""
    _client_data(client_data, expected_type="webauthn.create", challenge=challenge, origin=origin)

    try:
        attestation = cbor.decode(attestation_object)
    except cbor.CborError as exc:
        raise WebAuthnRejected(MALFORMED, str(exc)) from exc
    if not isinstance(attestation, dict):
        raise WebAuthnRejected(MALFORMED, "attestation object is not a map")

    fmt = attestation.get("fmt")
    if fmt != "none":
        # Refused by name rather than ignored. Accepting a statement we do not
        # verify would let an enrolment claim a provenance nothing checked.
        raise WebAuthnRejected(UNSUPPORTED_ATTESTATION, f"format {fmt!r}")

    raw = attestation.get("authData")
    if not isinstance(raw, bytes):
        raise WebAuthnRejected(MALFORMED, "attestation object has no authData")

    authenticator = parse_authenticator_data(raw, expect_credential=True)
    _common(authenticator, rp_id)

    if authenticator.credential_id is None or authenticator.public_key is None:
        raise WebAuthnRejected(MALFORMED, "registration carries no credential")

    algorithm = _algorithm(authenticator.public_key)
    # Built here and thrown away, so a key this broker could never verify with
    # is refused at enrolment rather than at the first login that needed it. A
    # credential that registers and then never works is the worst outcome
    # available: the person believes they have a second factor.
    _public_key(authenticator.public_key)

    return Registration(
        credential_id=authenticator.credential_id,
        public_key=authenticator.public_key,
        sign_count=authenticator.sign_count,
        user_verified=authenticator.user_verified,
        algorithm=algorithm,
    )


# --- assertion --------------------------------------------------------------


def verify(
    *,
    client_data: bytes,
    authenticator_data: bytes,
    signature: bytes,
    public_key: bytes,
    credential_id: bytes,
    stored_sign_count: int,
    challenge: bytes,
    origin: str,
    rp_id: str,
) -> Assertion:
    """Check a `navigator.credentials.get()` result (FR-MFA-02).

    The signature covers the authenticator data followed by the hash of the
    client data, in that order. Composing the signed message here rather than
    accepting one from the caller is what keeps the check honest: a caller that
    could supply the message could supply one that never mentions the origin.
    """
    client_hash = _client_data(
        client_data, expected_type="webauthn.get", challenge=challenge, origin=origin
    )
    authenticator = parse_authenticator_data(authenticator_data, expect_credential=False)
    _common(authenticator, rp_id)

    _check_signature(
        key=_public_key(public_key),
        algorithm=_algorithm(public_key),
        signature=signature,
        message=authenticator_data + client_hash,
    )
    _check_counter(stored_sign_count, authenticator.sign_count)

    return Assertion(
        credential_id=credential_id,
        sign_count=authenticator.sign_count,
        user_verified=authenticator.user_verified,
    )


# --- the pieces -------------------------------------------------------------


def parse_authenticator_data(raw: bytes, *, expect_credential: bool) -> AuthenticatorData:
    """Split the authenticator data into its fixed and optional parts.

    The layout is a 32-byte RP ID hash, a flags byte and a big-endian counter,
    optionally followed by attested credential data and extensions. Every length
    inside it is checked against the bytes actually present, because the length
    of the credential id is a number the authenticator chose.
    """
    if len(raw) < 37:
        raise WebAuthnRejected(MALFORMED, f"authenticator data is {len(raw)} bytes")

    rp_id_hash = raw[:32]
    flags = raw[32]
    (sign_count,) = struct.unpack(">I", raw[33:37])

    credential_id: bytes | None = None
    public_key: bytes | None = None
    offset = 37

    if flags & AT:
        if len(raw) < offset + 18:
            raise WebAuthnRejected(MALFORMED, "attested credential data is truncated")
        # The AAGUID identifies the authenticator model. Skipped deliberately:
        # acting on it is the inventory decision that attestation `none` declines
        # to make, and reading it without acting on it would be decoration.
        offset += 16
        (id_length,) = struct.unpack(">H", raw[offset : offset + 2])
        offset += 2
        if len(raw) < offset + id_length:
            raise WebAuthnRejected(MALFORMED, "credential id runs past the end")
        credential_id = raw[offset : offset + id_length]
        offset += id_length

        try:
            _, used = cbor.decode_prefix(raw[offset:])
        except cbor.CborError as exc:
            raise WebAuthnRejected(MALFORMED, str(exc)) from exc
        # Sliced rather than re-encoded, so what is stored is exactly what
        # arrived. Re-encoding would make the stored key depend on this module's
        # encoder agreeing with the authenticator's forever.
        public_key = raw[offset : offset + used]
        offset += used

    elif expect_credential:
        raise WebAuthnRejected(MALFORMED, "registration carries no attested credential data")

    if flags & ED:
        try:
            _, used = cbor.decode_prefix(raw[offset:])
        except cbor.CborError as exc:
            raise WebAuthnRejected(MALFORMED, str(exc)) from exc
        offset += used

    if offset != len(raw):
        # Trailing bytes mean the structure was not what it claimed, and a
        # parser that ignores them is one an attacker can hide a second reading
        # inside.
        raise WebAuthnRejected(MALFORMED, f"{len(raw) - offset} bytes after the structure")

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        credential_id=credential_id,
        public_key=public_key,
    )


def _client_data(raw: bytes, *, expected_type: str, challenge: bytes, origin: str) -> bytes:
    """Check the browser's half and return its hash.

    The hash is of the bytes as they arrived, never of a re-serialisation. The
    authenticator signed those exact bytes, and a JSON round trip that reorders
    a key or normalises an escape produces a different hash and a signature
    failure nobody can explain.
    """
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise WebAuthnRejected(MALFORMED, "client data is not JSON") from exc
    if not isinstance(payload, dict):
        raise WebAuthnRejected(MALFORMED, "client data is not an object")

    if payload.get("type") != expected_type:
        # A registration response replayed into the login endpoint, or the
        # reverse. The type is the field that makes the two ceremonies
        # different messages rather than the same one used twice.
        raise WebAuthnRejected(WRONG_TYPE, str(payload.get("type")))

    if not _constant_equals(_b64url_decode(str(payload.get("challenge", ""))), challenge):
        raise WebAuthnRejected(CHALLENGE_MISMATCH, "challenge does not match the outstanding one")

    if payload.get("origin") != origin:
        # The phishing check. A credential relayed from a lookalike domain
        # arrives with the lookalike's origin here, because the browser puts it
        # there and the authenticator signs it.
        raise WebAuthnRejected(ORIGIN_MISMATCH, str(payload.get("origin")))

    return hashlib.sha256(raw).digest()


def _common(authenticator: AuthenticatorData, rp_id: str) -> None:
    """The two checks both ceremonies share."""
    if authenticator.rp_id_hash != hashlib.sha256(rp_id.encode("utf-8")).digest():
        # The other half of the phishing check, from the authenticator's side
        # rather than the browser's.
        raise WebAuthnRejected(RP_MISMATCH, "authenticator data is for another relying party")
    if not authenticator.user_present:
        # Somebody was there. Without it a credential on a plugged-in key could
        # be used by malware on the host without anybody touching anything.
        raise WebAuthnRejected(USER_NOT_PRESENT, "user-presence flag is not set")


def _check_counter(stored: int, presented: int) -> None:
    """FR-MFA-02's clone detection.

    Both zero means the authenticator does not implement counters, which the
    specification permits and many platform authenticators do. That case is
    allowed explicitly, so it cannot be reached by an attacker resetting a
    counter to zero on a credential that had one.
    """
    if stored == 0 and presented == 0:
        return
    if presented <= stored:
        raise WebAuthnRejected(CLONED, f"counter went from {stored} to {presented}")


def _check_signature(
    *, key: PublicKeyTypes, algorithm: int, signature: bytes, message: bytes
) -> None:
    try:
        if algorithm == ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif algorithm == RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == EDDSA and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:  # pragma: no cover - the allowlist and the parser agree by construction
            raise WebAuthnRejected(UNSUPPORTED_ALGORITHM, str(algorithm))
    except InvalidSignature as exc:
        raise WebAuthnRejected(SIGNATURE_INVALID, "signature does not verify") from exc


def _algorithm(cose_key: bytes) -> int:
    """The credential's algorithm, checked against the allowlist."""
    parameters = _cose(cose_key)
    algorithm = parameters.get(COSE_ALG)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise WebAuthnRejected(UNSUPPORTED_ALGORITHM, str(algorithm))
    return int(algorithm)


def _public_key(cose_key: bytes) -> PublicKeyTypes:
    """Turn a COSE key into something that can verify a signature.

    Each branch insists on the parameters its key type requires. A missing
    coordinate is a rejection rather than a zero, because a key assembled from
    defaults verifies nothing an attacker did not choose.
    """
    parameters = _cose(cose_key)
    kty = parameters.get(COSE_KTY)

    if kty == KTY_EC2:
        if parameters.get(COSE_CRV) != CRV_P256:
            raise WebAuthnRejected(UNSUPPORTED_ALGORITHM, f"curve {parameters.get(COSE_CRV)}")
        x, y = parameters.get(COSE_X), parameters.get(COSE_Y)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnRejected(MALFORMED, "EC2 key is missing a coordinate")
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:
            # A point that is not on the curve. Constructing it anyway would
            # mean verifying against a key the curve's arithmetic does not
            # describe.
            raise WebAuthnRejected(MALFORMED, "EC2 point is not on the curve") from exc

    if kty == KTY_RSA:
        modulus, exponent = parameters.get(COSE_RSA_N), parameters.get(COSE_RSA_E)
        if not isinstance(modulus, bytes) or not isinstance(exponent, bytes):
            raise WebAuthnRejected(MALFORMED, "RSA key is missing a parameter")
        try:
            return rsa.RSAPublicNumbers(
                int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
            ).public_key()
        except ValueError as exc:
            raise WebAuthnRejected(MALFORMED, "RSA parameters are not a key") from exc

    if kty == KTY_OKP:
        if parameters.get(COSE_CRV) != CRV_ED25519:
            raise WebAuthnRejected(UNSUPPORTED_ALGORITHM, f"curve {parameters.get(COSE_CRV)}")
        x = parameters.get(COSE_X)
        if not isinstance(x, bytes):
            raise WebAuthnRejected(MALFORMED, "OKP key is missing its public value")
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        except ValueError as exc:
            raise WebAuthnRejected(MALFORMED, "OKP public value is not a key") from exc

    raise WebAuthnRejected(UNSUPPORTED_ALGORITHM, f"key type {kty}")


def _cose(cose_key: bytes) -> dict[Any, Any]:
    try:
        parameters = cbor.decode(cose_key)
    except cbor.CborError as exc:
        raise WebAuthnRejected(MALFORMED, str(exc)) from exc
    if not isinstance(parameters, dict):
        raise WebAuthnRejected(MALFORMED, "COSE key is not a map")
    return parameters


def _b64url_decode(value: str) -> bytes:
    """Base64url without padding, as `clientDataJSON` carries it."""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        # An unparseable challenge is a mismatched challenge. Distinguishing
        # them would only tell the sender how their guess was wrong.
        return b""


def _constant_equals(left: bytes, right: bytes) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def b64url(value: bytes) -> str:
    """Encode as the browser expects a challenge to arrive."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
