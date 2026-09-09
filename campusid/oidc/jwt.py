"""JWT signing and verification.

Hand-written against `cryptography` rather than delegated to a JWT library, for
one reason: **the verifier must never take its algorithm from the token.**

That single sentence is the whole of the two classic JWT vulnerabilities.
`{"alg": "none"}` says a token needs no signature, and a verifier that believes
it accepts anything. Algorithm confusion says `{"alg": "HS256"}` over an
RSA-issued token, so a verifier that dispatches on the header uses the *public*
key as an HMAC secret — and the public key is published in our own JWKS.

Both disappear if the caller states the algorithm and the header is merely
checked against it, which is what `decode` does. There is no dispatch table
here and no way to reach one, so there is nothing for a header to steer.

Everything else follows the ordinary rules: `kid` selects a key from a set we
control, the signature is checked before any claim is read, and the time claims
are validated with a bounded leeway rather than trusted.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RS256: Final = "RS256"
"""The only algorithm this broker signs or accepts.

Narrow on purpose. Every JWT vulnerability of consequence has come from a
verifier being flexible about algorithms, and a campus broker has no need to be.
"""

TYPE_JWT: Final = "JWT"
TYPE_AT_JWT: Final = "at+jwt"
"""RFC 9068's media type for a JWT access token. Distinguishing it from an ID
token in the header is what stops a resource server accepting one where the
other was meant."""


class JwtError(Exception):
    """A token could not be trusted.

    Deliberately one exception with a short message. Which check failed is
    useful to an operator reading a log, not to whoever supplied the token.
    """


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private key and the `kid` that names it in our JWKS."""

    kid: str
    private_key: rsa.RSAPrivateKey


def b64url(raw: bytes) -> str:
    """Base64url with padding stripped, as every JWS field uses."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Reverse `b64url`, restoring the padding the encoding drops."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encode(claims: dict[str, Any], key: SigningKey, *, typ: str = TYPE_JWT) -> str:
    """Sign a claim set as a compact JWS."""
    header = {"alg": RS256, "typ": typ, "kid": key.kid}
    signing_input = (
        f"{b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    )
    signature = key.private_key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{signing_input}.{b64url(signature)}"


def decode(
    token: str,
    public_keys: dict[str, rsa.RSAPublicKey],
    *,
    issuer: str,
    audience: str | None,
    now: datetime,
    leeway: timedelta = timedelta(seconds=60),
    expected_typ: str | None = None,
) -> dict[str, Any]:
    """Verify a token and return its claims, or raise `JwtError`.

    ``public_keys`` is keyed by `kid` and is the *only* source of verification
    material. A token naming a `kid` we do not hold is refused rather than
    verified against whatever else is lying around, which is how key rotation
    stays safe: retiring a key removes it from this map and every token signed
    with it stops verifying at once.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("malformed token")

    encoded_header, encoded_claims, encoded_signature = parts
    header = _json(encoded_header, "header")

    # The algorithm is asserted, never adopted. `alg: none` and algorithm
    # confusion both need a verifier that dispatches on this field; this one
    # only compares it.
    if header.get("alg") != RS256:
        raise JwtError("unsupported algorithm")
    if expected_typ is not None and header.get("typ") != expected_typ:
        raise JwtError("unexpected token type")

    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in public_keys:
        raise JwtError("unknown signing key")

    try:
        public_keys[kid].verify(
            b64url_decode(encoded_signature),
            f"{encoded_header}.{encoded_claims}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise JwtError("signature verification failed") from exc

    # Only now are the claims worth reading.
    claims = _json(encoded_claims, "claims")
    _check_claims(claims, issuer=issuer, audience=audience, now=now, leeway=leeway)
    return claims


def _json(segment: str, what: str) -> dict[str, Any]:
    try:
        decoded = json.loads(b64url_decode(segment))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtError(f"malformed {what}") from exc
    if not isinstance(decoded, dict):
        raise JwtError(f"malformed {what}")
    return decoded


def _check_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    audience: str | None,
    now: datetime,
    leeway: timedelta,
) -> None:
    if claims.get("iss") != issuer:
        raise JwtError("issuer mismatch")

    if audience is not None and not _audience_matches(claims.get("aud"), audience):
        raise JwtError("audience mismatch")

    timestamp = now.timestamp()
    slack = leeway.total_seconds()

    expiry = claims.get("exp")
    if not isinstance(expiry, int | float):
        raise JwtError("missing expiry")
    if timestamp >= expiry + slack:
        raise JwtError("token has expired")

    issued = claims.get("iat")
    if isinstance(issued, int | float) and timestamp + slack < issued:
        raise JwtError("token issued in the future")

    not_before = claims.get("nbf")
    if isinstance(not_before, int | float) and timestamp + slack < not_before:
        raise JwtError("token is not yet valid")


def _audience_matches(claim: Any, expected: str) -> bool:
    """`aud` is a string or an array of strings; both are legal.

    Membership, not equality: a token addressed to several audiences is valid
    at each of them, and comparing the whole list against one value would
    reject perfectly good multi-audience tokens.
    """
    if isinstance(claim, str):
        return claim == expected
    if isinstance(claim, list):
        return expected in claim
    return False
