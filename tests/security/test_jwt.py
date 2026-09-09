"""JWT signing and verification (FR-OP-02, FR-OP-10).

The two classic JWT vulnerabilities are both attacks on a verifier that takes
its algorithm from the token it is verifying. Most of this file is about
proving this one does not.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from campusid.oidc import keys
from campusid.oidc.jwt import (
    RS256,
    TYPE_AT_JWT,
    TYPE_JWT,
    JwtError,
    SigningKey,
    b64url,
    b64url_decode,
    decode,
    encode,
)

pytestmark = pytest.mark.security

ISSUER = "https://broker.test"
AUDIENCE = "campus-portal"
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def key() -> SigningKey:
    return keys.generate(key_size=2048)


@pytest.fixture(scope="module")
def other_key() -> SigningKey:
    return keys.generate(key_size=2048)


def _claims(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "opaque-subject",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    base.update(overrides)
    return base


def _decode(token: str, key: SigningKey, **overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "now": NOW,
    }
    arguments.update(overrides)
    return decode(token, {key.kid: key.private_key.public_key()}, **arguments)  # type: ignore[arg-type]


# --- the happy path --------------------------------------------------------


def test_a_token_round_trips(key: SigningKey) -> None:
    token = encode(_claims(name="Samira"), key)

    assert _decode(token, key)["name"] == "Samira"


def test_the_header_names_the_key(key: SigningKey) -> None:
    """`kid` is what lets a verifier pick the right key during a rotation
    instead of trying all of them."""
    header = json.loads(b64url_decode(encode(_claims(), key).split(".")[0]))

    assert header == {"alg": RS256, "typ": TYPE_JWT, "kid": key.kid}


def test_an_access_token_declares_its_own_type(key: SigningKey) -> None:
    """RFC 9068. Distinguishing an access token from an ID token in the header
    is what stops a resource server accepting one where the other was meant."""
    token = encode(_claims(), key, typ=TYPE_AT_JWT)

    assert _decode(token, key, expected_typ=TYPE_AT_JWT)


def test_a_token_of_the_wrong_type_is_refused(key: SigningKey) -> None:
    with pytest.raises(JwtError, match="type"):
        _decode(encode(_claims(), key, typ=TYPE_JWT), key, expected_typ=TYPE_AT_JWT)


# --- the algorithm attacks -------------------------------------------------


def test_alg_none_is_refused(key: SigningKey) -> None:
    """The oldest JWT vulnerability: a header claiming the token needs no
    signature, and a verifier that believes it."""
    header = b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": key.kid}).encode())
    claims = b64url(json.dumps(_claims()).encode())
    forged = f"{header}.{claims}."

    with pytest.raises(JwtError, match="algorithm"):
        _decode(forged, key)


def test_algorithm_confusion_is_refused(key: SigningKey) -> None:
    """HS256 over an RSA-issued token.

    A verifier that dispatched on the header would use our *public* key as an
    HMAC secret — and that key is published in our own JWKS, so anyone could
    mint tokens. This verifier compares the header against RS256 and never
    consults it to choose a method.
    """
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key.kid}).encode())
    claims = b64url(json.dumps(_claims()).encode())
    forged = f"{header}.{claims}.{b64url(b'forged-hmac')}"

    with pytest.raises(JwtError, match="algorithm"):
        _decode(forged, key)


def test_a_token_signed_by_an_unknown_key_is_refused(
    key: SigningKey, other_key: SigningKey
) -> None:
    """`kid` selects from a set we control, so a stranger's key is not merely
    wrong — it is not present."""
    with pytest.raises(JwtError, match="signing key"):
        _decode(encode(_claims(), other_key), key)


def test_a_tampered_payload_is_refused(key: SigningKey) -> None:
    header, claims, signature = encode(_claims(), key).split(".")
    swapped = b64url(json.dumps(_claims(sub="somebody-else")).encode())

    with pytest.raises(JwtError, match="signature"):
        _decode(f"{header}.{swapped}.{signature}", key)


@pytest.mark.parametrize("malformed", ["", "a.b", "a.b.c.d", "not-a-token", "...", "a.b.c"])
def test_malformed_tokens_are_refused(key: SigningKey, malformed: str) -> None:
    with pytest.raises(JwtError):
        _decode(malformed, key)


def test_a_segment_that_is_not_an_object_is_refused(key: SigningKey) -> None:
    """`["alg"]` is valid JSON. Every field lookup on it would raise an
    unhandled `TypeError` deep in the verifier rather than a refusal, which is
    how a parser difference becomes a crash on unauthenticated input.
    """
    forged = f"{b64url(b'[\"RS256\"]')}.{b64url(json.dumps(_claims()).encode())}.{b64url(b'x')}"

    with pytest.raises(JwtError, match="malformed"):
        _decode(forged, key)


# --- claim validation ------------------------------------------------------


def test_the_signature_is_checked_before_the_claims(key: SigningKey) -> None:
    """Claims inside an unverified token are attacker-authored text.

    This token is both wrongly-signed and expired; the signature failure is
    what must be reported, because reporting the expiry would mean the verifier
    had read - and acted on - claims from a forgery.
    """
    header, claims, _ = encode(_claims(exp=int((NOW - timedelta(hours=1)).timestamp())), key).split(
        "."
    )

    with pytest.raises(JwtError, match="signature"):
        _decode(f"{header}.{claims}.{b64url(b'not-a-signature')}", key)


def test_an_expired_token_is_refused(key: SigningKey) -> None:
    token = encode(_claims(exp=int((NOW - timedelta(minutes=10)).timestamp())), key)

    with pytest.raises(JwtError, match="expired"):
        _decode(token, key)


def test_expiry_allows_a_bounded_leeway(key: SigningKey) -> None:
    """Clock skew between an issuer and a resource server is ordinary; a
    verifier with no tolerance rejects valid tokens at the boundary."""
    just_expired = encode(_claims(exp=int((NOW - timedelta(seconds=30)).timestamp())), key)

    assert _decode(just_expired, key, leeway=timedelta(seconds=60))

    with pytest.raises(JwtError, match="expired"):
        _decode(just_expired, key, leeway=timedelta(seconds=0))


def test_a_token_without_an_expiry_is_refused(key: SigningKey) -> None:
    """A token that never expires cannot be revoked by waiting, which is the
    only revocation a stateless verifier has."""
    claims = _claims()
    del claims["exp"]

    with pytest.raises(JwtError, match="expiry"):
        _decode(encode(claims, key), key)


def test_a_token_from_another_issuer_is_refused(key: SigningKey) -> None:
    with pytest.raises(JwtError, match="issuer"):
        _decode(encode(_claims(iss="https://elsewhere.test"), key), key)


def test_a_token_for_another_audience_is_refused(key: SigningKey) -> None:
    """Without this, a token minted for the analytics client would be accepted
    by the portal — the confused-deputy shape of token misuse."""
    with pytest.raises(JwtError, match="audience"):
        _decode(encode(_claims(aud="another-client"), key), key)


def test_an_array_audience_is_matched_by_membership(key: SigningKey) -> None:
    """`aud` may be an array, and a token addressed to several audiences is
    valid at each of them."""
    token = encode(_claims(aud=["another-client", AUDIENCE]), key)

    assert _decode(token, key)


@pytest.mark.parametrize("claim", [42, {"aud": AUDIENCE}, None])
def test_an_audience_of_the_wrong_shape_is_refused(key: SigningKey, claim: object) -> None:
    """`aud` is a string or an array of strings and nothing else. Anything else
    fails closed rather than being coerced into something comparable."""
    with pytest.raises(JwtError, match="audience"):
        _decode(encode(_claims(aud=claim), key), key)


def test_a_token_issued_in_the_future_is_refused(key: SigningKey) -> None:
    token = encode(_claims(iat=int((NOW + timedelta(hours=1)).timestamp())), key)

    with pytest.raises(JwtError, match="future"):
        _decode(token, key)


def test_a_not_yet_valid_token_is_refused(key: SigningKey) -> None:
    token = encode(_claims(nbf=int((NOW + timedelta(hours=1)).timestamp())), key)

    with pytest.raises(JwtError, match="not yet valid"):
        _decode(token, key)


def test_audience_may_be_skipped_for_introspection(key: SigningKey) -> None:
    """Introspection examines a token addressed to somebody else, so it cannot
    assert an audience of its own."""
    assert _decode(encode(_claims(aud="another-client"), key), key, audience=None)


# --- the key set -----------------------------------------------------------


def test_the_jwks_publishes_only_public_parameters(key: SigningKey) -> None:
    """Built field by field rather than by filtering a serialised key: a
    private component leaking into this document would be catastrophic and
    silent."""
    jwks = keys.KeySet(active=key).as_jwks()

    assert jwks["keys"][0].keys() == {"kty", "use", "alg", "kid", "n", "e"}
    assert "d" not in jwks["keys"][0]
    assert "p" not in jwks["keys"][0]


def test_a_rotation_publishes_both_keys(key: SigningKey, other_key: SigningKey) -> None:
    """Tokens already issued must keep verifying until they expire. Retiring a
    key early breaks every session holding one."""
    key_set = keys.KeySet(active=other_key, retiring=(key,))

    published = {entry["kid"] for entry in key_set.as_jwks()["keys"]}

    assert published == {key.kid, other_key.kid}
    assert set(key_set.verification_keys) == {key.kid, other_key.kid}


def test_a_token_from_a_retiring_key_still_verifies(key: SigningKey, other_key: SigningKey) -> None:
    key_set = keys.KeySet(active=other_key, retiring=(key,))
    issued_before_rotation = encode(_claims(), key)

    assert decode(
        issued_before_rotation,
        key_set.verification_keys,
        issuer=ISSUER,
        audience=AUDIENCE,
        now=NOW,
    )


def test_a_token_from_a_fully_retired_key_stops_verifying(
    key: SigningKey, other_key: SigningKey
) -> None:
    """The end of a rotation: dropping the `kid` invalidates every token that
    bore it, which is what makes the overlap window the thing to get right."""
    issued_before_rotation = encode(_claims(), key)

    with pytest.raises(JwtError, match="signing key"):
        decode(
            issued_before_rotation,
            keys.KeySet(active=other_key).verification_keys,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=NOW,
        )


def test_the_kid_is_derived_from_the_key(key: SigningKey) -> None:
    """RFC 7638. A key cannot be silently swapped underneath a name, and two
    brokers given the same key agree on what to call it."""
    assert key.kid == keys.thumbprint(key.private_key.public_key())
    assert len(key.kid) >= 40


def test_distinct_keys_get_distinct_identifiers() -> None:
    assert keys.generate(2048).kid != keys.generate(2048).kid


def test_the_thumbprint_hashes_exactly_the_canonical_members(key: SigningKey) -> None:
    """RFC 7638's hash input is exactly `e`, `kty` and `n`, lexicographic and
    unspaced. Recomputed here by hand rather than compared to itself: hashing
    the published JWK instead would fold in `use`, `alg` and `kid`, and the
    identifier would depend on presentation rather than on the key.
    """
    published = keys.public_jwk(key)
    canonical = f'{{"e":"{published["e"]}","kty":"RSA","n":"{published["n"]}"}}'.encode()

    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).decode("ascii").rstrip("=")
    )

    assert key.kid == expected
