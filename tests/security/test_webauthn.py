"""WebAuthn registration and assertion (FR-MFA-02).

Against a virtual authenticator holding a real key, so a passing test means a
real signature verified rather than that a stub agreed.

The two tests worth reading are the phishing pair. WebAuthn's whole claim over
every other second factor is that a credential cannot be relayed from a lookalike
domain, and that claim rests on two comparisons the server has to make: the
origin the browser recorded, and the relying-party hash the authenticator signed.
A server that skips either has a factor a proxy can relay, and nothing about the
ceremony would look different.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from campusid.mfa import webauthn
from campusid.mfa.webauthn import (
    CHALLENGE_MISMATCH,
    CLONED,
    ES256,
    MALFORMED,
    ORIGIN_MISMATCH,
    RP_MISMATCH,
    RS256,
    SIGNATURE_INVALID,
    UNSUPPORTED_ALGORITHM,
    UNSUPPORTED_ATTESTATION,
    USER_NOT_PRESENT,
    WRONG_TYPE,
    WebAuthnRejected,
)
from tests.support.authenticator import VirtualAuthenticator, encode

pytestmark = pytest.mark.security

ORIGIN = "https://broker.campus.test"
RP_ID = "broker.campus.test"
EVIL_ORIGIN = "https://broker.campus.test.evil.example"
EVIL_RP = "broker.campus.test.evil.example"


@pytest.fixture
def challenge() -> bytes:
    return os.urandom(32)


@pytest.fixture
def authenticator() -> VirtualAuthenticator:
    return VirtualAuthenticator()


def _register(
    authenticator: VirtualAuthenticator, challenge: bytes, **overrides: Any
) -> webauthn.Registration:
    client_data, attestation = authenticator.register(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID, **overrides
    )
    return webauthn.register(
        client_data=client_data,
        attestation_object=attestation,
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
    )


def _verify(
    authenticator: VirtualAuthenticator,
    registered: webauthn.Registration,
    challenge: bytes,
    *,
    stored: int | None = None,
    **overrides: Any,
) -> webauthn.Assertion:
    client_data, data, signature = authenticator.assert_(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID, **overrides
    )
    return webauthn.verify(
        client_data=client_data,
        authenticator_data=data,
        signature=signature,
        public_key=registered.public_key,
        credential_id=registered.credential_id,
        stored_sign_count=registered.sign_count if stored is None else stored,
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
    )


# --- the happy path ---------------------------------------------------------


def test_a_credential_registers(authenticator: VirtualAuthenticator, challenge: bytes) -> None:
    registered = _register(authenticator, challenge)

    assert registered.credential_id == authenticator.credential_id
    assert registered.algorithm == ES256
    assert registered.user_verified is True


def test_a_registered_credential_asserts(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    registered = _register(authenticator, challenge)

    assertion = _verify(authenticator, registered, os.urandom(32))

    assert assertion.credential_id == registered.credential_id
    assert assertion.sign_count > registered.sign_count


@pytest.mark.parametrize("algorithm", [ES256, RS256, webauthn.EDDSA])
def test_every_allowed_algorithm_round_trips(algorithm: int, challenge: bytes) -> None:
    """An allowlist that only ever runs one branch is an allowlist nobody has
    checked."""
    authenticator = VirtualAuthenticator(algorithm=algorithm)
    registered = _register(authenticator, challenge)

    assert _verify(authenticator, registered, os.urandom(32)).sign_count == 1


# --- phishing resistance ----------------------------------------------------


def test_a_credential_from_a_lookalike_origin_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The claim WebAuthn makes over every other second factor. A proxy in front
    of a lookalike domain produces exactly this: a well-formed response whose
    client data names the attacker's origin, because the browser put it there."""
    client_data, attestation = authenticator.register(
        challenge=challenge, origin=EVIL_ORIGIN, rp_id=RP_ID
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=client_data,
            attestation_object=attestation,
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == ORIGIN_MISMATCH


def test_an_assertion_from_a_lookalike_origin_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    registered = _register(authenticator, challenge)
    used = os.urandom(32)
    client_data, data, signature = authenticator.assert_(
        challenge=used, origin=EVIL_ORIGIN, rp_id=RP_ID
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.verify(
            client_data=client_data,
            authenticator_data=data,
            signature=signature,
            public_key=registered.public_key,
            credential_id=registered.credential_id,
            stored_sign_count=0,
            challenge=used,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == ORIGIN_MISMATCH


def test_a_credential_scoped_to_another_relying_party_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The same check from the authenticator's side. Both are needed: the origin
    is what the browser saw, the hash is what the authenticator signed, and only
    the second survives a compromised browser."""
    client_data, attestation = authenticator.register(
        challenge=challenge, origin=ORIGIN, rp_id=EVIL_RP
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=client_data,
            attestation_object=attestation,
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == RP_MISMATCH


# --- the challenge ----------------------------------------------------------


def test_a_response_to_another_challenge_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """Without this the whole ceremony is replayable: a response captured once
    works forever."""
    client_data, attestation = authenticator.register(
        challenge=os.urandom(32), origin=ORIGIN, rp_id=RP_ID
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=client_data,
            attestation_object=attestation,
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == CHALLENGE_MISMATCH


def test_a_registration_replayed_into_the_login_endpoint_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The ceremony type is what makes the two messages different rather than
    the same one used twice."""
    registered = _register(authenticator, challenge)
    used = os.urandom(32)
    client_data, data, signature = authenticator.assert_(
        challenge=used, origin=ORIGIN, rp_id=RP_ID, client_type="webauthn.create"
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.verify(
            client_data=client_data,
            authenticator_data=data,
            signature=signature,
            public_key=registered.public_key,
            credential_id=registered.credential_id,
            stored_sign_count=0,
            challenge=used,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == WRONG_TYPE


# --- the signature ----------------------------------------------------------


def test_somebody_elses_key_does_not_verify(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    registered = _register(authenticator, challenge)

    with pytest.raises(WebAuthnRejected) as raised:
        _verify(authenticator, registered, os.urandom(32), sign_with=VirtualAuthenticator())

    assert raised.value.reason == SIGNATURE_INVALID


def test_an_altered_response_does_not_verify(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """A signature over part of the message would let the rest be rewritten in
    flight, and the rest is where the counter and the flags live."""
    registered = _register(authenticator, challenge)

    with pytest.raises(WebAuthnRejected) as raised:
        _verify(authenticator, registered, os.urandom(32), tamper=True)

    assert raised.value.reason == SIGNATURE_INVALID


# --- presence and verification ----------------------------------------------


def test_a_ceremony_nobody_touched_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """Without the presence flag, a credential on a plugged-in key could be used
    by malware on the host without anybody touching anything."""
    with pytest.raises(WebAuthnRejected) as raised:
        _register(authenticator, challenge, user_present=False)

    assert raised.value.reason == USER_NOT_PRESENT


def test_user_verification_is_recorded_rather_than_required(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """A security key with a touch and a passkey with a PIN are both second
    factors; only one is a *second* factor on its own, and the step-up decision
    needs to be able to tell."""
    registered = _register(authenticator, challenge, user_verified=False)

    assert registered.user_verified is False
    assert _verify(authenticator, registered, os.urandom(32), user_verified=True).user_verified


# --- clone detection --------------------------------------------------------


def test_a_counter_that_goes_backwards_is_a_cloned_credential(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """FR-MFA-02's named case. Counters are per-credential and monotonic, so a
    value at or below the stored one means the private key is in use in two
    places — the one signal WebAuthn gives that a credential was copied."""
    registered = _register(authenticator, challenge)

    with pytest.raises(WebAuthnRejected) as raised:
        _verify(authenticator, registered, os.urandom(32), stored=10, sign_count=9)

    assert raised.value.reason == CLONED


def test_a_repeated_counter_is_also_a_clone(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """At or below, not below. Two authenticators alternating would otherwise
    each be accepted forever at the same value."""
    registered = _register(authenticator, challenge)

    with pytest.raises(WebAuthnRejected) as raised:
        _verify(authenticator, registered, os.urandom(32), stored=7, sign_count=7)

    assert raised.value.reason == CLONED


def test_an_authenticator_without_a_counter_is_allowed(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """Many platform authenticators report zero forever, which the specification
    permits. Allowed explicitly, so it cannot be reached by resetting a counter
    that had a value."""
    registered = _register(authenticator, challenge, sign_count=0)

    assert _verify(authenticator, registered, os.urandom(32), stored=0, sign_count=0)


def test_a_counter_reset_to_zero_is_still_a_clone(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The reason the both-zero case is written as a pair rather than as "zero
    is fine"."""
    registered = _register(authenticator, challenge)

    with pytest.raises(WebAuthnRejected) as raised:
        _verify(authenticator, registered, os.urandom(32), stored=5, sign_count=0)

    assert raised.value.reason == CLONED


# --- attestation ------------------------------------------------------------


def test_an_attestation_statement_we_do_not_verify_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """Silently accepting a statement nothing checks is worse than not asking
    for one: it lets an enrolment claim a provenance no code verified."""
    with pytest.raises(WebAuthnRejected) as raised:
        _register(authenticator, challenge, fmt="packed")

    assert raised.value.reason == UNSUPPORTED_ATTESTATION


# --- keys we will not take --------------------------------------------------


def test_an_algorithm_outside_the_allowlist_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The identifier arrives with the credential, so honouring it blindly would
    let the enrolling party choose the verification path."""
    with pytest.raises(WebAuthnRejected) as raised:
        _register(
            authenticator,
            challenge,
            cose_key=encode({1: 2, 3: -36, -1: 1, -2: b"x" * 32, -3: b"y" * 32}),
        )

    assert raised.value.reason == UNSUPPORTED_ALGORITHM


def test_a_curve_we_do_not_support_is_refused_at_enrolment(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """A key labelled ES256 on a curve that is not P-256 passes the algorithm
    allowlist and fails at the first login. Refusing it at enrolment is the
    difference between an error the person can act on and a second factor they
    believe they have."""
    with pytest.raises(WebAuthnRejected) as raised:
        _register(
            authenticator,
            challenge,
            cose_key=encode({1: 2, 3: ES256, -1: 2, -2: b"x" * 48, -3: b"y" * 48}),
        )

    assert raised.value.reason == UNSUPPORTED_ALGORITHM


def test_a_point_that_is_not_on_the_curve_is_refused() -> None:
    """Constructing the key anyway would mean verifying against something the
    curve's arithmetic does not describe."""
    with pytest.raises(WebAuthnRejected) as raised:
        webauthn._public_key(encode({1: 2, 3: ES256, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}))

    assert raised.value.reason == MALFORMED


def test_a_key_missing_a_coordinate_is_refused() -> None:
    with pytest.raises(WebAuthnRejected) as raised:
        webauthn._public_key(encode({1: 2, 3: ES256, -1: 1, -2: b"\x01" * 32}))

    assert raised.value.reason == MALFORMED


def test_an_unknown_key_type_is_refused() -> None:
    with pytest.raises(WebAuthnRejected) as raised:
        webauthn._public_key(encode({1: 9, 3: ES256}))

    assert raised.value.reason == UNSUPPORTED_ALGORITHM


# --- what the parser will not read ------------------------------------------


def test_truncated_authenticator_data_is_refused() -> None:
    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.parse_authenticator_data(b"\x00" * 20, expect_credential=False)

    assert raised.value.reason == MALFORMED


def test_a_credential_id_running_past_the_end_is_refused() -> None:
    """The length is a number the authenticator chose, so it is checked against
    the bytes actually present."""
    data = b"\x00" * 32 + bytes([webauthn.UP | webauthn.AT]) + b"\x00\x00\x00\x01"
    data += b"\x00" * 16 + b"\xff\xff"

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.parse_authenticator_data(data, expect_credential=True)

    assert raised.value.reason == MALFORMED


def test_bytes_after_the_structure_are_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """A parser that ignores a suffix is one an attacker can hide a second
    reading inside."""
    data = authenticator.authenticator_data(
        rp_id=RP_ID,
        user_present=True,
        user_verified=True,
        sign_count=1,
        credential_id=None,
        cose_key=None,
        extensions=None,
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.parse_authenticator_data(data + b"extra", expect_credential=False)

    assert raised.value.reason == MALFORMED


def test_extensions_are_parsed_rather_than_tripped_over(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """Real authenticators send them, and a parser that treated them as trailing
    bytes would refuse working hardware."""
    registered = _register(authenticator, challenge, extensions={"credProtect": 2})

    assert registered.credential_id == authenticator.credential_id


def test_a_registration_without_a_credential_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    """The attested-credential flag is what says a registration carries one, and
    a response without it registers nothing that could ever be verified."""
    data = authenticator.authenticator_data(
        rp_id=RP_ID,
        user_present=True,
        user_verified=True,
        sign_count=0,
        credential_id=None,
        cose_key=None,
        extensions=None,
    )

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=authenticator.client_data("webauthn.create", challenge, ORIGIN),
            attestation_object=encode({"fmt": "none", "attStmt": {}, "authData": data}),
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == MALFORMED


def test_client_data_that_is_not_json_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    _, attestation = authenticator.register(challenge=challenge, origin=ORIGIN, rp_id=RP_ID)

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=b"{not json",
            attestation_object=attestation,
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == MALFORMED


def test_an_attestation_object_that_is_not_cbor_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    client_data = authenticator.client_data("webauthn.create", challenge, ORIGIN)

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=client_data,
            attestation_object=b"\xff\xff\xff",
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == MALFORMED


def test_an_attestation_object_without_authdata_is_refused(
    authenticator: VirtualAuthenticator, challenge: bytes
) -> None:
    client_data = authenticator.client_data("webauthn.create", challenge, ORIGIN)

    with pytest.raises(WebAuthnRejected) as raised:
        webauthn.register(
            client_data=client_data,
            attestation_object=encode({"fmt": "none", "attStmt": {}}),
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
        )

    assert raised.value.reason == MALFORMED
