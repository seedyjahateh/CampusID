"""The partial CBOR decoder WebAuthn needs (FR-MFA-02).

Half of these test that it reads what an authenticator sends, and half that it
refuses what one never would. The second half is the point: a general decoder
accepts tags, indefinite-length streams and non-canonical integers, none of which
can appear in a legitimate credential, so accepting them only widens what an
attacker can hand the verifier.

The test vectors are RFC 8949 appendix A's, which is what makes the first half
mean "correct" rather than "agrees with itself".
"""

from __future__ import annotations

import pytest

from campusid.mfa.cbor import MAX_DEPTH, CborError, decode, decode_prefix
from tests.support.authenticator import encode


# --- RFC 8949 appendix A ----------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x00", 0),
        (b"\x01", 1),
        (b"\x0a", 10),
        (b"\x17", 23),
        (b"\x18\x18", 24),
        (b"\x18\x64", 100),
        (b"\x19\x03\xe8", 1000),
        (b"\x1a\x00\x0f\x42\x40", 1000000),
        (b"\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00", 1000000000000),
        (b"\x20", -1),
        (b"\x29", -10),
        (b"\x38\x63", -100),
        (b"\x39\x03\xe7", -1000),
        (b"\x40", b""),
        (b"\x44\x01\x02\x03\x04", b"\x01\x02\x03\x04"),
        (b"\x60", ""),
        (b"\x61\x61", "a"),
        (b"\x64IETF", "IETF"),
        (b"\x80", []),
        (b"\x83\x01\x02\x03", [1, 2, 3]),
        (b"\xa0", {}),
        (b"\xa2\x01\x02\x03\x04", {1: 2, 3: 4}),
        (b"\xf4", False),
        (b"\xf5", True),
        (b"\xf6", None),
    ],
)
def test_the_rfc_vectors(data: bytes, expected: object) -> None:
    assert decode(data) == expected


def test_nesting_round_trips() -> None:
    value = {"fmt": "none", "attStmt": {}, "authData": b"\x00\x01", "list": [1, [2, [3]]]}

    assert decode(encode(value)) == value


def test_a_cose_key_round_trips() -> None:
    """Negative integer keys are what COSE uses for its key parameters, and a
    decoder that only handled unsigned ones would read every credential wrong."""
    key = {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}

    assert decode(encode(key)) == key


# --- what it will not read --------------------------------------------------


def test_a_tag_is_refused() -> None:
    """A tag asks the reader to reinterpret the value it wraps, which is exactly
    the instruction an attacker would like to give."""
    with pytest.raises(CborError, match="major type 6"):
        decode(b"\xc0\x00")


def test_an_indefinite_length_item_is_refused() -> None:
    """Nothing an authenticator sends uses it, and reassembling chunks is where
    length-check bugs live."""
    with pytest.raises(CborError, match="indefinite"):
        decode(b"\x5f\x41\x01\xff")


@pytest.mark.parametrize("data", [b"\x18\x17", b"\x19\x00\xff", b"\x1a\x00\x00\xff\xff"])
def test_an_integer_with_a_shorter_encoding_is_refused(data: bytes) -> None:
    """Accepting both makes one credential two byte strings, and a check that
    compares encoded bytes can then be made to disagree with one that compares
    decoded values."""
    with pytest.raises(CborError, match="fewest bytes"):
        decode(data)


def test_a_repeated_map_key_is_refused() -> None:
    """Two values under one key means two readers can disagree about the
    structure."""
    with pytest.raises(CborError, match="duplicate"):
        decode(b"\xa2\x01\x02\x01\x03")


def test_a_float_is_refused() -> None:
    with pytest.raises(CborError, match="simple value"):
        decode(b"\xfa\x47\xc3\x50\x00")


@pytest.mark.parametrize("minor", [28, 29, 30])
def test_reserved_additional_information_is_refused(minor: int) -> None:
    with pytest.raises(CborError, match="reserved"):
        decode(bytes([minor]))


def test_trailing_bytes_are_refused() -> None:
    """A decoder that stops at the end of the first item lets an attacker append
    a second one a different reader would see."""
    with pytest.raises(CborError, match="trailing"):
        decode(b"\x01\x02")


def test_a_length_longer_than_the_input_is_refused() -> None:
    """The check precedes the read, so a claim of four gigabytes costs a
    rejection rather than an allocation."""
    with pytest.raises(CborError, match="remaining"):
        decode(b"\x5a\xff\xff\xff\xff")


def test_running_out_of_input_is_refused() -> None:
    with pytest.raises(CborError, match="ran out"):
        decode(b"\x82\x01")


def test_text_that_is_not_utf8_is_refused() -> None:
    """Decoding with replacement characters would silently change a credential
    id."""
    with pytest.raises(CborError, match="UTF-8"):
        decode(b"\x62\xff\xfe")


def test_a_map_key_of_the_wrong_type_is_refused() -> None:
    with pytest.raises(CborError, match="map key of type"):
        decode(b"\xa1\x80\x01")


def test_deep_nesting_is_refused() -> None:
    """Refused before the stack runs out, rather than by it."""
    data = b"\x81" * (MAX_DEPTH + 2) + b"\x00"

    with pytest.raises(CborError, match="nested"):
        decode(data)


def test_nesting_within_the_limit_is_read() -> None:
    data = b"\x81" * (MAX_DEPTH - 1) + b"\x00"

    assert decode(data) is not None


# --- the prefix form --------------------------------------------------------


def test_the_prefix_form_reports_what_it_used() -> None:
    """The attested credential data is a COSE key followed by whatever else the
    authenticator appended, so the verifier needs the key's exact length to
    slice it out."""
    value, used = decode_prefix(b"\x83\x01\x02\x03trailing")

    assert value == [1, 2, 3]
    assert used == 4
