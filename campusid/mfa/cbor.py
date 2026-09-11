"""A deliberately partial CBOR decoder (RFC 8949), for WebAuthn.

WebAuthn carries two CBOR structures: the attestation object returned at
registration, and the COSE public key inside it. Both are produced by an
authenticator following CTAP2's canonical encoding rules, which is a small,
strictly-specified subset of CBOR — definite lengths, shortest-form integers, no
tags, no indefinite-length strings.

**Partial is the point.** A general decoder accepts things this protocol never
sends: tags that ask the reader to reinterpret a value, indefinite-length streams
that have to be reassembled, bignums, half-precision floats. None of that can
appear in a legitimate credential, so accepting it only widens what an attacker
can hand us. Everything outside the subset is refused by name.

**Canonical form is checked, not assumed.** An integer encoded in more bytes than
it needs, or a map with a repeated key, is rejected rather than normalised.
Otherwise two encodings of the same credential exist, and a check that compares
encoded bytes somewhere downstream can be made to disagree with a check that
compares decoded values — which is the shape of every parser-differential bug.
Key *ordering* is not enforced: it is canonical CBOR's one rule that real
authenticators are known to get wrong, and rejecting on it would refuse working
hardware without closing anything the duplicate-key check leaves open.

**Nothing here allocates on the sender's word.** A length field is checked
against the bytes actually remaining before anything is read, so a claim of four
gigabytes costs a rejection rather than four gigabytes.
"""

from __future__ import annotations

import struct
from typing import Any, Final

MAX_DEPTH: Final = 16
"""Deeper than any legitimate attestation object, shallow enough that a nested
structure cannot exhaust the stack before it is refused."""

UNSIGNED: Final = 0
NEGATIVE: Final = 1
BYTES: Final = 2
TEXT: Final = 3
ARRAY: Final = 4
MAP: Final = 5
SIMPLE: Final = 7

FALSE: Final = 20
TRUE: Final = 21
NULL: Final = 22


class CborError(ValueError):
    """Anything this decoder will not accept, with the reason it will not."""


def decode(data: bytes) -> Any:
    """Decode one CBOR item, refusing anything left over.

    Trailing data is an error rather than an ignored suffix: a decoder that stops
    at the end of the first item lets an attacker append a second one that a
    different reader would see.
    """
    value, offset = decode_prefix(data)
    if offset != len(data):
        raise CborError(f"{len(data) - offset} trailing bytes after the item")
    return value


def decode_prefix(data: bytes) -> tuple[Any, int]:
    """Decode one item, returning it and how many bytes it used.

    Separate from `decode` because the attestation object's `authData` is a byte
    string that is itself parsed further, and because CTAP responses prepend a
    status byte. Nothing in this module uses the remainder silently.
    """
    return _item(data, 0, 0)


def _item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CborError(f"nested deeper than {MAX_DEPTH}")
    if offset >= len(data):
        raise CborError("ran out of input")

    initial = data[offset]
    major, minor = initial >> 5, initial & 0x1F

    if major in (UNSIGNED, NEGATIVE):
        value, offset = _argument(data, offset, minor)
        return (value if major == UNSIGNED else -1 - value), offset

    if major in (BYTES, TEXT):
        length, offset = _argument(data, offset, minor)
        chunk = _take(data, offset, length)
        if major == BYTES:
            return chunk, offset + length
        try:
            return chunk.decode("utf-8"), offset + length
        except UnicodeDecodeError as exc:
            # A text string is defined as UTF-8. Accepting invalid bytes with
            # replacement characters would silently change a credential id.
            raise CborError("text string is not valid UTF-8") from exc

    if major == ARRAY:
        count, offset = _argument(data, offset, minor)
        items = []
        for _ in range(count):
            item, offset = _item(data, offset, depth + 1)
            items.append(item)
        return items, offset

    if major == MAP:
        count, offset = _argument(data, offset, minor)
        mapping: dict[Any, Any] = {}
        for _ in range(count):
            key, offset = _item(data, offset, depth + 1)
            if not isinstance(key, int | str | bytes):
                raise CborError(f"map key of type {type(key).__name__}")
            if key in mapping:
                # Two values under one key means two readers can disagree about
                # the structure, which is the whole parser-differential family.
                raise CborError(f"duplicate map key {key!r}")
            value, offset = _item(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset

    if major == SIMPLE:
        if minor == FALSE:
            return False, offset + 1
        if minor == TRUE:
            return True, offset + 1
        if minor == NULL:
            return None, offset + 1
        raise CborError(f"unsupported simple value {minor}")

    # Major type 6 is tags. A tag asks the reader to reinterpret the value it
    # wraps, which is exactly the instruction an attacker would like to give.
    raise CborError(f"unsupported major type {major}")


def _argument(data: bytes, offset: int, minor: int) -> tuple[int, int]:
    """Read an item's argument, insisting it is encoded in the fewest bytes."""
    if minor < 24:
        return minor, offset + 1
    if minor == 24:
        value = _take(data, offset + 1, 1)[0]
        _shortest(value, 24)
        return value, offset + 2
    if minor == 25:
        (value,) = struct.unpack(">H", _take(data, offset + 1, 2))
        _shortest(value, 25)
        return value, offset + 3
    if minor == 26:
        (value,) = struct.unpack(">I", _take(data, offset + 1, 4))
        _shortest(value, 26)
        return value, offset + 5
    if minor == 27:
        (value,) = struct.unpack(">Q", _take(data, offset + 1, 8))
        _shortest(value, 27)
        return value, offset + 9
    if minor == 31:
        # Indefinite length: a stream of chunks terminated by a break. Nothing
        # an authenticator sends uses it, and reassembling chunks is where
        # length-check bugs live.
        raise CborError("indefinite-length item")
    raise CborError(f"reserved additional information {minor}")


MINIMUM: Final = {24: 24, 25: 1 << 8, 26: 1 << 16, 27: 1 << 32}
"""The smallest value each argument width is allowed to carry.

Anything below it had a shorter encoding available, and accepting both makes one
credential two byte strings.
"""


def _shortest(value: int, minor: int) -> None:
    if value < MINIMUM[minor]:
        raise CborError(f"{value} is not encoded in the fewest bytes")


def _take(data: bytes, offset: int, length: int) -> bytes:
    """Read `length` bytes, checking the input holds them first.

    The check precedes the read, so a length field claiming four gigabytes costs
    a rejection rather than an allocation.
    """
    end = offset + length
    if end > len(data):
        raise CborError(f"claimed {length} bytes with {len(data) - offset} remaining")
    return data[offset:end]
