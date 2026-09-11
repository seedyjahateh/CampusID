"""Recovery codes (FR-MFA-05).

The factor of last resort: ten single-use codes, shown once, for the person whose
phone is in a lake. Everything about them is a trade between "the person can get
back in" and "so can whoever finds the printout", and the choices are worth
stating because the defaults are all wrong.

**Eighty bits each.** Far more than a six-digit code needs, because a recovery
code has no expiry and no rate window of its own beyond the shared one. The
guessing bound has to come from the code itself.

**Hashed with Argon2id, not with SHA-256.** The codes are high-entropy, so a
plain hash would in fact be unguessable — but they are also the one credential
here that is written down, photographed, and pasted into notes applications,
which means a leak is likelier to arrive as a *partial* than as a database dump.
A memory-hard function is what keeps a partially-known code expensive to
complete, and it costs nothing on a path used once a year.

**Argon2 blocks, so it runs in a thread.** The same treatment the directory
client gets, for the same reason: ~50 ms of deliberate CPU per verification,
times ten candidates, is half a second of event loop nobody else can use.

**Codes are checked one at a time and every candidate is tried.** There is no
lookup key, because a lookup key on a credential is a value an attacker can
enumerate against — so verification is a scan of the person's unused codes.

**Issuing replaces the whole set.** Reissuing while old codes still worked would
mean somebody who printed a sheet last year and somebody who printed one today
can both get in, and only one of them knows the other exists.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from argon2.low_level import Type

COUNT: Final = 10
"""FR-MFA-05's number. Enough that losing a phone is survivable and few enough
that a sheet of them is not a permanent second password."""

CODE_BYTES: Final = 10
"""80 bits, rendered as sixteen base32 characters."""

GROUP: Final = 4
"""Characters per group in the displayed form. Grouping is not decoration — a
code read aloud or copied by hand is where transcription errors come from."""

ALPHABET: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
"""Crockford's base32 rather than RFC 4648's.

RFC 4648's alphabet contains I, L and O, which is precisely wrong for a string
somebody reads off paper and types back. Crockford's drops those and U — the
first three because they are confusable with 1 and 0, and U because excluding it
keeps accidental obscenities out of a code people have to read aloud to a service
desk.
"""

CONFUSABLE: Final = {"O": "0", "I": "1", "L": "1"}
"""What to do with the characters the alphabet deliberately omits.

Mapped on input rather than rejected. Somebody who types the letter O meant the
digit zero, because the letter is not in the alphabet the code came from, and
telling them their code is wrong would be true of nothing but their keyboard.
"""

MEMORY_COST: Final = 19 * 1024
TIME_COST: Final = 2
PARALLELISM: Final = 1
"""OWASP's first recommended Argon2id configuration: 19 MiB, two passes, one lane.

Named here rather than left to a library default that may move, because these
are a security decision and a quiet change to them is invisible until somebody
has the database.

OWASP lists several configurations of equivalent strength, of which 64 MiB with
four lanes is another. The 19 MiB one is chosen because verification here is a
*scan*: ten candidates per attempt, since a credential must not have a lookup
key. Four lanes at 64 MiB would put two seconds of deliberate CPU behind every
recovery attempt, which is a denial-of-service surface bought with no additional
resistance — the codes carry eighty bits of entropy, so the hash is defending
against a partial leak rather than against a dictionary.

The stored form is PHC-encoded and carries its own parameters, so raising these
later does not invalidate codes already issued.
"""

_hasher = PasswordHasher(
    # Argon2id: resistant to both the GPU attack that hurts Argon2i and the
    # side-channel attack that hurts Argon2d.
    type=Type.ID,
    time_cost=TIME_COST,
    memory_cost=MEMORY_COST,
    parallelism=PARALLELISM,
)


def generate() -> tuple[str, ...]:
    """A fresh set of codes, in the form the person will see them."""
    return tuple(_format(secrets.token_bytes(CODE_BYTES)) for _ in range(COUNT))


def normalise(code: str) -> str:
    """The comparable form of whatever the person typed.

    Case and grouping are presentation. Somebody reading a code off paper will
    lower-case it, drop the hyphens, or add a space, and refusing that teaches
    them the code is wrong when it is not. The confusable letters are folded for
    the same reason.
    """
    folded = (CONFUSABLE.get(ch, ch) for ch in code.upper())
    return "".join(ch for ch in folded if ch in ALPHABET)


async def hash_code(code: str) -> str:
    """The stored form of one code."""
    return await asyncio.to_thread(_hasher.hash, normalise(code))


async def matches(stored: str, code: str) -> bool:
    """Whether a typed code is the one behind a stored hash.

    A mismatch is False rather than an exception, because a scan over a person's
    codes expects most of them not to match. A *malformed* stored hash is also
    False: it means the row cannot authenticate anybody, and raising would turn
    one corrupt row into a failure for every code the person has.
    """
    try:
        return bool(await asyncio.to_thread(_hasher.verify, stored, normalise(code)))
    except (VerifyMismatchError, VerificationError, ValueError):
        return False


def _format(raw: bytes) -> str:
    """Render bytes as grouped base32, without the padding base32 would add."""
    digits = "".join(ALPHABET[index] for index in _expand(raw))
    return "-".join(digits[i : i + GROUP] for i in range(0, len(digits), GROUP))


def _expand(raw: bytes) -> bytes:
    """Five bytes of entropy become eight characters, as base32 does.

    Written out rather than using `base64.b32encode` so the alphabet above is the
    one actually used — the standard encoder's alphabet is the same, but relying
    on that coincidence would break silently if either changed.
    """
    out = bytearray()
    for offset in range(0, len(raw), 5):
        chunk = raw[offset : offset + 5].ljust(5, b"\x00")
        value = int.from_bytes(chunk, "big")
        for shift in range(35, -1, -5):
            out.append((value >> shift) & 0x1F)
    return bytes(out)
