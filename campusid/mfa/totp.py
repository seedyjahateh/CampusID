"""Time-based one-time passwords (FR-MFA-01).

RFC 6238 over RFC 4226, implemented here rather than pulled in, because the
algorithm is thirty lines and the interesting decisions are all in how it is
*used* — the drift window, the replay rule, the comparison. A dependency would
hide exactly the parts worth reading.

**SHA-1, six digits, thirty seconds.** Not a security choice — a compatibility
one. Google Authenticator and most of its imitators ignore the `algorithm` and
`digits` parameters in the provisioning URI and assume these values, so a broker
that enrolled SHA-256 secrets would hand out codes that never match, with no
error to point at. HMAC-SHA-1 is not affected by the SHA-1 collision work: HMAC
rests on the compression function being a pseudorandom function, not on collision
resistance, and no attack on HMAC-SHA-1 is known. The secret is 160 bits, which
is what actually bounds the guess.

**A used step is never valid again.** RFC 6238 §5.2 requires it and the reason is
the whole threat model of a one-time password: a code phished, shoulder-surfed or
read off a proxy is valid for the rest of its window, and without this rule that
window is thirty seconds of free reuse. Enforced by remembering the highest step
accepted for a factor and refusing anything at or below it — monotonic rather
than a set of consumed steps, because a set has to expire and a high-water mark
does not.

**The drift window is one step either side.** Ninety seconds of tolerance for the
phone's clock, which is the spread RFC 6238 §6 suggests and which every
authenticator app assumes. Wider would be an accommodation for a broken clock
paid for by every user, since the window is also how long a captured code lives.

**Comparison is constant time.** A one-time password compared with `==` leaks its
prefix through timing, and six digits guessed one at a time is a million times
easier than six digits guessed at once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from urllib.parse import quote, urlencode

DIGITS: Final = 6
PERIOD: Final = 30
"""Seconds per step. Thirty is what the apps assume; see the module docstring."""

ALGORITHM: Final = "SHA1"
SECRET_BYTES: Final = 20
"""160 bits, RFC 4226 §4 R6's recommendation and the length the apps expect."""

DRIFT: Final = 1
"""Steps of clock skew tolerated either side of now."""


class TotpRejected(Exception):
    """A code that did not verify, with the reason it did not.

    Separate reasons because they mean different things to the caller: a code
    that never matched is a failed attempt to count against the rate limit, and
    a code that matched a step already used is a *replay*, which is worth
    auditing on its own — it usually means the code reached somebody else.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


MALFORMED: Final = "mfa.totp_malformed"
MISMATCH: Final = "mfa.totp_mismatch"
REPLAY: Final = "mfa.totp_replay"


def new_secret() -> str:
    """A fresh 160-bit secret, base32 without padding.

    Unpadded because the `=` characters are legal in the URI but several
    authenticator apps reject them, and the decoder here puts them back.
    """
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def step_at(moment: datetime) -> int:
    """The counter value for a moment — `floor(unix_seconds / period)`."""
    return int(moment.timestamp()) // PERIOD


def code_at(secret: str, step: int, *, digits: int = DIGITS) -> str:
    """The HOTP value for a counter (RFC 4226 §5.3).

    HMAC the counter, take the low four bits of the last byte as an offset,
    read four bytes from there, clear the sign bit, and take the last `digits`
    decimal digits. The offset is what makes the truncation dynamic, so the
    same four bytes of the MAC are not always the ones that leak.
    """
    mac = hmac.new(_decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(truncated % (10**digits)).zfill(digits)


@dataclass(frozen=True, slots=True)
class Verified:
    """A code that matched, and the step it matched.

    The step is the return value that matters: the caller has to store it as the
    factor's new high-water mark, and a verifier that returned only `True` would
    make the replay rule impossible to enforce.
    """

    step: int


def verify(
    secret: str,
    code: str,
    *,
    at: datetime | None = None,
    last_step: int | None = None,
    drift: int = DRIFT,
) -> Verified:
    """Check a code, raising `TotpRejected` with a reason if it does not hold.

    `last_step` is the highest step this factor has already accepted. Anything at
    or below it is refused as a replay even though the arithmetic matches, which
    is the rule that makes the password one-time rather than thirty-seconds-long.

    Steps are tried nearest-first so a clock that is exactly right does the least
    work, but every candidate in the window is evaluated regardless of whether an
    earlier one matched — returning as soon as one does would make the response
    time reveal how far off the phone's clock is.
    """
    digits = "".join(ch for ch in code if not ch.isspace())
    if len(digits) != DIGITS or not digits.isdigit():
        # Apps display the code in two groups of three, so a pasted code often
        # carries a space. Anything else is not an attempt worth timing.
        raise TotpRejected(MALFORMED)

    now = step_at(at or datetime.now(UTC))
    matched: int | None = None
    for offset in _window(drift):
        candidate = now + offset
        if hmac.compare_digest(code_at(secret, candidate), digits) and matched is None:
            matched = candidate

    if matched is None:
        raise TotpRejected(MISMATCH)
    if last_step is not None and matched <= last_step:
        raise TotpRejected(REPLAY)
    return Verified(step=matched)


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The `otpauth://` URI an authenticator app reads out of a QR code.

    The issuer appears twice — as a prefix on the label and as a parameter —
    which looks redundant and is not: the prefix is what older apps display and
    the parameter is what current ones use to group accounts. Apps that read only
    one of them are the reason the spec asks for both.

    `algorithm`, `digits` and `period` are stated even though they are the
    defaults, so the URI stays honest if those constants ever move.
    """
    label = quote(f"{issuer}:{account}", safe="")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": ALGORITHM,
            "digits": DIGITS,
            "period": PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def _window(drift: int) -> tuple[int, ...]:
    """Offsets to try, nearest first: 0, -1, +1, -2, +2 …"""
    offsets = [0]
    for step in range(1, drift + 1):
        offsets.extend((-step, step))
    return tuple(offsets)


def _decode(secret: str) -> bytes:
    """Base32 back to bytes, restoring the padding stripped for the URI."""
    padded = secret.upper() + "=" * (-len(secret) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except Exception as exc:  # pragma: no cover - only a corrupted stored secret
        raise TotpRejected(MALFORMED) from exc
