"""Time-based one-time passwords (FR-MFA-01).

Two halves. The first is that the arithmetic is RFC 6238's and not something
close to it, pinned against the specification's own test vectors — an
implementation that is subtly wrong produces codes no authenticator app agrees
with, and the failure looks like every user typing the wrong number.

The second is the part a library would not give us: a code that has been used is
not valid again. That rule is what makes a one-time password one-time, and
without it a code phished, shoulder-surfed or read off a proxy stays good for the
rest of its thirty seconds.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from campusid.mfa.totp import (
    ALGORITHM,
    DIGITS,
    DRIFT,
    MALFORMED,
    MISMATCH,
    PERIOD,
    REPLAY,
    SECRET_BYTES,
    TotpRejected,
    code_at,
    new_secret,
    provisioning_uri,
    step_at,
    verify,
)

pytestmark = pytest.mark.security

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
"""RFC 6238 appendix B's SHA-1 seed — ASCII "12345678901234567890" in base32."""

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _at(seconds: int) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


# --- the arithmetic is the RFC's --------------------------------------------


@pytest.mark.parametrize(
    ("unix", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_the_rfc_test_vectors(unix: int, expected: str) -> None:
    """RFC 6238 appendix B, SHA-1 rows. An implementation that disagrees with
    these disagrees with every authenticator app on the phone."""
    assert code_at(RFC_SECRET, step_at(_at(unix)), digits=8) == expected


def test_a_step_is_thirty_seconds_wide() -> None:
    assert step_at(_at(0)) == 0
    assert step_at(_at(PERIOD - 1)) == 0
    assert step_at(_at(PERIOD)) == 1


def test_the_code_is_six_digits() -> None:
    code = code_at(SECRET, step_at(_at(1700000000)))

    assert len(code) == DIGITS
    assert code.isdigit()


def test_a_code_with_leading_zeros_keeps_them() -> None:
    """Truncation to six digits produces a value below 100000 about one time in
    ten, and an implementation that renders it as an integer drops the zeros and
    fails one login in ten with no pattern anybody can report."""
    step = next(s for s in range(200000) if int(code_at(SECRET, s)) < 100000)

    assert len(code_at(SECRET, step)) == DIGITS


# --- secrets ----------------------------------------------------------------


def test_a_secret_is_a_hundred_and_sixty_bits() -> None:
    """What actually bounds guessing. RFC 4226 §4 asks for 160 bits and the apps
    expect that length."""
    assert len(new_secret()) == (SECRET_BYTES * 8 + 4) // 5


def test_secrets_are_not_repeated() -> None:
    assert len({new_secret() for _ in range(50)}) == 50


def test_a_secret_carries_no_padding() -> None:
    """Legal in the URI, rejected by several apps, and the decoder puts it back."""
    assert "=" not in new_secret()


def test_a_fresh_secret_produces_a_verifiable_code() -> None:
    secret = new_secret()
    now = datetime.now(UTC)

    assert verify(secret, code_at(secret, step_at(now)), at=now).step == step_at(now)


# --- drift ------------------------------------------------------------------


@pytest.mark.parametrize("offset", [-DRIFT, 0, DRIFT])
def test_a_code_within_the_drift_window_is_accepted(offset: int) -> None:
    """Ninety seconds of tolerance for the phone's clock, which is RFC 6238 §6's
    suggestion and what every app assumes."""
    now = datetime.now(UTC)
    code = code_at(SECRET, step_at(now) + offset)

    assert verify(SECRET, code, at=now).step == step_at(now) + offset


@pytest.mark.parametrize("offset", [-(DRIFT + 1), DRIFT + 1])
def test_a_code_outside_the_window_is_refused(offset: int) -> None:
    """The window is also how long a captured code lives, so widening it to
    accommodate a broken clock is paid for by everybody."""
    now = datetime.now(UTC)
    code = code_at(SECRET, step_at(now) + offset)

    with pytest.raises(TotpRejected) as raised:
        verify(SECRET, code, at=now)

    assert raised.value.reason == MISMATCH


def test_a_narrower_window_can_be_asked_for() -> None:
    now = datetime.now(UTC)

    with pytest.raises(TotpRejected):
        verify(SECRET, code_at(SECRET, step_at(now) - 1), at=now, drift=0)


# --- the one-time part ------------------------------------------------------


def test_a_used_code_is_refused() -> None:
    """FR-MFA-01's acceptance test. A code that stayed valid for the rest of its
    window would make phishing it worth the trouble."""
    now = datetime.now(UTC)
    code = code_at(SECRET, step_at(now))
    used = verify(SECRET, code, at=now)

    with pytest.raises(TotpRejected) as raised:
        verify(SECRET, code, at=now, last_step=used.step)

    assert raised.value.reason == REPLAY


def test_an_earlier_code_is_refused_after_a_later_one() -> None:
    """The high-water mark is monotonic rather than a set of consumed steps: a
    set has to expire, and until it does an attacker who captured the previous
    code can still use it inside the drift window."""
    now = datetime.now(UTC)
    earlier = code_at(SECRET, step_at(now) - 1)

    with pytest.raises(TotpRejected) as raised:
        verify(SECRET, earlier, at=now, last_step=step_at(now))

    assert raised.value.reason == REPLAY


def test_the_next_step_is_accepted_after_a_use() -> None:
    """Refusing everything after a use would be a lockout, not a replay rule."""
    now = datetime.now(UTC)
    used = verify(SECRET, code_at(SECRET, step_at(now)), at=now)
    later = now + timedelta(seconds=PERIOD)

    assert verify(SECRET, code_at(SECRET, step_at(later)), at=later, last_step=used.step).step > (
        used.step
    )


def test_a_replay_is_distinguishable_from_a_wrong_code() -> None:
    """They mean different things: a wrong code is an attempt to count against
    the rate limit, and a replay usually means the code reached somebody else."""
    assert len({MALFORMED, MISMATCH, REPLAY}) == 3


# --- what is not a code -----------------------------------------------------


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5", "12345a"])
def test_a_malformed_code_is_named_as_such(code: str) -> None:
    with pytest.raises(TotpRejected) as raised:
        verify(SECRET, code)

    assert raised.value.reason == MALFORMED


def test_a_pasted_code_with_spaces_is_accepted() -> None:
    """Apps display the code in two groups of three, so a pasted one usually
    carries a space and rejecting it teaches people to retype it."""
    now = datetime.now(UTC)
    code = code_at(SECRET, step_at(now))

    assert verify(SECRET, f"{code[:3]} {code[3:]}", at=now).step == step_at(now)


def test_a_wrong_code_of_the_right_shape_is_a_mismatch() -> None:
    now = datetime.now(UTC)
    code = code_at(SECRET, step_at(now))
    wrong = str((int(code) + 1) % 10**DIGITS).zfill(DIGITS)

    with pytest.raises(TotpRejected) as raised:
        verify(SECRET, wrong, at=now)

    assert raised.value.reason == MISMATCH


# --- provisioning -----------------------------------------------------------


def test_the_provisioning_uri_names_everything_the_app_needs() -> None:
    uri = provisioning_uri(SECRET, account="sam.obrien@campus.test", issuer="CampusID")

    assert uri.startswith("otpauth://totp/")
    assert f"secret={SECRET}" in uri
    assert "issuer=CampusID" in uri
    assert f"algorithm={ALGORITHM}" in uri
    assert f"digits={DIGITS}" in uri
    assert f"period={PERIOD}" in uri


def test_the_issuer_appears_in_the_label_as_well() -> None:
    """Not redundant: the prefix is what older apps display and the parameter is
    what current ones group by, and apps that read only one are why the spec asks
    for both."""
    uri = provisioning_uri(SECRET, account="sam.obrien@campus.test", issuer="CampusID")

    assert "CampusID%3Asam.obrien%40campus.test" in uri


def test_a_label_with_a_slash_cannot_break_out_of_the_path() -> None:
    """The account name comes from the directory, so it is not ours to trust."""
    uri = provisioning_uri(SECRET, account="a/b?c=d", issuer="CampusID")

    assert uri.count("?") == 1
    assert "/a/b" not in uri
