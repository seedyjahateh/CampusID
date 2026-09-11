"""What `amr` and `acr` are allowed to say (FR-MFA-08).

These two claims are the whole of what a relying party learns about how somebody
authenticated, and every failure mode here is in the generous direction: an
`amr` that names a method nobody used, an `acr` of `aal2` for one factor, an
`mfa` marker on a single-factor session. A broker that is generous here is lying
to every service that trusts it, which is why these tests are mostly about what
must *not* be claimed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from campusid.authz.engine import AAL1, AAL2
from campusid.mfa.assurance import (
    HWK,
    MAX_SPAN,
    MFA,
    OTP,
    PUSH,
    PWD,
    elevated,
    primary,
    satisfies_aal2,
)

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
EARLIER = NOW - timedelta(minutes=5)


# --- primary authentication -------------------------------------------------


def test_a_password_alone_is_aal1() -> None:
    result = primary((PWD,), at=NOW)

    assert result.acr == AAL1
    assert result.amr == (PWD,)


def test_an_idps_claim_does_not_promote_us() -> None:
    """An upstream `AuthnContextClassRef` is a claim by somebody else about a
    ceremony this broker did not witness. Promoting it would make our `acr` only
    as honest as the least careful IdP in the federation."""
    assert primary((PWD, HWK), at=NOW).acr == AAL1


def test_the_marker_is_never_asserted_by_the_caller() -> None:
    """RFC 8176 defines `mfa` as "multiple factors were used", so it is derived
    from the rest of the list rather than accepted alongside it."""
    assert MFA not in primary((PWD, MFA), at=NOW).amr


# --- step-up ----------------------------------------------------------------


@pytest.mark.parametrize("second", [OTP, HWK, PUSH])
def test_a_second_category_reaches_aal2(second: str) -> None:
    result = elevated(methods=(PWD,), category=second, since=EARLIER, now=NOW)

    assert result.acr == AAL2
    assert MFA in result.amr
    assert second in result.amr


def test_the_same_category_twice_does_not() -> None:
    """Somebody with the same TOTP seed on a phone and a tablet has one factor on
    two devices, and counting them separately would let one stolen seed reach
    AAL2. The session here has only ever presented a code."""
    result = elevated(methods=(OTP,), category=OTP, since=EARLIER, now=NOW)

    assert result.acr == AAL1
    assert MFA not in result.amr


def test_a_session_that_already_has_two_categories_keeps_aal2() -> None:
    """Presenting a code again on a session that already did a step-up is not a
    downgrade. The rule counts categories held, not the last thing presented."""
    result = elevated(methods=(PWD, OTP), category=OTP, since=EARLIER, now=NOW)

    assert result.acr == AAL2


def test_a_second_factor_with_no_first_does_not() -> None:
    """A session that somehow recorded no primary method is one factor, whatever
    it has just presented."""
    assert elevated(methods=(), category=OTP, since=EARLIER, now=NOW).acr == AAL1


def test_the_factor_is_recorded_even_when_it_does_not_reach_aal2() -> None:
    """It was still presented. Dropping it would make `amr` understate what
    happened, which is the same kind of untruth in the other direction."""
    result = elevated(methods=(OTP,), category=OTP, since=EARLIER, now=NOW)

    assert result.acr == AAL1
    assert OTP in result.amr


def test_factors_too_far_apart_are_not_one_authentication() -> None:
    """Twelve hours is NIST SP 800-63B's reauthentication limit for AAL2 and the
    session's own absolute timeout. A password from yesterday plus a code now is
    two authentications, not one with two factors."""
    stale = NOW - MAX_SPAN - timedelta(minutes=1)

    assert elevated(methods=(PWD,), category=OTP, since=stale, now=NOW).acr == AAL1


def test_factors_at_the_edge_of_the_window_still_count() -> None:
    assert elevated(methods=(PWD,), category=OTP, since=NOW - MAX_SPAN, now=NOW).acr == AAL2


def test_a_third_factor_keeps_the_level() -> None:
    result = elevated(methods=(PWD, OTP, MFA), category=HWK, since=EARLIER, now=NOW)

    assert result.acr == AAL2
    assert set(result.amr) == {PWD, OTP, HWK, MFA}


# --- the list itself --------------------------------------------------------


def test_the_list_has_no_duplicates_and_is_ordered() -> None:
    """Deterministic, so a relying party comparing two tokens sees a change when
    something changed rather than when a set iterated differently."""
    result = elevated(methods=(OTP, PWD, PWD), category=OTP, since=EARLIER, now=NOW)

    assert result.amr == tuple(sorted(set(result.amr)))


def test_a_stale_marker_is_dropped() -> None:
    """Carrying `mfa` forward would let a session that was once AAL2 keep
    claiming multiple factors after the reason for it was gone."""
    result = elevated(methods=(PWD, MFA), category=PWD, since=EARLIER, now=NOW)

    assert MFA not in result.amr
    assert result.acr == AAL1


# --- auth_time --------------------------------------------------------------


def test_auth_time_moves_with_the_assurance() -> None:
    """A relying party using `max_age` is asking when the person last proved
    something, and a step-up is exactly that."""
    assert elevated(methods=(PWD,), category=OTP, since=EARLIER, now=NOW).auth_time == NOW


def test_auth_time_moves_even_when_the_level_does_not() -> None:
    """The person still proved something, so the session is not stale."""
    assert elevated(methods=(PWD, OTP), category=OTP, since=EARLIER, now=NOW).auth_time == NOW


# --- checking a claim against its evidence ----------------------------------


@pytest.mark.parametrize(
    ("amr", "expected"),
    [
        ((PWD, OTP, MFA), True),
        ((PWD, HWK), True),
        ((PWD,), False),
        ((OTP,), False),
        ((PWD, MFA), False),
        ((), False),
    ],
)
def test_a_claim_is_checkable_against_the_methods(amr: tuple[str, ...], expected: bool) -> None:
    """An `acr` that agrees with itself proves nothing, so the test of this
    requirement has to compare the claim with the evidence — including the case
    where `mfa` is present and the methods do not support it."""
    assert satisfies_aal2(amr) is expected
