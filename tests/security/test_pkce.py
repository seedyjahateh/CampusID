"""PKCE is mandatory and S256-only (FR-OP-03).

Three negative cases the PRD names explicitly — `plain` refused, a missing
`code_challenge` refused, a mismatched verifier refused — plus the one that is
easy to miss: an *absent* `code_challenge_method`, which RFC 7636 says defaults
to `plain`.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable

import pytest

from campusid.errors import ReasonCode
from campusid.oidc import pkce
from campusid.oidc.errors import (
    INVALID_GRANT,
    INVALID_REQUEST,
    OAuthError,
    may_be_redirected,
)

pytestmark = pytest.mark.security

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
"""RFC 7636's own appendix B verifier, so the challenge below is checkable
against the RFC rather than against this implementation."""

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_the_challenge_matches_the_rfc_worked_example() -> None:
    assert pkce.compute_challenge(VERIFIER) == CHALLENGE


def test_a_matching_verifier_is_accepted() -> None:
    pkce.verify(VERIFIER, CHALLENGE)


def test_a_mismatched_verifier_is_refused() -> None:
    other = base64.urlsafe_b64encode(hashlib.sha256(b"different").digest()).decode().rstrip("=")

    with pytest.raises(OAuthError) as raised:
        pkce.verify(other, CHALLENGE)

    assert raised.value.reason is ReasonCode.PKCE_VERIFICATION_FAILED


def test_a_missing_verifier_is_refused() -> None:
    with pytest.raises(OAuthError) as raised:
        pkce.verify(None, CHALLENGE)

    assert raised.value.reason is ReasonCode.PKCE_VERIFICATION_FAILED


def test_the_failure_is_invalid_grant_and_says_nothing_more() -> None:
    """The client learns `invalid_grant` whether the verifier was absent,
    malformed or simply wrong. Whoever is holding a stolen code should not be
    told how close they are."""
    errors = []
    for candidate in [None, "short", "!" * 43, pkce.compute_challenge("wrong")]:
        with pytest.raises(OAuthError) as raised:
            pkce.verify(candidate, CHALLENGE)
        errors.append(raised.value.error)

    assert errors == [INVALID_GRANT] * 4


@pytest.mark.parametrize(
    "verifier",
    [
        "a" * (pkce.MIN_VERIFIER_LENGTH - 1),
        "a" * (pkce.MAX_VERIFIER_LENGTH + 1),
    ],
)
def test_a_verifier_of_the_wrong_length_is_refused(verifier: str) -> None:
    """43 characters is where 256 bits of entropy lands. A short verifier is
    brute-forceable by exactly the attacker PKCE defends against — the one who
    already holds the code and the challenge."""
    with pytest.raises(OAuthError, match="length"):
        pkce.verify(verifier, pkce.compute_challenge(verifier))


def test_a_verifier_outside_the_unreserved_set_is_refused() -> None:
    """A verifier containing characters some client will percent-encode is a
    comparison waiting to fail for reasons that look like an attack."""
    verifier = "/" * pkce.MIN_VERIFIER_LENGTH

    with pytest.raises(OAuthError, match="illegal characters"):
        pkce.verify(verifier, pkce.compute_challenge(verifier))


# --- what the authorization request must carry -----------------------------


def test_s256_is_the_supported_method() -> None:
    pkce.assert_supported_method(pkce.S256)


def test_plain_is_refused() -> None:
    """`plain` puts the verifier in the authorization request, so the attacker
    who captured the code captured the proof with it."""
    with pytest.raises(OAuthError) as raised:
        pkce.assert_supported_method(pkce.PLAIN)

    assert raised.value.reason is ReasonCode.PKCE_METHOD_UNSUPPORTED
    assert raised.value.error == INVALID_REQUEST


def test_an_absent_method_does_not_default_to_plain() -> None:
    """RFC 7636 §4.3 says a missing `code_challenge_method` means `plain`.
    Honouring that would let any client disable the strongest control in the
    flow by omitting a parameter."""
    with pytest.raises(OAuthError) as raised:
        pkce.assert_supported_method(None)

    assert raised.value.reason is ReasonCode.PKCE_METHOD_UNSUPPORTED


def test_an_unknown_method_is_refused() -> None:
    with pytest.raises(OAuthError, match="S256 only"):
        pkce.assert_supported_method("S512")


def test_a_valid_challenge_is_accepted() -> None:
    pkce.assert_valid_challenge(CHALLENGE)


@pytest.mark.parametrize("challenge", [None, "", CHALLENGE[:-1], CHALLENGE + "a", "!" * 43])
def test_a_missing_or_malformed_challenge_is_refused(challenge: str | None) -> None:
    """Checked at authorization time, where the client can be told what is
    wrong. At the token endpoint the only honest answer left is
    `invalid_grant`, which says nothing useful to an honest client."""
    with pytest.raises(OAuthError) as raised:
        pkce.assert_valid_challenge(challenge)

    assert raised.value.reason is ReasonCode.PKCE_REQUIRED
    assert raised.value.error == INVALID_REQUEST


def test_a_pkce_failure_is_reportable_to_the_client() -> None:
    """This module does not decide where its errors go, and an earlier version
    that tried to was wrong.

    Whether there is somewhere safe to send a refusal is a property of where in
    the flow it happened, not of the check: these same functions fail at the
    authorization endpoint, where the client's registered URI is known and an
    error belongs there, and at the token endpoint, where there is no redirect
    at all. Only an error *about* the destination is intrinsically unsendable.
    """
    calls: list[Callable[[], None]] = [
        lambda: pkce.assert_supported_method(None),
        lambda: pkce.assert_valid_challenge(None),
        lambda: pkce.verify(None, CHALLENGE),
    ]

    for call in calls:
        with pytest.raises(OAuthError) as raised:
            call()
        assert may_be_redirected(raised.value)
