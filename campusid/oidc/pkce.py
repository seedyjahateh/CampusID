"""Proof Key for Code Exchange (FR-OP-03), RFC 7636.

PKCE binds an authorization code to the client instance that requested it. The
client picks a random `code_verifier`, sends only its hash on the front channel,
and presents the verifier itself at the token endpoint. An attacker who steals
the code — from a browser history, a referrer header, a malicious app claiming
the same custom URI scheme — cannot redeem it without the verifier, which never
travelled over the channel they compromised.

Two rules here are the whole of it:

**S256 only.** `plain` sends the verifier in the authorization request, so the
attacker who captured the code captured the proof alongside it and PKCE does
nothing. RFC 7636 §7.2 says a server that supports S256 must reject `plain` from
a client capable of S256; we take the simpler line and require S256 of everyone.

**Mandatory for every client, confidential ones included.** The original framing
made PKCE a public-client measure because confidential clients authenticate at
the token endpoint. But client authentication proves *which application* redeems
the code, not *which browser session* it belongs to; a code injected into a
confidential client's own callback is still redeemed with that client's valid
credentials. OAuth 2.1 and the Security BCP both now require it universally.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Final

from campusid.errors import ReasonCode
from campusid.oidc.errors import INVALID_GRANT, INVALID_REQUEST, OAuthError

S256: Final = "S256"
"""The only challenge method advertised or accepted."""

PLAIN: Final = "plain"
"""Named so it can be refused by name rather than falling through to "unknown"."""

MIN_VERIFIER_LENGTH: Final = 43
MAX_VERIFIER_LENGTH: Final = 128
"""RFC 7636 §4.1. The lower bound is a security parameter, not a formatting
rule: 43 base64url characters is where a 256-bit verifier lands, and a short
verifier is guessable by whoever holds the stolen code and the challenge."""

_VERIFIER_CHARSET: Final = re.compile(r"^[A-Za-z0-9._~-]+$")
"""The unreserved set. Anything else means the verifier will not survive some
client's URL encoding intact, and a verifier that changes in transit fails a
comparison that was supposed to mean something."""


def compute_challenge(verifier: str) -> str:
    """S256: base64url(SHA-256(ASCII(verifier))), unpadded."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def assert_supported_method(method: str | None) -> None:
    """Check what an authorization request asked for, before a code exists.

    A missing method is not defaulted. RFC 7636 says an absent
    `code_challenge_method` means `plain`, and honouring that default would make
    the strongest requirement in this module silently optional for any client
    that simply omits a parameter.
    """
    if method is None:
        raise OAuthError(
            INVALID_REQUEST,
            ReasonCode.PKCE_METHOD_UNSUPPORTED,
            "code_challenge_method is required; it does not default to plain here",
        )
    if method != S256:
        raise OAuthError(
            INVALID_REQUEST,
            ReasonCode.PKCE_METHOD_UNSUPPORTED,
            f"{method!r} is not supported; S256 only",
        )


def assert_valid_challenge(challenge: str | None) -> None:
    """Check the challenge accompanying an authorization request.

    The challenge is the SHA-256 digest in base64url, so its length is fixed at
    43 characters. Validating it here means a client that sends a truncated or
    mis-encoded challenge learns at authorization time rather than at the token
    endpoint, where the only honest answer left is `invalid_grant`.
    """
    if not challenge:
        raise OAuthError(INVALID_REQUEST, ReasonCode.PKCE_REQUIRED, "code_challenge is required")
    if len(challenge) != MIN_VERIFIER_LENGTH or not _VERIFIER_CHARSET.match(challenge):
        raise OAuthError(
            INVALID_REQUEST,
            ReasonCode.PKCE_REQUIRED,
            "code_challenge is not a base64url-encoded SHA-256 digest",
        )


def verify(verifier: str | None, challenge: str) -> None:
    """Check a token request's verifier against the stored challenge.

    Failure is `invalid_grant` and nothing more specific. A malformed verifier
    and a wrong one are the same event to whoever is presenting a code they
    should not have.
    """
    if verifier is None:
        raise OAuthError(
            INVALID_GRANT, ReasonCode.PKCE_VERIFICATION_FAILED, "code_verifier is required"
        )
    if not MIN_VERIFIER_LENGTH <= len(verifier) <= MAX_VERIFIER_LENGTH:
        raise OAuthError(
            INVALID_GRANT,
            ReasonCode.PKCE_VERIFICATION_FAILED,
            "code_verifier length is out of range",
        )
    if not _VERIFIER_CHARSET.match(verifier):
        raise OAuthError(
            INVALID_GRANT,
            ReasonCode.PKCE_VERIFICATION_FAILED,
            "code_verifier has illegal characters",
        )
    # Constant time. The comparison is against a value an attacker chose the
    # input to, and leaking a prefix match one byte at a time is the classic way
    # a digest comparison stops being a digest comparison.
    if not hmac.compare_digest(compute_challenge(verifier), challenge):
        raise OAuthError(
            INVALID_GRANT, ReasonCode.PKCE_VERIFICATION_FAILED, "code_verifier does not match"
        )
