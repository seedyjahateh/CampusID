"""Registered OIDC clients and what they are allowed to ask for (FR-OP-05).

A client registration is a trust decision written down: this `client_id` may
send users to these exact URIs, request these scopes, and — if confidential —
prove itself with this secret. Everything the authorization endpoint does is a
comparison against one of those.

The redirect URI rule is the one that matters most, and it is deliberately the
dumbest thing in the module: **exact string comparison against a registered
value.** No wildcards, no path prefixes, no "same origin is close enough". Every
flexible matcher ever shipped has turned into an open redirect, because the
matcher and the attacker disagree about where a URL ends —
`https://app.test/cb` prefix-matches `https://app.test/cb.evil.test`, and
`https://app.test` origin-matches an unreviewed page on the same host that
forwards the fragment onward. An open redirect on the authorization endpoint is
not a redirect bug; it is the authorization code leaving with the wrong person.

The single exception is the loopback interface for native clients, and it is
narrow: RFC 8252 §7.3 has a desktop app bind an ephemeral port, so the port is
genuinely unknowable at registration time and only the port may vary.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

from campusid.errors import ReasonCode
from campusid.oidc.errors import (
    INVALID_CLIENT,
    INVALID_REQUEST,
    INVALID_SCOPE,
    OAuthError,
)

SCOPE_OPENID: Final = "openid"
"""Without it the request is plain OAuth 2.0 and no ID token is issued. Required
here, because this broker exists to authenticate people."""

LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "[::1]"})
"""Literal addresses only. RFC 8252 §8.3 excludes `localhost` on purpose: it
resolves through the hosts file and DNS, so another process on the machine can
be handed the authorization code by winning a name-resolution race."""

MIN_SECRET_LENGTH: Final = 32
"""Enforced at registration so the fast-hash decision below stays true."""


class ClientType(StrEnum):
    """How a client can be authenticated, which decides what it may do."""

    CONFIDENTIAL = "confidential"
    """A server-side application that can keep a secret."""

    PUBLIC = "public"
    """A browser application. Holds no secret, so PKCE is the only binding
    between the request and the redemption."""

    NATIVE = "native"
    """An installed application. Public, plus the loopback redirect allowance —
    which is why it is a separate type rather than a flag on `PUBLIC`."""


@dataclass(frozen=True, slots=True)
class OidcClient:
    """One registration."""

    client_id: str
    client_type: ClientType
    redirect_uris: tuple[str, ...]
    allowed_scopes: frozenset[str]
    secret_hash: str | None = None
    """SHA-256 of the secret, hex. None for public and native clients."""

    display_name: str | None = None
    require_pushed_authorization_requests: bool = False
    """FR-OP-07. When set, an authorization request that did not arrive by
    reference is refused, keeping the whole request off the front channel."""

    backchannel_logout_uri: str | None = None
    post_logout_redirect_uris: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.redirect_uris:
            raise ValueError(f"client {self.client_id!r} registers no redirect URI")
        for uri in self.redirect_uris:
            _assert_registrable(uri, self.client_type)
        if self.client_type is ClientType.CONFIDENTIAL and not self.secret_hash:
            raise ValueError(f"confidential client {self.client_id!r} has no secret")
        if self.client_type is not ClientType.CONFIDENTIAL and self.secret_hash:
            raise ValueError(f"public client {self.client_id!r} cannot hold a secret")
        if SCOPE_OPENID not in self.allowed_scopes:
            raise ValueError(f"client {self.client_id!r} cannot request openid")

    # --- redirect URIs ----------------------------------------------------

    def validated_redirect_uri(self, candidate: str | None) -> str:
        """Return `candidate` if it is registered, else refuse.

        The refusal is never redirectable. An error about a `redirect_uri`
        cannot be reported *to* that `redirect_uri` without becoming the open
        redirect this method exists to prevent — it belongs on the broker's own
        error page, which is also where the user can see who is asking.
        """
        if not candidate:
            raise OAuthError(
                INVALID_REQUEST, ReasonCode.REDIRECT_URI_MISMATCH, "redirect_uri is required"
            )
        if candidate in self.redirect_uris:
            return candidate
        if self.client_type is ClientType.NATIVE and self._matches_loopback(candidate):
            return candidate
        raise OAuthError(
            INVALID_REQUEST,
            ReasonCode.REDIRECT_URI_MISMATCH,
            f"{candidate!r} is not registered for {self.client_id!r}",
        )

    def _matches_loopback(self, candidate: str) -> bool:
        """RFC 8252 §7.3: the port, and only the port, may differ.

        Split before comparing rather than string-manipulating the port out.
        Everything else — scheme, host, path, query — must be equal, so a
        registration of `http://127.0.0.1/cb` does not admit
        `http://127.0.0.1/cb/../elsewhere` or a host that merely starts the same.
        """
        parsed = urlsplit(candidate)
        if parsed.scheme != "http" or parsed.fragment:
            return False
        host = _bracketed(parsed.hostname or "")
        if host not in LOOPBACK_HOSTS:
            return False
        return any(
            registered.scheme == "http"
            and _bracketed(registered.hostname or "") == host
            and registered.path == parsed.path
            and registered.query == parsed.query
            for registered in map(urlsplit, self.redirect_uris)
        )

    # --- authentication ---------------------------------------------------

    def authenticate(self, secret: str | None) -> None:
        """Verify a confidential client's secret (RFC 6749 §2.3.1).

        SHA-256 rather than a password hash, deliberately. Slow hashes exist to
        make offline guessing of *low-entropy human-chosen* secrets expensive;
        a client secret here is 256 bits from `secrets.token_urlsafe` and
        registration refuses anything short, so there is nothing to guess and a
        memory-hard KDF would only add latency to every token request. That
        argument depends on `MIN_SECRET_LENGTH` being enforced, which is why it
        is enforced rather than documented.
        """
        if self.client_type is not ClientType.CONFIDENTIAL:
            raise OAuthError(
                INVALID_CLIENT,
                ReasonCode.CLIENT_AUTHENTICATION_FAILED,
                f"{self.client_id!r} is not a confidential client",
            )
        if secret is None or not hmac.compare_digest(hash_secret(secret), self.secret_hash or ""):
            raise OAuthError(
                INVALID_CLIENT,
                ReasonCode.CLIENT_AUTHENTICATION_FAILED,
                f"bad secret for {self.client_id!r}",
            )

    # --- scopes -----------------------------------------------------------

    def granted_scopes(self, requested: str | None) -> frozenset[str]:
        """Narrow a request's scopes to what this client may have.

        Unknown scopes are refused rather than dropped. Silently narrowing lets
        a client believe it received `email` and read a claim that is not there,
        and the resulting bug surfaces as missing data somewhere far from here.
        """
        asked = frozenset((requested or "").split())
        if SCOPE_OPENID not in asked:
            raise OAuthError(
                INVALID_SCOPE,
                ReasonCode.SCOPE_NOT_PERMITTED,
                "the openid scope is required",
            )
        excess = asked - self.allowed_scopes
        if excess:
            raise OAuthError(
                INVALID_SCOPE,
                ReasonCode.SCOPE_NOT_PERMITTED,
                f"{sorted(excess)} not permitted for {self.client_id!r}",
            )
        return asked


def hash_secret(secret: str) -> str:
    """The stored form of a client secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_secret() -> str:
    """A new client secret: 256 bits, URL-safe."""
    return secrets.token_urlsafe(32)


def _assert_registrable(uri: str, client_type: ClientType) -> None:
    """Reject a redirect URI that could never be safe, at registration time.

    Registration is the only moment a human is looking. A URI that is wrong here
    becomes an exact-matched, permanently-trusted destination the moment it is
    stored, so the checks are worth making while someone can still fix them.
    """
    parsed = urlsplit(uri)
    if not parsed.scheme:
        raise ValueError(f"redirect URI {uri!r} is not absolute")
    if parsed.scheme in {"http", "https"} and not parsed.netloc:
        raise ValueError(f"redirect URI {uri!r} has no host")
    if parsed.fragment:
        # RFC 6749 §3.1.2. The fragment is where the broker puts its own
        # response; a registered one would be silently overwritten.
        raise ValueError(f"redirect URI {uri!r} must not contain a fragment")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http":
        if client_type is ClientType.NATIVE and _bracketed(parsed.hostname or "") in LOOPBACK_HOSTS:
            return
        raise ValueError(f"redirect URI {uri!r} must use https")
    if client_type is not ClientType.NATIVE:
        # A private-use scheme (`com.example.app:/cb`) is only meaningful for an
        # installed application, and any app on the device may claim it — which
        # is precisely why PKCE is mandatory.
        raise ValueError(f"redirect URI {uri!r} uses a scheme only native clients may register")


def _bracketed(host: str) -> str:
    """`urlsplit` strips the brackets from an IPv6 literal; put them back so a
    host comparison against `[::1]` is a comparison and not a near-miss."""
    return f"[{host}]" if ":" in host else host
