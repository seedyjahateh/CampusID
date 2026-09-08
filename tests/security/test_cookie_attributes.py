"""Cookie attributes, asserted exactly (NFR-SEC-01, PRD acceptance criterion 7).

Matching the whole `Set-Cookie` header rather than probing attributes one at a
time: a cookie's security is the combination, and an assertion that checks four
of five attributes passes while the fifth quietly regresses.
"""

from __future__ import annotations

import pytest
from starlette.responses import Response

from campusid.session.cookies import (
    REQUEST_BINDING_COOKIE,
    REQUEST_BINDING_MAX_AGE,
    SESSION_COOKIE,
    clear_request_binding_cookie,
    clear_session_cookie,
    set_request_binding_cookie,
    set_session_cookie,
)

pytestmark = pytest.mark.security


def _header(response: Response) -> str:
    return response.headers["set-cookie"]


def test_the_session_cookie_header_is_exact() -> None:
    response = Response()

    set_session_cookie(response, "opaque-sid")

    assert _header(response) == (
        "__Host-campusid_session=opaque-sid; HttpOnly; Path=/; SameSite=lax; Secure"
    )


def test_the_request_binding_cookie_header_is_exact() -> None:
    response = Response()

    set_request_binding_cookie(response, "opaque-nonce")

    assert _header(response) == (
        f"__Host-campusid_req=opaque-nonce; HttpOnly; Max-Age={REQUEST_BINDING_MAX_AGE}; "
        "Path=/; SameSite=none; Secure"
    )


def test_the_binding_cookie_is_samesite_none_and_the_session_cookie_is_not() -> None:
    """The whole reason there are two cookies.

    An external IdP finishes authentication by auto-POSTing to our ACS from its
    own origin — a cross-*site* POST, on which a `Lax` cookie is not sent. So
    the in-flight binding must be `None`, while the session cookie keeps `Lax`
    and the CSRF protection that comes with it.

    The dev stack cannot catch a regression here: `localhost:8000` and
    `localhost:8080` are the same site (ports are irrelevant to site), so a
    `Lax`-only design works locally and fails against a real federation
    partner. This assertion is the only thing standing in for that.
    """
    session_response, binding_response = Response(), Response()

    set_session_cookie(session_response, "sid")
    set_request_binding_cookie(binding_response, "nonce")

    assert "SameSite=lax" in _header(session_response)
    assert "SameSite=none" in _header(binding_response)


@pytest.mark.parametrize(
    ("name", "setter"),
    [
        (SESSION_COOKIE, set_session_cookie),
        (REQUEST_BINDING_COOKIE, set_request_binding_cookie),
    ],
)
def test_both_cookies_satisfy_the_host_prefix_rules(name: str, setter: object) -> None:
    """`__Host-` is a browser-enforced guarantee that a cookie was set by this
    exact origin. It requires `Secure`, `Path=/` and no `Domain`; a cookie
    named with the prefix that breaks any of them is silently discarded."""
    response = Response()
    setter(response, "value")  # type: ignore[operator]

    header = _header(response)

    assert header.startswith(f"{name}=")
    assert name.startswith("__Host-")
    assert "; Secure" in header
    assert "; Path=/" in header
    assert "Domain=" not in header


def test_both_cookies_are_http_only() -> None:
    """Neither is ever read by script, so exposing them to the DOM would add
    only an XSS-to-session-theft path."""
    session_response, binding_response = Response(), Response()

    set_session_cookie(session_response, "sid")
    set_request_binding_cookie(binding_response, "nonce")

    assert "HttpOnly" in _header(session_response)
    assert "HttpOnly" in _header(binding_response)


def test_the_session_cookie_has_no_max_age() -> None:
    """A browser-session cookie. `Max-Age` would be a *request* to the browser;
    the authoritative lifetime is the stored idle and absolute deadlines the
    server checks (FR-SES-02)."""
    response = Response()

    set_session_cookie(response, "sid")

    assert "Max-Age" not in _header(response)


def test_the_binding_cookie_expires_quickly() -> None:
    response = Response()

    set_request_binding_cookie(response, "nonce")

    assert f"Max-Age={REQUEST_BINDING_MAX_AGE}" in _header(response)
    assert REQUEST_BINDING_MAX_AGE <= 600


@pytest.mark.parametrize(
    ("clearer", "name"),
    [
        (clear_session_cookie, SESSION_COOKIE),
        (clear_request_binding_cookie, REQUEST_BINDING_COOKIE),
    ],
)
def test_clearing_a_cookie_keeps_its_attributes(clearer: object, name: str) -> None:
    """A deletion whose attributes differ from the original addresses a
    different cookie, so the one that matters survives."""
    response = Response()

    clearer(response)  # type: ignore[operator]

    header = _header(response)
    assert header.startswith(f"{name}=")
    assert "; Secure" in header
    assert "; Path=/" in header
    assert "Max-Age=0" in header or "Expires=" in header
