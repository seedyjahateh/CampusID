"""Cookie policy (NFR-SEC-01).

Two cookies, and the reason there are two is the interesting part.

`__Host-campusid_session` is `SameSite=Lax`. That is right for a session
cookie: it is not sent on cross-site requests the user did not initiate, which
is most of CSRF gone for free.

`__Host-campusid_req` is `SameSite=None`, and it has to be. The IdP finishes
authentication by auto-POSTing the response to our ACS from *its* origin. With
a genuinely external IdP that is a cross-**site** POST, and a `Lax` cookie is
not sent on it — so the in-flight request state could not be bound to the
browser that started the flow. Without that binding an attacker can hand a
victim a valid `RelayState` and log them in as somebody else: login CSRF.

**The development stack hides this.** `http://localhost:8000` and
`http://localhost:8080` are the same *site* — site is registrable-domain based
and ports are irrelevant — so the Keycloak-to-ACS POST is same-site locally and
a `Lax`-only design appears to work perfectly, then fails against a real
federation partner. `test_cookie_attributes.py` pins `SameSite=None` on the
binding cookie for exactly that reason.

The `__Host-` prefix requires `Secure`, `Path=/` and no `Domain`, which is why
those are not configurable. Chrome and Firefox honour `Secure` on
`http://localhost`; Safari does not, so local development there needs the TLS
profile.
"""

from __future__ import annotations

from typing import Final

from starlette.responses import Response

SESSION_COOKIE: Final = "__Host-campusid_session"
REQUEST_BINDING_COOKIE: Final = "__Host-campusid_req"

REQUEST_BINDING_MAX_AGE: Final = 300
"""Five minutes: long enough for a user to authenticate at the IdP, short
enough that an abandoned attempt stops being useful to anyone."""


def set_session_cookie(response: Response, sid: str) -> None:
    """Attach the session cookie."""
    response.set_cookie(
        SESSION_COOKIE,
        sid,
        max_age=None,  # a browser-session cookie; the server owns the real lifetime
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie.

    Cosmetic on its own — the session is destroyed server-side, so a client
    that ignores this is holding an identifier that addresses nothing.
    """
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def set_request_binding_cookie(response: Response, nonce: str) -> None:
    """Attach the in-flight request binding.

    `SameSite=None` because this one *must* survive the IdP's cross-site POST
    to our ACS. See the module docstring: it is the only cookie in the system
    that has to, and it carries nothing but an opaque nonce.
    """
    response.set_cookie(
        REQUEST_BINDING_COOKIE,
        nonce,
        max_age=REQUEST_BINDING_MAX_AGE,
        path="/",
        secure=True,
        httponly=True,
        samesite="none",
    )


def clear_request_binding_cookie(response: Response) -> None:
    """Remove the binding cookie once its request has been answered."""
    response.delete_cookie(
        REQUEST_BINDING_COOKIE, path="/", secure=True, httponly=True, samesite="none"
    )
