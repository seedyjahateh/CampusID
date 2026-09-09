"""Global logout and administrative termination (FR-SES-04, FR-SES-05, FR-OP-12).

Logging out has to mean something at the applications the person actually used,
or "sign out" is a button that clears one cookie and leaves five live sessions
behind it.

The property most of this file defends is the awkward half of FR-SES-04:
*partial failures do not block local destruction*. A client whose logout endpoint
is down, slow, or returning 500 must not be able to keep somebody signed in at
the broker — so the local session is destroyed before any of it runs, and a
delivery failure is audited rather than raised.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.oidc.clients import ClientType, OidcClient, hash_secret
from campusid.oidc.errors import OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.jwt import b64url_decode
from campusid.oidc.keys import KeySet
from campusid.oidc.logout import ClientSessionIndex, LogoutNotifier
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import MAIL
from campusid.policy.release import ReleasePolicy, ReleaseRule
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PORTAL = "campus-portal"
ANALYTICS = "analytics"
BROKEN = "broken-client"
PORTAL_REDIRECT = "https://portal.campus.test/oidc/callback"
ANALYTICS_REDIRECT = "https://analytics.campus.test/cb"
BROKEN_REDIRECT = "https://broken.campus.test/cb"
PORTAL_LOGOUT = "https://portal.campus.test/backchannel-logout"
ANALYTICS_LOGOUT = "https://analytics.campus.test/backchannel-logout"
BROKEN_LOGOUT = "https://broken.campus.test/backchannel-logout"
POST_LOGOUT = "https://portal.campus.test/goodbye"
SECRET = "s" * 43
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

SUBJECT_KEY = "https://idp.campus.test/saml|opaque-name-id"


class _Clients:
    def __init__(self, *clients: OidcClient) -> None:
        self._clients = {client.client_id: client for client in clients}

    async def get(self, client_id: str) -> OidcClient | None:
        return self._clients.get(client_id)

    async def require(self, client_id: str | None) -> OidcClient:
        from campusid.errors import ReasonCode
        from campusid.oidc.errors import INVALID_CLIENT

        client = self._clients.get(client_id or "")
        if client is None:
            raise OAuthError(INVALID_CLIENT, ReasonCode.UNKNOWN_CLIENT, "no such client")
        return client


class _Policies:
    def get(self, sp_entity_id: str) -> ReleasePolicy:
        return ReleasePolicy(
            sp_entity_id="https://portal.campus.test/sp",
            rules=(ReleaseRule("mail", "allow", MAIL),),
        )


class _Backchannel:
    """A stand-in for the clients' logout endpoints.

    Records every delivery so the tests can assert *what was sent*, not merely
    that something was. The `broken` endpoint always fails, which is how the
    "partial failures do not block" requirement gets exercised for real.
    """

    def __init__(self) -> None:
        self.received: list[tuple[str, str]] = []
        self.attempts: dict[str, int] = {}

    async def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.attempts[url] = self.attempts.get(url, 0) + 1
        body = parse_qs(request.content.decode())
        token = body.get("logout_token", [""])[0]
        if url == BROKEN_LOGOUT:
            return httpx.Response(500)
        self.received.append((url, token))
        return httpx.Response(200)


def _client(client_id: str, redirect: str, logout_uri: str | None, **extra: Any) -> OidcClient:
    return OidcClient(
        client_id=client_id,
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(redirect,),
        allowed_scopes=frozenset({"openid", "email"}),
        secret_hash=hash_secret(SECRET),
        backchannel_logout_uri=logout_uri,
        **extra,
    )


@pytest.fixture
def backchannel() -> _Backchannel:
    return _Backchannel()


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    oidc_key_set: KeySet,
    backchannel: _Backchannel,
) -> FastAPI:
    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.client_sessions = ClientSessionIndex(redis)
    app.state.oidc_keys = oidc_key_set
    app.state.policies = _Policies()
    app.state.clients = _Clients(
        _client(
            PORTAL,
            PORTAL_REDIRECT,
            PORTAL_LOGOUT,
            post_logout_redirect_uris=(POST_LOGOUT,),
        ),
        _client(ANALYTICS, ANALYTICS_REDIRECT, ANALYTICS_LOGOUT),
        _client(BROKEN, BROKEN_REDIRECT, BROKEN_LOGOUT),
    )
    app.state.logout_notifier = LogoutNotifier(
        issuer=BASE,
        client=httpx.AsyncClient(transport=httpx.MockTransport(backchannel.handle)),
        # No sleeping in tests. The delays are the notifier's own constant and
        # are exercised by their own test; paying them here would add seconds
        # to every case for nothing.
        retry_delays=(0.0, 0.0),
    )
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


@pytest.fixture
async def session(wired: FastAPI) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="opaque-name-id",
        auth_time=datetime(2026, 9, 8, 11, 55, tzinfo=UTC),
        attributes={MAIL: ["sam.obrien@campus.test"]},
    )
    return established


async def _sign_in_to(
    http: AsyncClient, session: Session, client_id: str, redirect: str
) -> dict[str, Any]:
    """Complete a full authorization and token exchange for one client."""
    authorized = await http.get(
        "/oauth2/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "openid email",
            "state": "s",
            "nonce": "n",
            "code_challenge": compute_challenge(VERIFIER),
            "code_challenge_method": "S256",
        },
        cookies={SESSION_COOKIE: session.sid},
    )
    code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]

    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
            "code_verifier": VERIFIER,
            "client_id": client_id,
            "client_secret": SECRET,
        },
    )
    body: dict[str, Any] = response.json()
    return body


def _claims(token: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(b64url_decode(token.split(".")[1]))
    return payload


# --- what logout reaches ---------------------------------------------------


async def test_logout_destroys_the_local_session(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert await wired.state.sessions.load(session.sid) is None


async def test_logout_clears_the_cookie(http: AsyncClient, session: Session) -> None:
    """Cosmetic on its own — the session is already gone server-side — but a
    browser left holding an identifier that addresses nothing will keep sending
    it on every request."""
    response = await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert SESSION_COOKIE in response.headers.get("set-cookie", "")


async def test_every_client_that_held_the_session_is_told(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """FR-OP-12. The index is what makes this possible: an authorization code is
    the only moment we learn that a client now holds a session for this person,
    and by logout time that moment is long past."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)
    await _sign_in_to(http, session, ANALYTICS, ANALYTICS_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert {url for url, _ in backchannel.received} == {PORTAL_LOGOUT, ANALYTICS_LOGOUT}


async def test_a_client_that_was_never_signed_into_is_not_told(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """The notification names a `sid`, so telling a client about a session it
    never had is both noise and a small disclosure of where this person goes."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert {url for url, _ in backchannel.received} == {PORTAL_LOGOUT}


async def test_the_logout_token_names_the_session(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """`backchannel_logout_session_supported` is advertised as true, so the
    token has to carry `sid` — otherwise a client can only log the person out
    of every session they have, including ones in other browsers."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    _, token = backchannel.received[0]
    claims = _claims(token)
    assert claims["sid"] == session.sid
    assert claims["aud"] == PORTAL


async def test_the_logout_token_carries_the_event_and_no_nonce(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """Back-Channel Logout 1.0 §2.4 forbids `nonce`, so a logout token can never
    be replayed into a client's login handler as proof somebody signed in."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    claims = _claims(backchannel.received[0][1])
    assert "events" in claims
    assert "nonce" not in claims


async def test_logout_revokes_the_tokens_the_session_produced(
    http: AsyncClient, session: Session
) -> None:
    """A destroyed session already stops `/userinfo`. This is the rest: without
    it an access token stays introspectable and a refresh token keeps rotating
    against a session that no longer exists."""
    tokens = await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    refreshed = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": PORTAL,
            "client_secret": SECRET,
        },
    )
    introspected = await http.post(
        "/oauth2/introspect",
        data={"token": tokens["access_token"], "client_id": PORTAL, "client_secret": SECRET},
    )
    assert refreshed.status_code == 400
    assert introspected.json() == {"active": False}


# --- partial failure --------------------------------------------------------


async def test_a_broken_client_does_not_block_the_logout(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """The requirement, as one assertion. A client whose endpoint returns 500
    must not be able to keep somebody signed in at the broker."""
    await _sign_in_to(http, session, BROKEN, BROKEN_REDIRECT)

    response = await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert response.status_code == 303
    assert await wired.state.sessions.load(session.sid) is None


async def test_a_broken_client_does_not_stop_the_others_being_told(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """Delivered concurrently, so the worst client is not the cost of every
    logout — and one failure does not abandon the rest of the list."""
    await _sign_in_to(http, session, BROKEN, BROKEN_REDIRECT)
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert {url for url, _ in backchannel.received} == {PORTAL_LOGOUT}


async def test_a_failing_delivery_is_retried(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """Three attempts: enough to ride out a restart or a blip. Anything longer
    is a queue, and a queue needs durability and a dead-letter story this does
    not pretend to have."""
    await _sign_in_to(http, session, BROKEN, BROKEN_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert backchannel.attempts[BROKEN_LOGOUT] == 3


async def test_a_successful_delivery_is_not_retried(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert backchannel.attempts[PORTAL_LOGOUT] == 1


async def test_logging_out_twice_is_harmless(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """The back button, or a second tab. The second call finds no session and
    notifies nobody, rather than telling every client again."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)
    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    second = await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert second.status_code == 303
    assert len(backchannel.received) == 1


async def test_logging_out_without_a_session_is_harmless(http: AsyncClient) -> None:
    assert (await http.get("/oauth2/logout")).status_code == 303


# --- the post-logout redirect ----------------------------------------------


async def test_a_registered_post_logout_uri_is_honoured(
    http: AsyncClient, session: Session
) -> None:
    response = await http.get(
        "/oauth2/logout",
        params={"client_id": PORTAL, "post_logout_redirect_uri": POST_LOGOUT},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == POST_LOGOUT


async def test_the_state_is_echoed_to_the_post_logout_uri(
    http: AsyncClient, session: Session
) -> None:
    response = await http.get(
        "/oauth2/logout",
        params={
            "client_id": PORTAL,
            "post_logout_redirect_uri": POST_LOGOUT,
            "state": "xyz",
        },
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == f"{POST_LOGOUT}?state=xyz"


async def test_an_unregistered_post_logout_uri_is_ignored(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """Without this the end-session endpoint is an open redirect that also logs
    people out — the log-out part making it *more* attractive, since the user is
    mid-flow and expecting to be sent somewhere.

    Ignored rather than refused: the user asked to be logged out and has been,
    and an error page would report a misconfigured client as a failed logout.
    """
    response = await http.get(
        "/oauth2/logout",
        params={"client_id": PORTAL, "post_logout_redirect_uri": "https://evil.test/"},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == "/"
    assert await wired.state.sessions.load(session.sid) is None


async def test_another_clients_registered_uri_is_not_borrowed(
    http: AsyncClient, session: Session
) -> None:
    """The URI is checked against the registration of the client the request
    claims to come from, so naming a different client does not grant its list."""
    response = await http.get(
        "/oauth2/logout",
        params={"client_id": ANALYTICS, "post_logout_redirect_uri": POST_LOGOUT},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == "/"


async def test_an_id_token_hint_identifies_the_client(http: AsyncClient, session: Session) -> None:
    """The usual way a client asks: it presents the ID token we gave it rather
    than naming itself."""
    tokens = await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    response = await http.get(
        "/oauth2/logout",
        params={
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": POST_LOGOUT,
        },
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == POST_LOGOUT


async def test_an_unsigned_hint_is_not_believed(http: AsyncClient, session: Session) -> None:
    """The hint decides which registration the redirect URI is checked against.
    Believing an unverified one would let anyone borrow a client's registered
    post-logout URIs by asserting its name in a token nobody signed."""
    forged = ".".join(
        [
            "eyJhbGciOiJub25lIn0",
            "eyJpc3MiOiJodHRwczovL2Jyb2tlci50ZXN0IiwiYXVkIjoiY2FtcHVzLXBvcnRhbCJ9",
            "",
        ]
    )

    response = await http.get(
        "/oauth2/logout",
        params={"id_token_hint": forged, "post_logout_redirect_uri": POST_LOGOUT},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"] == "/"


# --- administrative termination (FR-SES-05) --------------------------------


async def test_an_administrator_ends_every_session(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    second = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="opaque-name-id",
        attributes={},
    )

    response = await http.post("/admin/sessions/terminate", data={"subject_key": SUBJECT_KEY})

    assert response.json()["terminated"] == 2
    assert await wired.state.sessions.load(session.sid) is None
    assert await wired.state.sessions.load(second.sid) is None


async def test_termination_notifies_the_clients(
    http: AsyncClient, session: Session, backchannel: _Backchannel
) -> None:
    """US-04: "I force-terminate a session for a compromised account and every
    downstream app logs the user out"."""
    await _sign_in_to(http, session, PORTAL, PORTAL_REDIRECT)

    response = await http.post("/admin/sessions/terminate", data={"subject_key": SUBJECT_KEY})

    assert {url for url, _ in backchannel.received} == {PORTAL_LOGOUT}
    assert response.json()["notified"] == [PORTAL]


async def test_termination_reports_the_clients_it_could_not_reach(
    http: AsyncClient, session: Session
) -> None:
    """An administrator acting on an incident needs to know what actually
    happened — "done" is not an answer when the next question is whether the
    attacker still has a live session somewhere."""
    await _sign_in_to(http, session, BROKEN, BROKEN_REDIRECT)

    response = await http.post("/admin/sessions/terminate", data={"subject_key": SUBJECT_KEY})

    assert response.json()["unreachable"] == [BROKEN]


async def test_terminating_an_unknown_subject_reports_nothing_ended(
    http: AsyncClient,
) -> None:
    response = await http.post("/admin/sessions/terminate", data={"subject_key": "nobody|at-all"})

    assert response.json()["terminated"] == 0


async def test_another_persons_sessions_are_untouched(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """The blast radius is one person. An administrator ending a compromised
    account's sessions must not sign out the rest of the campus."""
    other = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="somebody-else",
        attributes={},
    )

    await http.post("/admin/sessions/terminate", data={"subject_key": SUBJECT_KEY})

    assert await wired.state.sessions.load(other.sid) is not None


async def test_a_destroyed_session_leaves_the_index(wired: FastAPI, session: Session) -> None:
    """A dead sid left in the index would make "terminate everything" report
    successes for sessions that no longer exist — the wrong direction for that
    particular reassurance."""
    await wired.state.sessions.destroy(session.sid)

    assert await wired.state.sessions.sids_for(SUBJECT_KEY) == []
