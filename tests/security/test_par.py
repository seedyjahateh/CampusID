"""Pushed Authorization Requests (FR-OP-07), RFC 9126.

The point of PAR is that the authorization request stops travelling through the
browser, so most of these tests are about what a browser can no longer do to it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.oidc.clients import ClientType, OidcClient, hash_secret
from campusid.oidc.errors import OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.keys import KeySet
from campusid.oidc.logout import ClientSessionIndex
from campusid.oidc.par import REQUEST_URI_PREFIX, PushedRequestStore
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import MAIL
from campusid.policy.release import ReleasePolicy, ReleaseRule
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore

pytestmark = pytest.mark.security

BASE = "https://broker.test"
CLIENT_ID = "campus-portal"
STRICT_CLIENT_ID = "high-assurance"
OTHER_CLIENT_ID = "analytics"
REDIRECT = "https://portal.campus.test/oidc/callback"
STRICT_REDIRECT = "https://finance.campus.test/cb"
OTHER_REDIRECT = "https://analytics.campus.test/cb"
SECRET = "s" * 43
STRICT_SECRET = "h" * 43
OTHER_SECRET = "o" * 43
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

PUSHABLE = {
    "response_type": "code",
    "redirect_uri": REDIRECT,
    "scope": "openid email",
    "state": "client-state",
    "nonce": "client-nonce",
    "code_challenge": compute_challenge(VERIFIER),
    "code_challenge_method": "S256",
}


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


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def wired(app: FastAPI, redis: aioredis.FakeRedis, oidc_key_set: KeySet) -> FastAPI:
    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.pushed_requests = PushedRequestStore(redis)
    app.state.client_sessions = ClientSessionIndex(redis)
    app.state.oidc_keys = oidc_key_set
    app.state.policies = _Policies()
    app.state.clients = _Clients(
        OidcClient(
            client_id=CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(REDIRECT,),
            allowed_scopes=frozenset({"openid", "email"}),
            secret_hash=hash_secret(SECRET),
        ),
        OidcClient(
            client_id=STRICT_CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(STRICT_REDIRECT,),
            allowed_scopes=frozenset({"openid"}),
            secret_hash=hash_secret(STRICT_SECRET),
            require_pushed_authorization_requests=True,
        ),
        OidcClient(
            client_id=OTHER_CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(OTHER_REDIRECT,),
            allowed_scopes=frozenset({"openid"}),
            secret_hash=hash_secret(OTHER_SECRET),
        ),
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


async def _push(http: AsyncClient, **overrides: Any) -> Any:
    return await http.post(
        "/oauth2/par",
        data={
            **PUSHABLE,
            **overrides,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )


def _query(response: Any) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}


# --- pushing ---------------------------------------------------------------


async def test_a_pushed_request_returns_a_reference(http: AsyncClient) -> None:
    response = await _push(http)

    body = response.json()
    assert response.status_code == 201
    assert body["request_uri"].startswith(REQUEST_URI_PREFIX)
    assert body["expires_in"] == 90


async def test_the_reference_is_not_guessable(http: AsyncClient) -> None:
    """It is the only thing standing between an observer and a request that has
    already been authenticated, so it is sized like a session id."""
    first = (await _push(http)).json()["request_uri"]
    second = (await _push(http)).json()["request_uri"]

    assert first != second
    assert len(first[len(REQUEST_URI_PREFIX) :]) >= 40


async def test_pushing_needs_client_authentication(http: AsyncClient) -> None:
    """The whole value of PAR is that `client_id` means something here. An
    unauthenticated push would be an ordinary authorization request with an
    extra round trip."""
    response = await http.post("/oauth2/par", data={**PUSHABLE, "client_id": CLIENT_ID})

    assert response.status_code == 401


async def test_pushing_is_never_cached(http: AsyncClient) -> None:
    assert (await _push(http)).headers["cache-control"] == "no-store"


# --- validated where the client can be told --------------------------------


async def test_an_invalid_request_is_refused_at_push_time(http: AsyncClient) -> None:
    """Most of the value in practice: a client integrating against this endpoint
    gets a 400 with a reason, rather than its user seeing an error page."""
    response = await _push(http, code_challenge_method="plain")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


async def test_an_unregistered_redirect_uri_is_refused_at_push_time(
    http: AsyncClient,
) -> None:
    response = await _push(http, redirect_uri="https://evil.test/cb")

    assert response.status_code == 400


async def test_an_unpermitted_scope_is_refused_at_push_time(http: AsyncClient) -> None:
    response = await _push(http, scope="openid admin")

    assert response.json()["error"] == "invalid_scope"


async def test_pushing_a_reference_is_refused(http: AsyncClient) -> None:
    """RFC 9126 §2.1. A pushed request that pushes a reference is either
    confused or an attempt to make us dereference something."""
    response = await _push(http, request_uri=f"{REQUEST_URI_PREFIX}anything")

    assert response.status_code == 400


# --- redeeming -------------------------------------------------------------


async def test_a_pushed_request_authorizes(http: AsyncClient, session: Session) -> None:
    reference = (await _push(http)).json()["request_uri"]

    response = await http.get(
        "/oauth2/authorize",
        params={"client_id": CLIENT_ID, "request_uri": reference},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"].startswith(f"{REDIRECT}?")
    assert _query(response)["state"] == "client-state"


async def test_the_query_cannot_override_what_was_pushed(
    http: AsyncClient, session: Session
) -> None:
    """The point of the whole mechanism. A parameter that could be overridden
    here would undo the reason for pushing the request at all — and `scope` is
    the one an attacker would reach for."""
    reference = (await _push(http)).json()["request_uri"]

    response = await http.get(
        "/oauth2/authorize",
        params={
            "client_id": CLIENT_ID,
            "request_uri": reference,
            "scope": "openid admin",
            "state": "attacker-state",
            "redirect_uri": "https://evil.test/cb",
        },
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"].startswith(f"{REDIRECT}?")
    assert _query(response)["state"] == "client-state"


async def test_a_reference_is_single_use(http: AsyncClient, session: Session) -> None:
    """A reusable reference would let a captured URL restart the same
    authorization long after the user thought they had finished."""
    reference = (await _push(http)).json()["request_uri"]
    parameters = {"client_id": CLIENT_ID, "request_uri": reference}
    await http.get("/oauth2/authorize", params=parameters, cookies={SESSION_COOKIE: session.sid})

    replay = await http.get(
        "/oauth2/authorize", params=parameters, cookies={SESSION_COOKIE: session.sid}
    )

    assert replay.status_code == 400


async def test_another_client_cannot_redeem_a_reference(
    http: AsyncClient, session: Session
) -> None:
    """Unbound, one client could redeem another's authenticated request and
    receive a code against it."""
    reference = (await _push(http)).json()["request_uri"]

    response = await http.get(
        "/oauth2/authorize",
        params={"client_id": OTHER_CLIENT_ID, "request_uri": reference},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.status_code == 400
    assert "location" not in response.headers


async def test_a_mismatched_reference_is_still_spent(http: AsyncClient, session: Session) -> None:
    """The binding is checked after the delete, so a client cannot probe for
    another's pending requests by presenting references until one is accepted."""
    reference = (await _push(http)).json()["request_uri"]
    await http.get(
        "/oauth2/authorize",
        params={"client_id": OTHER_CLIENT_ID, "request_uri": reference},
        cookies={SESSION_COOKIE: session.sid},
    )

    rightful = await http.get(
        "/oauth2/authorize",
        params={"client_id": CLIENT_ID, "request_uri": reference},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert rightful.status_code == 400


async def test_an_unknown_reference_lands_on_our_own_page(
    http: AsyncClient, session: Session
) -> None:
    """There is no validated redirect URI yet — the request we would have read
    one from is the thing that is missing."""
    response = await http.get(
        "/oauth2/authorize",
        params={"client_id": CLIENT_ID, "request_uri": f"{REQUEST_URI_PREFIX}made-up"},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.status_code == 400
    assert "location" not in response.headers


async def test_a_reference_of_the_wrong_shape_is_refused(
    http: AsyncClient, session: Session
) -> None:
    response = await http.get(
        "/oauth2/authorize",
        params={"client_id": CLIENT_ID, "request_uri": "https://evil.test/request.jwt"},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.status_code == 400


async def test_a_pushed_request_survives_a_login(http: AsyncClient, session: Session) -> None:
    """The reference is spent when the browser first arrives; the parameters
    then travel through the login on the server-side stash, so a PAR client's
    request is not lost by the user having to authenticate."""
    reference = (await _push(http)).json()["request_uri"]
    started = await http.get(
        "/oauth2/authorize", params={"client_id": CLIENT_ID, "request_uri": reference}
    )
    pending = _query(started)["return_to"].split("pending=")[1]

    resumed = await http.get(
        "/oauth2/authorize",
        params={"pending": pending},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert resumed.headers["location"].startswith(f"{REDIRECT}?")


# --- mandatory PAR ---------------------------------------------------------


async def test_a_strict_client_must_push(http: AsyncClient, session: Session) -> None:
    response = await http.get(
        "/oauth2/authorize",
        params={
            "client_id": STRICT_CLIENT_ID,
            "redirect_uri": STRICT_REDIRECT,
            "response_type": "code",
            "scope": "openid",
            "state": "s",
            "nonce": "n",
            "code_challenge": compute_challenge(VERIFIER),
            "code_challenge_method": "S256",
        },
        cookies={SESSION_COOKIE: session.sid},
    )

    assert _query(response)["error"] == "invalid_request"


async def test_a_strict_client_succeeds_by_pushing(http: AsyncClient, session: Session) -> None:
    """The check is on how the request arrived, not on whether a `request_uri`
    parameter is present. The record a client pushes does not itself contain
    one, so testing for the parameter would reject exactly the clients the
    setting exists to protect."""
    reference = (
        await http.post(
            "/oauth2/par",
            data={
                "response_type": "code",
                "redirect_uri": STRICT_REDIRECT,
                "scope": "openid",
                "state": "s",
                "nonce": "n",
                "code_challenge": compute_challenge(VERIFIER),
                "code_challenge_method": "S256",
                "client_id": STRICT_CLIENT_ID,
                "client_secret": STRICT_SECRET,
            },
        )
    ).json()["request_uri"]

    response = await http.get(
        "/oauth2/authorize",
        params={"client_id": STRICT_CLIENT_ID, "request_uri": reference},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert response.headers["location"].startswith(f"{STRICT_REDIRECT}?")
    assert "code" in _query(response)
