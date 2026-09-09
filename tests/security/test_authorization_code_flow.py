"""The authorization code flow end to end (FR-OP-03 to FR-OP-06, FR-OP-10).

Exercised through the real ASGI app against `fakeredis`, so the Redis semantics
that make codes single-use are the real ones. The client registry and the policy
store are the only doubles: both are covered against Postgres and against real
files elsewhere, and substituting them is what lets this file be about the flow.

The recurring question is *where a refusal goes*. Before the client and its
redirect URI are known there is nowhere safe to send one; after, an error
belongs at the client so its user sees something useful. Confusing the two is
exactly an open redirect, so several tests here assert only the destination.
"""

from __future__ import annotations

import base64
import json
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
from campusid.oidc.jwt import b64url_decode
from campusid.oidc.keys import KeySet
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import DISPLAY_NAME, EPPN, MAIL, SCOPED_AFFILIATION
from campusid.policy.release import ReleasePolicy, ReleaseRule
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore

pytestmark = pytest.mark.security

BASE = "https://broker.test"
CLIENT_ID = "campus-portal"
REDIRECT = "https://portal.campus.test/oidc/callback"
SECRET = "s" * 43
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = compute_challenge(VERIFIER)

AUTHORIZE = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT,
    "response_type": "code",
    "scope": "openid profile email",
    "state": "client-state",
    "nonce": "client-nonce",
    "code_challenge": CHALLENGE,
    "code_challenge_method": "S256",
}


class _Clients:
    """Stands in for the Postgres-backed registry, which has its own suite."""

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
    """A fixed policy for every SP, so this file is about the flow."""

    def __init__(self, policy: ReleasePolicy) -> None:
        self._policy = policy

    def get(self, sp_entity_id: str) -> ReleasePolicy:
        return self._policy


@pytest.fixture
def confidential() -> OidcClient:
    return OidcClient(
        client_id=CLIENT_ID,
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(REDIRECT,),
        allowed_scopes=frozenset({"openid", "profile", "email"}),
        secret_hash=hash_secret(SECRET),
    )


@pytest.fixture
def public_client() -> OidcClient:
    return OidcClient(
        client_id="browser-app",
        client_type=ClientType.PUBLIC,
        redirect_uris=("https://spa.campus.test/cb",),
        allowed_scopes=frozenset({"openid", "email"}),
    )


@pytest.fixture
def policy() -> ReleasePolicy:
    return ReleasePolicy(
        sp_entity_id="https://portal.campus.test/sp",
        rules=(
            ReleaseRule("mail", "allow", MAIL),
            ReleaseRule("eppn", "allow", EPPN),
            ReleaseRule("name", "allow", DISPLAY_NAME),
            ReleaseRule("affiliation", "allow", SCOPED_AFFILIATION),
        ),
    )


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    confidential: OidcClient,
    public_client: OidcClient,
    policy: ReleasePolicy,
    oidc_key_set: KeySet,
) -> FastAPI:
    """Everything the lifespan would normally attach."""
    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.clients = _Clients(confidential, public_client)
    app.state.policies = _Policies(policy)
    app.state.oidc_keys = oidc_key_set
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
        acr="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        amr=("pwd",),
        attributes={
            EPPN: ["sam.obrien@campus.test"],
            MAIL: ["sam.obrien@campus.test"],
            DISPLAY_NAME: ["Samira O'Brien"],
            SCOPED_AFFILIATION: ["student@campus.test"],
        },
    )
    return established


def _query(response: Any) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}


def _claims(token: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(b64url_decode(token.split(".")[1]))
    return payload


async def _authorize(http: AsyncClient, session: Session, **overrides: Any) -> Any:
    parameters = {**AUTHORIZE, **overrides}
    return await http.get(
        "/oauth2/authorize", params=parameters, cookies={SESSION_COOKIE: session.sid}
    )


async def _code(http: AsyncClient, session: Session, **overrides: Any) -> str:
    return _query(await _authorize(http, session, **overrides))["code"]


async def _token(http: AsyncClient, **form: Any) -> Any:
    return await http.post(
        "/oauth2/token",
        data={"client_id": CLIENT_ID, "client_secret": SECRET, **form},
    )


# --- the happy path --------------------------------------------------------


async def test_an_authenticated_request_gets_a_code(http: AsyncClient, session: Session) -> None:
    response = await _authorize(http, session)

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"{REDIRECT}?")
    assert _query(response)["code"]


async def test_the_state_comes_back_unchanged(http: AsyncClient, session: Session) -> None:
    """The client's CSRF defence. It is echoed, never interpreted."""
    response = await _authorize(http, session, state="a b&c=d")

    assert _query(response)["state"] == "a b&c=d"


async def test_the_response_names_its_issuer(http: AsyncClient, session: Session) -> None:
    """RFC 9207. A client configured with several providers can otherwise be
    fed a code from the wrong one — the mix-up attack."""
    assert _query(await _authorize(http, session))["iss"] == BASE


async def test_a_code_exchanges_for_the_three_tokens(http: AsyncClient, session: Session) -> None:
    code = await _code(http, session)

    response = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
    )

    body = response.json()
    assert response.status_code == 200
    assert body["token_type"] == "Bearer"
    assert {"access_token", "id_token", "refresh_token"} <= set(body)


async def test_the_id_token_carries_the_clients_nonce(http: AsyncClient, session: Session) -> None:
    """What binds the token to this browser's request. A client compares it
    against the value it generated, and a token captured elsewhere fails."""
    code = await _code(http, session, nonce="a-specific-nonce")

    body = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    assert _claims(body["id_token"])["nonce"] == "a-specific-nonce"


async def test_the_id_token_carries_the_released_claims(
    http: AsyncClient, session: Session
) -> None:
    """Through the same release engine the SAML side uses, so what this client
    learns over OIDC is what it would have learned over SAML."""
    code = await _code(http, session)

    body = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    claims = _claims(body["id_token"])
    assert claims["email"] == "sam.obrien@campus.test"
    assert claims["name"] == "Samira O'Brien"


async def test_the_subject_is_pairwise_and_not_the_name_id(
    http: AsyncClient, session: Session
) -> None:
    """The client never learns the identifier the IdP asserted. That is the
    point of a broker: two applications comparing notes cannot tell they are
    talking about one person."""
    code = await _code(http, session)

    body = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    subject = _claims(body["id_token"])["sub"]
    assert "opaque-name-id" not in subject
    assert subject.endswith("@campus.test")


async def test_a_scope_the_client_did_not_request_yields_no_claim(
    http: AsyncClient, session: Session
) -> None:
    code = await _code(http, session, scope="openid")

    body = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    assert "email" not in _claims(body["id_token"])


async def test_token_responses_are_never_cached(http: AsyncClient, session: Session) -> None:
    """RFC 6749 §5.1. An intermediary caching one hands the next person through
    it somebody else's tokens."""
    code = await _code(http, session)

    response = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
    )

    assert response.headers["cache-control"] == "no-store"


# --- PKCE ------------------------------------------------------------------


async def test_a_wrong_verifier_is_refused(http: AsyncClient, session: Session) -> None:
    code = await _code(http, session)

    response = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=compute_challenge("something-else"),
    )

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}


async def test_a_failed_verifier_still_spends_the_code(http: AsyncClient, session: Session) -> None:
    """A code is single-use whatever the reason its redemption failed. Leaving
    it live would let whoever stole it keep guessing the verifier."""
    code = await _code(http, session)
    await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=compute_challenge("wrong"),
    )

    retry = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
    )

    assert retry.status_code == 400


@pytest.mark.parametrize(
    "override",
    [
        {"code_challenge_method": "plain", "code_challenge": VERIFIER},
        {"code_challenge_method": None},
        {"code_challenge": None},
    ],
)
async def test_a_request_without_usable_pkce_is_refused(
    http: AsyncClient, session: Session, override: dict[str, Any]
) -> None:
    """FR-OP-03's three negative cases. The missing-method one matters most:
    RFC 7636 says an absent method means `plain`, and honouring that default
    would let any client disable PKCE by omitting a parameter."""
    parameters = {k: v for k, v in {**AUTHORIZE, **override}.items() if v is not None}

    response = await http.get(
        "/oauth2/authorize", params=parameters, cookies={SESSION_COOKIE: session.sid}
    )

    assert _query(response)["error"] == "invalid_request"


# --- where refusals go -----------------------------------------------------


async def test_an_unknown_client_lands_on_our_own_page(http: AsyncClient) -> None:
    """There is no registered URI to redirect to, and the one supplied is
    exactly the value in question."""
    response = await http.get("/oauth2/authorize", params={**AUTHORIZE, "client_id": "nobody"})

    assert response.status_code == 400
    assert "location" not in response.headers


async def test_an_unregistered_redirect_uri_lands_on_our_own_page(
    http: AsyncClient,
) -> None:
    """The refusal that must never be redirected: reporting it *to* the URI in
    question would forward the user to the attacker's URL with our blessing."""
    response = await http.get(
        "/oauth2/authorize", params={**AUTHORIZE, "redirect_uri": "https://evil.test/cb"}
    )

    assert response.status_code == 400
    assert "location" not in response.headers


async def test_the_error_page_names_no_reason(http: AsyncClient) -> None:
    """Uniform, like the SAML one. Telling the caller which check refused them
    is free reconnaissance."""
    response = await http.get("/oauth2/authorize", params={**AUTHORIZE, "client_id": "nobody"})

    assert "client" not in response.text.lower()
    assert "redirect" not in response.text.lower()


async def test_a_protocol_error_goes_back_to_the_client(
    http: AsyncClient, session: Session
) -> None:
    """Once the redirect URI is known to be registered, an error belongs at the
    client, where its user can be shown something useful."""
    response = await _authorize(http, session, response_type="token")

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"{REDIRECT}?")
    assert _query(response)["error"] == "unsupported_response_type"


async def test_an_error_redirect_carries_the_state(http: AsyncClient, session: Session) -> None:
    """So the client can match the failure to the request it made rather than
    treating it as an unsolicited callback."""
    response = await _authorize(http, session, response_type="token", state="xyz")

    assert _query(response)["state"] == "xyz"


@pytest.mark.parametrize("missing", ["state", "nonce"])
async def test_a_request_missing_state_or_nonce_is_refused(
    http: AsyncClient, session: Session, missing: str
) -> None:
    """FR-OP-06. A provider that accepts a request without `state` has removed
    the client's CSRF defence whether the client noticed or not."""
    parameters = {k: v for k, v in AUTHORIZE.items() if k != missing}

    response = await http.get(
        "/oauth2/authorize", params=parameters, cookies={SESSION_COOKIE: session.sid}
    )

    assert response.status_code == 303
    assert _query(response)["error"] == "invalid_request"


async def test_an_unpermitted_scope_is_refused(http: AsyncClient, session: Session) -> None:
    response = await _authorize(http, session, scope="openid admin")

    assert _query(response)["error"] == "invalid_scope"


# --- the login handoff -----------------------------------------------------


async def test_an_unauthenticated_request_starts_a_login(http: AsyncClient) -> None:
    response = await http.get("/oauth2/authorize", params=AUTHORIZE)

    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert location.path == "/saml/sso"


async def test_the_login_carries_a_local_return_path(http: AsyncClient) -> None:
    """The stash id travels in `return_to`, which `/saml/sso` validates as a
    local path and then keeps server-side on the outstanding request."""
    response = await http.get("/oauth2/authorize", params=AUTHORIZE)

    return_to = _query(response)["return_to"]
    assert return_to.startswith("/oauth2/authorize?pending=")


async def test_the_request_is_not_reflected_into_the_login_url(
    http: AsyncClient,
) -> None:
    """Only an opaque id crosses to the IdP and back. The parameters stay on the
    server, so a browser returning from an IdP cannot alter the request it
    started — nor can anyone read it out of a URL in a proxy log."""
    response = await http.get("/oauth2/authorize", params=AUTHORIZE)

    location = response.headers["location"]
    assert REDIRECT not in location
    assert "client-nonce" not in location


async def test_resuming_after_a_login_issues_the_code(http: AsyncClient, session: Session) -> None:
    started = await http.get("/oauth2/authorize", params=AUTHORIZE)
    pending = _query(started)["return_to"].split("pending=")[1]

    resumed = await http.get(
        "/oauth2/authorize",
        params={"pending": pending},
        cookies={SESSION_COOKIE: session.sid},
    )

    assert resumed.headers["location"].startswith(f"{REDIRECT}?")
    assert _query(resumed)["state"] == "client-state"


async def test_a_stashed_request_is_single_use(http: AsyncClient, session: Session) -> None:
    """A stash id that survived its redemption would let the back button mint a
    second code for a request the user made once."""
    started = await http.get("/oauth2/authorize", params=AUTHORIZE)
    pending = _query(started)["return_to"].split("pending=")[1]
    await http.get(
        "/oauth2/authorize", params={"pending": pending}, cookies={SESSION_COOKIE: session.sid}
    )

    replay = await http.get(
        "/oauth2/authorize", params={"pending": pending}, cookies={SESSION_COOKIE: session.sid}
    )

    assert replay.status_code == 400


async def test_an_unknown_stash_lands_on_our_own_page(http: AsyncClient) -> None:
    response = await http.get("/oauth2/authorize", params={"pending": "never-stashed"})

    assert response.status_code == 400
    assert "location" not in response.headers


async def test_an_expired_session_starts_a_fresh_login(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """A cookie naming a session that is gone is not an authenticated request.
    Treating it as one would issue a code for a person who is not there."""
    await wired.state.sessions.destroy(session.sid)

    response = await _authorize(http, session)

    assert urlsplit(response.headers["location"]).path == "/saml/sso"


# --- client authentication at the token endpoint ---------------------------


async def test_basic_authentication_is_accepted(http: AsyncClient, session: Session) -> None:
    """RFC 6749 §2.3.1 requires it, and some clients send only this."""
    code = await _code(http, session)
    credentials = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()

    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
        },
        headers={"Authorization": f"Basic {credentials}"},
    )

    assert response.status_code == 200


async def test_a_wrong_secret_is_refused(http: AsyncClient, session: Session) -> None:
    code = await _code(http, session)

    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "client_id": CLIENT_ID,
            "client_secret": "wrong",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"error": "invalid_client"}


async def test_a_confidential_client_cannot_skip_authentication(
    http: AsyncClient, session: Session
) -> None:
    code = await _code(http, session)

    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "client_id": CLIENT_ID,
        },
    )

    assert response.status_code == 401


async def test_a_public_client_presenting_a_secret_is_refused(http: AsyncClient) -> None:
    """Either misconfigured or somebody who found one. Neither should be
    quietly accepted."""
    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": "irrelevant",
            "client_id": "browser-app",
            "client_secret": "found-this-somewhere",
        },
    )

    assert response.status_code == 401


async def test_an_unsupported_grant_type_is_refused(http: AsyncClient) -> None:
    response = await _token(http, grant_type="password", username="sam", password="hunter2")

    assert response.json() == {"error": "unsupported_grant_type"}


async def test_the_token_endpoint_explains_nothing(http: AsyncClient, session: Session) -> None:
    """It answers a server. A caller holding a code they should not have learns
    nothing from being told which check refused them, while a legitimate
    client's integration bug is visible in our logs."""
    response = await _token(
        http, grant_type="authorization_code", code="made-up", redirect_uri=REDIRECT
    )

    assert set(response.json()) == {"error"}


# --- code binding and reuse ------------------------------------------------


async def test_a_code_is_bound_to_its_redirect_uri(http: AsyncClient, session: Session) -> None:
    code = await _code(http, session)

    response = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri="https://portal.campus.test/oidc/callback2",
        code_verifier=VERIFIER,
    )

    assert response.status_code == 400


async def test_reusing_a_code_kills_the_tokens_it_produced(
    http: AsyncClient, session: Session
) -> None:
    """FR-OP-04. The replay and the original are indistinguishable, so both
    parties lose the tokens and the real user signs in again."""
    code = await _code(http, session)
    first = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    replay = await _token(
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
    )
    refresh = await _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])

    assert replay.json() == {"error": "invalid_grant"}
    assert refresh.status_code == 400


# --- refresh ---------------------------------------------------------------


async def test_a_refresh_token_rotates(http: AsyncClient, session: Session) -> None:
    code = await _code(http, session)
    first = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    second = (
        await _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
    ).json()

    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"]


async def test_a_refresh_issues_no_id_token(http: AsyncClient, session: Session) -> None:
    """An ID token asserts that somebody authenticated just now. Reissuing one
    because a machine presented a refresh token would assert a login that did
    not happen, and a client enforcing `max_age` would be misled by it."""
    code = await _code(http, session)
    first = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()

    second = (
        await _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
    ).json()

    assert "id_token" not in second


async def test_a_rotated_away_refresh_token_kills_the_family(
    http: AsyncClient, session: Session
) -> None:
    """FR-OP-08. Revoking only the replayed token leaves whichever party
    rotated successfully holding a valid one."""
    code = await _code(http, session)
    first = (
        await _token(
            http,
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        )
    ).json()
    second = (
        await _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
    ).json()

    replay = await _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
    latest = await _token(http, grant_type="refresh_token", refresh_token=second["refresh_token"])

    assert replay.json() == {"error": "invalid_grant"}
    assert latest.status_code == 400
