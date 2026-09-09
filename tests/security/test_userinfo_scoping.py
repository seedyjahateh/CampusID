"""`/userinfo`, introspection and revocation (FR-OP-09, FR-OP-11).

The three endpoints that consume an access token rather than issue one, so all
of them go through the same verification and all of them have to agree about
what "active" means.

The requirement worth pinning is FR-OP-11's: OIDC and SAML must release
identical sets for the same policy. Here that is asserted directly — the same
session and the same policy, evaluated once through the release engine as the
SAML side would and once through `/userinfo`, produce the same attributes.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.oidc.clients import ClientType, OidcClient, hash_secret
from campusid.oidc.errors import OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.keys import KeySet
from campusid.oidc.logout import ClientSessionIndex
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import DISPLAY_NAME, EPPN, MAIL, SCOPED_AFFILIATION
from campusid.policy.release import ReleasePolicy, ReleaseRule, Subject, evaluate
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore

pytestmark = pytest.mark.security

BASE = "https://broker.test"
CLIENT_ID = "campus-portal"
OTHER_CLIENT_ID = "analytics"
REDIRECT = "https://portal.campus.test/oidc/callback"
OTHER_REDIRECT = "https://analytics.campus.test/cb"
SECRET = "s" * 43
OTHER_SECRET = "o" * 43
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

HELD = {
    EPPN: ["sam.obrien@campus.test"],
    MAIL: ["sam.obrien@campus.test"],
    DISPLAY_NAME: ["Samira O'Brien"],
    SCOPED_AFFILIATION: ["student@campus.test", "member@campus.test"],
}

AUTHORIZE = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT,
    "response_type": "code",
    "scope": "openid profile email",
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
    def __init__(self, policy: ReleasePolicy) -> None:
        self.policy = policy

    def get(self, sp_entity_id: str) -> ReleasePolicy:
        return self.policy


@pytest.fixture
def policy() -> ReleasePolicy:
    """Deliberately not "allow everything": the release decision has to be
    visible in the result for FR-OP-11's comparison to mean anything."""
    return ReleasePolicy(
        sp_entity_id="https://portal.campus.test/sp",
        rules=(
            ReleaseRule("mail", "allow", MAIL),
            ReleaseRule("name", "allow", DISPLAY_NAME),
            ReleaseRule("eppn", "allow", EPPN),
            ReleaseRule("students", "allow-value", SCOPED_AFFILIATION, r"student@campus\.test"),
        ),
    )


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    policy: ReleasePolicy,
    oidc_key_set: KeySet,
) -> FastAPI:
    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.client_sessions = ClientSessionIndex(redis)
    app.state.oidc_keys = oidc_key_set
    app.state.policies = _Policies(policy)
    app.state.clients = _Clients(
        OidcClient(
            client_id=CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(REDIRECT,),
            allowed_scopes=frozenset({"openid", "profile", "email", "campus:affiliation"}),
            secret_hash=hash_secret(SECRET),
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
        attributes=dict(HELD),
    )
    return established


async def _tokens(http: AsyncClient, session: Session, **overrides: Any) -> dict[str, Any]:
    """Run a full flow and return the token response."""
    from urllib.parse import parse_qs, urlsplit

    authorized = await http.get(
        "/oauth2/authorize",
        params={**AUTHORIZE, **overrides},
        cookies={SESSION_COOKIE: session.sid},
    )
    code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]

    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    body: dict[str, Any] = response.json()
    return body


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- userinfo --------------------------------------------------------------


async def test_userinfo_returns_the_released_claims(http: AsyncClient, session: Session) -> None:
    tokens = await _tokens(http, session)

    response = await http.get("/userinfo", headers=_bearer(tokens["access_token"]))

    assert response.status_code == 200
    assert response.json()["email"] == "sam.obrien@campus.test"


async def test_oidc_and_saml_release_the_same_set(
    http: AsyncClient, session: Session, policy: ReleasePolicy, wired: FastAPI
) -> None:
    """FR-OP-11, asserted directly.

    The SAML side calls `evaluate` with this policy and this subject; the OIDC
    side reaches the same engine through `/userinfo`. The claim names differ
    because OIDC has its own vocabulary, but the *attributes released* are the
    same set — which is the property that matters, since it is what the policy
    decided.
    """
    tokens = await _tokens(http, session, scope="openid profile email campus:affiliation")
    over_oidc = (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()

    from campusid.oidc.claims import BY_ATTRIBUTE
    from campusid.policy.normalize import normalize

    normalised = normalize(session.attributes, scope="campus.test").attributes
    over_saml = evaluate(policy, Subject(person_key=session.subject_key), normalised)

    expected = {BY_ATTRIBUTE[name].claim for name in over_saml.attributes if name in BY_ATTRIBUTE}
    assert set(over_oidc) - {"sub"} == expected


async def test_userinfo_respects_the_granted_scope(http: AsyncClient, session: Session) -> None:
    """The scope narrows what a policy already permitted. A client that asked
    only for `openid` receives nothing but its subject, whatever policy says."""
    tokens = await _tokens(http, session, scope="openid")

    body = (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()

    assert set(body) == {"sub"}


async def test_the_value_filter_applies_over_oidc_too(http: AsyncClient, session: Session) -> None:
    """A partial release survives the trip into claims: the member affiliation
    did not pass the filter and does not appear."""
    tokens = await _tokens(http, session, scope="openid campus:affiliation")

    body = (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()

    assert body["campus_scoped_affiliation"] == ["student@campus.test"]


async def test_userinfo_returns_the_same_subject_as_the_id_token(
    http: AsyncClient, session: Session
) -> None:
    """A client keys its own records on `sub`. Two endpoints disagreeing about
    it would split one person into two accounts inside the application."""
    import json

    from campusid.oidc.jwt import b64url_decode

    tokens = await _tokens(http, session)
    in_id_token = json.loads(b64url_decode(tokens["id_token"].split(".")[1]))["sub"]

    body = (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()

    assert body["sub"] == in_id_token


async def test_userinfo_reflects_a_policy_change_without_a_new_login(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """Evaluated fresh on every call. A withdrawal that only took effect at the
    next login would leave the disclosure running for as long as the session."""
    tokens = await _tokens(http, session)
    assert "email" in (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()

    wired.state.policies.policy = ReleasePolicy(
        sp_entity_id="https://portal.campus.test/sp",
        rules=(ReleaseRule("name", "allow", DISPLAY_NAME),),
    )

    body = (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).json()
    assert "email" not in body


# --- what userinfo refuses -------------------------------------------------


async def test_userinfo_needs_a_token(http: AsyncClient) -> None:
    response = await http.get("/userinfo")

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_an_id_token_is_not_a_bearer_credential(http: AsyncClient, session: Session) -> None:
    """RFC 9068's `typ` earning its place: the refusal is by token type rather
    than by noticing a missing claim, so a client confusing the two is told
    rather than accommodated."""
    tokens = await _tokens(http, session)

    response = await http.get("/userinfo", headers=_bearer(tokens["id_token"]))

    assert response.status_code == 401


async def test_a_tampered_token_is_refused(http: AsyncClient, session: Session) -> None:
    tokens = await _tokens(http, session)
    header, claims, signature = tokens["access_token"].split(".")

    response = await http.get("/userinfo", headers=_bearer(f"{header}.{claims}.{signature[:-4]}"))

    assert response.status_code == 401


async def test_a_token_in_the_query_string_is_not_accepted(
    http: AsyncClient, session: Session
) -> None:
    """RFC 6750 permits it and we do not: a token in a URL reaches browser
    history, referrer headers, and every access log in between."""
    tokens = await _tokens(http, session)

    response = await http.get("/userinfo", params={"access_token": tokens["access_token"]})

    assert response.status_code == 401


async def test_a_revoked_family_stops_working_immediately(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """The answer to "a JWT cannot be revoked". The signature is still perfectly
    good; the family marker is what makes reuse detection take effect before the
    token expires."""
    tokens = await _tokens(http, session)
    body = (
        await http.post(
            "/oauth2/introspect",
            data={
                "token": tokens["access_token"],
                "client_id": CLIENT_ID,
                "client_secret": SECRET,
            },
        )
    ).json()
    await wired.state.grants.revoke_family(
        (await wired.state.grants.describe_refresh_token(tokens["refresh_token"])).family_id
    )

    assert body["active"] is True
    assert (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).status_code == 401


async def test_a_destroyed_session_ends_userinfo(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """Signed out, expired, or killed by an administrator. The signature says
    nothing about any of that, which is why the endpoint consults the session."""
    tokens = await _tokens(http, session)
    await wired.state.sessions.destroy(session.sid)

    assert (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).status_code == 401


async def test_userinfo_is_never_cached(http: AsyncClient, session: Session) -> None:
    tokens = await _tokens(http, session)

    response = await http.get("/userinfo", headers=_bearer(tokens["access_token"]))

    assert response.headers["cache-control"] == "no-store"


# --- introspection ---------------------------------------------------------


async def test_introspection_describes_a_live_token(http: AsyncClient, session: Session) -> None:
    tokens = await _tokens(http, session)

    body = (
        await http.post(
            "/oauth2/introspect",
            data={
                "token": tokens["access_token"],
                "client_id": CLIENT_ID,
                "client_secret": SECRET,
            },
        )
    ).json()

    assert body["active"] is True
    assert body["client_id"] == CLIENT_ID
    assert "openid" in body["scope"]


async def test_introspection_needs_client_authentication(
    http: AsyncClient, session: Session
) -> None:
    """An unauthenticated introspection endpoint is an oracle: anyone holding a
    stolen token can ask us to decode it for them."""
    tokens = await _tokens(http, session)

    response = await http.post("/oauth2/introspect", data={"token": tokens["access_token"]})

    assert response.status_code == 401


async def test_another_clients_token_is_reported_inactive(
    http: AsyncClient, session: Session
) -> None:
    """FR-OP-09. The same answer as an expired token, deliberately, so the
    endpoint cannot be used to enumerate which tokens exist."""
    tokens = await _tokens(http, session)

    body = (
        await http.post(
            "/oauth2/introspect",
            data={
                "token": tokens["access_token"],
                "client_id": OTHER_CLIENT_ID,
                "client_secret": OTHER_SECRET,
            },
        )
    ).json()

    assert body == {"active": False}


async def test_a_nonsense_token_is_reported_inactive(http: AsyncClient) -> None:
    body = (
        await http.post(
            "/oauth2/introspect",
            data={"token": "not-a-token", "client_id": CLIENT_ID, "client_secret": SECRET},
        )
    ).json()

    assert body == {"active": False}


async def test_introspection_accepts_basic_authentication(
    http: AsyncClient, session: Session
) -> None:
    tokens = await _tokens(http, session)
    credentials = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()

    response = await http.post(
        "/oauth2/introspect",
        data={"token": tokens["access_token"]},
        headers={"Authorization": f"Basic {credentials}"},
    )

    assert response.json()["active"] is True


# --- revocation ------------------------------------------------------------


async def test_revoking_an_access_token_ends_the_family(
    http: AsyncClient, session: Session
) -> None:
    """RFC 7009 says revoking a refresh token should invalidate the access
    tokens issued with it. Ours are JWTs, so the family marker is the only way
    to do that — and it makes revocation work in both directions, which is what
    a client calling this at logout actually wants."""
    tokens = await _tokens(http, session)

    revoked = await http.post(
        "/oauth2/revoke",
        data={"token": tokens["access_token"], "client_id": CLIENT_ID, "client_secret": SECRET},
    )

    assert revoked.status_code == 200
    assert (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).status_code == 401


async def test_revoking_a_refresh_token_ends_the_family(
    http: AsyncClient, session: Session
) -> None:
    tokens = await _tokens(http, session)

    await http.post(
        "/oauth2/revoke",
        data={"token": tokens["refresh_token"], "client_id": CLIENT_ID, "client_secret": SECRET},
    )

    refreshed = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    assert refreshed.status_code == 400


async def test_a_wrong_type_hint_does_not_prevent_revocation(
    http: AsyncClient, session: Session
) -> None:
    """RFC 7009 §2.1: the hint is an optimisation, and a server must try the
    other type when it fails. Believing it would make revocation silently do
    nothing for a client that got it wrong."""
    tokens = await _tokens(http, session)

    await http.post(
        "/oauth2/revoke",
        data={
            "token": tokens["refresh_token"],
            "token_type_hint": "access_token",
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )

    assert (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).status_code == 401


async def test_revoking_an_unknown_token_succeeds(http: AsyncClient) -> None:
    """The RFC requires 200. A caller that could tell "revoked" from "never
    existed" could enumerate tokens through the endpoint meant to destroy
    them."""
    response = await http.post(
        "/oauth2/revoke",
        data={"token": "never-issued", "client_id": CLIENT_ID, "client_secret": SECRET},
    )

    assert response.status_code == 200


async def test_a_client_cannot_revoke_another_clients_token(
    http: AsyncClient, session: Session
) -> None:
    """Otherwise any registered client could sign every user out of every other
    application by presenting tokens it happened to observe."""
    tokens = await _tokens(http, session)

    await http.post(
        "/oauth2/revoke",
        data={
            "token": tokens["access_token"],
            "client_id": OTHER_CLIENT_ID,
            "client_secret": OTHER_SECRET,
        },
    )

    assert (await http.get("/userinfo", headers=_bearer(tokens["access_token"]))).status_code == 200


async def test_revocation_needs_client_authentication(http: AsyncClient, session: Session) -> None:
    tokens = await _tokens(http, session)

    response = await http.post("/oauth2/revoke", data={"token": tokens["access_token"]})

    assert response.status_code == 401


async def test_revocation_does_not_spend_the_refresh_token(
    http: AsyncClient, session: Session, wired: FastAPI
) -> None:
    """Looked up without being consumed. Marking it spent would make a second
    revocation call look like reuse — and a client retrying a request it is not
    sure landed is the ordinary case, not an attack."""
    tokens = await _tokens(http, session)
    form = {"token": tokens["refresh_token"], "client_id": CLIENT_ID, "client_secret": SECRET}

    first = await http.post("/oauth2/revoke", data=form)
    second = await http.post("/oauth2/revoke", data=form)

    assert (first.status_code, second.status_code) == (200, 200)
