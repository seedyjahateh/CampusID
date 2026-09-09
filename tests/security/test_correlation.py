"""One id across the whole chain (FR-AUD-01, FR-AUD-02, FR-ARP-06).

The requirement is that a single login produces at least six events sharing one
correlation id. The reason is that the question an investigator asks is never
"did this event happen" but "what else happened around it" — and without a
shared id the answer has to be reconstructed from timestamps, which stops
working the moment two people log in at once.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import REDACTED, EventType, Outcome
from campusid.oidc.clients import ClientType, OidcClient, hash_secret
from campusid.oidc.errors import OAuthError
from campusid.oidc.grants import GrantStore
from campusid.oidc.keys import KeySet
from campusid.oidc.logout import ClientSessionIndex, LogoutNotifier
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import DISPLAY_NAME, MAIL, STUDENT_ID
from campusid.policy.release import Basis, ReleasePolicy, ReleaseRule
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
CLIENT_ID = "campus-portal"
REDIRECT = "https://portal.campus.test/oidc/callback"
SECRET = "s" * 43
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

AUTHORIZE = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT,
    "response_type": "code",
    "scope": "openid email",
    "state": "client-state",
    "nonce": "client-nonce",
    "code_challenge": compute_challenge(VERIFIER),
    "code_challenge_method": "S256",
}


class _Clients:
    def __init__(self, client: OidcClient) -> None:
        self._client = client

    async def get(self, client_id: str) -> OidcClient | None:
        return self._client if client_id == self._client.client_id else None

    async def require(self, client_id: str | None) -> OidcClient:
        from campusid.errors import ReasonCode
        from campusid.oidc.errors import INVALID_CLIENT

        if client_id != self._client.client_id:
            raise OAuthError(INVALID_CLIENT, ReasonCode.UNKNOWN_CLIENT, "no such client")
        return self._client


class _Policies:
    def get(self, sp_entity_id: str) -> ReleasePolicy:
        return ReleasePolicy(
            sp_entity_id="https://portal.campus.test/sp",
            rules=(
                ReleaseRule("mail", "allow", MAIL),
                # Denied on purpose: FR-ARP-06 wants the denials in the record
                # too, and this is what makes the "why does this app *not* see
                # my name?" case testable.
                ReleaseRule("no-name", "deny", DISPLAY_NAME),
            ),
        )


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    oidc_key_set: KeySet,
    audit: RecordingAuditLog,
) -> FastAPI:
    import httpx

    app.state.redis = redis
    app.state.grants = GrantStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.client_sessions = ClientSessionIndex(redis)
    app.state.oidc_keys = oidc_key_set
    app.state.policies = _Policies()
    app.state.audit = audit
    app.state.clients = _Clients(
        OidcClient(
            client_id=CLIENT_ID,
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(REDIRECT,),
            allowed_scopes=frozenset({"openid", "email"}),
            secret_hash=hash_secret(SECRET),
            backchannel_logout_uri="https://portal.campus.test/logout",
        )
    )
    app.state.logout_notifier = LogoutNotifier(
        issuer=BASE,
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200))),
        retry_delays=(),
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
        attributes={
            MAIL: ["sam.obrien@campus.test"],
            DISPLAY_NAME: ["Samira O'Brien"],
            STUDENT_ID: ["S00184213"],
        },
    )
    return established


async def _full_flow(http: AsyncClient, session: Session) -> dict[str, Any]:
    authorized = await http.get(
        "/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid}
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


# --- the chain -------------------------------------------------------------


async def test_the_oidc_half_of_a_login_produces_its_own_chain(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """The downstream half: disclosure, code issuance, token issuance, refresh
    and logout are five separable facts, and each is worth finding on its own.

    FR-AUD-02 counts six across the *whole* chain, and the missing three are the
    SAML side — `auth.request`, `auth.success`, `session.created` — which this
    file cannot produce because its session fixture is made directly rather than
    by authenticating. `tests/integration/test_audit_chain.py` asserts the full
    six against a real Keycloak login and the real Postgres table, which is the
    only place the claim can be made honestly.
    """
    tokens = await _full_flow(http, session)
    await http.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    assert audit.types == [
        EventType.ATTRIBUTE_RELEASE,
        EventType.AUTHZ_CODE_ISSUED,
        EventType.TOKEN_ISSUED,
        EventType.TOKEN_REFRESHED,
        EventType.SESSION_ENDED,
    ]


async def test_every_event_in_one_request_shares_an_id(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """Within a request, the id comes from a contextvar set by middleware — not
    threaded through call signatures, because the sixteenth call site is where
    somebody forgets, and an event with no correlation id is present but
    unjoinable."""
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    assert len({event.correlation_id for event in audit.events}) == 1


async def test_separate_requests_get_separate_ids(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """Otherwise the id joins nothing: two people logging in at once would share
    a chain, which is the failure the id exists to prevent."""
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})
    first = {event.correlation_id for event in audit.events}

    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})
    everything = {event.correlation_id for event in audit.events}

    assert len(everything) == 2
    assert first < everything


async def test_the_id_is_echoed_to_the_caller(http: AsyncClient) -> None:
    """So a user quoting the reference on the error page and an operator reading
    a proxy log are talking about the same request."""
    response = await http.get("/.well-known/jwks.json")

    assert response.headers["x-correlation-id"]


async def test_an_inbound_correlation_header_is_not_honoured(http: AsyncClient) -> None:
    """It would let a caller merge their requests into somebody else's chain, or
    flood one id until the trail for it is unreadable — and the broker is not
    behind a trusted mesh that would have set one."""
    response = await http.get(
        "/.well-known/jwks.json", headers={"X-Correlation-ID": "attacker-chosen"}
    )

    assert response.headers["x-correlation-id"] != "attacker-chosen"


# --- what each event says --------------------------------------------------


async def test_the_code_issuance_names_actor_subject_and_target(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """Actor is who did it, subject is who it was about, target is what it was
    done through. Collapsing them loses the only question an incident review
    actually asks: not "was this account touched" but "who touched it"."""
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    event = audit.of_type(EventType.AUTHZ_CODE_ISSUED)[0]
    assert event.actor == session.subject_key
    assert event.subject == session.subject_key
    assert event.target == CLIENT_ID
    assert event.session_id == session.sid


async def test_a_token_issuance_is_recorded(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    await _full_flow(http, session)

    assert audit.of_type(EventType.TOKEN_ISSUED)


async def test_a_refused_grant_is_recorded_as_denied(
    http: AsyncClient, audit: RecordingAuditLog
) -> None:
    """`DENIED` and `FAILURE` are separate outcomes because they mean opposite
    things: a denial is the system working, a failure is it not working."""
    await http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": "never-issued",
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )

    assert audit.of_type(EventType.AUTHZ_DENIED)[0].outcome is Outcome.DENIED


async def test_grant_reuse_is_its_own_event(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """The one event here that is a security incident rather than a record of
    normal operation."""
    tokens = await _full_flow(http, session)
    form = {
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": CLIENT_ID,
        "client_secret": SECRET,
    }
    await http.post("/oauth2/token", data=form)
    await http.post("/oauth2/token", data=form)

    assert audit.of_type(EventType.GRANT_REUSE_DETECTED)


async def test_a_logout_records_who_was_told(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    await _full_flow(http, session)

    await http.get("/oauth2/logout", cookies={SESSION_COOKIE: session.sid})

    ended = audit.of_type(EventType.SESSION_ENDED)[0]
    assert ended.detail["notified"] == [CLIENT_ID]


async def test_an_administrative_termination_is_a_different_event(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """The actor is an administrator rather than the person, and an
    investigation reads the two very differently."""
    await http.post("/admin/sessions/terminate", data={"subject_key": session.subject_key})

    assert audit.of_type(EventType.SESSION_TERMINATED)
    assert audit.of_type(EventType.ADMIN_ACTION)[0].actor == "administrator"


# --- the disclosure record (FR-ARP-06, FERPA §99.32) -----------------------


async def test_a_release_decision_is_recorded(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    release = audit.of_type(EventType.ATTRIBUTE_RELEASE)[0]
    assert release.subject == session.subject_key
    assert release.target == CLIENT_ID


async def test_the_record_carries_the_denials_too(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """A record of only what was released cannot answer "why does this app not
    see my name?", and that is where every incident starts."""
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    decisions = audit.of_type(EventType.ATTRIBUTE_RELEASE)[0].detail["decisions"]
    by_attribute = {decision["attribute"]: decision for decision in decisions}

    assert by_attribute[DISPLAY_NAME]["released"] is False
    assert by_attribute[DISPLAY_NAME]["basis"] == Basis.EXPLICIT_DENY.value
    assert by_attribute[DISPLAY_NAME]["rule_id"] == "no-name"


async def test_the_record_names_the_rule_that_decided(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    decisions = audit.of_type(EventType.ATTRIBUTE_RELEASE)[0].detail["decisions"]
    released = next(d for d in decisions if d["attribute"] == MAIL)

    assert released["released"] is True
    assert released["rule_id"] == "mail"


async def test_an_education_record_appears_as_a_refusal_not_a_value(
    http: AsyncClient, session: Session, audit: RecordingAuditLog
) -> None:
    """The session holds a student number. It must appear in the disclosure
    record as something that was considered and refused — and never as a
    value, in the very record that exists to prove it is never disclosed."""
    await http.get("/oauth2/authorize", params=AUTHORIZE, cookies={SESSION_COOKIE: session.sid})

    release = audit.of_type(EventType.ATTRIBUTE_RELEASE)[0]
    decisions = {d["attribute"]: d for d in release.detail["decisions"]}

    assert decisions[STUDENT_ID]["released"] is False
    assert decisions[STUDENT_ID]["basis"] == Basis.RESTRICTED.value
    assert "S00184213" not in repr(release.detail)


async def test_the_authentication_record_redacts_the_attribute_values(
    audit: RecordingAuditLog,
) -> None:
    """The ACS records what the IdP asserted. Names yes, values no — except for
    the ones the catalogue calls public."""
    event = await audit.record(
        EventType.AUTH_SUCCESS,
        Outcome.SUCCESS,
        detail={"attributes": {MAIL: ["sam.obrien@campus.test"]}},
    )

    assert event.detail["attributes"][MAIL] == REDACTED
