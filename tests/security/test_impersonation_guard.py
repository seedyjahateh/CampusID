"""Acting as a fixture user, and the guards around it (FR-ADM-03).

"Act as any user" is the most dangerous capability a broker can offer, and it is
offered here because testing an SP integration against a synthetic account of a
chosen affiliation is a real need that the alternative — creating real accounts
and knowing their passwords — meets far worse.

Three guards make that trade acceptable, and each has tests here. The endpoint
does not exist in production. Only enumerated fixture accounts can be assumed.
And every action an impersonated session takes is recorded against the
administrator who started it, which is the one that has to hold for *every*
downstream event rather than for the ones somebody remembered.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType, Outcome
from campusid.audit.log import impersonator, set_impersonator
from campusid.authz.engine import AAL1, AAL2
from campusid.config import Environment
from campusid.mfa.assurance import MFA, OTP, PWD
from campusid.routes.admin import ADMIN_ROLE, IMPERSONATION_ISSUER
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
ADMIN = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
FIXTURE = "sam.obrien@campus.test"
FIXTURE_UUID = UUID("c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b")
REAL_PERSON = "priya.nair@campus.test"


class _Assignments:
    def __init__(self) -> None:
        self.roles = {ADMIN_ROLE}

    async def roles_for(self, person_uuid: str) -> set[str]:
        return set(self.roles)


class _Identity:
    def __init__(self) -> None:
        self.known: dict[str, UUID] = {FIXTURE: FIXTURE_UUID}

    async def person_for(self, eppn: str) -> UUID | None:
        return self.known.get(eppn)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def assignments() -> _Assignments:
    return _Assignments()


@pytest.fixture
def identity() -> _Identity:
    return _Identity()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    assignments: _Assignments,
    identity: _Identity,
    audit: RecordingAuditLog,
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.role_assignments = assignments
    app.state.identity = identity
    app.state.registry = None
    app.state.audit = audit
    app.state.settings = app.state.settings.model_copy(update={"impersonation_fixtures": FIXTURE})
    return app


@pytest.fixture(autouse=True)
def _clean_context() -> Any:
    """The marker is per request. A test that left it set would make the next
    one's events claim an impersonation that never happened."""
    set_impersonator(None)
    yield
    set_impersonator(None)


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


@pytest.fixture
async def admin(wired: FastAPI) -> dict[str, str]:
    session: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=1),
        acr=AAL2,
        amr=(PWD, OTP, MFA),
        person_uuid=ADMIN,
    )
    return {SESSION_COOKIE: session.sid}


def _body(**overrides: Any) -> dict[str, Any]:
    return {"subject": FIXTURE, "reason": "testing the LMS integration", **overrides}


# --- not in production ------------------------------------------------------


async def test_the_endpoint_does_not_exist_in_production(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """Absent, not disabled. A feature that can be re-enabled by configuration is
    a feature an attacker can re-enable by configuration, and this is the one
    capability where that trade has no upside."""
    wired.state.settings = wired.state.settings.model_copy(
        update={"environment": Environment.PRODUCTION}
    )

    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)

    assert response.status_code == 404


async def test_production_answers_before_the_guard(
    http: AsyncClient, wired: FastAPI, audit: RecordingAuditLog
) -> None:
    """So it is not even an authenticated probe: the 404 is indistinguishable
    from a build that never had the route."""
    wired.state.settings = wired.state.settings.model_copy(
        update={"environment": Environment.PRODUCTION}
    )

    response = await http.post("/admin/impersonate", json=_body())

    assert response.status_code == 404
    assert audit.events == []


# --- the guard --------------------------------------------------------------


async def test_impersonation_needs_a_session(http: AsyncClient) -> None:
    assert (await http.post("/admin/impersonate", json=_body())).status_code == 401


async def test_impersonation_needs_the_role(
    http: AsyncClient, admin: dict[str, str], assignments: _Assignments
) -> None:
    assignments.roles = {"student"}

    assert (await http.post("/admin/impersonate", json=_body(), cookies=admin)).status_code == 404


async def test_impersonation_needs_a_second_factor(http: AsyncClient, wired: FastAPI) -> None:
    single = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC),
        acr=AAL1,
        amr=(PWD,),
        person_uuid=ADMIN,
    )

    response = await http.post(
        "/admin/impersonate", json=_body(), cookies={SESSION_COOKIE: single.sid}
    )

    assert response.status_code == 403


# --- only fixture accounts --------------------------------------------------


async def test_a_real_account_cannot_be_impersonated(
    http: AsyncClient, admin: dict[str, str], identity: _Identity
) -> None:
    """The set is enumerated rather than inferred, because "a test account" is
    not a property anybody can read off a row."""
    identity.known[REAL_PERSON] = UUID(int=7)

    response = await http.post("/admin/impersonate", json=_body(subject=REAL_PERSON), cookies=admin)

    assert response.status_code == 403
    assert response.json()["error"] == "not_a_fixture_account"


async def test_refusing_a_real_account_is_audited(
    http: AsyncClient, admin: dict[str, str], audit: RecordingAuditLog
) -> None:
    """An administrator trying to assume a real identity is the event an
    investigation most wants to find."""
    await http.post("/admin/impersonate", json=_body(subject=REAL_PERSON), cookies=admin)

    recorded = audit.of_type(EventType.ADMIN_ACTION)[0]
    assert recorded.outcome is Outcome.DENIED
    assert recorded.detail["subject"] == REAL_PERSON


async def test_an_unknown_subject_is_refused(http: AsyncClient, admin: dict[str, str]) -> None:
    response = await http.post(
        "/admin/impersonate", json=_body(subject="nobody@campus.test"), cookies=admin
    )

    assert response.status_code == 403


async def test_a_fixture_the_registry_does_not_know_is_not_found(
    http: AsyncClient, admin: dict[str, str], identity: _Identity
) -> None:
    """Configured as a fixture but never provisioned. A different problem from
    not being a fixture, and the operator fixes it in a different place."""
    identity.known = {}

    assert (await http.post("/admin/impersonate", json=_body(), cookies=admin)).status_code == 404


# --- the reason -------------------------------------------------------------


@pytest.mark.parametrize("reason", [None, "", "   "])
async def test_impersonation_needs_a_reason(
    http: AsyncClient, admin: dict[str, str], reason: str | None
) -> None:
    body = _body()
    if reason is None:
        body.pop("reason")
    else:
        body["reason"] = reason

    response = await http.post("/admin/impersonate", json=body, cookies=admin)

    assert response.status_code == 400
    assert response.json()["error"] == "reason_required"


# --- what the session looks like --------------------------------------------


async def test_impersonating_mints_a_marked_session(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)

    assert response.status_code == 201
    session = await wired.state.sessions.load(response.cookies[SESSION_COOKIE])
    assert session.person_uuid == str(FIXTURE_UUID)
    assert session.impersonated_by == ADMIN


async def test_the_marker_survives_rotation(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """It is on the session rather than tracked separately, so there is no way to
    hold an impersonated session that does not know it is one."""
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)
    sid = response.cookies[SESSION_COOKIE]

    rotated = await wired.state.sessions.rotate(sid)

    assert rotated is not None
    assert rotated.impersonated_by == ADMIN


async def test_the_session_is_not_authenticated_by_any_idp(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """Nothing authenticated. Recording the campus IdP would put a lie in the one
    field an investigator uses to ask where a session came from."""
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)

    session = await wired.state.sessions.load(response.cookies[SESSION_COOKIE])
    assert session.idp_entity_id == IMPERSONATION_ISSUER


async def test_an_impersonated_session_cannot_reach_the_console(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """Single-factor by construction, or an administrator could impersonate
    their way into administering as somebody else."""
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)
    impersonated = {SESSION_COOKIE: response.cookies[SESSION_COOKIE]}

    assert (await http.get("/admin/entities", cookies=impersonated)).status_code == 403


async def test_the_administrators_own_session_is_replaced(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """Holding both at once is how somebody performs an administrative action
    believing they are the fixture user, or the reverse."""
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)

    assert response.cookies[SESSION_COOKIE] != admin[SESSION_COOKIE]


async def test_the_response_says_what_is_happening(
    http: AsyncClient, admin: dict[str, str]
) -> None:
    """Loudly labelled, so a console cannot render an impersonated session as an
    ordinary one by omission."""
    body = (await http.post("/admin/impersonate", json=_body(), cookies=admin)).json()

    assert body["impersonation"] is True
    assert body["impersonated_by"] == ADMIN
    assert "acting as another user" in body["warning"]


# --- the downstream marker --------------------------------------------------


async def test_loading_an_impersonated_session_sets_the_marker(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str]
) -> None:
    """Set where the session is loaded, so no route has to remember — which is
    what makes "every downstream event" true rather than aspirational."""
    response = await http.post("/admin/impersonate", json=_body(), cookies=admin)

    await wired.state.sessions.load(response.cookies[SESSION_COOKIE])

    assert impersonator() == ADMIN


async def test_loading_an_ordinary_session_clears_it(wired: FastAPI, admin: dict[str, str]) -> None:
    """Set to None rather than left alone, so the marker cannot survive into the
    next request on a reused worker and attach an administrator's name to a
    stranger's login."""
    set_impersonator(ADMIN)

    await wired.state.sessions.load(admin[SESSION_COOKIE])

    assert impersonator() is None


async def test_every_event_from_an_impersonated_session_is_marked(
    wired: FastAPI, audit: RecordingAuditLog
) -> None:
    """The requirement's own wording. Merged where the event is written rather
    than at each call site, because a rule applied at forty call sites is a rule
    somebody forgets at the forty-first."""
    set_impersonator(ADMIN)

    recorded = await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject="somebody")

    assert recorded.detail["impersonation"] is True
    assert recorded.detail["impersonated_by"] == ADMIN


async def test_an_ordinary_event_carries_no_marker(audit: RecordingAuditLog) -> None:
    recorded = await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, subject="somebody")

    assert "impersonation" not in recorded.detail
