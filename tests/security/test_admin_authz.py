"""Who may reach the administrative API (FR-ADM-01).

The console is protected by the broker it administers: no separate password, no
bypass, no token in the environment. That is not tidiness — an escape hatch on
the administrative surface is the one credential nobody rotates, and a broker
whose own console sits outside its authorization model cannot honestly claim the
model is enforced anywhere.

Three conditions, and what the caller is told differs by which one failed. The
difference is deliberate and is most of what these tests are about.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.authz.engine import AAL1, AAL2
from campusid.mfa.assurance import HWK, MFA, OTP, PWD
from campusid.routes.admin import ADMIN_ROLE
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"

ENDPOINTS = [
    ("GET", "/admin/entities", None),
    ("GET", "/admin/entities/https://idp.test/saml", None),
    ("POST", "/admin/entities", {"reason": "a reason", "metadata": "<x/>"}),
    (
        "POST",
        "/admin/entities/https://idp.test/saml/enabled",
        {"reason": "a reason", "enabled": False},
    ),
]


class _Assignments:
    def __init__(self, roles: set[str]) -> None:
        self.roles = roles

    async def roles_for(self, person_uuid: str) -> set[str]:
        return set(self.roles)


class _Registry:
    """The federation registry, reduced to what the console calls."""

    def __init__(self) -> None:
        self.entities: list[Any] = []
        self.registered: list[dict[str, Any]] = []
        self.enabled: list[tuple[str, bool]] = []

    async def list_idps(self) -> list[Any]:
        return list(self.entities)

    async def describe(self, entity_id: str) -> Any:
        return None

    async def register_idp(self, document: bytes, **kwargs: Any) -> Any:
        self.registered.append({"document": document, **kwargs})
        raise AssertionError("not reached in these tests")  # pragma: no cover

    async def set_enabled(self, entity_id: str, enabled: bool) -> None:
        self.enabled.append((entity_id, enabled))


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def assignments() -> _Assignments:
    return _Assignments({ADMIN_ROLE})


@pytest.fixture
def registry() -> _Registry:
    return _Registry()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    assignments: _Assignments,
    registry: _Registry,
    audit: RecordingAuditLog,
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.role_assignments = assignments
    app.state.registry = registry
    app.state.audit = audit
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


async def _session(
    wired: FastAPI,
    *,
    person: str | None = PERSON,
    amr: tuple[str, ...] = (PWD, OTP, MFA),
) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=1),
        acr=AAL2 if MFA in amr else AAL1,
        amr=amr,
        person_uuid=person,
    )
    return established


def _cookie(session: Session) -> dict[str, str]:
    return {SESSION_COOKIE: session.sid}


async def _call(
    http: AsyncClient, method: str, path: str, body: dict[str, Any] | None, **kwargs: Any
) -> Any:
    if method == "GET":
        return await http.get(path, **kwargs)
    return await http.post(path, json=body or {}, **kwargs)


# --- no session -------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
async def test_an_anonymous_request_is_unauthenticated(
    http: AsyncClient, method: str, path: str, body: dict[str, Any] | None
) -> None:
    """Every endpoint, not a sample. A guard applied to most of a surface is a
    guard nobody can rely on."""
    assert (await _call(http, method, path, body)).status_code == 401


async def test_an_unknown_cookie_is_not_a_session(http: AsyncClient) -> None:
    response = await http.get("/admin/entities", cookies={SESSION_COOKIE: "not-a-session"})

    assert response.status_code == 401


async def test_an_unresolved_session_is_unauthenticated(http: AsyncClient, wired: FastAPI) -> None:
    """Roles hang off `person_uuid`. A session the registry has not matched
    holds no roles, so it cannot hold this one."""
    session = await _session(wired, person=None)

    assert (await http.get("/admin/entities", cookies=_cookie(session))).status_code == 401


# --- no role ----------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
async def test_somebody_without_the_role_sees_no_console(
    http: AsyncClient,
    wired: FastAPI,
    assignments: _Assignments,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    """404, not 403. A 403 confirms the console exists and that this account is
    merely not on the list, which is a useful thing for somebody choosing whom
    to phish."""
    session = await _session(wired)
    assignments.roles = {"student"}

    response = await _call(http, method, path, body, cookies=_cookie(session))

    assert response.status_code == 404


async def test_a_related_role_is_not_the_role(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """An auditor reads the trail and changes nothing. Being close to the role
    is not holding it."""
    session = await _session(wired)
    assignments.roles = {"auditor"}

    assert (await http.get("/admin/entities", cookies=_cookie(session))).status_code == 404


# --- no second factor -------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
async def test_a_single_factor_administrator_is_challenged(
    http: AsyncClient, wired: FastAPI, method: str, path: str, body: dict[str, Any] | None
) -> None:
    """The one case that gets a specific answer, because it is the one whose
    problem the caller can solve."""
    session = await _session(wired, amr=(PWD,))

    response = await _call(http, method, path, body, cookies=_cookie(session))

    assert response.status_code == 403
    assert response.json() == {"error": "step_up_required"}


async def test_the_level_is_checked_against_the_methods(http: AsyncClient, wired: FastAPI) -> None:
    """An `acr` that agrees with itself proves nothing. A session carrying the
    `mfa` marker with one factor behind it is a bug upstream, and this route
    must not be where it becomes administrative access."""
    session = await _session(wired, amr=(PWD, MFA))

    assert (await http.get("/admin/entities", cookies=_cookie(session))).status_code == 403


async def test_a_passkey_session_is_admitted(http: AsyncClient, wired: FastAPI) -> None:
    """Any two distinct categories, not one blessed factor."""
    session = await _session(wired, amr=(PWD, HWK, MFA))

    assert (await http.get("/admin/entities", cookies=_cookie(session))).status_code == 200


# --- the order the checks run in --------------------------------------------


async def test_somebody_without_the_role_is_not_told_to_step_up(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """Otherwise the refusal is an oracle in the other direction: complete a
    step-up and watch the answer change from 403 to 404."""
    session = await _session(wired, amr=(PWD,))
    assignments.roles = {"student"}

    response = await http.get("/admin/entities", cookies=_cookie(session))

    assert response.status_code == 404


async def test_an_administrator_with_both_gets_in(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)

    assert (await http.get("/admin/entities", cookies=_cookie(session))).status_code == 200


async def test_nothing_administrative_is_cacheable(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)

    response = await http.get("/admin/entities", cookies=_cookie(session))

    assert response.headers["cache-control"] == "no-store"
