"""Who may read the audit trail, and what the endpoints do with a URL
(FR-AUD-03, FR-ADM-01).

The query itself is tested against live Postgres next door. These are about the
two things the HTTP layer owns: who is let in, and whether a malformed parameter
becomes a refusal or a stack trace.

The access rule is the interesting one. Reading what happened and being able to
change what happens are different privileges, so an auditor passes here and is
refused everywhere else — otherwise every audit request would carry the rights to
cause the thing being audited.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.models import AuditEventRecord
from campusid.audit.query import Page, Query
from campusid.authz.engine import AAL1, AAL2
from campusid.mfa.assurance import MFA, OTP, PWD
from campusid.routes.admin import ADMIN_ROLE, AUDITOR_ROLE
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
SUBJECT = "sam.obrien@campus.test"


@dataclass
class _Record:
    seq: int = 1
    event_id: str = "event-1"
    event_type: str = "auth.success"
    outcome: str = "success"
    occurred_at: datetime = field(default_factory=lambda: datetime(2026, 9, 3, tzinfo=UTC))
    correlation_id: str = "chain-1"
    actor: str | None = None
    subject: str | None = SUBJECT
    target: str | None = None
    reason: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    hash: str = "a" * 64


def _rows() -> list[AuditEventRecord]:
    """A stand-in row, cast rather than constructed.

    The real model needs a database session to be useful and these tests have
    none; what the routes actually touch is the attribute surface, which the
    dataclass above reproduces exactly.
    """
    return cast("list[AuditEventRecord]", [_Record()])


class _Queries:
    def __init__(self) -> None:
        self.asked: list[Query] = []
        self.timelines: list[tuple[str, int]] = []
        self.page = Page(events=_rows(), next_cursor=None)

    async def search(self, query: Query) -> Page:
        self.asked.append(query)
        return self.page

    async def timeline(self, subject: str, *, limit: int = 50) -> list[Any]:
        self.timelines.append((subject, limit))
        return list(self.page.events)


class _Assignments:
    def __init__(self) -> None:
        self.roles = {ADMIN_ROLE}

    async def roles_for(self, person_uuid: str) -> set[str]:
        return set(self.roles)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def queries() -> _Queries:
    return _Queries()


@pytest.fixture
def assignments() -> _Assignments:
    return _Assignments()


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    queries: _Queries,
    assignments: _Assignments,
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.role_assignments = assignments
    app.state.audit_query = queries
    app.state.audit = RecordingAuditLog()
    app.state.registry = None
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


async def _session(wired: FastAPI, *, amr: tuple[str, ...] = (PWD, OTP, MFA)) -> dict[str, str]:
    session: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=1),
        acr=AAL2 if MFA in amr else AAL1,
        amr=amr,
        person_uuid=PERSON,
    )
    return {SESSION_COOKIE: session.sid}


# --- who may read -----------------------------------------------------------


async def test_reading_needs_a_session(http: AsyncClient) -> None:
    assert (await http.get("/admin/audit")).status_code == 401


async def test_an_auditor_may_read(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """Reading what happened and being able to change what happens are different
    privileges. Requiring the administrator role to read would put the rights to
    cause an incident in the hands of everybody investigating one."""
    assignments.roles = {AUDITOR_ROLE}

    assert (await http.get("/admin/audit", cookies=await _session(wired))).status_code == 200


async def test_an_auditor_may_not_change_the_federation(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """The other half of that separation, and the half that makes it worth
    having."""
    assignments.roles = {AUDITOR_ROLE}

    response = await http.post(
        "/admin/entities",
        json={"metadata": "<x/>", "reason": "trying it on"},
        cookies=await _session(wired),
    )

    assert response.status_code == 404


async def test_somebody_with_neither_role_sees_nothing(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    assignments.roles = {"student"}

    assert (await http.get("/admin/audit", cookies=await _session(wired))).status_code == 404


async def test_reading_needs_a_second_factor(http: AsyncClient, wired: FastAPI) -> None:
    """The trail names everybody who has ever logged in. A single-factor session
    is not enough to read it."""
    response = await http.get("/admin/audit", cookies=await _session(wired, amr=(PWD,)))

    assert response.status_code == 403


async def test_the_timeline_is_guarded_the_same_way(http: AsyncClient) -> None:
    assert (await http.get(f"/admin/audit/subject/{SUBJECT}")).status_code == 401


# --- the query string -------------------------------------------------------


async def test_filters_reach_the_store(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    await http.get(
        "/admin/audit",
        params={
            "subject": SUBJECT,
            "target": "https://portal.campus.test/sp",
            "event_type": "auth.success",
            "outcome": "success",
            "correlation_id": "chain-1",
        },
        cookies=await _session(wired),
    )

    asked = queries.asked[0]
    assert asked.subject == SUBJECT
    assert asked.event_type == "auth.success"
    assert asked.correlation_id == "chain-1"


async def test_an_empty_parameter_is_not_a_filter(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    """A form that submits every field posts blanks for the ones nobody filled
    in, and a blank filter that matched the empty string would return nothing at
    all with no hint why."""
    await http.get("/admin/audit", params={"subject": ""}, cookies=await _session(wired))

    assert queries.asked[0].subject is None


async def test_a_time_range_is_parsed(http: AsyncClient, wired: FastAPI, queries: _Queries) -> None:
    await http.get(
        "/admin/audit",
        params={"since": "2026-09-03T00:00:00+00:00", "until": "2026-09-04"},
        cookies=await _session(wired),
    )

    asked = queries.asked[0]
    assert asked.since == datetime(2026, 9, 3, tzinfo=UTC)
    assert asked.until == datetime(2026, 9, 4, tzinfo=UTC)


async def test_a_date_without_an_offset_is_read_as_utc(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    """An operator typing a date into a URL means the day, not the day in
    whatever timezone the server happens to run in. A naive value compared
    against `timestamptz` is also an error Postgres raises rather than an answer
    anybody wanted."""
    await http.get("/admin/audit", params={"since": "2026-09-03"}, cookies=await _session(wired))

    assert queries.asked[0].since is not None
    assert queries.asked[0].since.tzinfo is not None


@pytest.mark.parametrize(
    "params",
    [
        {"since": "yesterday"},
        {"until": "2026-13-45"},
        {"limit": "lots"},
        {"cursor": "somewhere"},
    ],
)
async def test_a_malformed_parameter_is_a_bad_request(
    http: AsyncClient, wired: FastAPI, queries: _Queries, params: dict[str, str]
) -> None:
    """Rather than a 500 that says the broker is broken when the caller's URL is."""
    response = await http.get("/admin/audit", params=params, cookies=await _session(wired))

    assert response.status_code == 400
    assert queries.asked == []


async def test_the_cursor_is_passed_through(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    await http.get("/admin/audit", params={"cursor": "42"}, cookies=await _session(wired))

    assert queries.asked[0].before_seq == 42


# --- the response -----------------------------------------------------------


async def test_a_page_carries_its_events_and_a_cursor(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    queries.page = Page(events=_rows(), next_cursor=7)

    body = (await http.get("/admin/audit", cookies=await _session(wired))).json()

    assert body["events"][0]["event_id"] == "event-1"
    assert body["next_cursor"] == 7


async def test_the_last_page_says_so_explicitly(http: AsyncClient, wired: FastAPI) -> None:
    """Null rather than absent, so a caller looping until the key disappears and
    one looping until it is null both terminate."""
    body = (await http.get("/admin/audit", cookies=await _session(wired))).json()

    assert "next_cursor" in body
    assert body["next_cursor"] is None


async def test_events_carry_their_chain_columns(http: AsyncClient, wired: FastAPI) -> None:
    """An auditor should be able to verify the links themselves rather than take
    the console's word for it."""
    body = (await http.get("/admin/audit", cookies=await _session(wired))).json()

    assert len(body["events"][0]["hash"]) == 64


async def test_the_trail_is_not_cacheable(http: AsyncClient, wired: FastAPI) -> None:
    response = await http.get("/admin/audit", cookies=await _session(wired))

    assert response.headers["cache-control"] == "no-store"


async def test_a_timeline_names_its_subject(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    body = (await http.get(f"/admin/audit/subject/{SUBJECT}", cookies=await _session(wired))).json()

    assert body["subject"] == SUBJECT
    assert queries.timelines[0][0] == SUBJECT


async def test_a_timeline_honours_its_limit(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    await http.get(
        f"/admin/audit/subject/{SUBJECT}", params={"limit": "5"}, cookies=await _session(wired)
    )

    assert queries.timelines[0][1] == 5


async def test_a_malformed_timeline_limit_is_a_bad_request(
    http: AsyncClient, wired: FastAPI, queries: _Queries
) -> None:
    response = await http.get(
        f"/admin/audit/subject/{SUBJECT}", params={"limit": "all"}, cookies=await _session(wired)
    )

    assert response.status_code == 400
    assert queries.timelines == []
