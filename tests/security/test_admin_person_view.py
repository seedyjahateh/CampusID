"""The person detail view and session management (FR-ADM-04, FR-ADM-06).

The stores are substituted, because what is being tested is not whether each of
them answers correctly — they have their own tests — but what the view does with
their answers. Two things matter more than the assembly.

Nothing on the page is a credential. A seed, a recovery code and a session
identifier are all things the broker holds about a person, and none of them
belong somewhere an administrator can screenshot.

Reading and changing are different privileges. An auditor can see why an
application received somebody's name; ending that person's session is an
administrator's act.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, cast

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.admin.people import SESSION_HANDLE, PersonDirectory
from campusid.audit.events import EventType
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
ADMIN = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
PERSON = "c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b"
PORTAL = "https://portal.campus.test/sp"
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@dataclass
class _Person:
    status: str = "active"
    edu_person_unique_id: str = "abc123@campus.test"


@dataclass
class _Identifier:
    id_type: str
    value: str
    released_at: datetime | None = None


@dataclass
class _Account:
    idp_entity_id: str = "https://idp.campus.test/saml"
    last_seen_at: datetime | None = None


@dataclass
class _Factor:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    kind: str = "totp"
    label: str = "my phone"
    confirmed_at: datetime | None = None
    disabled_at: datetime | None = None
    last_used_at: datetime | None = None
    # Deliberately present, so a view that leaked it would be caught rather than
    # passing because the stand-in never held one.
    secret: str = SECRET


@dataclass
class _Event:
    occurred_at: datetime
    target: str | None
    correlation_id: str
    detail: dict[str, Any] = field(default_factory=dict)


class _Identity:
    def __init__(self) -> None:
        self.person: _Person | None = _Person()
        self.rows = [
            _Identifier("eppn", "sam.obrien@campus.test"),
            _Identifier("eppn", "s.obrien@campus.test", released_at=datetime.now(UTC)),
        ]
        self.affiliations = ["student", "member"]

    async def get(self, person_uuid: str) -> _Person | None:
        return self.person

    async def identifiers(self, person_uuid: str, *, include_released: bool = False) -> list[Any]:
        return list(self.rows)

    async def affiliations_on(self, person_uuid: str, when: date) -> list[str]:
        return list(self.affiliations)

    async def accounts(self, person_uuid: str) -> list[_Account]:
        return [_Account()]


class _Lifecycle:
    def __init__(self) -> None:
        self.entitlements = {"urn:b", "urn:a"}

    async def held(self, person_uuid: uuid.UUID, *, on: date | None = None) -> set[str]:
        return set(self.entitlements)


class _Roles:
    async def roles_for(self, person_uuid: str, *, on: date | None = None) -> set[str]:
        return {"student"}


class _Factors:
    def __init__(self) -> None:
        self.rows = [_Factor(confirmed_at=datetime.now(UTC))]

    async def factors_for(self, person_uuid: str) -> list[_Factor]:
        return list(self.rows)


class _Groups:
    async def groups_for(self, person_uuid: str) -> list[tuple[str, str]]:
        return [("g-1", "Chemistry 101")]


class _Audit:
    def __init__(self) -> None:
        self.asked: list[Query] = []

    async def search(self, query: Query) -> Page:
        self.asked.append(query)
        return Page(
            events=cast(
                "list[AuditEventRecord]",
                [
                    _Event(
                        occurred_at=datetime(2026, 9, 3, tzinfo=UTC),
                        target=PORTAL,
                        correlation_id="chain-1",
                        detail={"attributes": ["mail", "displayName"]},
                    )
                ],
            ),
            next_cursor=None,
        )


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def identity() -> _Identity:
    return _Identity()


@pytest.fixture
def factors() -> _Factors:
    return _Factors()


@pytest.fixture
def audit_query() -> _Audit:
    return _Audit()


class _Assignments:
    def __init__(self) -> None:
        self.roles = {ADMIN_ROLE}

    async def roles_for(self, person_uuid: str, *, on: date | None = None) -> set[str]:
        return set(self.roles)


@pytest.fixture
def assignments() -> _Assignments:
    return _Assignments()


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    identity: _Identity,
    factors: _Factors,
    audit_query: _Audit,
    assignments: _Assignments,
) -> FastAPI:
    sessions = SessionStore(redis)
    app.state.redis = redis
    app.state.sessions = sessions
    app.state.role_assignments = assignments
    app.state.audit = RecordingAuditLog()
    app.state.registry = None
    app.state.people = PersonDirectory(
        identity=identity,
        lifecycle=_Lifecycle(),
        roles=_Roles(),
        factors=factors,
        sessions=sessions,
        audit=audit_query,
        groups=_Groups(),
    )
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


async def _admin_cookie(
    wired: FastAPI, *, amr: tuple[str, ...] = (PWD, OTP, MFA)
) -> dict[str, str]:
    session: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=1),
        acr=AAL2 if MFA in amr else AAL1,
        amr=amr,
        person_uuid=ADMIN,
    )
    return {SESSION_COOKIE: session.sid}


async def _their_session(wired: FastAPI, *, impersonated_by: str | None = None) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="sam.obrien@campus.test",
        auth_time=datetime.now(UTC),
        person_uuid=PERSON,
        impersonated_by=impersonated_by,
    )
    return established


# --- who may look -----------------------------------------------------------


async def test_looking_needs_a_session(http: AsyncClient) -> None:
    assert (await http.get(f"/admin/people/{PERSON}")).status_code == 401


async def test_an_auditor_may_look(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """Answering "why does this application see my name" is reading, and it
    should not require the rights to change the answer."""
    assignments.roles = {AUDITOR_ROLE}

    assert (
        await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))
    ).status_code == 200


async def test_looking_needs_a_second_factor(http: AsyncClient, wired: FastAPI) -> None:
    cookie = await _admin_cookie(wired, amr=(PWD,))

    assert (await http.get(f"/admin/people/{PERSON}", cookies=cookie)).status_code == 403


async def test_an_unknown_person_is_not_found(
    http: AsyncClient, wired: FastAPI, identity: _Identity
) -> None:
    identity.person = None

    assert (
        await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))
    ).status_code == 404


async def test_a_malformed_id_is_not_found(http: AsyncClient, wired: FastAPI) -> None:
    """Checked before the store, so a malformed id is a 404 rather than a
    database error — and the two are indistinguishable to somebody guessing."""
    assert (
        await http.get("/admin/people/not-a-uuid", cookies=await _admin_cookie(wired))
    ).status_code == 404


# --- what the view shows ----------------------------------------------------


async def test_the_view_gathers_every_section(http: AsyncClient, wired: FastAPI) -> None:
    body = (await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))).json()

    assert body["status"] == "active"
    assert body["affiliations"] == ["student", "member"]
    assert body["entitlements"] == ["urn:a", "urn:b"]
    assert body["roles"] == ["student"]
    assert body["groups"] == [{"id": "g-1", "display_name": "Chemistry 101"}]


async def test_released_identifiers_are_shown(http: AsyncClient, wired: FastAPI) -> None:
    """ "Why can this person not log in with the name they have always used" is
    answered by seeing that the name was released. A view listing only live
    identifiers would answer it with silence."""
    body = (await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))).json()

    released = [row for row in body["identifiers"] if row["released_at"]]
    assert [row["value"] for row in released] == ["s.obrien@campus.test"]


async def test_the_releases_come_from_the_audit_trail(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """Rather than from a second table. The trail is the record of disclosures
    FERPA asks for, and a second copy would be a second answer."""
    body = (await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))).json()

    assert audit_query.asked[0].subject == PERSON
    assert audit_query.asked[0].event_type == EventType.ATTRIBUTE_RELEASE.value
    assert body["releases"][0]["target"] == PORTAL
    assert body["releases"][0]["attributes"] == ["displayName", "mail"]


async def test_a_deployment_without_groups_shows_none(
    app: FastAPI, redis: aioredis.FakeRedis, identity: _Identity, audit_query: _Audit
) -> None:
    """A missing collaborator is an empty section rather than an error, or the
    console is unusable for the deployments that need it least."""
    directory = PersonDirectory(
        identity=identity,
        lifecycle=_Lifecycle(),
        roles=_Roles(),
        factors=_Factors(),
        sessions=SessionStore(redis),
        audit=audit_query,
    )

    view = await directory.view(PERSON)

    assert view is not None
    assert view.groups == ()


# --- nothing on the page is a credential ------------------------------------


async def test_a_factor_is_listed_without_its_material(http: AsyncClient, wired: FastAPI) -> None:
    """A seed on an administrator's screen is a seed in a screenshot."""
    response = await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))

    assert SECRET not in response.text
    assert response.json()["factors"][0]["label"] == "my phone"


async def test_a_session_is_named_by_a_handle_not_its_identifier(
    http: AsyncClient, wired: FastAPI
) -> None:
    session = await _their_session(wired)

    response = await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))

    assert session.sid not in response.text
    assert response.json()["sessions"][0]["handle"] == session.sid[:SESSION_HANDLE]


async def test_an_impersonated_session_says_so(http: AsyncClient, wired: FastAPI) -> None:
    """An administrator looking at somebody's sessions should see immediately
    that one of them is another person acting as them."""
    await _their_session(wired, impersonated_by=ADMIN)

    body = (await http.get(f"/admin/people/{PERSON}", cookies=await _admin_cookie(wired))).json()

    assert body["sessions"][0]["impersonated_by"] == ADMIN


# --- ending sessions --------------------------------------------------------


async def test_an_auditor_may_not_end_a_session(
    http: AsyncClient, wired: FastAPI, assignments: _Assignments
) -> None:
    """Ending somebody's session is a change, and an auditor reads."""
    assignments.roles = {AUDITOR_ROLE}
    await _their_session(wired)

    response = await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"reason": "reported stolen"},
        cookies=await _admin_cookie(wired),
    )

    assert response.status_code == 404


async def test_ending_a_session_needs_a_reason(http: AsyncClient, wired: FastAPI) -> None:
    await _their_session(wired)

    response = await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={},
        cookies=await _admin_cookie(wired),
    )

    assert response.status_code == 400


async def test_one_session_can_be_ended_by_its_handle(http: AsyncClient, wired: FastAPI) -> None:
    kept = await _their_session(wired)
    doomed = await _their_session(wired)

    response = await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"handle": doomed.sid[:SESSION_HANDLE], "reason": "reported stolen"},
        cookies=await _admin_cookie(wired),
    )

    assert response.json()["terminated"] == [doomed.sid[:SESSION_HANDLE]]
    assert await wired.state.sessions.load(doomed.sid) is None
    assert await wired.state.sessions.load(kept.sid) is not None


async def test_every_session_can_be_ended_at_once(http: AsyncClient, wired: FastAPI) -> None:
    """FR-SES-05's administrative half: a compromised account is not one
    browser."""
    first = await _their_session(wired)
    second = await _their_session(wired)

    response = await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"reason": "account compromised"},
        cookies=await _admin_cookie(wired),
    )

    assert len(response.json()["terminated"]) == 2
    assert await wired.state.sessions.load(first.sid) is None
    assert await wired.state.sessions.load(second.sid) is None


async def test_ending_sessions_is_audited_with_the_reason(
    http: AsyncClient, wired: FastAPI
) -> None:
    await _their_session(wired)

    await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"reason": "reported stolen"},
        cookies=await _admin_cookie(wired),
    )

    recorded = wired.state.audit.of_type(EventType.SESSION_TERMINATED)[0]
    assert recorded.actor == ADMIN
    assert recorded.subject == PERSON
    assert recorded.reason == "reported stolen"


async def test_the_audit_record_carries_handles_not_identifiers(
    http: AsyncClient, wired: FastAPI
) -> None:
    """An audit record is read by more people than a session identifier should
    be."""
    session = await _their_session(wired)

    await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"reason": "reported stolen"},
        cookies=await _admin_cookie(wired),
    )

    recorded = wired.state.audit.of_type(EventType.SESSION_TERMINATED)[0]
    assert session.sid not in str(recorded.detail)


async def test_ending_a_handle_that_matches_nothing_ends_nothing(
    http: AsyncClient, wired: FastAPI
) -> None:
    kept = await _their_session(wired)

    response = await http.post(
        f"/admin/people/{PERSON}/sessions/terminate",
        json={"handle": "zzzzzzzz", "reason": "tidying up"},
        cookies=await _admin_cookie(wired),
    )

    assert response.json()["terminated"] == []
    assert await wired.state.sessions.load(kept.sid) is not None
