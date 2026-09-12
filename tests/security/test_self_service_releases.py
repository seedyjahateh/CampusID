"""A person's own release history (FR-ARP-07, FERPA §99.10).

The right of inspection, made usable. A right that requires filing a request with
somebody who has a console is a right in name, so this shows a student the same
record the console shows an administrator — filtered to them, and to them only.

The test that matters most is the one asserting there is no way to ask about
somebody else. This route is reachable by everybody who can log in, which makes
it a different kind of surface from the administrative views next door.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType
from campusid.audit.models import AuditEventRecord
from campusid.audit.query import Page, Query
from campusid.routes.me import LIMIT, WINDOW
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
OTHER = "c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b"
PORTAL = "https://portal.campus.test/sp"
LIBRARY = "https://library.campus.test/sp"

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


@dataclass
class _Release:
    occurred_at: datetime
    target: str
    detail: dict[str, Any] = field(default_factory=dict)


class _Audit:
    def __init__(self) -> None:
        self.asked: list[Query] = []
        self.events: list[_Release] = []

    async def search(self, query: Query) -> Page:
        self.asked.append(query)
        # Newest first, as the real store returns.
        ordered = sorted(self.events, key=lambda e: e.occurred_at, reverse=True)
        return Page(events=cast("list[AuditEventRecord]", ordered), next_cursor=None)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def audit_query() -> _Audit:
    return _Audit()


@pytest.fixture
def wired(app: FastAPI, redis: aioredis.FakeRedis, audit_query: _Audit) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.audit_query = audit_query
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


async def _session(wired: FastAPI, *, person: str | None = PERSON) -> dict[str, str]:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="sam.obrien@campus.test",
        auth_time=datetime.now(UTC),
        person_uuid=person,
    )
    return {SESSION_COOKIE: established.sid}


# --- who is asking ----------------------------------------------------------


async def test_an_anonymous_caller_sees_nothing(http: AsyncClient) -> None:
    response = await http.get("/me/releases")

    assert response.status_code == 401
    assert response.json() == {"authenticated": False}


async def test_the_subject_comes_from_the_session(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """There is no parameter to name a person, so reading somebody else's history
    is unexpressible rather than refused. That matters more here than on an
    administrative route, because this one is reachable by everybody."""
    await http.get("/me/releases", cookies=await _session(wired))

    assert audit_query.asked[0].subject == PERSON


async def test_naming_another_person_changes_nothing(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """The parameter is not there, so supplying one is not an attack the route
    has to refuse — it is a query string nothing reads."""
    await http.get(
        "/me/releases",
        params={"subject": OTHER, "person_uuid": OTHER},
        cookies=await _session(wired),
    )

    assert audit_query.asked[0].subject == PERSON


async def test_an_unresolved_session_has_nothing_to_show(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """The trail is keyed on the person. A session the registry has not matched
    has nothing to show rather than nothing to find, and asking anyway would be
    a query with no subject at all."""
    response = await http.get("/me/releases", cookies=await _session(wired, person=None))

    assert response.status_code == 200
    assert response.json()["applications"] == []
    assert audit_query.asked == []


# --- what is shown ----------------------------------------------------------


async def test_only_releases_are_shown(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """A login is not a disclosure. Showing every event would answer "who has my
    data" with a list of things that happened to the person instead."""
    await http.get("/me/releases", cookies=await _session(wired))

    assert audit_query.asked[0].event_type == EventType.ATTRIBUTE_RELEASE.value


async def test_the_window_is_ninety_days(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    await http.get("/me/releases", cookies=await _session(wired))

    asked = audit_query.asked[0]
    assert asked.since is not None
    assert timedelta(days=90) == WINDOW
    elapsed = (datetime.now(UTC) - asked.since).total_seconds()
    assert elapsed == pytest.approx(WINDOW.total_seconds(), abs=5)


async def test_the_window_is_stated_in_the_response(http: AsyncClient, wired: FastAPI) -> None:
    """So a bounded view is not mistaken for the whole history."""
    body = (await http.get("/me/releases", cookies=await _session(wired))).json()

    assert body["window_days"] == 90
    assert "since" in body


async def test_the_page_is_bounded(http: AsyncClient, wired: FastAPI, audit_query: _Audit) -> None:
    await http.get("/me/releases", cookies=await _session(wired))

    assert audit_query.asked[0].limit == LIMIT


async def test_the_history_is_not_cacheable(http: AsyncClient, wired: FastAPI) -> None:
    """It is somebody's own record of who holds their data."""
    response = await http.get("/me/releases", cookies=await _session(wired))

    assert response.headers["cache-control"] == "no-store"


# --- how it is grouped ------------------------------------------------------


async def test_releases_are_grouped_by_application(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """The question this page answers is "who has my data", not "what happened at
    14:07 on Tuesday"."""
    audit_query.events = [
        _Release(NOW, PORTAL, {"attributes": ["mail"]}),
        _Release(NOW - timedelta(days=1), PORTAL, {"attributes": ["displayName"]}),
        _Release(NOW - timedelta(days=2), LIBRARY, {"attributes": ["eduPersonScopedAffiliation"]}),
    ]

    body = (await http.get("/me/releases", cookies=await _session(wired))).json()

    assert {entry["target"] for entry in body["applications"]} == {PORTAL, LIBRARY}


async def test_an_application_shows_everything_it_has_ever_seen(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """The union across the window, because a service that received an email
    address once has it, whether or not the most recent sign-in included it."""
    audit_query.events = [
        _Release(NOW, PORTAL, {"attributes": ["mail"]}),
        _Release(NOW - timedelta(days=1), PORTAL, {"attributes": ["displayName", "mail"]}),
    ]

    body = (await http.get("/me/releases", cookies=await _session(wired))).json()

    entry = body["applications"][0]
    assert entry["attributes"] == ["displayName", "mail"]
    assert entry["releases"] == 2


async def test_an_application_reports_when_it_first_and_last_saw_anything(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """ "Since when" is the second question anybody asks after "who"."""
    audit_query.events = [
        _Release(NOW, PORTAL, {"attributes": ["mail"]}),
        _Release(NOW - timedelta(days=30), PORTAL, {"attributes": ["mail"]}),
    ]

    entry = (await http.get("/me/releases", cookies=await _session(wired))).json()["applications"][
        0
    ]

    assert entry["last_seen"].startswith("2026-09-11")
    assert entry["first_seen"].startswith("2026-08-12")


async def test_the_attributes_are_ordered(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """So two loads of the same page list them the same way."""
    audit_query.events = [_Release(NOW, PORTAL, {"attributes": ["mail", "displayName", "eppn"]})]

    entry = (await http.get("/me/releases", cookies=await _session(wired))).json()["applications"][
        0
    ]

    assert entry["attributes"] == sorted(entry["attributes"])


async def test_a_release_with_no_attributes_recorded_is_still_shown(
    http: AsyncClient, wired: FastAPI, audit_query: _Audit
) -> None:
    """A disclosure whose detail is missing is still a disclosure, and dropping
    it would understate what an application received."""
    audit_query.events = [_Release(NOW, PORTAL)]

    body = (await http.get("/me/releases", cookies=await _session(wired))).json()

    assert body["applications"][0]["releases"] == 1
    assert body["applications"][0]["attributes"] == []


async def test_nobody_with_no_history_sees_an_empty_list(http: AsyncClient, wired: FastAPI) -> None:
    """Rather than an error. Somebody who has signed into nothing has a correct
    and empty answer."""
    body = (await http.get("/me/releases", cookies=await _session(wired))).json()

    assert body["applications"] == []
