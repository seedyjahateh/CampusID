"""The push factor, approve, deny and timeout (FR-MFA-03).

The service on the other end is a simulator, and both its approval page and the
README say so. What these tests cover is the broker's half, which is real: a
request bound to the person who raised it, an approval that elevates once, a
denial and a timeout that do not, and a service outage that is neither.

The binding is the test worth reading. A request id comes back from the service
and then goes to a browser, so anything accepting a decision on the strength of
the id alone would let one person's approval elevate another person's session.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType
from campusid.authz.engine import AAL1, AAL2
from campusid.mfa import push
from campusid.mfa.assurance import PUSH, PWD
from campusid.mfa.challenges import ChallengeStore
from campusid.mfa.push import PushClient, PushUnavailable
from campusid.mfa.ratelimit import AttemptLimiter
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
SERVICE = "http://push-sim:8100"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
OTHER = "c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b"


class _Service:
    """The simulator, reduced to the two calls the client makes.

    A transport rather than a stub client, so the request the broker actually
    builds is the one being answered — a stub would let a wrong URL or a missing
    field pass unnoticed.
    """

    def __init__(self) -> None:
        self.requests: dict[str, str] = {}
        self.sent: list[dict[str, Any]] = []
        self.fail = False
        self._next = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            raise httpx.ConnectError("push service is gone")

        if request.method == "POST" and request.url.path == "/push":
            import json

            self.sent.append(json.loads(request.content))
            self._next += 1
            request_id = f"request-{self._next}"
            self.requests[request_id] = push.PENDING
            return httpx.Response(
                201, json={"id": request_id, "status": push.PENDING, "expires_in": 60}
            )

        if request.method == "GET" and request.url.path.startswith("/push/"):
            request_id = request.url.path.removeprefix("/push/")
            if request_id not in self.requests:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"id": request_id, "status": self.requests[request_id]})

        return httpx.Response(404)  # pragma: no cover - not a path the client uses


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def service() -> _Service:
    return _Service()


@pytest.fixture
def client(service: _Service, redis: aioredis.FakeRedis) -> PushClient:
    return PushClient(SERVICE, redis, client=httpx.AsyncClient(transport=service.transport()))


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def wired(
    app: FastAPI, redis: aioredis.FakeRedis, client: PushClient, audit: RecordingAuditLog
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.mfa_challenges = ChallengeStore(redis)
    app.state.mfa_limiter = AttemptLimiter(redis)
    app.state.push = client
    app.state.audit = audit
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as c:
        yield c


async def _session(wired: FastAPI, *, person: str | None = PERSON) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="sam.obrien@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=2),
        acr=AAL1,
        amr=(PWD,),
        person_uuid=person,
    )
    return established


def _cookie(session: Session) -> dict[str, str]:
    return {SESSION_COOKIE: session.sid}


# --- the client -------------------------------------------------------------


async def test_a_request_is_raised_for_the_person(client: PushClient, service: _Service) -> None:
    await client.send(PERSON)

    assert service.sent[0]["subject"] == PERSON


async def test_a_pending_request_is_pending(client: PushClient) -> None:
    request_id = await client.send(PERSON)

    assert await client.outcome(PERSON, request_id) == push.PENDING


@pytest.mark.parametrize("settled", [push.APPROVED, push.DENIED, push.EXPIRED])
async def test_a_settled_request_reports_what_happened(
    client: PushClient, service: _Service, settled: str
) -> None:
    request_id = await client.send(PERSON)
    service.requests[request_id] = settled

    assert await client.outcome(PERSON, request_id) == settled


async def test_somebody_elses_request_is_not_readable(
    client: PushClient, service: _Service
) -> None:
    """The binding. Without it, one person's approval elevates another person's
    session, which is the whole failure a push factor invites."""
    request_id = await client.send(PERSON)
    service.requests[request_id] = push.APPROVED

    assert await client.outcome(OTHER, request_id) == push.EXPIRED


async def test_an_unknown_request_looks_expired(client: PushClient) -> None:
    """The same answer as somebody else's, because distinguishing them would say
    whether the id was real."""
    assert await client.outcome(PERSON, "request-999") == push.EXPIRED


async def test_an_approval_can_only_be_spent_once(client: PushClient, service: _Service) -> None:
    """The binding is dropped when the request settles, so a second poll cannot
    elevate a second session on one approval."""
    request_id = await client.send(PERSON)
    service.requests[request_id] = push.APPROVED
    assert await client.outcome(PERSON, request_id) == push.APPROVED

    assert await client.outcome(PERSON, request_id) == push.EXPIRED


async def test_the_binding_expires_on_our_clock(
    service: _Service, redis: aioredis.FakeRedis
) -> None:
    """Two clocks agreeing is not something to depend on when one of them is a
    container somebody can restart."""
    client = PushClient(SERVICE, redis, client=httpx.AsyncClient(transport=service.transport()))
    request_id = await client.send(PERSON)

    ttl = await redis.ttl(f"mfa:push:{request_id}")

    assert 0 < ttl <= push.WINDOW.total_seconds()


async def test_a_service_outage_is_not_a_denial(client: PushClient, service: _Service) -> None:
    """Telling somebody their approval was refused when the service was down
    sends them to the service desk for the wrong problem."""
    request_id = await client.send(PERSON)
    service.fail = True

    assert await client.outcome(PERSON, request_id) == push.UNAVAILABLE


async def test_sending_against_a_dead_service_says_so(
    client: PushClient, service: _Service
) -> None:
    service.fail = True

    with pytest.raises(PushUnavailable):
        await client.send(PERSON)


def test_an_unconfigured_client_knows_it(redis: aioredis.FakeRedis) -> None:
    """Absent is a state an operator chose, the same as the directory."""
    assert PushClient("", redis).configured is False
    assert PushClient(SERVICE, redis).configured is True


# --- the routes -------------------------------------------------------------


async def test_push_is_offered_when_it_is_configured(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)
    wired.state.mfa = _NoFactors()

    body = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()

    assert PUSH in body["factors"]
    assert body["simulated"] == [PUSH]


class _NoFactors:
    async def categories_for(self, person_uuid: str) -> set[str]:
        return set()

    async def credential_ids(self, person_uuid: str) -> list[bytes]:
        return []


async def test_an_approved_push_elevates(
    http: AsyncClient, wired: FastAPI, service: _Service, audit: RecordingAuditLog
) -> None:
    session = await _session(wired)
    started = await http.post("/mfa/challenge/push", cookies=_cookie(session))
    request_id = started.json()["id"]
    service.requests[request_id] = push.APPROVED

    response = await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(session))

    assert response.status_code == 200
    assert response.json()["acr"] == AAL2
    assert PUSH in response.json()["amr"]
    assert EventType.MFA_STEP_UP in audit.types


async def test_a_pending_push_is_not_an_answer_yet(http: AsyncClient, wired: FastAPI) -> None:
    """202 rather than 200 with a status field, so a caller does not have to read
    the body to find out whether to keep asking."""
    session = await _session(wired)
    request_id = (await http.post("/mfa/challenge/push", cookies=_cookie(session))).json()["id"]

    response = await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(session))

    assert response.status_code == 202
    assert response.json()["status"] == push.PENDING


@pytest.mark.parametrize("settled", [push.DENIED, push.EXPIRED])
async def test_a_denial_or_a_timeout_does_not_elevate(
    http: AsyncClient, wired: FastAPI, service: _Service, settled: str
) -> None:
    session = await _session(wired)
    request_id = (await http.post("/mfa/challenge/push", cookies=_cookie(session))).json()["id"]
    service.requests[request_id] = settled

    response = await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(session))

    assert response.status_code == 400
    assert (await wired.state.sessions.load(session.sid)).acr == AAL1


async def test_a_denial_is_audited_with_its_reason(
    http: AsyncClient, wired: FastAPI, service: _Service, audit: RecordingAuditLog
) -> None:
    session = await _session(wired)
    request_id = (await http.post("/mfa/challenge/push", cookies=_cookie(session))).json()["id"]
    service.requests[request_id] = push.DENIED

    await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(session))

    failures = audit.of_type(EventType.MFA_FAILED)
    assert [event.detail["reason"] for event in failures] == ["mfa.push_denied"]


async def test_somebody_elses_request_does_not_elevate(
    http: AsyncClient, wired: FastAPI, service: _Service
) -> None:
    session = await _session(wired)
    stranger = await _session(wired, person=OTHER)
    request_id = (await http.post("/mfa/challenge/push", cookies=_cookie(session))).json()["id"]
    service.requests[request_id] = push.APPROVED

    response = await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(stranger))

    assert response.status_code == 400


async def test_an_outage_while_polling_is_not_a_failed_attempt(
    http: AsyncClient, wired: FastAPI, service: _Service, audit: RecordingAuditLog
) -> None:
    """Locking somebody out because the push service was down would be the wrong
    answer to the wrong problem."""
    session = await _session(wired)
    request_id = (await http.post("/mfa/challenge/push", cookies=_cookie(session))).json()["id"]
    service.fail = True

    response = await http.post(f"/mfa/challenge/push/{request_id}", cookies=_cookie(session))

    assert response.status_code == 503
    assert EventType.MFA_FAILED not in audit.types


async def test_a_broker_with_no_push_service_says_so(http: AsyncClient, wired: FastAPI) -> None:
    wired.state.push = None

    assert (
        await http.post("/mfa/challenge/push", cookies=_cookie(await _session(wired)))
    ).status_code == 503


async def test_starting_a_push_needs_a_session(http: AsyncClient) -> None:
    assert (await http.post("/mfa/challenge/push")).status_code == 401


async def test_polling_needs_a_session(http: AsyncClient) -> None:
    assert (await http.post("/mfa/challenge/push/request-1")).status_code == 401


async def test_starting_a_push_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    assert (await http.post("/mfa/challenge/push", cookies=_cookie(session))).status_code == 409


async def test_polling_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    assert (
        await http.post("/mfa/challenge/push/request-1", cookies=_cookie(session))
    ).status_code == 409
