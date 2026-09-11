"""Managing your own second factors over HTTP (FR-MFA-01).

The store is substituted, because what is being tested here is not whether TOTP
works — `test_totp.py` and `test_mfa_enrolment.py` cover that — but whether the
routes can be made to act on somebody else's account, whether they leak which
factors exist, and whether the secret can be read back after enrolment.

The shape of every one of these tests is the same: the person is taken from the
session and never from the request, so the interesting cases are the ones where
the request tries to say who it is.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType
from campusid.mfa import totp
from campusid.mfa.store import DUPLICATE_LABEL, NO_FACTOR, Enrolment, MfaError
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
FACTOR = uuid.UUID("c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b")
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@dataclass
class _Row:
    id: uuid.UUID
    kind: str
    label: str
    confirmed_at: datetime | None
    disabled_at: datetime | None = None
    last_used_at: datetime | None = None


class _Factors:
    """The store, reduced to what the routes call and what they can be told."""

    def __init__(self) -> None:
        self.rows: list[_Row] = []
        self.begun: list[tuple[str, str, str]] = []
        self.confirmed: list[tuple[str, uuid.UUID, str]] = []
        self.disabled: list[tuple[str, uuid.UUID]] = []
        self.raises: Exception | None = None

    async def begin_totp(self, person_uuid: str, *, label: str, account: str) -> Enrolment:
        if self.raises is not None:
            raise self.raises
        self.begun.append((person_uuid, label, account))
        return Enrolment(
            factor_id=FACTOR,
            secret=SECRET,
            uri=totp.provisioning_uri(SECRET, account=account, issuer="CampusID"),
        )

    async def confirm_totp(self, person_uuid: str, factor_id: uuid.UUID, code: str) -> None:
        if self.raises is not None:
            raise self.raises
        self.confirmed.append((person_uuid, factor_id, code))

    async def factors_for(self, person_uuid: str) -> list[_Row]:
        return list(self.rows)

    async def disable(self, person_uuid: str, factor_id: uuid.UUID) -> None:
        if self.raises is not None:
            raise self.raises
        self.disabled.append((person_uuid, factor_id))


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def factors() -> _Factors:
    return _Factors()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def wired(
    app: FastAPI, redis: aioredis.FakeRedis, factors: _Factors, audit: RecordingAuditLog
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.mfa = factors
    app.state.audit = audit
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


async def _session(wired: FastAPI, *, person: str | None = PERSON) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="sam.obrien@campus.test",
        auth_time=datetime(2026, 9, 10, 11, 55, tzinfo=UTC),
        person_uuid=person,
    )
    return established


def _cookie(session: Session) -> dict[str, str]:
    return {SESSION_COOKIE: session.sid}


# --- who the caller is ------------------------------------------------------


async def test_enrolment_needs_a_session(http: AsyncClient) -> None:
    response = await http.post("/mfa/totp", json={"label": "my phone"})

    assert response.status_code == 401


async def test_enrolment_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    """Factors hang off `person_uuid`. Attaching one to a bare `NameID` would
    produce a credential that survives a rename and vanishes on a match."""
    session = await _session(wired, person=None)

    response = await http.post("/mfa/totp", json={"label": "my phone"}, cookies=_cookie(session))

    assert response.status_code == 409


async def test_the_person_comes_from_the_session_not_the_body(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """The case the whole module is arranged around: there is nowhere in the
    request to say whose factor this is."""
    session = await _session(wired)

    await http.post(
        "/mfa/totp",
        json={"label": "my phone", "person_uuid": "somebody-else"},
        cookies=_cookie(session),
    )

    assert factors.begun == [(PERSON, "my phone", "sam.obrien@campus.test")]


async def test_an_unknown_cookie_is_not_a_session(http: AsyncClient) -> None:
    response = await http.post(
        "/mfa/totp", json={"label": "my phone"}, cookies={SESSION_COOKIE: "not-a-session"}
    )

    assert response.status_code == 401


# --- enrolment --------------------------------------------------------------


async def test_enrolment_returns_the_provisioning_uri(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)

    response = await http.post("/mfa/totp", json={"label": "my phone"}, cookies=_cookie(session))

    assert response.status_code == 201
    body = response.json()
    assert body["secret"] == SECRET
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert body["id"] == str(FACTOR)


async def test_enrolment_is_not_cacheable(http: AsyncClient, wired: FastAPI) -> None:
    """It carries a secret exactly once. A cache holding it would make that
    once untrue."""
    session = await _session(wired)

    response = await http.post("/mfa/totp", json={"label": "my phone"}, cookies=_cookie(session))

    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("body", [{}, {"label": ""}, {"label": "   "}, {"label": "x" * 129}])
async def test_a_missing_or_oversized_label_is_refused(
    http: AsyncClient, wired: FastAPI, body: dict[str, Any]
) -> None:
    session = await _session(wired)

    response = await http.post("/mfa/totp", json=body, cookies=_cookie(session))

    assert response.status_code == 400


async def test_a_malformed_body_is_a_bad_request_not_a_crash(
    http: AsyncClient, wired: FastAPI
) -> None:
    """Letting the JSON decoder raise would say the broker is broken rather
    than that the caller is."""
    session = await _session(wired)

    response = await http.post(
        "/mfa/totp",
        content=b"{not json",
        headers={"content-type": "application/json"},
        cookies=_cookie(session),
    )

    assert response.status_code == 400


async def test_a_duplicate_label_is_a_conflict(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.raises = MfaError(DUPLICATE_LABEL)

    response = await http.post("/mfa/totp", json={"label": "my phone"}, cookies=_cookie(session))

    assert response.status_code == 409


async def test_a_started_enrolment_is_audited(
    http: AsyncClient, wired: FastAPI, audit: RecordingAuditLog
) -> None:
    """A started enrolment that never finishes is the shape of a QR code scanned
    into the wrong app, and it is invisible if only finished ones are recorded."""
    session = await _session(wired)

    await http.post("/mfa/totp", json={"label": "my phone"}, cookies=_cookie(session))

    assert EventType.MFA_ENROLMENT_STARTED in audit.types


# --- confirmation -----------------------------------------------------------


async def test_confirming_finishes_the_enrolment(
    http: AsyncClient, wired: FastAPI, factors: _Factors, audit: RecordingAuditLog
) -> None:
    session = await _session(wired)

    response = await http.post(
        f"/mfa/totp/{FACTOR}/confirm", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 200
    assert factors.confirmed == [(PERSON, FACTOR, "123456")]
    assert EventType.MFA_ENROLLED in audit.types


@pytest.mark.parametrize("reason", [totp.MISMATCH, totp.REPLAY, totp.MALFORMED])
async def test_every_rejected_code_gets_the_same_answer(
    http: AsyncClient, wired: FastAPI, factors: _Factors, reason: str
) -> None:
    """Telling the caller a code was *replayed* tells them it reached somebody
    else's hands first, which is not theirs to learn from a status code."""
    session = await _session(wired)
    factors.raises = totp.TotpRejected(reason)

    response = await http.post(
        f"/mfa/totp/{FACTOR}/confirm", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 400
    assert response.json() == {"error": "verification_failed"}


async def test_a_rejected_code_is_audited_with_its_reason(
    http: AsyncClient, wired: FastAPI, factors: _Factors, audit: RecordingAuditLog
) -> None:
    """The distinction the response withholds is kept where an investigator can
    find it."""
    session = await _session(wired)
    factors.raises = totp.TotpRejected(totp.REPLAY)

    await http.post(
        f"/mfa/totp/{FACTOR}/confirm", json={"code": "123456"}, cookies=_cookie(session)
    )

    failures = audit.of_type(EventType.MFA_ENROLMENT_FAILED)
    assert [event.detail["reason"] for event in failures] == [totp.REPLAY]


async def test_confirming_somebody_elses_factor_is_not_found(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """Not forbidden. Confirming the id exists would make factor ids worth
    guessing at."""
    session = await _session(wired)
    factors.raises = MfaError(NO_FACTOR)

    response = await http.post(
        f"/mfa/totp/{FACTOR}/confirm", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 404


async def test_a_malformed_factor_id_is_not_found(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)

    response = await http.post(
        "/mfa/totp/not-a-uuid/confirm", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 404


async def test_confirmation_needs_a_session(http: AsyncClient) -> None:
    response = await http.post(f"/mfa/totp/{FACTOR}/confirm", json={"code": "123456"})

    assert response.status_code == 401


async def test_confirmation_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    response = await http.post(
        f"/mfa/totp/{FACTOR}/confirm", json={"code": "1"}, cookies=_cookie(session)
    )

    assert response.status_code == 409


# --- listing ----------------------------------------------------------------


async def test_the_listing_never_carries_the_secret(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """The difference between stealing a session and stealing a second factor:
    a session that could read this back would be both."""
    session = await _session(wired)
    factors.rows = [_Row(id=FACTOR, kind="totp", label="my phone", confirmed_at=datetime.now(UTC))]

    response = await http.get("/mfa/factors", cookies=_cookie(session))

    assert SECRET not in response.text
    assert "otpauth" not in response.text


async def test_the_listing_says_what_is_confirmed(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.rows = [
        _Row(id=FACTOR, kind="totp", label="my phone", confirmed_at=datetime.now(UTC)),
        _Row(id=uuid.uuid4(), kind="totp", label="my tablet", confirmed_at=None),
    ]

    body = (await http.get("/mfa/factors", cookies=_cookie(session))).json()

    assert [row["confirmed"] for row in body["factors"]] == [True, False]
    assert [row["label"] for row in body["factors"]] == ["my phone", "my tablet"]


async def test_the_listing_needs_a_session(http: AsyncClient) -> None:
    assert (await http.get("/mfa/factors")).status_code == 401


async def test_the_listing_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    assert (await http.get("/mfa/factors", cookies=_cookie(session))).status_code == 409


# --- retiring ---------------------------------------------------------------


async def test_a_factor_can_be_retired(
    http: AsyncClient, wired: FastAPI, factors: _Factors, audit: RecordingAuditLog
) -> None:
    session = await _session(wired)

    response = await http.delete(f"/mfa/factors/{FACTOR}", cookies=_cookie(session))

    assert response.status_code == 200
    assert factors.disabled == [(PERSON, FACTOR)]
    assert EventType.MFA_FACTOR_REMOVED in audit.types


async def test_retiring_somebody_elses_factor_is_not_found(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.raises = MfaError(NO_FACTOR)

    response = await http.delete(f"/mfa/factors/{FACTOR}", cookies=_cookie(session))

    assert response.status_code == 404


async def test_retiring_a_malformed_id_is_not_found(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired)

    assert (await http.delete("/mfa/factors/nope", cookies=_cookie(session))).status_code == 404


async def test_retiring_needs_a_session(http: AsyncClient) -> None:
    assert (await http.delete(f"/mfa/factors/{FACTOR}")).status_code == 401


async def test_retiring_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    assert (await http.delete(f"/mfa/factors/{FACTOR}", cookies=_cookie(session))).status_code == (
        409
    )
