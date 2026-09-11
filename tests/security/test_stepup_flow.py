"""Step-up, end to end over HTTP (FR-MFA-04, FR-MFA-06, FR-MFA-08).

A session that authenticated with a password reaches a resource that needs a
second factor, presents one, and comes back elevated — without re-running primary
authentication, which is the whole requirement.

Three things are load-bearing and each has its own test. The session identifier
rotates, because assurance changing is a privilege change and a session captured
at the lower level must not be replayable at the higher one. The decisions cached
about the person are unmade, because the challenge that sent them here is one of
them. And the claims that come back are checked against the methods rather than
against themselves.
"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType
from campusid.authz.engine import AAL1, AAL2
from campusid.mfa import totp, webauthn
from campusid.mfa.assurance import HWK, MFA, OTP, PWD, satisfies_aal2
from campusid.mfa.challenges import ChallengeStore
from campusid.mfa.ratelimit import THRESHOLD, AttemptLimiter
from campusid.mfa.store import NO_FACTOR, MfaError
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog
from tests.support.authenticator import VirtualAuthenticator

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
FACTOR = uuid.UUID("c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b")
ORIGIN = "http://localhost:8000"
RP_ID = "localhost"


class _Factors:
    """The store, reduced to what the step-up routes ask of it."""

    def __init__(self) -> None:
        self.categories: set[str] = {"otp"}
        self.credentials: list[bytes] = []
        self.totp_raises: Exception | None = None
        self.webauthn_raises: Exception | None = None
        self.verified: list[str] = []
        self.assertions: list[dict[str, Any]] = []

    async def categories_for(self, person_uuid: str) -> set[str]:
        return set(self.categories)

    async def credential_ids(self, person_uuid: str) -> list[bytes]:
        return list(self.credentials)

    async def verify_totp(self, person_uuid: str, code: str) -> str:
        if self.totp_raises is not None:
            raise self.totp_raises
        self.verified.append(code)
        return str(FACTOR)

    async def verify_webauthn(self, person_uuid: str, **kwargs: Any) -> webauthn.Assertion:
        if self.webauthn_raises is not None:
            raise self.webauthn_raises
        self.assertions.append(kwargs)
        return webauthn.Assertion(
            credential_id=kwargs["credential_id"], sign_count=1, user_verified=True
        )


class _Decisions:
    def __init__(self) -> None:
        self.invalidated: list[str] = []

    async def invalidate(self, person_uuid: str) -> None:
        self.invalidated.append(person_uuid)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def factors() -> _Factors:
    return _Factors()


@pytest.fixture
def decisions() -> _Decisions:
    return _Decisions()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def wired(
    app: FastAPI,
    redis: aioredis.FakeRedis,
    factors: _Factors,
    decisions: _Decisions,
    audit: RecordingAuditLog,
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.mfa = factors
    app.state.mfa_challenges = ChallengeStore(redis)
    app.state.mfa_limiter = AttemptLimiter(redis)
    app.state.decision_cache = decisions
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
    amr: tuple[str, ...] = (PWD,),
    auth_time: datetime | None = None,
) -> Session:
    established: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="sam.obrien@campus.test",
        auth_time=auth_time or datetime.now(UTC) - timedelta(minutes=2),
        acr=AAL1,
        amr=amr,
        person_uuid=person,
    )
    return established


def _cookie(session: Session) -> dict[str, str]:
    return {SESSION_COOKIE: session.sid}


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _passkey_body(authenticator: VirtualAuthenticator, challenge: bytes) -> dict[str, str]:
    client_data, data, signature = authenticator.assert_(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID
    )
    return {
        "id": _encode(authenticator.credential_id),
        "clientDataJSON": _encode(client_data),
        "authenticatorData": _encode(data),
        "signature": _encode(signature),
    }


# --- what the caller is offered ---------------------------------------------


async def test_the_challenge_says_what_can_be_presented(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.categories = {"otp", "hwk"}
    factors.credentials = [b"credential-one"]

    body = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()

    assert body["factors"] == ["hwk", "otp"]
    assert body["acr"] == AAL1


async def test_the_challenge_carries_allow_credentials(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """Without it a security key holding several credentials cannot tell which
    one is wanted, and a platform authenticator will not offer one at all."""
    session = await _session(wired)
    factors.credentials = [b"credential-one"]

    body = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()

    assert body["webauthn"]["rpId"] == RP_ID
    assert body["webauthn"]["allowCredentials"][0]["id"] == _encode(b"credential-one")


async def test_a_person_with_no_passkey_gets_no_webauthn_challenge(
    http: AsyncClient, wired: FastAPI
) -> None:
    session = await _session(wired)

    body = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()

    assert "webauthn" not in body


async def test_the_challenge_is_answered_for_anybody_with_a_session(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """Refusing for somebody with no factor would make this endpoint an oracle
    for who holds one, which is a list worth having if you are choosing whom to
    phish."""
    session = await _session(wired)
    factors.categories = set()

    response = await http.post("/mfa/challenge", cookies=_cookie(session))

    assert response.status_code == 200
    assert response.json()["factors"] == []


async def test_the_challenge_needs_a_session(http: AsyncClient) -> None:
    assert (await http.post("/mfa/challenge")).status_code == 401


# --- stepping up with a code ------------------------------------------------


async def test_a_code_elevates_the_session(
    http: AsyncClient, wired: FastAPI, audit: RecordingAuditLog
) -> None:
    """FR-MFA-04, without re-running primary authentication."""
    session = await _session(wired)

    response = await http.post(
        "/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 200
    body = response.json()
    assert body["acr"] == AAL2
    assert set(body["amr"]) == {PWD, OTP, MFA}
    assert EventType.MFA_STEP_UP in audit.types


async def test_the_claims_are_supported_by_the_methods(http: AsyncClient, wired: FastAPI) -> None:
    """FR-MFA-08 checked against the evidence rather than against itself."""
    session = await _session(wired)

    body = (
        await http.post("/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session))
    ).json()

    assert satisfies_aal2(tuple(body["amr"])) is (body["acr"] == AAL2)


async def test_the_session_identifier_rotates(http: AsyncClient, wired: FastAPI) -> None:
    """Assurance changing is a privilege change. Reusing the identifier would let
    a session captured at AAL1 be replayed at AAL2."""
    session = await _session(wired)

    response = await http.post(
        "/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session)
    )

    issued = response.cookies.get(SESSION_COOKIE)
    assert issued is not None
    assert issued != session.sid
    assert await wired.state.sessions.load(session.sid) is None


async def test_the_elevated_session_is_the_one_that_works(
    http: AsyncClient, wired: FastAPI
) -> None:
    session = await _session(wired)
    response = await http.post(
        "/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session)
    )

    elevated = await wired.state.sessions.load(response.cookies[SESSION_COOKIE])

    assert elevated is not None
    assert elevated.acr == AAL2
    assert elevated.person_uuid == PERSON


async def test_cached_decisions_are_unmade(
    http: AsyncClient, wired: FastAPI, decisions: _Decisions
) -> None:
    """The challenge that sent them here is a cached decision, so a step-up that
    did not unmake it would send them round the same loop for a minute."""
    session = await _session(wired)

    await http.post("/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session))

    assert decisions.invalidated == [PERSON]


async def test_a_wrong_code_does_not_elevate(
    http: AsyncClient, wired: FastAPI, factors: _Factors, audit: RecordingAuditLog
) -> None:
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)

    response = await http.post(
        "/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session)
    )

    assert response.status_code == 400
    assert EventType.MFA_FAILED in audit.types
    assert (await wired.state.sessions.load(session.sid)).acr == AAL1


async def test_a_replayed_code_gets_the_same_answer_as_a_wrong_one(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.REPLAY)

    response = await http.post(
        "/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session)
    )

    assert response.json() == {"error": "verification_failed"}


async def test_a_step_up_needs_a_session(http: AsyncClient) -> None:
    assert (await http.post("/mfa/challenge/totp", json={"code": "1"})).status_code == 401


async def test_a_step_up_needs_a_resolved_person(http: AsyncClient, wired: FastAPI) -> None:
    session = await _session(wired, person=None)

    response = await http.post("/mfa/challenge/totp", json={"code": "1"}, cookies=_cookie(session))

    assert response.status_code == 409


# --- stepping up with a passkey ---------------------------------------------


async def test_a_passkey_elevates_the_session(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()
    challenge = base64.urlsafe_b64decode(
        issued["webauthn"]["challenge"] + "=" * (-len(issued["webauthn"]["challenge"]) % 4)
    )

    response = await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, challenge),
        cookies=_cookie(session),
    )

    assert response.status_code == 200
    assert response.json()["acr"] == AAL2
    assert HWK in response.json()["amr"]


async def test_the_challenge_reaches_the_verifier(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """The issued challenge, not one the request supplied. A verifier handed the
    caller's own challenge would verify a replay against itself."""
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()["webauthn"]
    challenge = base64.urlsafe_b64decode(
        issued["challenge"] + "=" * (-len(issued["challenge"]) % 4)
    )

    await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, challenge),
        cookies=_cookie(session),
    )

    assert factors.assertions[0]["challenge"] == challenge
    assert factors.assertions[0]["origin"] == ORIGIN
    assert factors.assertions[0]["rp_id"] == RP_ID


async def test_a_passkey_with_no_outstanding_challenge_is_refused(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    authenticator = VirtualAuthenticator()

    response = await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, os.urandom(32)),
        cookies=_cookie(session),
    )

    assert response.status_code == 400
    assert factors.assertions == []


async def test_a_challenge_cannot_be_spent_twice(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """The whole reason a challenge exists: a captured ceremony response must not
    keep working for the rest of its life."""
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()["webauthn"]
    challenge = base64.urlsafe_b64decode(
        issued["challenge"] + "=" * (-len(issued["challenge"]) % 4)
    )
    body = _passkey_body(authenticator, challenge)
    first = await http.post("/mfa/challenge/webauthn", json=body, cookies=_cookie(session))
    elevated = await wired.state.sessions.load(first.cookies[SESSION_COOKIE])

    second = await http.post(
        "/mfa/challenge/webauthn", json=body, cookies={SESSION_COOKIE: elevated.sid}
    )

    assert second.status_code == 400


async def test_a_rejected_assertion_does_not_elevate(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    factors.webauthn_raises = webauthn.WebAuthnRejected(webauthn.CLONED)
    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()["webauthn"]
    challenge = base64.urlsafe_b64decode(
        issued["challenge"] + "=" * (-len(issued["challenge"]) % 4)
    )

    response = await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, challenge),
        cookies=_cookie(session),
    )

    assert response.status_code == 400
    assert (await wired.state.sessions.load(session.sid)).acr == AAL1


async def test_somebody_elses_credential_does_not_elevate(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    factors.webauthn_raises = MfaError(NO_FACTOR)
    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()["webauthn"]
    challenge = base64.urlsafe_b64decode(
        issued["challenge"] + "=" * (-len(issued["challenge"]) % 4)
    )

    response = await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, challenge),
        cookies=_cookie(session),
    )

    assert response.status_code == 400


@pytest.mark.parametrize("missing", ["id", "clientDataJSON", "authenticatorData", "signature"])
async def test_a_passkey_response_missing_a_field_is_refused(
    http: AsyncClient, wired: FastAPI, factors: _Factors, missing: str
) -> None:
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    body = _passkey_body(authenticator, os.urandom(32))
    body.pop(missing)

    response = await http.post("/mfa/challenge/webauthn", json=body, cookies=_cookie(session))

    assert response.status_code == 400


# --- rate limiting ----------------------------------------------------------


async def test_repeated_failures_lock_the_account(
    http: AsyncClient, wired: FastAPI, factors: _Factors, audit: RecordingAuditLog
) -> None:
    """FR-MFA-06. Without it a six-digit code with a million values and a
    thirty-second life is not a second factor."""
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)

    for _ in range(THRESHOLD):
        response = await http.post(
            "/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session)
        )

    assert response.status_code == 429
    assert EventType.MFA_LOCKED_OUT in audit.types


async def test_a_locked_account_is_refused_before_verifying(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """The check comes first, so a locked-out account costs no verification —
    which is the point and a small denial-of-service defence of its own."""
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)
    for _ in range(THRESHOLD):
        await http.post("/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session))
    factors.totp_raises = None

    response = await http.post(
        "/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session)
    )

    assert response.status_code == 429
    assert factors.verified == []


async def test_the_refusal_says_when_to_come_back(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)

    for _ in range(THRESHOLD):
        response = await http.post(
            "/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session)
        )

    assert int(response.headers["retry-after"]) > 0


async def test_a_lock_on_one_kind_leaves_the_other_open(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """One lost phone must not be a complete lockout."""
    session = await _session(wired)
    authenticator = VirtualAuthenticator()
    factors.credentials = [authenticator.credential_id]
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)
    for _ in range(THRESHOLD):
        await http.post("/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session))

    issued = (await http.post("/mfa/challenge", cookies=_cookie(session))).json()["webauthn"]
    challenge = base64.urlsafe_b64decode(
        issued["challenge"] + "=" * (-len(issued["challenge"]) % 4)
    )
    response = await http.post(
        "/mfa/challenge/webauthn",
        json=_passkey_body(authenticator, challenge),
        cookies=_cookie(session),
    )

    assert response.status_code == 200


async def test_a_success_clears_the_count(
    http: AsyncClient, wired: FastAPI, factors: _Factors
) -> None:
    """Otherwise four mistypes over a month add up to a lockout on the fifth."""
    session = await _session(wired)
    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)
    for _ in range(THRESHOLD - 1):
        await http.post("/mfa/challenge/totp", json={"code": "000000"}, cookies=_cookie(session))
    factors.totp_raises = None
    elevated = await http.post(
        "/mfa/challenge/totp", json={"code": "123456"}, cookies=_cookie(session)
    )

    factors.totp_raises = totp.TotpRejected(totp.MISMATCH)
    again = await http.post(
        "/mfa/challenge/totp",
        json={"code": "000000"},
        cookies={SESSION_COOKIE: elevated.cookies[SESSION_COOKIE]},
    )

    assert again.status_code == 400
