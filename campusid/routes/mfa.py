"""Managing your own second factors (FR-MFA-01).

A small JSON API under `/mfa`, authenticated by the session cookie and by nothing
else. Every route acts on the caller's own factors, taken from the session rather
than from anything in the request, which is what makes "enrol a factor on
somebody else's account" unexpressible instead of merely refused.

**A session that has not been resolved to a person cannot enrol.** Factors hang
off `person_uuid`, and a session that has only a `NameID` is one the identity
registry has not matched yet. Attaching a factor to a name would produce a
credential that survives the person being renamed and vanishes when they are
matched.

**No route reveals whether a code was wrong or replayed.** The store makes the
distinction and the audit record keeps it; the response is the same either way,
because telling the caller which one it was tells them whether their code reached
somebody else's hands first.

**Enrolment answers with the secret exactly once.** It has to — the QR code is
the whole point — but the factor listing never shows it again, so a stolen
session cannot read back a factor enrolled before it.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from campusid.audit.events import EventType, Outcome
from campusid.logging import get_logger
from campusid.mfa import assurance, challenges, models, ratelimit, totp, webauthn
from campusid.mfa.ratelimit import LOCKED, RateLimited
from campusid.mfa.store import DUPLICATE_LABEL, MfaError
from campusid.saml.stores import utcnow
from campusid.session.cookies import SESSION_COOKIE, set_session_cookie

log = get_logger(__name__)

router = APIRouter(prefix="/mfa", tags=["mfa"])

NO_STORE = {"Cache-Control": "no-store"}

UNAUTHENTICATED = {"error": "authentication_required"}
UNRESOLVED = {"error": "identity_not_resolved"}
BAD_REQUEST = {"error": "invalid_request"}
REJECTED = {"error": "verification_failed"}
NOT_FOUND = {"error": "not_found"}

MAX_LABEL = 128


async def _caller(request: Request) -> Any:
    """The session behind the cookie, or None.

    Loaded rather than trusted: the cookie carries an opaque id and nothing else
    (FR-SES-06), so everything about who this is comes from the store.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    return await request.app.state.sessions.load(sid)


def _refuse(body: dict[str, str], status: int) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=NO_STORE)


@router.post("/totp")
async def begin_totp(request: Request) -> JSONResponse:
    """Issue a TOTP secret and return the provisioning URI (FR-MFA-01).

    The factor is stored unconfirmed. It becomes usable only when the caller
    returns a code computed from the secret, because a QR code scanned into the
    wrong app would otherwise register a factor the broker believes in and the
    person cannot produce.
    """
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    body = await _json(request)
    label = str(body.get("label") or "").strip()
    if not label or len(label) > MAX_LABEL:
        return _refuse(BAD_REQUEST, 400)

    try:
        enrolment = await request.app.state.mfa.begin_totp(
            session.person_uuid, label=label, account=session.name_id
        )
    except MfaError as exc:
        return _refuse({"error": exc.reason}, 409 if exc.reason == DUPLICATE_LABEL else 400)

    await request.app.state.audit.record(
        EventType.MFA_ENROLMENT_STARTED,
        Outcome.SUCCESS,
        subject=session.person_uuid,
        detail={"factor": str(enrolment.factor_id), "kind": "totp", "label": label},
    )
    return JSONResponse(
        {
            "id": str(enrolment.factor_id),
            "kind": "totp",
            "label": label,
            # Returned once and never again. The listing route does not carry it.
            "secret": enrolment.secret,
            "otpauth_uri": enrolment.uri,
        },
        status_code=201,
        headers=NO_STORE,
    )


@router.post("/totp/{factor_id}/confirm")
async def confirm_totp(factor_id: str, request: Request) -> JSONResponse:
    """Prove the secret arrived, which is what finishes the enrolment."""
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    try:
        parsed = uuid.UUID(factor_id)
    except ValueError:
        # A malformed id is not found rather than a bad request: both answers
        # are the same to a caller who is guessing at ids.
        return _refuse(NOT_FOUND, 404)

    body = await _json(request)
    code = str(body.get("code") or "")

    try:
        await request.app.state.mfa.confirm_totp(session.person_uuid, parsed, code)
    except totp.TotpRejected as exc:
        await request.app.state.audit.record(
            EventType.MFA_ENROLMENT_FAILED,
            Outcome.FAILURE,
            subject=session.person_uuid,
            detail={"factor": factor_id, "reason": exc.reason},
        )
        # One answer for a wrong code and for a replayed one. Which it was tells
        # the caller whether their code reached somebody else first.
        return _refuse(REJECTED, 400)
    except MfaError:
        return _refuse(NOT_FOUND, 404)

    await request.app.state.audit.record(
        EventType.MFA_ENROLLED,
        Outcome.SUCCESS,
        subject=session.person_uuid,
        detail={"factor": factor_id, "kind": "totp"},
    )
    return JSONResponse({"id": factor_id, "confirmed": True}, headers=NO_STORE)


@router.post("/webauthn/options")
async def webauthn_options(request: Request) -> JSONResponse:
    """Issue a challenge and describe the credential to create (FR-MFA-02).

    The options are built here rather than in the page, because every one of
    them is a security parameter: the relying-party id the credential is scoped
    to, the algorithms the broker can verify, and the challenge. A page that
    chose its own would be choosing what the credential is worth.
    """
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    state = request.app.state
    challenge = await state.mfa_challenges.issue(session.person_uuid, challenges.REGISTER)
    existing = await state.mfa.credential_ids(session.person_uuid)

    return JSONResponse(
        {
            "challenge": webauthn.b64url(challenge),
            "rp": {"id": state.settings.webauthn_rp_id, "name": state.settings.service_name},
            "user": {
                # The user handle is the person id and nothing else. A handle
                # carrying a name or an address would put it on the
                # authenticator, where the person cannot later take it back.
                "id": webauthn.b64url(session.person_uuid.encode("utf-8")),
                "name": session.name_id,
                "displayName": session.name_id,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg} for alg in webauthn.SUPPORTED_ALGORITHMS
            ],
            # `none` for the reason the verifier gives: anything stronger turns a
            # self-service enrolment into a procurement policy.
            "attestation": "none",
            "authenticatorSelection": {"userVerification": "preferred", "residentKey": "preferred"},
            # So an authenticator already registered here declines rather than
            # producing a second credential the person has no way to tell apart.
            "excludeCredentials": [
                {"type": "public-key", "id": webauthn.b64url(cid)} for cid in existing
            ],
            "timeout": int(challenges.TTL.total_seconds() * 1000),
        },
        headers=NO_STORE,
    )


@router.post("/webauthn")
async def register_webauthn(request: Request) -> JSONResponse:
    """Store the credential the browser just created (FR-MFA-02).

    One step, unlike TOTP: the response already carries a signature over a
    challenge this broker issued, so the ceremony is the proof and a second round
    trip would establish nothing.
    """
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    body = await _json(request)
    label = str(body.get("label") or "").strip()
    if not label or len(label) > MAX_LABEL:
        return _refuse(BAD_REQUEST, 400)

    client_data = _b64url(body.get("clientDataJSON"))
    attestation = _b64url(body.get("attestationObject"))
    if client_data is None or attestation is None:
        return _refuse(BAD_REQUEST, 400)

    state = request.app.state
    challenge = await state.mfa_challenges.consume(session.person_uuid, challenges.REGISTER)
    if challenge is None:
        # Expired, already spent, or never issued. One answer for all three: the
        # remedy is the same and the difference is only useful to somebody
        # replaying a captured response.
        return _refuse(REJECTED, 400)

    try:
        factor_id = await state.mfa.register_webauthn(
            session.person_uuid,
            label=label,
            client_data=client_data,
            attestation_object=attestation,
            challenge=challenge,
            origin=state.settings.webauthn_origin,
            rp_id=state.settings.webauthn_rp_id,
        )
    except webauthn.WebAuthnRejected as exc:
        await state.audit.record(
            EventType.MFA_ENROLMENT_FAILED,
            Outcome.FAILURE,
            subject=session.person_uuid,
            detail={"kind": "webauthn", "reason": exc.reason},
        )
        return _refuse(REJECTED, 400)
    except MfaError as exc:
        return _refuse({"error": exc.reason}, 409)

    await state.audit.record(
        EventType.MFA_ENROLLED,
        Outcome.SUCCESS,
        subject=session.person_uuid,
        detail={"factor": str(factor_id), "kind": "webauthn", "label": label},
    )
    return JSONResponse(
        {"id": str(factor_id), "kind": "webauthn", "label": label},
        status_code=201,
        headers=NO_STORE,
    )


# --- step-up ----------------------------------------------------------------


@router.post("/challenge")
async def challenge(request: Request) -> JSONResponse:
    """Start a step-up: say what the caller can present, and issue a challenge.

    Answered for any authenticated session rather than only for one that needs
    elevating, because the alternative is an endpoint whose 200 or 409 tells a
    caller whether the person holds a second factor.
    """
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    state = request.app.state
    categories = await state.mfa.categories_for(session.person_uuid)
    credentials = await state.mfa.credential_ids(session.person_uuid)

    body: dict[str, Any] = {
        "acr": session.acr,
        "amr": list(session.amr),
        "factors": sorted(categories),
    }
    if credentials:
        body["webauthn"] = {
            "challenge": webauthn.b64url(
                await state.mfa_challenges.issue(session.person_uuid, challenges.AUTHENTICATE)
            ),
            "rpId": state.settings.webauthn_rp_id,
            "allowCredentials": [
                {"type": "public-key", "id": webauthn.b64url(cid)} for cid in credentials
            ],
            "userVerification": "preferred",
            "timeout": int(challenges.TTL.total_seconds() * 1000),
        }
    return JSONResponse(body, headers=NO_STORE)


@router.post("/challenge/totp")
async def step_up_totp(request: Request) -> Response:
    """Elevate a session with a one-time code (FR-MFA-04)."""
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    state = request.app.state
    code = str((await _json(request)).get("code") or "")

    try:
        await state.mfa_limiter.check(session.person_uuid, models.TOTP)
    except RateLimited as exc:
        return _locked(exc)

    try:
        factor_id = await state.mfa.verify_totp(session.person_uuid, code)
    except totp.TotpRejected as exc:
        return await _failed(request, session, models.TOTP, exc.reason)

    return await _elevate(request, session, models.TOTP, factor_id)


@router.post("/challenge/webauthn")
async def step_up_webauthn(request: Request) -> Response:
    """Elevate a session with a passkey (FR-MFA-04)."""
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    state = request.app.state
    body = await _json(request)
    credential_id = _b64url(body.get("id"))
    client_data = _b64url(body.get("clientDataJSON"))
    authenticator_data = _b64url(body.get("authenticatorData"))
    signature = _b64url(body.get("signature"))
    if None in (credential_id, client_data, authenticator_data, signature):
        return _refuse(BAD_REQUEST, 400)

    try:
        await state.mfa_limiter.check(session.person_uuid, models.WEBAUTHN)
    except RateLimited as exc:
        return _locked(exc)

    outstanding = await state.mfa_challenges.consume(session.person_uuid, challenges.AUTHENTICATE)
    if outstanding is None:
        return await _failed(request, session, models.WEBAUTHN, "mfa.no_outstanding_challenge")

    try:
        assertion = await state.mfa.verify_webauthn(
            session.person_uuid,
            credential_id=credential_id,
            client_data=client_data,
            authenticator_data=authenticator_data,
            signature=signature,
            challenge=outstanding,
            origin=state.settings.webauthn_origin,
            rp_id=state.settings.webauthn_rp_id,
        )
    except webauthn.WebAuthnRejected as exc:
        return await _failed(request, session, models.WEBAUTHN, exc.reason)
    except MfaError as exc:
        return await _failed(request, session, models.WEBAUTHN, exc.reason)

    return await _elevate(
        request, session, models.WEBAUTHN, str(assertion.credential_id.hex()[:16])
    )


async def _elevate(request: Request, session: Any, kind: str, factor: str) -> Response:
    """Raise the session's assurance and hand back a rotated cookie.

    The rotation is not decoration: assurance changing is a privilege change, and
    reusing the identifier across it would let a session captured at AAL1 be
    replayed at AAL2. The cookie is therefore reissued on the way out, which is
    also why this returns a `Response` rather than a body.
    """
    state = request.app.state
    await state.mfa_limiter.record_success(session.person_uuid, kind)

    raised = assurance.elevated(
        methods=session.amr,
        category=models.CATEGORY[kind],
        since=session.auth_time,
        now=utcnow(),
    )
    elevated = await state.sessions.elevate(session.sid, acr=raised.acr, amr=raised.amr)
    if elevated is None:  # pragma: no cover - the session was loaded a moment ago
        return _refuse(UNAUTHENTICATED, 401)

    # Every decision cached about this person was made against the old
    # assurance, including the challenge that sent them here (FR-AZ-08).
    await _invalidate(state, session.person_uuid)

    await state.audit.record(
        EventType.MFA_STEP_UP,
        Outcome.SUCCESS,
        subject=session.person_uuid,
        detail={"kind": kind, "factor": factor, "acr": raised.acr, "amr": list(raised.amr)},
    )
    response = JSONResponse(
        {"acr": raised.acr, "amr": list(raised.amr), "auth_time": raised.auth_time.isoformat()},
        headers=NO_STORE,
    )
    set_session_cookie(response, elevated.sid)
    return response


async def _failed(request: Request, session: Any, kind: str, reason: str) -> Response:
    """Count the failure, audit it, and say nothing useful about why."""
    state = request.app.state
    try:
        outcome = await state.mfa_limiter.record_failure(session.person_uuid, kind)
    except RateLimited as exc:
        return _locked(exc)

    await state.audit.record(
        EventType.MFA_FAILED,
        Outcome.FAILURE,
        subject=session.person_uuid,
        detail={"kind": kind, "reason": reason, "attempts": outcome.attempts},
    )
    if outcome.locked:
        # Recorded separately and once, on the attempt that crossed the line, so
        # an alert on this event fires per lockout rather than per attempt.
        await state.audit.record(
            EventType.MFA_LOCKED_OUT,
            Outcome.DENIED,
            subject=session.person_uuid,
            detail={"kind": kind, "attempts": outcome.attempts},
        )
        return _locked(RateLimited(LOCKED, int(ratelimit.LOCKOUT.total_seconds())))
    return _refuse(REJECTED, 400)


def _locked(exc: RateLimited) -> Response:
    """Refuse an attempt that was never made.

    `Retry-After` is a real header for a real wait: somebody locked out needs to
    know whether to wait or to call the service desk, and an attacker already
    knows they are being refused.
    """
    return JSONResponse(
        {"error": exc.reason, "retry_after": exc.retry_after},
        status_code=429,
        headers={**NO_STORE, "Retry-After": str(exc.retry_after)},
    )


async def _invalidate(state: Any, person_uuid: str) -> None:
    cache = getattr(state, "decision_cache", None)
    if cache is not None:
        await cache.invalidate(person_uuid)


@router.get("/factors")
async def factors(request: Request) -> JSONResponse:
    """What the caller has registered, without any of the material.

    No secret and no provisioning URI. A session that reads this cannot
    reconstruct a factor enrolled before it, which is the difference between
    stealing a session and stealing a second factor.
    """
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    rows = await request.app.state.mfa.factors_for(session.person_uuid)
    return JSONResponse(
        {
            "factors": [
                {
                    "id": str(row.id),
                    "kind": row.kind,
                    "label": row.label,
                    "confirmed": row.confirmed_at is not None,
                    "disabled": row.disabled_at is not None,
                    "last_used": row.last_used_at.isoformat() if row.last_used_at else None,
                }
                for row in rows
            ]
        },
        headers=NO_STORE,
    )


@router.delete("/factors/{factor_id}")
async def disable_factor(factor_id: str, request: Request) -> JSONResponse:
    """Retire a factor. It is disabled rather than deleted, so "which factor
    approved that in March" stays answerable."""
    session = await _caller(request)
    if session is None:
        return _refuse(UNAUTHENTICATED, 401)
    if session.person_uuid is None:
        return _refuse(UNRESOLVED, 409)

    try:
        parsed = uuid.UUID(factor_id)
    except ValueError:
        return _refuse(NOT_FOUND, 404)

    try:
        await request.app.state.mfa.disable(session.person_uuid, parsed)
    except MfaError:
        # Includes somebody else's factor, which is reported as not found rather
        # than as forbidden: confirming the id exists would make factor ids worth
        # guessing at.
        return _refuse(NOT_FOUND, 404)

    await request.app.state.audit.record(
        EventType.MFA_FACTOR_REMOVED,
        Outcome.SUCCESS,
        subject=session.person_uuid,
        detail={"factor": factor_id},
    )
    return JSONResponse({"id": factor_id, "disabled": True}, headers=NO_STORE)


def _b64url(value: Any) -> bytes | None:
    """Decode a field the browser sent as base64url, or None if it is not one.

    None rather than an exception, so a malformed field is a bad request in the
    same shape as a missing one.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        # `validate=True`, because the default silently drops characters outside
        # the alphabet — so a field of punctuation decodes to nothing at all and
        # arrives at the verifier as an empty ceremony rather than as a refusal.
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    return decoded or None


async def _json(request: Request) -> dict[str, Any]:
    """The request body, treating anything unparseable as empty.

    A malformed body is a bad request either way, and letting the JSON decoder
    raise would turn it into a 500 that says the broker is broken rather than
    that the caller is.
    """
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}
