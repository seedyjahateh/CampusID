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

import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from campusid.audit.events import EventType, Outcome
from campusid.logging import get_logger
from campusid.mfa import totp
from campusid.mfa.store import DUPLICATE_LABEL, MfaError
from campusid.session.cookies import SESSION_COOKIE

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
