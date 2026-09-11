"""The administrative API (FR-ADM-01, FR-ADM-02, FR-ADM-07).

**The console is protected by the broker it administers.** No separate password,
no bypass, no `ADMIN_TOKEN` in the environment. That is not only tidiness: an
escape hatch on the administrative surface is the one credential nobody rotates
and every attacker looks for, and a broker whose own console sits outside its
authorization model cannot honestly claim the model is enforced anywhere.

**Three conditions, checked in one place and in this order.** A session; the
`iam-admin` role; and AAL2. The order matters for what the caller is told: an
anonymous request gets 401, somebody without the role gets 404, and an
administrator on a single-factor session gets a step-up challenge rather than a
refusal — because their problem is solvable and the others' are not.

**Not holding the role is a 404, not a 403.** A 403 confirms the console exists
and that this account is merely not on the list, which is a useful thing for
somebody enumerating who to phish. An administrator sees the console; everybody
else sees a broker with no `/admin`.

**AAL2 is checked against the methods, not against the stored `acr`.** An `acr`
that agrees with itself proves nothing, and a session whose `amr` carries the
`mfa` marker with one factor behind it is the shape of a bug upstream — this
route must not be the place it becomes administrative access.

**Every mutation needs a reason (FR-ADM-07).** Not a formality: the audit trail's
job is to answer "why did somebody do this", and a trail that records only what
was done leaves that question to memory. Refused before the change rather than
defaulted, because a default reason is a field everybody stops reading.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from campusid.audit.events import EventType, Outcome
from campusid.authz.engine import AAL1
from campusid.config import Environment
from campusid.errors import MetadataRejected, ReasonCode
from campusid.logging import get_logger
from campusid.mfa import assurance
from campusid.saml.parser import MAX_DOCUMENT_BYTES
from campusid.session.cookies import SESSION_COOKIE, set_session_cookie

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_ROLE: Final = "iam-admin"

NO_STORE: Final = {"Cache-Control": "no-store"}

UNAUTHENTICATED: Final = {"error": "authentication_required"}
NOT_FOUND: Final = {"error": "not_found"}
STEP_UP_REQUIRED: Final = {"error": "step_up_required"}
BAD_REQUEST: Final = {"error": "invalid_request"}
REASON_REQUIRED: Final = {"error": "reason_required"}
NOT_A_FIXTURE: Final = {"error": "not_a_fixture_account"}

IMPERSONATION_ISSUER: Final = "urn:campusid:impersonation"
"""The `idp_entity_id` on an impersonated session.

Not the campus IdP's. Nothing authenticated here, and recording an entity that
did not assert anything would put a lie in the one field an investigator uses to
ask where a session came from.
"""

IMPERSONATION_WARNING: Final = (
    "You are acting as another user. Every action is recorded against your own "
    "account with impersonation: true."
)

MAX_REASON: Final = 512

MAX_METADATA: Final = MAX_DOCUMENT_BYTES
"""The same ceiling the SAML parser uses, deliberately.

A *pasted* document never reaches this check: the body-size middleware refuses an
oversized request while it is still being received, which is the right place for
it. This cap is for the *fetched* path, where the bytes arrive from a server the
middleware never sees — and it is the parser's number rather than a second one,
because a document this would admit and the parser would refuse is a registration
that succeeds and a login that fails.
"""

FETCH_TIMEOUT: Final = 10.0


@dataclass(frozen=True, slots=True)
class Caller:
    """An administrator who has passed all three checks."""

    person_uuid: str
    sid: str


class Refused(Exception):
    """The guard said no, and what to answer."""

    def __init__(self, body: dict[str, str], status: int) -> None:
        super().__init__(body["error"])
        self.body = body
        self.status = status


async def _admin(request: Request) -> Caller:
    """The three conditions, in the order that decides what the caller is told."""
    sid = request.cookies.get(SESSION_COOKIE)
    session = await request.app.state.sessions.load(sid) if sid else None
    if session is None or session.person_uuid is None:
        raise Refused(UNAUTHENTICATED, 401)

    roles = await request.app.state.role_assignments.roles_for(session.person_uuid)
    if ADMIN_ROLE not in roles:
        # 404 rather than 403. A 403 confirms the console exists and that this
        # account is merely not on the list.
        raise Refused(NOT_FOUND, 404)

    if not assurance.satisfies_aal2(session.amr):
        # Checked against the methods rather than the stored `acr`, which would
        # only agree with itself. Their problem is solvable, so they are told
        # how — which is the one case here that gets a specific answer.
        raise Refused(STEP_UP_REQUIRED, 403)

    return Caller(person_uuid=session.person_uuid, sid=session.sid)


def _refuse(body: dict[str, str], status: int) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=NO_STORE)


# --- federation entities (FR-ADM-02) ----------------------------------------


@router.get("/entities")
async def list_entities(request: Request) -> JSONResponse:
    """Every registered identity provider, enabled or not.

    Disabled ones are listed rather than hidden: an operator asking why a login
    fails needs to see that the entity is registered and switched off, which is
    a different problem from it never having been registered.
    """
    try:
        await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    entities = await request.app.state.registry.list_idps()
    return JSONResponse(
        {
            "entities": [
                {
                    "entity_id": entity.entity_id,
                    "display_name": entity.display_name,
                    "role": entity.role,
                    "enabled": entity.enabled,
                    "metadata_url": entity.metadata_url,
                    "valid_until": _iso(entity.valid_until),
                    "last_refreshed_at": _iso(entity.last_refreshed_at),
                }
                for entity in entities
            ]
        },
        headers=NO_STORE,
    )


@router.get("/entities/{entity_id:path}")
async def describe_entity(entity_id: str, request: Request) -> JSONResponse:
    """What the parser makes of a registered entity's metadata.

    Parsed on read rather than served from stored columns, so what an
    administrator sees is what the gate will actually use. A stored summary that
    drifted from the document would be a console confidently describing trust
    the broker does not have.
    """
    try:
        await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    try:
        descriptor = await request.app.state.registry.describe(entity_id)
    except MetadataRejected as exc:
        # A registered document that has become unusable — lapsed, or invalid
        # under a stricter parser than the one that accepted it. Surfaced rather
        # than hidden, because it is exactly the thing an operator is looking
        # for when logins from one partner stop working.
        return JSONResponse(
            {"error": "metadata_unusable", "reason": exc.reason.value, "detail": str(exc)},
            status_code=409,
            headers=NO_STORE,
        )
    if descriptor is None:
        return _refuse(NOT_FOUND, 404)

    return JSONResponse(
        {
            "entity_id": descriptor.entity_id,
            "valid_until": _iso(descriptor.valid_until),
            "sso_endpoints": [
                {"binding": endpoint.binding, "location": endpoint.location}
                for endpoint in descriptor.sso_endpoints
            ],
            # Fingerprints, not certificates. An administrator comparing a key
            # rollover against what the partner sent needs to tell two apart,
            # and a page of base64 is not how anybody does that.
            "signing_certificates": [
                _fingerprint(certificate) for certificate in descriptor.signing_certificates
            ],
        },
        headers=NO_STORE,
    )


@router.post("/entities")
async def register_entity(request: Request) -> JSONResponse:
    """Register or re-register an identity provider from its metadata.

    Metadata may be pasted or fetched from a URL. Either way it goes through the
    same parser the gate uses, so an entity that would not work cannot be
    registered — the alternative is a console that accepts anything and a login
    that fails an hour later with a reason code nobody connects to this action.
    """
    try:
        caller = await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    body = await _json(request)
    reason = _reason(body)
    if reason is None:
        return _refuse(REASON_REQUIRED, 400)

    try:
        document = await _document(body, getattr(request.app.state, "metadata_http", None))
    except _BadDocument as exc:
        return _refuse({"error": exc.args[0]}, 400)

    try:
        descriptor = await request.app.state.registry.register_idp(
            document,
            metadata_url=str(body.get("metadata_url") or "") or None,
            display_name=str(body.get("display_name") or "") or None,
            enabled=bool(body.get("enabled", True)),
        )
    except MetadataRejected as exc:
        await _record(
            request,
            caller,
            Outcome.FAILURE,
            action="entity.register",
            reason=reason,
            detail={"error": exc.reason.value},
        )
        return JSONResponse(
            {"error": "metadata_rejected", "reason": exc.reason.value, "detail": str(exc)},
            status_code=400,
            headers=NO_STORE,
        )

    await _record(
        request,
        caller,
        Outcome.SUCCESS,
        action="entity.register",
        reason=reason,
        detail={"entity_id": descriptor.entity_id},
    )
    return JSONResponse(
        {"entity_id": descriptor.entity_id, "valid_until": _iso(descriptor.valid_until)},
        status_code=201,
        headers=NO_STORE,
    )


@router.post("/entities/{entity_id:path}/enabled")
async def set_enabled(entity_id: str, request: Request) -> JSONResponse:
    """Turn an entity's trust on or off without losing its history.

    Disabling rather than deleting, so the reason a partner was cut off stays
    answerable — and so turning them back on is one call rather than a metadata
    exchange somebody has to arrange again during an incident.
    """
    try:
        caller = await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    body = await _json(request)
    reason = _reason(body)
    if reason is None:
        return _refuse(REASON_REQUIRED, 400)
    if not isinstance(body.get("enabled"), bool):
        return _refuse(BAD_REQUEST, 400)

    enabled = bool(body["enabled"])
    try:
        await request.app.state.registry.set_enabled(entity_id, enabled)
    except MetadataRejected:
        return _refuse(NOT_FOUND, 404)

    await _record(
        request,
        caller,
        Outcome.SUCCESS,
        action="entity.enabled",
        reason=reason,
        detail={"entity_id": entity_id, "enabled": enabled},
    )
    return JSONResponse({"entity_id": entity_id, "enabled": enabled}, headers=NO_STORE)


# --- impersonation (FR-ADM-03) ----------------------------------------------


@router.post("/impersonate")
async def impersonate(request: Request) -> Response:
    """Act as a fixture user, so an SP integration can be tested (FR-ADM-03).

    **The endpoint does not exist in production.** Not disabled, not guarded by a
    flag somebody can flip — absent, answering 404 the way any unrouted path
    does. A feature that can be re-enabled by configuration is a feature an
    attacker can re-enable by configuration, and "act as any user" is the one
    capability where that trade has no upside.

    **Only fixture users.** The set is enumerated from configuration rather than
    inferred, because "a test account" is not a property anybody can read off a
    row, and a rule like "accounts whose name starts with test" is a rule
    somebody will name a real person into.

    **Every session it mints is marked, and the mark is on the session.** So it
    survives rotation, cannot be lost between two stores disagreeing, and there
    is no way to hold an impersonated session that does not know it is one.
    Everything the session then does is audited with `impersonation: true`,
    merged in where the event is written rather than at each call site.
    """
    settings = request.app.state.settings
    if settings.environment is Environment.PRODUCTION:
        # Answered before the guard, so it is not even an authenticated probe.
        # A 404 here is indistinguishable from a build that never had the route.
        return _refuse(NOT_FOUND, 404)

    try:
        caller = await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    body = await _json(request)
    reason = _reason(body)
    if reason is None:
        return _refuse(REASON_REQUIRED, 400)

    subject = str(body.get("subject") or "").strip()
    if subject not in settings.impersonation_fixture_set:
        # Refused rather than confirmed either way: the answer to "is this a
        # real account" is not something this endpoint should be able to give.
        await _record(
            request,
            caller,
            Outcome.DENIED,
            action="impersonate",
            reason=reason,
            detail={"subject": subject},
        )
        return _refuse(NOT_A_FIXTURE, 403)

    resolved = await request.app.state.identity.person_for(subject)
    if resolved is None:
        return _refuse(NOT_FOUND, 404)

    session = await request.app.state.sessions.create(
        idp_entity_id=IMPERSONATION_ISSUER,
        name_id=subject,
        # Single-factor by construction. An impersonated session must not be
        # able to reach the console that minted it, or an administrator could
        # impersonate their way into administering as somebody else.
        acr=AAL1,
        amr=(),
        person_uuid=str(resolved),
        impersonated_by=caller.person_uuid,
    )

    await _record(
        request,
        caller,
        Outcome.SUCCESS,
        action="impersonate",
        reason=reason,
        detail={"subject": subject, "person_uuid": str(resolved)},
    )
    response = JSONResponse(
        {
            "subject": subject,
            "person_uuid": str(resolved),
            # Said in the response as well as in the trail, so a console cannot
            # render an impersonated session as an ordinary one by omission.
            "impersonation": True,
            "impersonated_by": caller.person_uuid,
            "warning": IMPERSONATION_WARNING,
        },
        status_code=201,
        headers=NO_STORE,
    )
    # The administrator's own session is replaced, not supplemented. Holding both
    # at once is how somebody performs an administrative action believing they
    # are the fixture user, or the reverse.
    set_session_cookie(response, session.sid)
    return response


# --- helpers ----------------------------------------------------------------


class _BadDocument(Exception):
    """Why a metadata document could not even be read."""


async def _document(body: dict[str, Any], client: httpx.AsyncClient | None = None) -> bytes:
    """The metadata itself, pasted or fetched.

    A fetch is a server-side request to an operator-supplied URL, which is the
    shape of a server-side request forgery. It is accepted because registering a
    partner by their published metadata URL is the normal way federation works,
    and because reaching it requires the `iam-admin` role and AAL2 — but the
    response is size-capped and the redirect chain is not followed blindly.
    """
    pasted = body.get("metadata")
    if isinstance(pasted, str) and pasted.strip():
        encoded = pasted.encode("utf-8")
        if len(encoded) > MAX_METADATA:
            raise _BadDocument("metadata_too_large")
        return encoded

    url = str(body.get("metadata_url") or "")
    if not url.startswith(("http://", "https://")):
        raise _BadDocument("metadata_required")

    fetcher = client or httpx.AsyncClient(follow_redirects=False)
    try:
        response = await fetcher.get(url, timeout=FETCH_TIMEOUT)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise _BadDocument("metadata_unreachable") from exc
    finally:
        if client is None:
            await fetcher.aclose()

    if len(response.content) > MAX_METADATA:
        raise _BadDocument("metadata_too_large")
    return bytes(response.content)


def _reason(body: dict[str, Any]) -> str | None:
    """The `reason` field, or None if there is not a usable one (FR-ADM-07).

    Refused before the change rather than defaulted, because a default reason is
    a field everybody stops reading.
    """
    reason = str(body.get("reason") or "").strip()
    if not reason or len(reason) > MAX_REASON:
        return None
    return reason


async def _record(
    request: Request,
    caller: Caller,
    outcome: Outcome,
    *,
    action: str,
    reason: str,
    detail: dict[str, Any],
) -> None:
    """One admin event, with the actor and the reason in their own columns.

    The reason goes in the field the audit schema already has for it rather than
    into `detail`, so a query for "every administrative change and why" is a
    column read instead of a search through JSON.
    """
    await request.app.state.audit.record(
        EventType.ADMIN_ACTION,
        outcome,
        actor=caller.person_uuid,
        target=str(detail.get("entity_id") or ""),
        reason=reason,
        session_id=caller.sid,
        detail={"action": action, **detail},
    )


async def _json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def _iso(moment: Any) -> str | None:
    return moment.isoformat() if moment is not None else None


def _fingerprint(certificate: str) -> str:
    """SHA-256 over the DER, in the form every other tool prints it.

    The same string `openssl x509 -fingerprint -sha256` produces, so an
    administrator can compare what the broker holds with what the partner sent
    without converting anything.
    """
    import base64
    import hashlib

    body = "".join(
        line for line in certificate.splitlines() if line and not line.startswith("-----")
    )
    try:
        der = base64.b64decode(body, validate=True)
    except (ValueError, TypeError):  # pragma: no cover - a stored document that parsed
        return "unreadable"
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


__all__ = ["ADMIN_ROLE", "ReasonCode", "router"]
