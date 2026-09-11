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

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response, StreamingResponse

from campusid.admin.people import as_json as person_json
from campusid.audit.dashboard import DEFAULT_STEP, DEFAULT_WINDOW, Window
from campusid.audit.dashboard import as_json as dashboard_json
from campusid.audit.events import EventType, Outcome
from campusid.audit.export import CONTENT_TYPE, filename, ndjson
from campusid.audit.query import DEFAULT_LIMIT, Query, as_json
from campusid.authz.engine import AAL1
from campusid.config import Environment
from campusid.errors import MetadataRejected, ReasonCode
from campusid.logging import get_logger
from campusid.mfa import assurance
from campusid.saml.parser import MAX_DOCUMENT_BYTES
from campusid.saml.stores import utcnow
from campusid.session.cookies import SESSION_COOKIE, set_session_cookie

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_ROLE: Final = "iam-admin"
AUDITOR_ROLE: Final = "auditor"

READERS: Final = frozenset({ADMIN_ROLE, AUDITOR_ROLE})
"""Who may read the audit trail.

Reading it and changing the federation are different privileges. An auditor
should be able to answer "what happened" without also being able to disable an
identity provider — and requiring the administrator role to read the trail would
mean every audit request carried the rights to cause the thing being audited.
"""

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


async def _admin(request: Request, *, roles: frozenset[str] = frozenset({ADMIN_ROLE})) -> Caller:
    """The three conditions, in the order that decides what the caller is told.

    `roles` names who may pass. It is a set rather than a single name because
    reading the trail and changing the federation are different privileges: an
    auditor should be able to answer "what happened" without also being able to
    disable an identity provider, and collapsing the two would make every audit
    request require the rights to cause the thing being audited.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    session = await request.app.state.sessions.load(sid) if sid else None
    if session is None or session.person_uuid is None:
        raise Refused(UNAUTHENTICATED, 401)

    held = await request.app.state.role_assignments.roles_for(session.person_uuid)
    if not roles & set(held):
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


# --- people (FR-ADM-04, FR-ADM-06) ------------------------------------------


@router.get("/people/{person_uuid}")
async def person(person_uuid: str, request: Request) -> JSONResponse:
    """Everything the broker knows about one person (FR-ADM-04).

    The question a service desk actually asks: somebody says they cannot reach a
    system, and the person on the other end needs to see what the broker believes
    about them without opening six tables.

    Open to auditors as well as administrators. Answering "why does this
    application see my name" is reading, and it should not require the rights to
    change the answer.
    """
    try:
        await _admin(request, roles=READERS)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    if not _is_uuid(person_uuid):
        return _refuse(NOT_FOUND, 404)

    view = await request.app.state.people.view(person_uuid)
    if view is None:
        return _refuse(NOT_FOUND, 404)
    return JSONResponse(person_json(view), headers=NO_STORE)


@router.post("/people/{person_uuid}/sessions/terminate")
async def terminate_sessions(person_uuid: str, request: Request) -> JSONResponse:
    """End one of a person's sessions, or all of them (FR-ADM-06).

    Administrators only, unlike the view beside it: ending somebody's session is
    a change, and an auditor reads.

    Sessions are addressed by the abbreviated handle the view shows rather than
    by the session identifier, because the identifier is a credential and a
    console that had to put one in a URL would be putting it in a browser
    history.
    """
    try:
        caller = await _admin(request)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    if not _is_uuid(person_uuid):
        return _refuse(NOT_FOUND, 404)

    body = await _json(request)
    reason = _reason(body)
    if reason is None:
        return _refuse(REASON_REQUIRED, 400)

    handle = str(body.get("handle") or "").strip() or None
    ended = await request.app.state.people.terminate(person_uuid, handle)

    await request.app.state.audit.record(
        EventType.SESSION_TERMINATED,
        Outcome.SUCCESS,
        actor=caller.person_uuid,
        subject=person_uuid,
        reason=reason,
        session_id=caller.sid,
        # The handles, not the identifiers. An audit record is read by more
        # people than a session identifier should be.
        detail={"sessions": ended, "scope": "one" if handle else "all"},
    )
    return JSONResponse({"terminated": ended}, headers=NO_STORE)


def _is_uuid(value: str) -> bool:
    """Whether a path segment could be a person at all.

    Checked before the store, so a malformed id is a 404 rather than a database
    error — and so the two are indistinguishable to somebody guessing.
    """
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


# --- the audit trail (FR-AUD-03) --------------------------------------------


@router.get("/audit")
async def search_audit(request: Request) -> JSONResponse:
    """Query the trail by subject, actor, relying party, type, outcome or window.

    Open to auditors as well as administrators: reading what happened and being
    able to change what happens are different privileges, and requiring the
    second to do the first would put the rights to cause an incident in the hands
    of everybody investigating one.
    """
    try:
        await _admin(request, roles=READERS)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    try:
        query = _query_from(request)
    except ValueError as exc:
        return _refuse({"error": "invalid_request", "detail": str(exc)}, 400)

    page = await request.app.state.audit_query.search(query)
    return JSONResponse(
        {
            "events": [as_json(event) for event in page.events],
            # Null when this is the last page, rather than absent: a caller
            # looping until the key disappears and a caller looping until it is
            # null should both terminate.
            "next_cursor": page.next_cursor,
        },
        headers=NO_STORE,
    )


@router.get("/audit/subject/{subject:path}")
async def subject_timeline(subject: str, request: Request) -> JSONResponse:
    """One person's history, oldest first (US-02, FR-ADM-05).

    The most recent page, reversed for reading. A timeline that started at the
    beginning of a busy account's history would open on a first login from three
    years ago and show nothing since.
    """
    try:
        await _admin(request, roles=READERS)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    try:
        limit = _int(request.query_params.get("limit"), default=DEFAULT_LIMIT)
    except ValueError as exc:
        return _refuse({"error": "invalid_request", "detail": str(exc)}, 400)

    events = await request.app.state.audit_query.timeline(subject, limit=limit)
    return JSONResponse(
        {"subject": subject, "events": [as_json(event) for event in events]},
        headers=NO_STORE,
    )


@router.get("/dashboard")
async def dashboard(request: Request) -> JSONResponse:
    """Every panel for one window, in one read (FR-AUD-07).

    One call rather than seven endpoints, because a dashboard drawn from seven
    separate reads shows seven slightly different moments — and the one thing
    worse than a stale number is a set of numbers that cannot all have been true
    at once.

    Everything is derived from the audit trail rather than from a separate
    metrics store. That costs read performance and buys the property that
    matters: when the console and the trail disagree, one of them is wrong, and
    there is only one of them.
    """
    try:
        await _admin(request, roles=READERS)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    try:
        window = _window_from(request)
    except ValueError as exc:
        return _refuse({"error": "invalid_request", "detail": str(exc)}, 400)

    return JSONResponse(
        {
            "window": {
                "since": window.since.isoformat(),
                "until": window.until.isoformat(),
                "step_seconds": int(window.step.total_seconds()),
            },
            **dashboard_json(await request.app.state.dashboard.panels(window)),
        },
        headers=NO_STORE,
    )


def _window_from(request: Request) -> Window:
    """The span a dashboard request covers.

    Defaults to the last week at hourly resolution, which is the shape somebody
    opening a console without asking for anything means. The ceiling is applied
    by the store rather than here, so a caller is clamped rather than refused.
    """
    params = request.query_params
    until = _moment(params.get("until")) or utcnow()
    since = _moment(params.get("since")) or until - DEFAULT_WINDOW
    step = timedelta(seconds=_int(params.get("step"), default=int(DEFAULT_STEP.total_seconds())))

    if since >= until:
        raise ValueError("the window ends before it starts")
    if step <= timedelta(0):
        raise ValueError("a bucket has to have a width")
    return Window(since=since, until=until, step=step)


@router.get("/audit/export")
async def export_audit(request: Request) -> Response:
    """Stream matching events as newline-delimited JSON (FR-AUD-08).

    The format every SIEM ingests without being told anything: one event per
    line, no enclosing array, and a file that can be split and resumed at a line
    boundary. Streamed rather than assembled, because a year of a real trail does
    not fit in memory at either end of the wire.

    Every line carries its hash and the one before it, so a SIEM holding the
    export can verify the chain without asking the broker anything — which is
    most of the point of exporting an audit trail.
    """
    try:
        caller = await _admin(request, roles=READERS)
    except Refused as exc:
        return _refuse(exc.body, exc.status)

    try:
        query = _query_from(request)
    except ValueError as exc:
        return _refuse({"error": "invalid_request", "detail": str(exc)}, 400)

    # An export is a bulk read of the trail by a named person. Recorded as a
    # first-class event rather than left to the web server's access log, because
    # "who took a copy of the audit trail, and of what" is a question the audit
    # trail should be able to answer about itself.
    await request.app.state.audit.record(
        EventType.AUDIT_EXPORTED,
        Outcome.SUCCESS,
        actor=caller.person_uuid,
        session_id=caller.sid,
        detail={
            "since": query.since.isoformat() if query.since else None,
            "until": query.until.isoformat() if query.until else None,
            "subject": query.subject,
        },
    )

    return StreamingResponse(
        ndjson(request.app.state.audit_query, query),
        media_type=CONTENT_TYPE,
        headers={
            **NO_STORE,
            # Named so the wrong window does not get ingested from somebody's
            # downloads folder.
            "Content-Disposition": f'attachment; filename="{filename(query)}"',
        },
    )


def _query_from(request: Request) -> Query:
    """Build a query from the URL, refusing anything that is not one.

    Parsed rather than passed through: a malformed timestamp that reached the
    database would come back as a 500 that says the broker is broken, and an
    unbounded `limit` would turn one request into a full table read.
    """
    params = request.query_params
    return Query(
        subject=params.get("subject") or None,
        actor=params.get("actor") or None,
        target=params.get("target") or None,
        event_type=params.get("event_type") or None,
        outcome=params.get("outcome") or None,
        correlation_id=params.get("correlation_id") or None,
        since=_moment(params.get("since")),
        until=_moment(params.get("until")),
        limit=_int(params.get("limit"), default=DEFAULT_LIMIT),
        before_seq=_int(params.get("cursor"), default=None),
    )


def _moment(value: str | None) -> datetime | None:
    """An ISO-8601 timestamp, read as UTC when it carries no offset.

    Assumed rather than rejected, because an operator typing a date into a URL
    means the day, not the day in whatever timezone the server happens to run
    in — and a naive value compared against `timestamptz` is an error Postgres
    raises rather than an answer anybody wanted.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not an ISO-8601 timestamp") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _int(value: str | None, *, default: int | None) -> Any:
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a number") from exc


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
