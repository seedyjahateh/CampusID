"""Ending a session, everywhere (FR-SES-04, FR-SES-05, FR-OP-12).

`GET /oauth2/logout` is the OIDC end-session endpoint: a user pressing "sign
out" in one application. `POST /admin/sessions/terminate` is FR-SES-05: an
administrator ending every session a compromised account has.

Both do the same three things, and the order is the requirement:

1. **Destroy the local session first.** Everything after this is best-effort,
   and doing it first is what makes "partial failures do not block local
   destruction" true by construction rather than by remembering to catch the
   right exceptions. A client whose logout endpoint is down must not be able to
   keep somebody signed in here.
2. **Revoke the token families.** A destroyed session already stops `/userinfo`,
   but an access token would otherwise stay introspectable and a refresh token
   would still rotate. Revocation is what makes the logout reach the tokens.
3. **Notify the clients**, concurrently, with bounded retries, auditing every
   failure.

The SAML half of FR-SES-04 — SLO to the upstream IdP — is not here. Keycloak's
descriptor advertises a `SingleLogoutService` and honouring it properly means
minting a signed `LogoutRequest`, handling the asynchronous `LogoutResponse`,
and deciding what to do when the IdP has other service providers in the same
session. That is a milestone of its own rather than a paragraph, and shipping a
half-version that sometimes logs the user out of the IdP would be worse than a
documented gap: an operator would believe the upstream session was gone.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Final
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from campusid.audit.events import EventType, Outcome
from campusid.errors import ReasonCode
from campusid.logging import get_logger
from campusid.oidc.jwt import JwtError, decode
from campusid.oidc.logout import DeliveryOutcome
from campusid.routes.errors import reject
from campusid.saml.stores import utcnow
from campusid.session.cookies import SESSION_COOKIE, clear_session_cookie
from campusid.session.store import Session

log = get_logger(__name__)

router = APIRouter(tags=["oidc"])

NO_STORE: Final = {"Cache-Control": "no-store"}
DEFAULT_LANDING: Final = "/"

HINT_LEEWAY: Final = timedelta(days=3650)
"""What makes an *expired* `id_token_hint` acceptable.

Named rather than inlined, because "leeway of ten years" needs its reason beside
it. A hint is by definition presented after the token it refers to has done its
job, and requiring a live one would make logout fail for exactly the long
sessions where it matters most. The signature is what is being trusted here, not
the freshness.
"""


@router.get("/oauth2/logout")
async def end_session(
    request: Request,
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
    client_id: str | None = None,
) -> Response:
    """End the browser's session and tell every client that held it.

    `post_logout_redirect_uri` is matched against the registration of the client
    that vouched for the request, exactly like an authorization redirect URI. An
    unmatched one is *ignored* rather than refused: the user asked to be logged
    out, they have been logged out, and turning that into an error page would
    make a misconfigured client look like a failed logout. What it must never do
    is redirect there.
    """
    state_ = request.app.state
    sid = request.cookies.get(SESSION_COOKIE)
    session = await state_.sessions.load(sid) if sid else None

    if session is not None:
        await _end(request, session)

    destination = await _post_logout_destination(
        request, id_token_hint, post_logout_redirect_uri, client_id, state
    )
    response = RedirectResponse(destination, status_code=303, headers=NO_STORE)
    clear_session_cookie(response)
    return response


@router.post("/admin/sessions/terminate")
async def terminate_sessions(
    request: Request,
    subject_key: Annotated[str, Form()],
) -> Response:
    """End every session belonging to one person (FR-SES-05).

    The operator affordance behind "this account is compromised". It reports how
    many sessions were ended and which clients were told, because an
    administrator acting on an incident needs to know what actually happened —
    "done" is not an answer when the next question is whether the attacker still
    has a live session somewhere.
    """
    if request.app.state.settings.is_production:
        # M5 puts this behind real administrator authentication. Until then it
        # is refused in production rather than left reachable, because an
        # unauthenticated endpoint that ends anybody's session on request is a
        # denial-of-service tool with a helpful name.
        return reject(ReasonCode.CLIENT_AUTHENTICATION_FAILED, "administrator auth required")

    sessions = request.app.state.sessions
    sids = await sessions.sids_for(subject_key)

    outcomes: list[DeliveryOutcome] = []
    for sid in sids:
        session = await sessions.load(sid)
        if session is not None:
            # A different event type from an ordinary logout: the actor is an
            # administrator rather than the person, and an investigation reads
            # the two very differently.
            outcomes.extend(await _end(request, session, event=EventType.SESSION_TERMINATED))
    await sessions.terminate_subject(subject_key)

    await request.app.state.audit.record(
        EventType.ADMIN_ACTION,
        Outcome.SUCCESS,
        actor="administrator",
        subject=subject_key,
        detail={"action": "terminate_sessions", "sessions": len(sids)},
        **_provenance(request),
    )
    log.warning("session.terminated_by_administrator", sessions=len(sids))
    return JSONResponse(
        {
            "terminated": len(sids),
            "notified": [outcome.client_id for outcome in outcomes if outcome.delivered],
            "unreachable": [outcome.client_id for outcome in outcomes if not outcome.delivered],
        },
        headers=NO_STORE,
    )


async def _end(
    request: Request, session: Session, *, event: EventType = EventType.SESSION_ENDED
) -> list[DeliveryOutcome]:
    """Destroy a session and propagate the fact.

    Local destruction first. Everything after it is best-effort, and doing it in
    this order is what makes that guarantee structural rather than a matter of
    catching the right exceptions.
    """
    state = request.app.state
    client_ids = await state.client_sessions.clients_for(session.sid)

    await state.sessions.destroy(session.sid)
    await state.client_sessions.forget(session.sid)
    # A destroyed session already stops `/userinfo`, which consults it. This is
    # for the rest: an access token would otherwise stay introspectable until it
    # expired, and a refresh token would keep rotating against a session that no
    # longer exists.
    await state.grants.revoke_session_families(session.sid)

    clients = []
    for client_id in client_ids:
        client = await state.clients.get(client_id)
        if client is not None:
            clients.append(client)

    outcomes: list[DeliveryOutcome] = await state.logout_notifier.notify(
        clients,
        sid=session.sid,
        subject=session.subject_key,
        key=state.oidc_keys.active,
        now=utcnow(),
    )
    await state.audit.record(
        event,
        Outcome.SUCCESS,
        subject=session.subject_key,
        session_id=session.sid,
        detail={
            "notified": [outcome.client_id for outcome in outcomes if outcome.delivered],
            "unreachable": [outcome.client_id for outcome in outcomes if not outcome.delivered],
        },
        **_provenance(request),
    )
    for failure in (outcome for outcome in outcomes if not outcome.delivered):
        # Its own event, not a field on the one above. "Which clients never got
        # the message" is the question an operator asks after an incident, and
        # it should be answerable by event type rather than by unpacking JSON.
        await state.audit.record(
            EventType.LOGOUT_DELIVERY_FAILED,
            Outcome.FAILURE,
            subject=session.subject_key,
            target=failure.client_id,
            session_id=session.sid,
            detail={"attempts": failure.attempts, "detail": failure.detail},
            **_provenance(request),
        )

    log.info(
        "session.ended",
        clients=len(clients),
        delivered=sum(1 for outcome in outcomes if outcome.delivered),
    )
    return outcomes


def _provenance(request: Request) -> dict[str, str | None]:
    """Where a request came from. See the note in `routes/saml.py`."""
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:512] or None,
    }


async def _post_logout_destination(
    request: Request,
    id_token_hint: str | None,
    post_logout_redirect_uri: str | None,
    client_id: str | None,
    state: str | None,
) -> str:
    """Where to send the browser afterwards, if anywhere safe.

    The URI has to be registered by the client the request claims to come from,
    and the claim has to be backed by something: either an `id_token_hint` we
    signed, or a `client_id` whose registration lists the URI. Without that this
    endpoint is an open redirect that also logs people out — the log-out part
    making it *more* attractive, since the user is mid-flow and expecting to be
    sent somewhere.
    """
    if not post_logout_redirect_uri:
        return DEFAULT_LANDING

    named = client_id or _client_from_hint(request, id_token_hint)
    client = await request.app.state.clients.get(named) if named else None
    if client is None or post_logout_redirect_uri not in client.post_logout_redirect_uris:
        # Ignored, not refused. The user asked to be logged out and has been;
        # an error page here would report a misconfigured client as a failed
        # logout, which is the wrong thing to tell somebody who is leaving.
        log.info("logout.redirect_ignored", client_id=named)
        return DEFAULT_LANDING

    return (
        f"{post_logout_redirect_uri}?{urlencode({'state': state})}"
        if state
        else (post_logout_redirect_uri)
    )


def _client_from_hint(request: Request, id_token_hint: str | None) -> str | None:
    """Read `aud` from an ID token we issued.

    Verified, not merely decoded. An unverified hint is an attacker-supplied
    claim about which client is asking, and it decides which registration the
    redirect URI is checked against — so believing it unverified would let
    anyone borrow a client's registered post-logout URIs.

    Expiry is not enforced: a hint is by definition presented after the token it
    refers to has done its job, and requiring a live one would make logout fail
    for exactly the long sessions it matters most for.
    """
    if not id_token_hint:
        return None
    try:
        claims = decode(
            id_token_hint,
            request.app.state.oidc_keys.verification_keys,
            issuer=request.app.state.settings.oidc_issuer,
            audience=None,
            now=utcnow(),
            leeway=HINT_LEEWAY,
        )
    except JwtError:
        return None

    audience: Any = claims.get("aud")
    if isinstance(audience, str):
        return audience
    if isinstance(audience, list) and len(audience) == 1:
        return str(audience[0])
    return None
