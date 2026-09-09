"""The SAML endpoints.

Three routes, and between them the whole browser-facing flow:

``GET /saml/metadata``  what peers load to trust us
``GET /saml/sso``       start a login
``POST /saml/acs``      receive the answer

The interesting decisions are about what the ACS does *around* the gate, since
the gate already decides whether the assertion itself is genuine.

**Errors are uniform.** Every rejection returns the same status and the same
page, carrying a correlation id and nothing else. The reason code is audited,
never rendered: telling an attacker which of fifteen checks refused their
forgery is free reconnaissance, and the distinction is worthless to a real user
who can only report the id anyway (NFR-UX-02).

**The request binding is checked before the gate runs.** It is cheap, needs no
crypto, and failing it means this response was not solicited by this browser —
a different and more alarming fact than a bad signature.
"""

from __future__ import annotations

import base64
import binascii
import secrets
from datetime import timedelta
from typing import Annotated, Final

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from campusid.errors import BrokerError, ReasonCode, SamlRejected
from campusid.logging import get_logger
from campusid.saml.authn_request import AuthnRequestPolicy, prepare_redirect
from campusid.saml.stores import OutstandingRequest, utcnow
from campusid.session.cookies import (
    REQUEST_BINDING_COOKIE,
    SESSION_COOKIE,
    clear_request_binding_cookie,
    set_request_binding_cookie,
    set_session_cookie,
)

log = get_logger(__name__)

router = APIRouter(tags=["saml"])

REQUEST_TTL: Final = timedelta(minutes=5)
BINDING_KEY_PREFIX: Final = "saml:binding:"

ERROR_PAGE: Final = """<!doctype html>
<title>Sign-in failed</title>
<h1>Sign-in failed</h1>
<p>We could not complete your sign-in. Please try again.</p>
<p>If you contact support, quote reference <code>{correlation_id}</code>.</p>
"""


@router.get("/saml/metadata")
async def metadata(request: Request) -> Response:
    """Publish our SP metadata.

    Rendered once at startup rather than per request: a descriptor that varied
    between fetches would give two peers different ideas of who we are.
    """
    return Response(
        content=request.app.state.sp_metadata,
        media_type="application/samlmetadata+xml",
        headers={"Content-Disposition": 'attachment; filename="campusid-metadata.xml"'},
    )


@router.get("/saml/sso")
async def start_sso(request: Request, idp: str | None = None) -> Response:
    """Begin SP-initiated SSO against a registered IdP."""
    state = request.app.state
    entity_id = idp or state.settings.saml_default_idp
    if entity_id is None:
        return _reject(ReasonCode.UNKNOWN_ISSUER, "no IdP named and no default configured")

    descriptor = await state.registry.describe(entity_id)
    if descriptor is None:
        return _reject(ReasonCode.UNKNOWN_ISSUER, f"{entity_id!r} is not a registered IdP")

    prepared = prepare_redirect(
        AuthnRequestPolicy(
            entity_id=state.settings.saml_entity_id,
            acs_url=state.settings.saml_acs_url,
        ),
        descriptor.redirect_sso_url,
        state.sp_signing_key.private_pem,
    )

    await state.request_store.remember(
        OutstandingRequest(
            request_id=prepared.request_id,
            idp_entity_id=descriptor.entity_id,
            relay_state=prepared.relay_state,
            created_at=utcnow(),
        ),
        ttl=REQUEST_TTL,
    )

    binding_nonce = secrets.token_urlsafe(32)
    await state.redis.set(
        _binding_key(prepared.relay_state),
        binding_nonce,
        ex=int(REQUEST_TTL.total_seconds()),
    )

    response = RedirectResponse(prepared.redirect_url, status_code=303)
    set_request_binding_cookie(response, binding_nonce)
    log.info("saml.authn_request.sent", idp=descriptor.entity_id, request_id=prepared.request_id)
    return response


@router.post("/saml/acs")
async def assertion_consumer_service(
    request: Request,
    SAMLResponse: Annotated[str, Form()],
    RelayState: Annotated[str | None, Form()] = None,
) -> Response:
    """Receive a SAML Response and, if it survives the gate, start a session."""
    state = request.app.state
    correlation_id = _correlation_id()

    # Every failure from here is a `BrokerError`, so there is one rejection
    # path rather than three shapes of it — which is what makes the uniform
    # error response easy to keep uniform.
    try:
        await assert_request_binding(request, RelayState)
        document = _decode(SAMLResponse)
        facts = await state.gate.validate(document)
    except BrokerError as exc:
        return _reject(exc.reason, exc.detail or "", correlation_id)

    session = await state.sessions.create(
        idp_entity_id=facts.issuer,
        name_id=facts.name_id,
        name_id_format=facts.name_id_format,
        auth_time=facts.authn_instant,
        acr=facts.authn_context,
        amr=("pwd",),
        session_index=facts.session_index,
        attributes=facts.attributes,
    )
    log.info(
        "session.established",
        idp=facts.issuer,
        acr=facts.authn_context,
        correlation_id=correlation_id,
    )

    response = RedirectResponse("/me", status_code=303)
    set_session_cookie(response, session.sid)
    clear_request_binding_cookie(response)
    return response


@router.get("/me")
async def whoami(request: Request) -> Response:
    """What the current session says about this browser.

    A landing place for a completed login, and the closest thing M1 has to a
    relying application. The self-service attribute-release view (FR-ARP-07)
    grows from here in M2.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    session = await request.app.state.sessions.load(sid) if sid else None
    if session is None:
        return JSONResponse({"authenticated": False}, status_code=401)

    return JSONResponse(
        {
            "authenticated": True,
            "subject": session.subject_key,
            "idp": session.idp_entity_id,
            "acr": session.acr,
            "auth_time": session.auth_time.isoformat(),
            "attributes": session.attributes,
        }
    )


# --- helpers ---------------------------------------------------------------


def _binding_key(relay_state: str) -> str:
    return f"{BINDING_KEY_PREFIX}{relay_state}"


async def assert_request_binding(request: Request, relay_state: str | None) -> None:
    """Confirm this response answers a request *this browser* started.

    Without it, an attacker can hand a victim a valid `RelayState` and have
    them log in as somebody else — login CSRF. The stored nonce is fetched and
    deleted in one step so a captured `RelayState` cannot be reused, and the
    comparison is constant-time because one side is attacker-supplied.

    Raises rather than returning a boolean so it composes with every other
    check in the ACS, all of which signal failure the same way.
    """
    if relay_state is None:
        raise SamlRejected(ReasonCode.REQUEST_BINDING_INVALID, "response carries no RelayState")

    presented = request.cookies.get(REQUEST_BINDING_COOKIE)
    expected = await request.app.state.redis.getdel(_binding_key(relay_state))
    if presented is None or expected is None or not secrets.compare_digest(presented, expected):
        raise SamlRejected(
            ReasonCode.REQUEST_BINDING_INVALID,
            "the response was not solicited by this browser",
        )


def _decode(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SamlRejected(
            ReasonCode.MALFORMED_RESPONSE, "SAMLResponse is not valid base64"
        ) from exc


def _correlation_id() -> str:
    return secrets.token_hex(8)


def _reject(reason: ReasonCode, detail: str, correlation_id: str | None = None) -> Response:
    """Audit the reason, show the user a page that reveals none of it.

    Same status and same body for every failure: varying the response by reason
    would let an attacker enumerate the gate's checks by observation.
    """
    correlation_id = correlation_id or _correlation_id()
    log.warning("saml.rejected", reason=reason.value, detail=detail, correlation_id=correlation_id)
    return HTMLResponse(
        ERROR_PAGE.format(correlation_id=correlation_id),
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )
