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
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from campusid.errors import BrokerError, ReasonCode, SamlRejected
from campusid.logging import get_logger
from campusid.routes.errors import correlation_id as new_correlation_id
from campusid.routes.errors import reject
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
DEFAULT_LANDING: Final = "/me"


def local_path(candidate: str | None) -> str | None:
    """Accept a same-origin path, or nothing.

    A login endpoint that redirects wherever it is told is an open redirect with
    a session cookie attached, so this is deliberately strict: one leading
    slash, no scheme, no host. `//evil.test` is the case that matters — it is
    protocol-relative, so a browser reads it as another origin while a naive
    `startswith("/")` check reads it as local. Backslashes are refused because
    some browsers normalise them to slashes and some do not, which is a
    disagreement no security check should sit on top of.
    """
    if candidate is None:
        return None
    if (
        not candidate.startswith("/")
        or candidate.startswith(("//", "/\\"))
        or "\\" in candidate
        or "://" in candidate
    ):
        raise BrokerError(ReasonCode.INVALID_RETURN_URL, f"{candidate!r} is not a local path")
    return candidate


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
async def start_sso(
    request: Request, idp: str | None = None, return_to: str | None = None
) -> Response:
    """Begin SP-initiated SSO against a registered IdP.

    ``return_to`` is where the browser goes once the login succeeds — used by
    the OIDC authorization endpoint to resume a pending request. It is validated
    as a local path here and then carried *server-side* on the outstanding
    request, so nothing an attacker can reach decides where a completed login
    lands.
    """
    state = request.app.state
    try:
        destination = local_path(return_to)
    except BrokerError as exc:
        return reject(exc.reason, exc.detail or "")

    entity_id = idp or state.settings.saml_default_idp
    if entity_id is None:
        # Nobody named an IdP and there is no default, so ask. Discovery sends
        # the browser back here with `?idp=`, which is why `returnIDParam` is
        # `idp` rather than the protocol's `entityID` default.
        query = urlencode({"return": state.settings.saml_sso_url, "returnIDParam": "idp"})
        return RedirectResponse(f"/disco?{query}", status_code=303)

    descriptor = await state.registry.describe(entity_id)
    if descriptor is None:
        return reject(ReasonCode.UNKNOWN_ISSUER, f"{entity_id!r} is not a registered IdP")

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
            return_to=destination,
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
    correlation_id = new_correlation_id()

    # Every failure from here is a `BrokerError`, so there is one rejection
    # path rather than three shapes of it — which is what makes the uniform
    # error response easy to keep uniform.
    try:
        await assert_request_binding(request, RelayState)
        document = _decode(SAMLResponse)
        facts = await state.gate.validate(document)
    except BrokerError as exc:
        return reject(exc.reason, exc.detail or "", correlation_id)

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

    response = RedirectResponse(facts.return_to or DEFAULT_LANDING, status_code=303)
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
