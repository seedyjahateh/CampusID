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
from typing import Annotated, Any, Final
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from campusid.audit.events import EventType, Outcome
from campusid.audit.log import correlation_id as audit_correlation_id
from campusid.audit.log import set_correlation_id
from campusid.errors import BrokerError, ReasonCode, SamlRejected
from campusid.identity.assertions import from_saml
from campusid.identity.registry import STATUS_ACTIVE
from campusid.identity.release import merge, registry_attributes
from campusid.logging import get_logger
from campusid.observability.tracing import span
from campusid.routes.errors import reject
from campusid.saml.authn_request import AuthnRequestPolicy, prepare_redirect
from campusid.saml.gate import AssertionFacts
from campusid.saml.stores import OutstandingRequest, utcnow
from campusid.security.throttle import Throttled
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
            correlation_id=audit_correlation_id(),
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
    # The first link in the chain FR-AUD-02 asks for. It names no subject
    # because at this point nobody has authenticated — the correlation id is
    # what joins it to the events that will.
    await state.audit.record(
        EventType.AUTH_REQUEST,
        Outcome.SUCCESS,
        target=descriptor.entity_id,
        detail={"request_id": prepared.request_id, "protocol": "saml"},
        **_provenance(request),
    )
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
    reference = audit_correlation_id()

    # Before the gate, because the gate is the expensive part: parsing and
    # verifying a signature on every request somebody cares to send is a denial
    # of service that costs the attacker nothing (NFR-SEC-10). Per address only
    # here — there is no account to charge until the assertion has been read,
    # and reading it is what this is protecting.
    try:
        await state.throttle.check(address=_address(request))
    except Throttled as exc:
        await state.audit.record(
            EventType.AUTH_FAILURE,
            Outcome.DENIED,
            reason=exc.reason,
            detail={"bucket": exc.bucket},
            **_provenance(request),
        )
        # `throttled` rather than `failure`: the credential was never examined,
        # and folding the two together would make a burst of refusals look like
        # a campus-wide authentication outage.
        state.metrics.authenticated(idp=None, protocol="saml", outcome="throttled")
        return _too_many(exc, reference)

    # Every failure from here is a `BrokerError`, so there is one rejection
    # path rather than three shapes of it — which is what makes the uniform
    # error response easy to keep uniform.
    try:
        # No span of its own: the request span the correlation middleware opens
        # is already this handler's, and a second one wrapping the same work
        # would add a layer to every trace and tell a reader nothing.
        await assert_request_binding(request, RelayState)
        document = _decode(SAMLResponse)
        facts = await state.gate.validate(document)
    except BrokerError as exc:
        # The audit record carries the reason code the browser is not told. That
        # asymmetry is the point: an attacker learns nothing, and an operator
        # searching the trail for the reference on the error page finds exactly
        # which of the fifteen checks refused it.
        await state.audit.record(
            EventType.AUTH_FAILURE,
            Outcome.FAILURE,
            reason=exc.reason.value,
            **_provenance(request),
        )
        # The issuer is deliberately not a label here. It comes off an assertion
        # that just failed validation, so it is whatever the sender wrote — and a
        # label taken from an unverified document is a label an attacker picks.
        state.metrics.authenticated(idp=None, protocol="saml", outcome="failure")
        state.metrics.assertion_refused(exc.reason.value)
        return reject(exc.reason, exc.detail or "", reference)

    if facts.correlation_id:
        # Rejoin the chain this login started in (FR-AUD-02). The id came off
        # the outstanding request, which only our own `/saml/sso` writes — an
        # id taken from the response would let an issuer merge its logins into
        # somebody else's chain.
        set_correlation_id(facts.correlation_id)
        reference = facts.correlation_id

    # Who this is, before there is a session to attach it to. A session for a
    # person the registry will not name is a session nothing can later revoke:
    # deprovisioning works by person, so an unresolved login would be
    # unreachable by every later lifecycle action.
    try:
        with span("identity.resolve"):
            person_uuid = await _resolve_person(state, facts)
    except BrokerError as exc:
        await state.audit.record(
            EventType.AUTH_FAILURE,
            Outcome.FAILURE,
            reason=exc.reason.value,
            target=facts.issuer,
            **_provenance(request),
        )
        # Past the gate, so the issuer is verified and safe to label with. This
        # is a refusal of our own — the assertion was genuine and we declined to
        # seat the person — which is worth telling apart from a bad signature.
        state.metrics.authenticated(idp=facts.issuer, protocol="saml", outcome="refused")
        return reject(exc.reason, exc.detail or "", reference)

    # What the IdP said, corrected by what we know. Identifiers we issue and
    # entitlements we derive replace anything asserted under those names — an
    # upstream that could assert `eduPersonEntitlement` into a session would be
    # able to grant itself anything.
    with span("attributes.merge", **{"saml.asserted_count": len(facts.attributes)}):
        attributes = merge(
            facts.attributes,
            await registry_attributes(
                person_uuid,
                registry=state.identity,
                lifecycle=state.lifecycle,
                scope=state.settings.scope,
            ),
            scope=state.settings.scope,
        )

    # Counts rather than names. A trace leaves this system and is read by people
    # who were never granted the identity registry, so what an attribute *was*
    # stays in the audit trail where the access controls are.
    with span("session.create", **{"identity.attribute_count": len(attributes)}):
        session = await state.sessions.create(
            idp_entity_id=facts.issuer,
            name_id=facts.name_id,
            name_id_format=facts.name_id_format,
            auth_time=facts.authn_instant,
            acr=facts.authn_context,
            amr=("pwd",),
            session_index=facts.session_index,
            attributes=attributes,
            person_uuid=person_uuid,
        )
    await state.audit.record(
        EventType.AUTH_SUCCESS,
        Outcome.SUCCESS,
        actor=session.subject_key,
        subject=session.subject_key,
        target=facts.issuer,
        session_id=session.sid,
        # The merged set, not what arrived: the record should say what the
        # session actually carries, and the two differ by exactly the values we
        # overrode.
        detail={"acr": facts.authn_context, "attributes": attributes},
        **_provenance(request),
    )
    await state.audit.record(
        EventType.SESSION_CREATED,
        Outcome.SUCCESS,
        actor=session.subject_key,
        subject=session.subject_key,
        target=facts.issuer,
        session_id=session.sid,
        **_provenance(request),
    )
    state.metrics.authenticated(idp=facts.issuer, protocol="saml", outcome="success")
    log.info(
        "session.established",
        idp=facts.issuer,
        acr=facts.authn_context,
        correlation_id=reference,
    )

    response = RedirectResponse(facts.return_to or DEFAULT_LANDING, status_code=303)
    set_session_cookie(response, session.sid)
    clear_request_binding_cookie(response)
    return response


async def _resolve_person(state: Any, facts: AssertionFacts) -> str:
    """Match a validated assertion to a person, or refuse the login.

    Two refusals, and they are different failures. A manual-review outcome means
    the assertion matched somebody on an email address and nothing stronger;
    linking on that is the account takeover PRD §8.4 rule 4 declines to perform,
    so a human decides. A suspended person means the upstream IdP will still
    happily authenticate them and our deprovisioning is what stops them — which
    is the entire point of holding identity here rather than at the IdP.
    """
    resolution = await state.identity.resolve(
        from_saml(facts.issuer, facts.name_id, facts.attributes)
    )
    if not resolution.linked:
        raise BrokerError(
            ReasonCode.IDENTITY_REVIEW_REQUIRED,
            f"{facts.issuer} asserted somebody who needs manual linking",
        )

    person_uuid = str(resolution.person_uuid)
    person = await state.identity.get(person_uuid)
    if person is not None and person.status != STATUS_ACTIVE:
        raise BrokerError(ReasonCode.IDENTITY_SUSPENDED, f"person {person_uuid} is {person.status}")
    return person_uuid


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
            # The upstream's own name for this person, alongside ours. Shown
            # because this is the person's own view of their own session, and
            # "which account at which IdP is this" is the first thing anybody
            # debugging a federated login needs.
            "name_id": session.name_id,
            "idp": session.idp_entity_id,
            "acr": session.acr,
            "auth_time": session.auth_time.isoformat(),
            "attributes": session.attributes,
        }
    )


# --- helpers ---------------------------------------------------------------


def _address(request: Request) -> str | None:
    """The peer we are actually talking to.

    Not `X-Forwarded-For`. Behind a proxy this is the proxy, which limits the
    whole fleet as one — honest, and the wrong direction only for availability.
    Trusting the header would let an attacker mint a fresh bucket per request by
    changing one string, which is the wrong direction for everything.
    """
    return request.client.host if request.client else None


def _too_many(exc: Throttled, reference: str) -> Response:
    """One shape for a refusal that never reached a credential.

    `Retry-After` is a real header for a real wait. Somebody who has tripped a
    limit needs to know whether to wait a moment or to stop, and an attacker
    already knows they are being refused.
    """
    return JSONResponse(
        {"error": "too_many_requests", "reference": reference},
        status_code=429,
        headers={"Retry-After": str(exc.retry_after), "Cache-Control": "no-store"},
    )


def _provenance(request: Request) -> dict[str, str | None]:
    """Where a request came from, for the audit record (FR-AUD-01).

    `client.host` is the peer we are actually talking to, not an
    `X-Forwarded-For` header. Behind a proxy that is the proxy's address, which
    is honest — a forwarded header is attacker-controlled unless the proxy chain
    is known and trusted, and recording an attacker's chosen IP as fact is worse
    than recording the hop we can see.
    """
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:512] or None,
    }


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
