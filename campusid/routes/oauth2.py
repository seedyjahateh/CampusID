"""The authorization and token endpoints (FR-OP-03…06, FR-OP-10, FR-OP-11).

Two routes carry the whole downstream flow, and the shape of each is dictated by
one question: *who is this response going to?*

**`GET /oauth2/authorize` answers to a browser**, so its refusals split in two.
Until the `client_id` and `redirect_uri` have both been checked against a
registration there is nowhere safe to send an error, and it lands on the
broker's own page. After that, errors go back to the client's registered URI
with `error` and `state`, which is what lets an application show its user
something useful. Getting that boundary wrong is precisely an open redirect, so
the phase is explicit in the code and `may_be_redirected` is asserted on the way
out rather than assumed.

**`POST /oauth2/token` answers to a server**, so it is JSON, `no-store`, and
uniformly `invalid_grant` — a caller holding a code they should not have learns
nothing about which check refused them.

**The login handoff is server-side.** An unauthenticated authorization request
is stashed in Redis under an opaque id, and the browser is sent through SAML
with a `return_to` that the outstanding request carries *on the server*. Nothing
an attacker can reach decides where a completed login lands, and no cookie has
to survive the cross-site POST back from the IdP.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from datetime import datetime, timedelta
from typing import Annotated, Any, Final
from urllib.parse import unquote, urlencode

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from campusid.audit.events import EventType, Outcome
from campusid.audit.log import correlation_id as audit_correlation_id
from campusid.audit.log import set_correlation_id
from campusid.errors import BrokerError, ReasonCode
from campusid.logging import get_logger
from campusid.oidc import bearer, pkce
from campusid.oidc.clients import ClientType, OidcClient
from campusid.oidc.errors import (
    INVALID_CLIENT,
    INVALID_REQUEST,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_GRANT_TYPE,
    UNSUPPORTED_RESPONSE_TYPE,
    OAuthError,
    may_be_redirected,
)
from campusid.oidc.grants import (
    AuthorizationCode,
    GrantReuse,
    RefreshToken,
    new_family_id,
)
from campusid.oidc.identity import ReleasedIdentity, release_to
from campusid.oidc.jwt import SigningKey
from campusid.oidc.tokens import (
    ACCESS_TOKEN_TTL,
    TokenContext,
    access_token,
    id_token,
)
from campusid.routes.errors import reject
from campusid.saml.stores import utcnow
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session

log = get_logger(__name__)

router = APIRouter(tags=["oidc"])

PENDING_KEY_PREFIX: Final = "oidc:pending:"
PENDING_TTL: Final = timedelta(minutes=10)
"""How long a login may take before the authorization request it interrupted is
forgotten. Generous enough for a password manager and an MFA prompt, short
enough that an abandoned request is not a stored record of who was trying to
sign in where."""

RESPONSE_TYPE_CODE: Final = "code"
GRANT_AUTHORIZATION_CODE: Final = "authorization_code"
# The literal grant-type name from RFC 6749, not a credential. Flagged by the
# bandit rule because of the word "token"; suppressed here rather than renamed,
# since the string has to be exactly this.
GRANT_REFRESH_TOKEN: Final = "refresh_token"  # noqa: S105
GRANT_CLIENT_CREDENTIALS: Final = "client_credentials"

NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}
"""RFC 6749 §5.1. These responses contain credentials; an intermediary caching
one hands the next person through it somebody else's tokens."""


# --- the authorization endpoint --------------------------------------------


@router.get("/oauth2/authorize")
async def authorize(
    request: Request,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    response_type: str | None = None,
    scope: str | None = None,
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    request_uri: str | None = None,
    pending: str | None = None,
) -> Response:
    """Authenticate the user, then hand the client an authorization code."""
    app_state = request.app.state
    reference = audit_correlation_id()

    if pending is not None:
        # Resuming after a login. The parameters come from the server-side
        # stash rather than from the query, so a browser returning from the IdP
        # cannot alter the request it started.
        stashed = await _take_pending(request, pending)
        if stashed is None:
            return reject(ReasonCode.GRANT_INVALID, "the authorization request expired", reference)
        parameters = stashed
        reference = _rejoin_chain(parameters, reference)
    elif request_uri is not None:
        # A pushed request (FR-OP-07). Everything comes from the record the
        # client authenticated to create; the rest of the query is ignored
        # entirely, because a parameter that could be overridden here would
        # undo the point of pushing the request in the first place.
        pushed = await app_state.pushed_requests.consume(request_uri, client_id=client_id or "")
        if pushed is None:
            return reject(
                ReasonCode.GRANT_INVALID, "the request_uri is unknown, spent or expired", reference
            )
        parameters = {**pushed, "client_id": client_id, "pushed": True}
        reference = _rejoin_chain(parameters, reference)
    else:
        parameters = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            # Records how the request arrived rather than whether a parameter
            # was present. A client configured for mandatory PAR is checked
            # against this, and the record a PAR client pushed does not itself
            # contain a `request_uri` — so testing for the parameter would
            # reject exactly the clients the setting is meant to protect.
            "pushed": False,
        }

    # Phase one: everything needed before there is a safe place to send errors.
    try:
        client = await app_state.clients.require(parameters.get("client_id"))
        destination = client.validated_redirect_uri(parameters.get("redirect_uri"))
    except BrokerError as exc:
        return reject(exc.reason, exc.detail or "", reference)

    # Phase two: from here a refusal can be reported to the client.
    try:
        _check_authorization_request(client, parameters)
        session = await _current_session(request)
    except OAuthError as exc:
        return _error_redirect(destination, exc, parameters.get("state"), reference)

    if session is None:
        return await _start_login(request, parameters)

    code = await _issue_code(request, client, parameters, session)
    query = {"code": code, "state": parameters["state"], "iss": app_state.settings.oidc_issuer}
    log.info("oidc.code.issued", client_id=client.client_id, correlation_id=reference)
    return RedirectResponse(f"{destination}?{urlencode(query)}", status_code=303, headers=NO_STORE)


def _provenance(request: Request) -> dict[str, str | None]:
    """Where a request came from. See the note in `routes/saml.py`: the peer we
    can see, never a forwarded header we cannot verify."""
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:512] or None,
    }


def _rejoin_chain(parameters: dict[str, Any], fallback: str) -> str:
    """Adopt the correlation id a stashed or pushed request was created under.

    An authorization request that had to wait for a login, or that was pushed
    minutes before the browser arrived, is the same event chain as the request
    that started it (FR-AUD-02). Both records are written by us and read only by
    us, which is the whole reason it is safe to adopt an id from them — a
    caller-supplied one would let anybody merge their requests into somebody
    else's chain.
    """
    stored = parameters.get("correlation_id")
    if not isinstance(stored, str) or not stored:
        return fallback
    set_correlation_id(stored)
    return stored


def _check_authorization_request(client: OidcClient, parameters: dict[str, Any]) -> None:
    """Everything the protocol requires of an authorization request.

    Runs after the redirect URI is validated, so every refusal here can be
    reported to the client rather than shown on our own page.
    """
    if parameters.get("response_type") != RESPONSE_TYPE_CODE:
        raise OAuthError(
            UNSUPPORTED_RESPONSE_TYPE,
            ReasonCode.GRANT_INVALID,
            "only the authorization code flow is supported",
        )
    if not parameters.get("state"):
        # FR-OP-06. `state` is the client's CSRF defence, and a provider that
        # accepts a request without one has removed the client's ability to
        # protect itself whether the client noticed or not.
        raise OAuthError(INVALID_REQUEST, ReasonCode.GRANT_INVALID, "state is required")
    if not parameters.get("nonce"):
        # Binds the ID token to this browser's request. Without it a token
        # captured elsewhere can be replayed into this client's login handler.
        raise OAuthError(INVALID_REQUEST, ReasonCode.GRANT_INVALID, "nonce is required")

    pkce.assert_supported_method(parameters.get("code_challenge_method"))
    pkce.assert_valid_challenge(parameters.get("code_challenge"))
    client.granted_scopes(parameters.get("scope"))

    if client.require_pushed_authorization_requests and not parameters.get("pushed"):
        raise OAuthError(
            INVALID_REQUEST,
            ReasonCode.GRANT_INVALID,
            "this client must use pushed authorization requests",
        )


async def _issue_code(
    request: Request,
    client: OidcClient,
    parameters: dict[str, Any],
    session: Session,
) -> str:
    """Record what was authorised and return the code that redeems it."""
    settings = request.app.state.settings
    policy = request.app.state.policies.get(client.client_id)
    scopes = client.granted_scopes(parameters.get("scope"))

    identity = release_to(
        session,
        policy,
        scopes,
        pairwise_salt=settings.pairwise_salt_bytes,
        scope=settings.scope,
    )

    code: str = await request.app.state.grants.issue_code(
        AuthorizationCode(
            client_id=client.client_id,
            redirect_uri=parameters["redirect_uri"],
            code_challenge=parameters["code_challenge"],
            scopes=tuple(sorted(scopes)),
            subject=identity.subject,
            sid=session.sid,
            family_id=new_family_id(),
            nonce=parameters.get("nonce"),
            auth_time=session.auth_time,
            acr=session.acr,
            amr=session.amr,
        )
    )
    # The only moment we learn that this client now holds a session for this
    # person. By logout time it is unrecoverable from anything else, so it is
    # recorded here rather than inferred later (FR-OP-12).
    await request.app.state.client_sessions.record(session.sid, client.client_id)

    await _record_release(request, client, session, identity)
    await request.app.state.audit.record(
        EventType.AUTHZ_CODE_ISSUED,
        Outcome.SUCCESS,
        actor=session.subject_key,
        subject=session.subject_key,
        target=client.client_id,
        session_id=session.sid,
        detail={"scopes": sorted(scopes)},
        **_provenance(request),
    )
    return code


async def _record_release(
    request: Request,
    client: OidcClient,
    session: Session,
    identity: ReleasedIdentity,
) -> None:
    """Write the disclosure record (FR-ARP-06, FERPA §99.32).

    Every attribute *considered*, released or not, with the basis and the rule
    id. A record of only what was released cannot answer "why does this app not
    see my email?", and under §99.32 the institution has to be able to produce
    what was disclosed to whom — which means the denials are part of the record,
    not noise beside it.

    The values are redacted by the emitter; the names and the reasoning are what
    make this useful.
    """
    await request.app.state.audit.record(
        EventType.ATTRIBUTE_RELEASE,
        Outcome.SUCCESS,
        actor=session.subject_key,
        subject=session.subject_key,
        target=client.client_id,
        session_id=session.sid,
        detail={
            "protocol": "oidc",
            "released": sorted(identity.claims),
            "decisions": [
                {
                    "attribute": decision.attribute,
                    "released": decision.released,
                    "basis": decision.basis.value,
                    "rule_id": decision.rule_id,
                }
                for decision in identity.decisions
            ],
        },
        **_provenance(request),
    )


# --- pushed authorization requests (FR-OP-07) ------------------------------


@router.post("/oauth2/par")
async def pushed_authorization_request(
    request: Request,
    response_type: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
    state: Annotated[str | None, Form()] = None,
    nonce: Annotated[str | None, Form()] = None,
    code_challenge: Annotated[str | None, Form()] = None,
    code_challenge_method: Annotated[str | None, Form()] = None,
    request_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> Response:
    """Accept an authorization request directly from a client (RFC 9126).

    The request is validated here, where the client is authenticated and can be
    told what is wrong, rather than at the redirect where the only audience is a
    browser. That is most of the value: a client integrating against this
    endpoint gets a 400 with a reason instead of a user seeing an error page.
    """
    state_ = request.app.state
    try:
        client = await _authenticated_client(request, client_id, client_secret)
        if request_uri is not None:
            # RFC 9126 §2.1. A pushed request that pushes a reference is either
            # confused or an attempt to make us dereference something; either
            # way there is no sensible meaning to give it.
            raise OAuthError(
                INVALID_REQUEST,
                ReasonCode.GRANT_INVALID,
                "request_uri is not accepted at this endpoint",
            )

        parameters: dict[str, Any] = {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "pushed": True,
            "correlation_id": audit_correlation_id(),
        }
        # Validated now rather than at redemption. The redirect URI check comes
        # first for the same reason as at the authorization endpoint: nothing
        # else is meaningful until we know where this would send somebody.
        client.validated_redirect_uri(redirect_uri)
        _check_authorization_request(client, parameters)
    except OAuthError as exc:
        return _token_error(exc)

    reference, expires_in = await state_.pushed_requests.push(client.client_id, parameters)
    log.info("oidc.par.pushed", client_id=client.client_id)
    return JSONResponse(
        {"request_uri": reference, "expires_in": expires_in},
        status_code=201,
        headers=NO_STORE,
    )


# --- the token endpoint ----------------------------------------------------


@router.post("/oauth2/token")
async def token(
    request: Request,
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> Response:
    """Exchange a code, a refresh token, or a client's own credentials."""
    try:
        client = await _authenticated_client(request, client_id, client_secret)
        if grant_type == GRANT_AUTHORIZATION_CODE:
            body = await _exchange_code(request, client, code, redirect_uri, code_verifier)
        elif grant_type == GRANT_REFRESH_TOKEN:
            body = await _exchange_refresh_token(request, client, refresh_token)
        elif grant_type == GRANT_CLIENT_CREDENTIALS:
            body = await _client_credentials(request, client, scope)
        else:
            raise OAuthError(
                UNSUPPORTED_GRANT_TYPE,
                ReasonCode.GRANT_INVALID,
                f"{grant_type!r} is not supported",
            )
    except GrantReuse as exc:
        # The one event in this module that is a security incident rather than a
        # record of normal operation: a credential was presented twice, so one
        # of the two presentations was not the client.
        log.error("oidc.grant.reuse_detected", reason=exc.reason.value, detail=exc.detail)
        await request.app.state.audit.record(
            EventType.GRANT_REUSE_DETECTED,
            Outcome.FAILURE,
            target=client_id,
            reason=exc.reason.value,
            **_provenance(request),
        )
        return _token_error(exc)
    except OAuthError as exc:
        await request.app.state.audit.record(
            EventType.AUTHZ_DENIED,
            Outcome.DENIED,
            target=client_id,
            reason=exc.reason.value,
            detail={"grant_type": grant_type},
            **_provenance(request),
        )
        return _token_error(exc)

    return JSONResponse(body, headers=NO_STORE)


async def _exchange_code(
    request: Request,
    client: OidcClient,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> dict[str, Any]:
    """Redeem an authorization code (FR-OP-04)."""
    if not code:
        raise OAuthError(INVALID_REQUEST, ReasonCode.GRANT_INVALID, "code is required")

    state = request.app.state
    grant = await state.grants.redeem_code(
        code, client_id=client.client_id, redirect_uri=redirect_uri or ""
    )
    # After the code is spent, so a failed verifier still consumes it: a code is
    # single-use whatever the reason its redemption failed, and leaving it live
    # would let an attacker who stole it retry the verifier.
    pkce.verify(code_verifier, grant.code_challenge)

    now = utcnow()
    context = TokenContext(
        issuer=state.settings.oidc_issuer,
        client_id=client.client_id,
        subject=grant.subject,
        sid=grant.sid,
        family_id=grant.family_id,
        scopes=frozenset(grant.scopes),
        auth_time=grant.auth_time or now,
        nonce=grant.nonce,
        acr=grant.acr,
        amr=grant.amr,
        claims=await _claims_for(request, client, grant),
    )
    refresh = await state.grants.issue_refresh_token(
        RefreshToken(
            client_id=client.client_id,
            scopes=grant.scopes,
            subject=grant.subject,
            sid=grant.sid,
            family_id=grant.family_id,
            generation=0,
            issued_at=now,
        )
    )
    await state.audit.record(
        EventType.TOKEN_ISSUED,
        Outcome.SUCCESS,
        actor=client.client_id,
        subject=grant.subject,
        target=client.client_id,
        session_id=grant.sid,
        detail={"scopes": sorted(grant.scopes), "family": grant.family_id},
        **_provenance(request),
    )
    return _token_response(state.oidc_keys.active, context, now, refresh, with_id_token=True)


async def _exchange_refresh_token(
    request: Request, client: OidcClient, presented: str | None
) -> dict[str, Any]:
    """Rotate a refresh token and reissue (FR-OP-08)."""
    if not presented:
        raise OAuthError(INVALID_REQUEST, ReasonCode.GRANT_INVALID, "refresh_token is required")

    state = request.app.state
    now = utcnow()
    rotated, record = await state.grants.rotate_refresh_token(
        presented, client_id=client.client_id, now=now
    )

    context = TokenContext(
        issuer=state.settings.oidc_issuer,
        client_id=client.client_id,
        subject=record.subject,
        sid=record.sid,
        family_id=record.family_id,
        scopes=frozenset(record.scopes),
        auth_time=now,
    )
    await state.audit.record(
        EventType.TOKEN_REFRESHED,
        Outcome.SUCCESS,
        actor=client.client_id,
        subject=record.subject,
        target=client.client_id,
        session_id=record.sid,
        detail={"generation": record.generation, "family": record.family_id},
        **_provenance(request),
    )
    # No ID token on refresh. An ID token asserts that somebody authenticated
    # just now; reissuing one because a machine presented a refresh token would
    # be asserting a login that did not happen, and a client enforcing `max_age`
    # would be misled by it.
    return _token_response(state.oidc_keys.active, context, now, rotated, with_id_token=False)


async def _client_credentials(
    request: Request, client: OidcClient, requested: str | None
) -> dict[str, Any]:
    """RFC 6749 §4.4 — a client acting as itself (FR-SCIM-13).

    The grant a provisioning client needs, because an SIS runs at three in the
    morning and there is nobody to authenticate. Four things follow from there
    being no person involved, and each is a deliberate omission rather than an
    unfinished edge:

    **Confidential clients only.** The secret *is* the authentication. A public
    client has none, so this grant would let anybody who knows a `client_id`
    mint a token in its name.

    **No `openid` and no ID token.** An ID token asserts that somebody signed
    in; issuing one here would assert a login that did not happen.

    **No refresh token.** The client holds a secret and can ask again whenever
    it likes, so a refresh token would be a second long-lived credential with
    nothing to justify it.

    **No session, so no `sid`.** The token carries the client as its own
    subject, which is what makes an audit record say "the SIS did this" rather
    than attributing a machine's action to whichever person it happened to be
    editing.
    """
    if client.client_type is not ClientType.CONFIDENTIAL:
        raise OAuthError(
            UNAUTHORIZED_CLIENT,
            ReasonCode.CLIENT_AUTHENTICATION_FAILED,
            "client_credentials requires a confidential client",
        )

    granted = client.machine_scopes(requested)
    state = request.app.state
    now = utcnow()

    context = TokenContext(
        issuer=state.settings.oidc_issuer,
        client_id=client.client_id,
        subject=client.client_id,
        sid="",
        family_id="",
        scopes=granted,
        auth_time=now,
    )
    access, _ = access_token(context, state.oidc_keys.active, now=now)

    await state.audit.record(
        EventType.TOKEN_ISSUED,
        Outcome.SUCCESS,
        actor=client.client_id,
        subject=client.client_id,
        target=client.client_id,
        detail={"grant": "client_credentials", "scopes": sorted(granted)},
        **_provenance(request),
    )
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
        "scope": " ".join(sorted(granted)),
    }


def _token_response(
    key: SigningKey,
    context: TokenContext,
    now: datetime,
    refresh: str,
    *,
    with_id_token: bool,
) -> dict[str, Any]:
    access, _ = access_token(context, key, now=now)
    body: dict[str, Any] = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
        "refresh_token": refresh,
        "scope": " ".join(sorted(context.scopes)),
    }
    if with_id_token:
        body["id_token"] = id_token(context, key, now=now)
    return body


async def _claims_for(
    request: Request, client: OidcClient, grant: AuthorizationCode
) -> dict[str, Any]:
    """Re-derive the identity claims at redemption time.

    Not carried on the authorization code, deliberately. A code lives sixty
    seconds, but re-evaluating means a policy change or a FERPA suppression that
    landed in between takes effect on this token rather than on the next one.
    The session is the source; if it is gone, the claims are empty and only the
    protocol claims remain.
    """
    session = await request.app.state.sessions.load(grant.sid)
    if session is None:
        return {}

    settings = request.app.state.settings
    identity = release_to(
        session,
        request.app.state.policies.get(client.client_id),
        frozenset(grant.scopes),
        pairwise_salt=settings.pairwise_salt_bytes,
        scope=settings.scope,
    )
    return identity.claims


# --- introspection and revocation (FR-OP-09) -------------------------------


@router.post("/oauth2/introspect")
async def introspect(
    request: Request,
    token: Annotated[str, Form()],
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> Response:
    """Report whether an access token is currently usable (RFC 7662).

    Two rules make this endpoint safe to expose.

    **It is authenticated.** An unauthenticated introspection endpoint is an
    oracle: anyone holding a stolen token can ask us to decode it for them, and
    learn the subject and scope they could not read from the signature alone.

    **A client may only introspect its own tokens.** Asking about somebody
    else's returns `{"active": false}` — the same answer as an expired token,
    deliberately, so the endpoint cannot be used to enumerate which tokens exist
    or which client issued them.

    Every failure is `active: false` rather than an error, which is what RFC
    7662 asks for and what keeps the response shape from leaking anything.
    """
    state = request.app.state
    try:
        client = await _authenticated_client(request, client_id, client_secret)
    except OAuthError as exc:
        return _token_error(exc)

    try:
        verified = await bearer.verify(
            token,
            keys=state.oidc_keys,
            grants=state.grants,
            issuer=state.settings.oidc_issuer,
            now=utcnow(),
        )
    except OAuthError:
        return JSONResponse({"active": False}, headers=NO_STORE)

    if verified.client_id != client.client_id:
        return JSONResponse({"active": False}, headers=NO_STORE)

    claims = verified.claims
    return JSONResponse(
        {
            "active": True,
            "sub": claims["sub"],
            "client_id": claims["client_id"],
            "scope": claims.get("scope", ""),
            "token_type": "Bearer",
            "exp": claims["exp"],
            "iat": claims["iat"],
            "iss": claims["iss"],
            "aud": claims["aud"],
            "jti": claims["jti"],
            "sid": claims["sid"],
        },
        headers=NO_STORE,
    )


@router.post("/oauth2/revoke")
async def revoke(
    request: Request,
    token: Annotated[str, Form()],
    token_type_hint: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> Response:
    """Revoke a token and everything descended from the same grant (RFC 7009).

    Returns 200 whether or not the token existed, which the RFC requires: a
    caller that could tell "revoked" from "never existed" could enumerate
    tokens through the endpoint meant to destroy them. Only a client
    authentication failure is an error.

    Revocation acts on the *family*, not the token. RFC 7009 says revoking a
    refresh token should invalidate the access tokens issued alongside it, and
    since ours are JWTs the only way to do that is the family marker the bearer
    check consults. Revoking an access token therefore also ends its refresh
    lineage — which is what a client calling this at logout actually wants, and
    is stated here because the narrower reading would leave a live refresh token
    behind after an explicit revocation.
    """
    state = request.app.state
    try:
        client = await _authenticated_client(request, client_id, client_secret)
    except OAuthError as exc:
        return _token_error(exc)

    family = await _family_of(request, token, client)
    if family is not None:
        await state.grants.revoke_family(family)
        await state.audit.record(
            EventType.TOKEN_REVOKED,
            Outcome.SUCCESS,
            actor=client.client_id,
            target=client.client_id,
            detail={"family": family, "hint": token_type_hint},
            **_provenance(request),
        )
        log.info("oidc.token.revoked", client_id=client.client_id)

    return Response(status_code=200, headers=NO_STORE)


async def _family_of(request: Request, token: str, client: OidcClient) -> str | None:
    """Find the grant family a presented token belongs to, if it is this
    client's.

    Tries the access-token shape first and the refresh-token store second,
    rather than trusting `token_type_hint`: the hint is a caller's optimisation,
    and RFC 7009 §2.1 requires a server to try the other type anyway when it
    fails. Believing it would make revocation silently do nothing for a client
    that got the hint wrong.
    """
    state = request.app.state
    try:
        verified = await bearer.verify(
            token,
            keys=state.oidc_keys,
            grants=state.grants,
            issuer=state.settings.oidc_issuer,
            now=utcnow(),
        )
    except OAuthError:
        pass
    else:
        return verified.family_id if verified.client_id == client.client_id else None

    record: RefreshToken | None = await state.grants.describe_refresh_token(token)
    if record is None or record.client_id != client.client_id:
        return None
    return record.family_id


# --- client authentication -------------------------------------------------


async def _authenticated_client(
    request: Request, client_id: str | None, client_secret: str | None
) -> OidcClient:
    """Identify the caller at the token endpoint (RFC 6749 §2.3.1).

    HTTP Basic first, because the RFC says a server must support it and some
    clients send only that; the form parameters are the documented alternative.
    A public client authenticates with nothing, and `authenticate` is what
    refuses a confidential client trying the same.
    """
    basic_id, basic_secret = _basic_credentials(request)
    presented_id = basic_id or client_id
    presented_secret = basic_secret if basic_id else client_secret

    client: OidcClient = await request.app.state.clients.require(presented_id)
    if client.client_type is ClientType.CONFIDENTIAL:
        client.authenticate(presented_secret)
    elif presented_secret:
        # A public client presenting a secret is either misconfigured or is
        # somebody who found one. Neither should be quietly accepted.
        raise OAuthError(
            INVALID_CLIENT,
            ReasonCode.CLIENT_AUTHENTICATION_FAILED,
            "a public client must not present a secret",
        )
    return client


def _basic_credentials(request: Request) -> tuple[str | None, str | None]:
    """Decode an `Authorization: Basic` header, if there is a usable one."""
    header = request.headers.get("authorization", "")
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None, None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None, None
    identifier, separator, secret = decoded.partition(":")
    if not separator:
        return None, None
    # RFC 6749 §2.3.1 requires both halves to be form-urlencoded before being
    # base64'd. A client_id containing a `:` or a `+` decodes to the wrong value
    # otherwise, and the failure looks like a bad secret.
    return unquote(identifier), unquote(secret)


# --- the login handoff -----------------------------------------------------


async def _current_session(request: Request) -> Session | None:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    session: Session | None = await request.app.state.sessions.load(sid)
    return session


async def _start_login(request: Request, parameters: dict[str, Any]) -> Response:
    """Stash the authorization request and send the browser through SAML.

    The stash id travels in the `return_to` we hand `/saml/sso`, which keeps it
    on the server-side outstanding request rather than in a cookie. A cookie
    would have to survive the cross-site POST back from the IdP, which means
    `SameSite=None` and one more thing to get right.
    """
    pending = secrets.token_urlsafe(24)
    await request.app.state.redis.set(
        f"{PENDING_KEY_PREFIX}{pending}",
        # The chain id travels with the request, so the code eventually issued
        # joins the authorization that asked for it even though a whole SAML
        # login happened in between (FR-AUD-02).
        json.dumps({**parameters, "correlation_id": audit_correlation_id()}),
        ex=int(PENDING_TTL.total_seconds()),
    )
    resume = f"/oauth2/authorize?{urlencode({'pending': pending})}"
    return RedirectResponse(
        f"/saml/sso?{urlencode({'return_to': resume})}", status_code=303, headers=NO_STORE
    )


async def _take_pending(request: Request, pending: str) -> dict[str, Any] | None:
    """Fetch and delete a stashed request.

    Single-use: a stash id that survived its redemption would let the back
    button replay a completed authorization and mint a second code for a request
    the user made once.
    """
    raw = await request.app.state.redis.getdel(f"{PENDING_KEY_PREFIX}{pending}")
    if raw is None:
        return None
    parameters: dict[str, Any] = json.loads(raw)
    return parameters


# --- error responses -------------------------------------------------------


def _error_redirect(
    destination: str, exc: OAuthError, state: str | None, reference: str
) -> Response:
    """Report a refusal to the client's registered redirect URI.

    Only reached from phase two, after the URI was matched against the
    registration. The assertion is the backstop for a future edit that calls
    this from phase one: an error about the destination must never be sent to
    the destination, and the consequence of getting it wrong is an open
    redirect.
    """
    assert may_be_redirected(exc), f"{exc.reason.value} must not be reported to the client"

    log.info(
        "oidc.authorize.rejected",
        error=exc.error,
        reason=exc.reason.value,
        correlation_id=reference,
    )
    query: dict[str, str] = {"error": exc.error}
    if state:
        query["state"] = state
    return RedirectResponse(f"{destination}?{urlencode(query)}", status_code=303, headers=NO_STORE)


def _token_error(exc: OAuthError) -> JSONResponse:
    """The token endpoint's uniform refusal.

    `error_description` is deliberately absent. The endpoint answers a server,
    and a server holding a code it should not have learns nothing useful from
    being told which check refused it — while a legitimate client's integration
    bug is visible in our logs, where the detail actually is.
    """
    status = 401 if exc.error == INVALID_CLIENT else 400
    log.info("oidc.token.rejected", error=exc.error, reason=exc.reason.value, detail=exc.detail)
    return JSONResponse({"error": exc.error}, status_code=status, headers=NO_STORE)
