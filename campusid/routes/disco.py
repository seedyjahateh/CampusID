"""The IdP discovery service (FR-SAML-10).

Implements the OASIS Identity Provider Discovery Service Protocol: a caller
arrives with `entityID`, `return` and `returnIDParam`, picks an IdP, and is
sent back to `return` with the choice appended.

**The `return` parameter is an open redirect waiting to happen**, and it is the
whole security story of this endpoint. A discovery service exists to redirect
somewhere it was told to go, which is the shape of the vulnerability, so the
destination is validated against our own origin and a bad one is *rejected*
rather than redirected to a default. The spec's own answer — check `return`
against the endpoints in the requesting SP's metadata — is the same idea; with
a single SP that reduces to same-origin.

The rest is convenience: the chosen IdP is remembered in a cookie so returning
users are not asked twice, and `isPassive` honours that cookie without showing
a page. A federation with two hundred IdPs lives or dies on that cookie.
"""

from __future__ import annotations

from html import escape
from typing import Annotated, Final
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from campusid.errors import BrokerError, ReasonCode
from campusid.logging import get_logger
from campusid.routes.errors import reject

log = get_logger(__name__)

router = APIRouter(tags=["saml"])

LAST_IDP_COOKIE: Final = "__Host-campusid_idp"
LAST_IDP_MAX_AGE: Final = 60 * 60 * 24 * 180
"""Six months. A preference, not a credential: it names a public entityID and
grants nothing on its own."""

CHOOSER_PAGE: Final = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Choose your institution</title>
<style>
  body {{ font: 16px/1.5 system-ui, sans-serif; margin: 0; padding: 2rem; }}
  main {{ max-width: 32rem; margin: 0 auto; }}
  h1 {{ font-size: 1.25rem; }}
  ul {{ list-style: none; padding: 0; }}
  li {{ margin: .5rem 0; }}
  a {{ display: block; padding: .75rem 1rem; border: 1px solid #ccd;
       border-radius: .375rem; text-decoration: none; color: inherit; }}
  a:hover, a:focus {{ border-color: #558; background: #f4f6fb; }}
  small {{ color: #667; }}
</style>
<main>
  <h1>Choose your institution</h1>
  <ul>{options}</ul>
</main>
"""


@router.get("/disco")
async def discovery(
    request: Request,
    entityID: Annotated[str | None, Query()] = None,
    return_to: Annotated[str | None, Query(alias="return")] = None,
    returnIDParam: Annotated[str, Query()] = "entityID",
    isPassive: Annotated[bool, Query()] = False,
    idpEntityID: Annotated[str | None, Query()] = None,
) -> Response:
    """Choose an IdP, or record a choice already made."""
    state = request.app.state
    try:
        destination = validated_return(return_to, state.settings.base_url)
    except BrokerError as exc:
        # Refused, not redirected somewhere safe: a discovery service that
        # quietly rewrites a bad `return` teaches callers that anything works,
        # and hides the attempt.
        #
        # `entityID` names the SP that sent the user here. Logged rather than
        # trusted: with one SP it tells us nothing we do not already know, but
        # a refused `return` alongside an unexpected entityID is the shape of
        # somebody probing the redirect.
        log.warning("disco.return_refused", requesting_sp=entityID, return_url=return_to)
        return reject(exc.reason, exc.detail or "")

    if idpEntityID is not None:
        return _remember_and_return(destination, returnIDParam, idpEntityID)

    remembered = request.cookies.get(LAST_IDP_COOKIE)
    if remembered is not None and (isPassive or return_to is not None):
        # The whole point of the cookie: a returning user is not asked again.
        return _remember_and_return(destination, returnIDParam, remembered)

    if isPassive:
        # Passive means "answer without interacting". With nothing remembered,
        # the correct answer is to return no selection at all.
        return RedirectResponse(destination, status_code=303)

    return await _chooser(request, destination, returnIDParam)


def validated_return(return_to: str | None, base_url: str) -> str:
    """Confirm the caller's return URL belongs to us, or refuse it.

    Compared on scheme *and* host *and* port together, because any one of them
    alone is forgeable: `https://broker.test.attacker.com` shares a prefix,
    `http://broker.test` shares a host, and `https://broker.test:8443` shares
    both while pointing somewhere else entirely.

    Raises rather than returning None so the failure carries its own reason
    code, the same way every other refusal in the broker does.
    """
    if return_to is None:
        return f"{base_url}/saml/sso"

    ours, theirs = urlsplit(base_url), urlsplit(return_to)
    if (theirs.scheme, theirs.netloc) != (ours.scheme, ours.netloc):
        raise BrokerError(
            ReasonCode.INVALID_RETURN_URL, f"return URL {return_to!r} is not one of ours"
        )
    return return_to


def _remember_and_return(destination: str, param: str, entity_id: str) -> Response:
    """Send the caller back with their choice, and remember it."""
    separator = "&" if "?" in destination else "?"
    response = RedirectResponse(
        f"{destination}{separator}{urlencode({param: entity_id})}", status_code=303
    )
    response.set_cookie(
        LAST_IDP_COOKIE,
        entity_id,
        max_age=LAST_IDP_MAX_AGE,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


async def _chooser(request: Request, destination: str, param: str) -> Response:
    """Render the list of registered IdPs."""
    entities = [entity for entity in await request.app.state.registry.list_idps() if entity.enabled]

    options = "".join(
        # Every value is escaped: an entityID and display name come from
        # metadata a peer supplied, so they are untrusted text on our page.
        '<li><a href="/disco?{query}">{name}<br><small>{entity_id}</small></a></li>'.format(
            query=escape(
                urlencode(
                    {"return": destination, "returnIDParam": param, "idpEntityID": entity.entity_id}
                )
            ),
            name=escape(entity.display_name or entity.entity_id),
            entity_id=escape(entity.entity_id),
        )
        for entity in entities
    )
    if not options:
        options = "<li><small>No identity providers are registered.</small></li>"

    return HTMLResponse(CHOOSER_PAGE.format(options=options), headers={"Cache-Control": "no-store"})
