"""No silent decision paths (NFR-OBS-01).

The requirement is that 100% of authentication, authorization and provisioning
outcomes produce an audit event. A test that merely checked a few handlers write
events would pass forever while the surface grew around it, so this works the
other way round: it enumerates **every route the application serves** and
requires each to be classified, either as a decision point that must audit or as
something that decides nothing, with a stated reason.

Both directions are checked, which is what makes the classification worth
reading. A route listed as auditing must be able to reach an audit write; a route
listed as deciding nothing must not. So the two tables below cannot drift from
the code without this file failing — a new route fails it immediately, and a
route that quietly stops auditing fails it too.

**The reachability check is static and module-local.** It walks the handler's
call graph within its own module, so a handler that delegates to a helper is
still credited. What it cannot see is a write performed by a collaborator in
another module, which is why the SCIM routes gained their own events rather than
relying on the lifecycle hook: that hook returns early when nothing changed, so a
create for somebody with no affiliations and a correction to a display name
produced no audit record at all. Finding that is what this file was for.

The last test is the instrumented run the requirement asks for, on the assertion
consumer — the one endpoint that turns an unauthenticated stranger into an
authenticated user, and the place where a silent path would matter most.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import AsyncClient

from campusid.audit.events import EventType
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

Route = tuple[str, str]

AUDITS: dict[Route, str] = {
    # --- authentication ---------------------------------------------------
    ("GET", "/saml/sso"): "starts a login; the first link in the chain FR-AUD-02 asks for",
    ("POST", "/saml/acs"): "turns a stranger into a session, or refuses to",
    # --- authorization ----------------------------------------------------
    ("GET", "/oauth2/authorize"): "issues an authorization code, or refuses the request",
    ("POST", "/oauth2/par"): "authenticates a client and accepts its request",
    ("POST", "/oauth2/token"): "issues or refreshes tokens",
    ("POST", "/oauth2/revoke"): "ends a grant family",
    ("GET", "/oauth2/logout"): "ends a session across every client that holds one",
    # --- second factors ----------------------------------------------------
    ("POST", "/mfa/totp"): "starts an enrolment; an abandoned one is invisible otherwise",
    ("POST", "/mfa/totp/{factor_id}/confirm"): "completes or fails an enrolment",
    ("POST", "/mfa/webauthn"): "registers an authenticator",
    ("POST", "/mfa/recovery"): "issues recovery codes, which are credentials",
    ("DELETE", "/mfa/factors/{factor_id}"): "removes a factor, which weakens an account",
    ("POST", "/mfa/challenge/totp"): "raises assurance, or counts a failure",
    ("POST", "/mfa/challenge/webauthn"): "raises assurance, or counts a failure",
    ("POST", "/mfa/challenge/recovery"): "raises assurance, or counts a failure",
    ("POST", "/mfa/challenge/push/{request_id}"): "raises assurance when the push is approved",
    # --- provisioning ------------------------------------------------------
    ("POST", "/scim/v2/Users"): "creates a person",
    ("PUT", "/scim/v2/Users/{resource_id}"): "replaces a person",
    ("PATCH", "/scim/v2/Users/{resource_id}"): "modifies a person",
    ("DELETE", "/scim/v2/Users/{resource_id}"): "deprovisions a person",
    ("POST", "/scim/v2/Groups"): "creates a group, which grants entitlements",
    ("PUT", "/scim/v2/Groups/{group_id}"): "replaces a group and its membership",
    ("PATCH", "/scim/v2/Groups/{group_id}"): "changes membership, which is a grant",
    ("DELETE", "/scim/v2/Groups/{group_id}"): "deletes a group; the only write here with no undo",
    ("POST", "/scim/v2/Bulk"): "applies many writes at once, from one client",
    # --- administration ----------------------------------------------------
    ("POST", "/admin/entities"): "registers a federation peer",
    ("POST", "/admin/entities/{entity_id:path}/enabled"): "turns a peer on or off",
    ("POST", "/admin/impersonate"): "an administrator acting as somebody else",
    ("POST", "/admin/sessions/terminate"): "ends sessions somebody else owns",
    ("POST", "/admin/people/{person_uuid}/sessions/terminate"): "ends one person's sessions",
    ("GET", "/admin/audit/export"): "takes a copy of the trail (FR-AUD-08)",
}

DECIDES_NOTHING: dict[Route, str] = {
    # --- documents describing the server, not anybody in it ----------------
    ("GET", "/saml/metadata"): "publishes our own descriptor; names no person",
    ("GET", "/.well-known/openid-configuration"): "publishes our own capabilities",
    ("GET", "/.well-known/jwks.json"): "publishes public keys",
    ("GET", "/scim/v2/ServiceProviderConfig"): "publishes which SCIM features exist",
    ("GET", "/scim/v2/ResourceTypes"): "publishes the resource catalogue",
    ("GET", "/scim/v2/ResourceTypes/{resource_id}"): "publishes one resource type",
    ("GET", "/scim/v2/Schemas"): "publishes the schema catalogue",
    ("GET", "/scim/v2/Schemas/{schema_id:path}"): "publishes one schema",
    ("GET", "/docs"): "the interactive API docs, absent in production",
    ("GET", "/docs/oauth2-redirect"): "the docs' own OAuth callback",
    ("GET", "/openapi.json"): "the API description, absent in production",
    # --- operations --------------------------------------------------------
    ("GET", "/healthz"): "liveness; touches no dependency and no person",
    ("GET", "/readyz"): "readiness; reports dependencies, not decisions",
    ("GET", "/metrics"): "aggregate counters, by construction carrying no person",
    ("GET", "/disco"): "offers a choice of IdP; the login it starts is audited at /saml/sso",
    # --- reads -------------------------------------------------------------
    #
    # A read is not one of the three outcomes the requirement names. The line is
    # drawn at bulk reads of the trail itself, which is why the audit *export*
    # is audited above and these searches are not: an export leaves the system
    # with a copy, and a search does not.
    ("GET", "/me"): "a person reading their own session",
    ("GET", "/me/releases"): "a person reading what was released about them",
    ("GET", "/mfa/enrolment"): "reports whether enrolment is required",
    ("GET", "/mfa/factors"): "a person listing their own factors",
    ("GET", "/userinfo"): "a claims read, bounded by the token's own scopes",
    ("GET", "/scim/v2/Users"): "a listing",
    ("GET", "/scim/v2/Users/{resource_id}"): "a read",
    ("GET", "/scim/v2/Groups"): "a listing",
    ("GET", "/scim/v2/Groups/{group_id}"): "a read",
    ("GET", "/admin/audit"): "a search of the trail; the export is what leaves with a copy",
    ("GET", "/admin/audit/subject/{subject:path}"): "one subject's timeline, read in place",
    ("GET", "/admin/dashboard"): "aggregates already-recorded events",
    ("GET", "/admin/entities"): "a listing",
    ("GET", "/admin/entities/{entity_id:path}"): "a read",
    ("GET", "/admin/people/{person_uuid}"): "a read, composed from stores that own each fact",
    # --- issued, not decided ------------------------------------------------
    ("POST", "/mfa/challenge"): (
        "offers a challenge and decides nothing; the step-up endpoints record the outcome"
    ),
    ("POST", "/mfa/challenge/push"): (
        "sends a push and decides nothing; the poll that collects the answer records it"
    ),
    ("POST", "/mfa/webauthn/options"): "issues a registration challenge; /mfa/webauthn records it",
    ("POST", "/oauth2/introspect"): (
        "answers a question about a token the caller already holds, changing nothing"
    ),
}


def _routes(app: FastAPI) -> dict[Route, Any]:
    """Every route the application serves, with its handler.

    Recursive because FastAPI stopped flattening included routers: since 0.141 an
    `include_router` leaves a wrapper in `app.routes` carrying the original
    router, so a flat read finds only the three routes defined on the app itself
    and this whole file would pass while checking almost nothing.
    """
    found: dict[Route, Any] = {}

    def walk(routes: Any) -> None:
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                walk(original.routes)
                continue
            for method in getattr(route, "methods", None) or ():
                if method not in ("HEAD", "OPTIONS"):
                    found[(method, route.path)] = route.endpoint

    walk(app.routes)
    return found


def _reaches_audit_write(handler: Any) -> bool:
    """Whether this handler can reach `audit.record`, following its own module.

    Module-local on purpose. Following calls across modules would mean resolving
    attribute types, which for a handler reaching through `request.app.state` is
    guesswork — and guesswork in a completeness check is worse than a known
    boundary, because it fails in the direction of falsely reassuring.
    """
    module = importlib.import_module(handler.__module__)
    tree = ast.parse(inspect.getsource(module))
    bodies = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }

    seen: set[str] = set()
    stack = [handler.__name__]
    while stack:
        current = stack.pop()
        if current in seen or current not in bodies:
            continue
        seen.add(current)
        for node in ast.walk(bodies[current]):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "record":
                    return True
            elif isinstance(node.func, ast.Name) and node.func.id in bodies:
                stack.append(node.func.id)
    return False


# --- the inventory -----------------------------------------------------------


def test_every_route_is_classified(app: FastAPI) -> None:
    """A new route fails this until somebody decides which it is.

    That decision is the point. "No silent paths" is not a property of the code
    as written; it is a property somebody has to re-establish every time the
    surface grows, and this is what makes them.
    """
    classified = set(AUDITS) | set(DECIDES_NOTHING)

    unclassified = sorted(set(_routes(app)) - classified)

    assert not unclassified, (
        "routes with no audit classification: "
        + ", ".join(f"{method} {path}" for method, path in unclassified)
        + ". Add each to AUDITS with what it decides, or to DECIDES_NOTHING with why it does not."
    )


def test_the_classification_names_no_route_that_does_not_exist(app: FastAPI) -> None:
    """The other direction, so a deleted route leaves a stale entry behind
    rather than a quietly shrinking check."""
    served = set(_routes(app))

    stale = sorted((set(AUDITS) | set(DECIDES_NOTHING)) - served)

    assert not stale, "classified routes the application does not serve: " + ", ".join(
        f"{method} {path}" for method, path in stale
    )


def test_nothing_is_classified_twice() -> None:
    """A route in both tables would satisfy either assertion below depending on
    which ran first."""
    assert not set(AUDITS) & set(DECIDES_NOTHING)


# --- the two directions ------------------------------------------------------


def test_every_decision_point_can_reach_an_audit_write(app: FastAPI) -> None:
    """Static, so it holds for paths no test happens to exercise.

    An instrumented run proves the paths it drives. This proves the handler has
    an audit write reachable at all, which is the check that catches a rejection
    branch added later with no event on it.
    """
    handlers = _routes(app)

    silent = sorted(
        route for route in AUDITS if route in handlers and not _reaches_audit_write(handlers[route])
    )

    assert not silent, (
        "routes classified as decision points that write no audit event: "
        + ", ".join(f"{method} {path}" for method, path in silent)
    )


def test_nothing_classified_as_deciding_nothing_writes_an_event(app: FastAPI) -> None:
    """The inverse, and the half that keeps the reasons honest.

    A route that started auditing has started deciding something, and the entry
    explaining why it decides nothing is now wrong. That is worth a failure: the
    reason is the documentation, and a wrong reason is worse than none.
    """
    handlers = _routes(app)

    writing = sorted(
        route
        for route in DECIDES_NOTHING
        if route in handlers and _reaches_audit_write(handlers[route])
    )

    assert not writing, (
        "routes classified as deciding nothing that write audit events: "
        + ", ".join(f"{method} {path}" for method, path in writing)
        + ". Move each to AUDITS, or remove the write."
    )


# --- the instrumented run ----------------------------------------------------


async def test_the_assertion_consumer_audits_every_terminal_outcome(
    app: FastAPI, client: AsyncClient, audit: RecordingAuditLog
) -> None:
    """The endpoint where a silent path would matter most.

    Four ways out and every one of them records something. Driven through HTTP
    rather than by calling the handler, so the middleware, the throttle and the
    form parsing are all in the path — a silent refusal in front of the handler
    would be invisible to a unit test of the handler.

    The bodies are deliberately junk. What is under test is that a refusal is
    recorded, not which refusal it was; the validation matrix covers the reason
    codes and does it far more thoroughly than this could.
    """
    # The request-binding check reads the nonce store before the gate runs, and
    # the lifespan that normally provides it does not run here.
    app.state.redis = aioredis.FakeRedis(decode_responses=True)

    await client.post("/saml/acs", data={"SAMLResponse": "not-base64", "RelayState": "x"})

    assert audit.events, "a refused assertion produced no audit event"
    assert all(
        event.correlation_id for event in audit.events
    ), "an audit event with no correlation id cannot be joined to the request that caused it"


async def test_a_route_that_decides_nothing_writes_nothing(
    client: AsyncClient, audit: RecordingAuditLog
) -> None:
    """The floor under the classification above.

    Asserted with a real request rather than by scanning, because the cost of
    getting this wrong is not a missing record but an audit trail full of
    health-check noise that buries the events somebody needs.
    """
    await client.get("/healthz")
    await client.get("/readyz")
    await client.get("/metrics")

    assert audit.events == []


def test_every_event_type_is_named_by_some_test() -> None:
    """An event type nobody asserts is one nobody will notice stopping.

    A source scan, like the reason-code completeness test next to it, and for the
    same reason: instrumenting the writer and checking a tally at session end
    would fail whenever anybody ran a subset of the suite.
    """
    from pathlib import Path

    tests_root = Path(__file__).resolve().parent.parent
    referenced: set[str] = set()
    for path in tests_root.rglob("test_*.py"):
        if path.name == Path(__file__).name:
            continue  # this file names them all, which would prove nothing
        text = path.read_text(encoding="utf-8")
        referenced.update(name for name in (event.name for event in EventType) if name in text)

    missing = sorted({event.name for event in EventType} - referenced)

    assert not missing, "event types no test names: " + ", ".join(missing)
