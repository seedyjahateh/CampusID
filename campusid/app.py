"""FastAPI application factory and lifespan management."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from campusid import __version__, health
from campusid.admin.people import PersonDirectory
from campusid.audit.dashboard import DashboardStore
from campusid.audit.log import AuditLog
from campusid.audit.query import AuditQueryStore
from campusid.authz.cache import CachingDecider, DecisionCache
from campusid.authz.loader import PolicyEngineStore
from campusid.authz.roles import RoleStore
from campusid.authz.store import RoleAssignmentStore
from campusid.cache import check_redis, create_redis
from campusid.config import Settings, get_settings
from campusid.db import check_database, create_engine, create_session_factory
from campusid.directory.client import DirectoryClient
from campusid.directory.connection import Connector, DirectoryUnavailable
from campusid.directory.profiles import profile as directory_profile
from campusid.directory.writes import DirectoryWriter
from campusid.federation.registry import FederationRegistry
from campusid.identity.registry import IdentityRegistry
from campusid.keys import load_or_create
from campusid.lifecycle.deadletter import DeadLetterQueue
from campusid.lifecycle.orchestrator import LifecycleOrchestrator
from campusid.lifecycle.reconciliation import Reconciler
from campusid.lifecycle.rules import RulesStore
from campusid.lifecycle.store import LifecycleStore
from campusid.lifecycle.sweeper import GraceSweeper
from campusid.lifecycle.targets import LdapTarget
from campusid.logging import configure_logging, get_logger
from campusid.mfa.challenges import ChallengeStore
from campusid.mfa.push import PushClient
from campusid.mfa.ratelimit import AttemptLimiter
from campusid.mfa.store import FactorStore
from campusid.middleware import (
    BodySizeLimitMiddleware,
    CorrelationMiddleware,
    SecurityHeadersMiddleware,
)
from campusid.oidc import keys as oidc_keys
from campusid.oidc.grants import GrantStore
from campusid.oidc.logout import ClientSessionIndex, LogoutNotifier
from campusid.oidc.par import PushedRequestStore
from campusid.oidc.registry import ClientRegistry
from campusid.policy.loader import PolicyStore
from campusid.routes import admin as admin_routes
from campusid.routes import disco as disco_routes
from campusid.routes import logout as logout_routes
from campusid.routes import me as me_routes
from campusid.routes import mfa as mfa_routes
from campusid.routes import oauth2 as oauth2_routes
from campusid.routes import oidc as oidc_routes
from campusid.routes import saml as saml_routes
from campusid.routes import scim as scim_routes
from campusid.saml.gate import AssertionGate, GatePolicy
from campusid.saml.metadata_sp import (
    DEFAULT_REQUESTED_ATTRIBUTES,
    ContactPerson,
    ServiceProviderDescription,
    build_sp_metadata,
)
from campusid.saml.stores import RedisReplayCache, RedisRequestStore
from campusid.scim.groups import GroupStore
from campusid.scim.store import UserStore
from campusid.security.throttle import Throttle
from campusid.session.store import SessionStore

SP_CONTACTS = (
    ContactPerson("technical", "CampusID", "Operations", "iam@campus.test"),
    # A monitored security contact is a federation Baseline Expectation and the
    # precondition for SIRTFI: without one, nobody can tell us we are breached.
    ContactPerson("other", "CampusID", "Security", "security@campus.test"),
)

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open data-tier connections on startup and drain them on shutdown."""
    settings: Settings = app.state.settings

    engine = create_engine(settings)
    redis = create_redis(settings)
    session_factory = create_session_factory(engine)

    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.redis = redis
    app.state.readiness_probes = {
        "database": functools.partial(check_database, engine),
        "redis": functools.partial(check_redis, redis),
    }

    # Generated on first start and kept in a mounted volume, so the identity a
    # peer has trusted survives a restart. See campusid/keys.py for why no
    # development key is committed.
    signing_key = load_or_create(
        Path(settings.saml_key_dir), "sp-signing", common_name=settings.base_url
    )
    registry = FederationRegistry(session_factory)

    app.state.sp_signing_key = signing_key
    app.state.registry = registry
    app.state.request_store = RedisRequestStore(redis)
    app.state.sessions = SessionStore(redis)
    app.state.sp_metadata = build_sp_metadata(
        ServiceProviderDescription(
            entity_id=settings.saml_entity_id,
            acs_url=settings.saml_acs_url,
            slo_url=settings.saml_slo_url,
            signing_certificates=(signing_key.certificate_pem,),
            contacts=SP_CONTACTS,
            requested_attributes=DEFAULT_REQUESTED_ATTRIBUTES,
        )
    )
    app.state.gate = AssertionGate(
        policy=GatePolicy(
            audience=settings.saml_entity_id,
            destination=settings.saml_acs_url,
            clock_skew=settings.saml_clock_skew,
        ),
        resolve_idp=registry.resolve_trusted_idp,
        replay_cache=RedisReplayCache(redis),
        request_store=app.state.request_store,
    )

    # The OIDC signing key shares the SAML volume: an ephemeral one would
    # invalidate every outstanding token on restart, and every client that
    # cached our JWKS would refuse tokens it should honour.
    app.state.oidc_keys = oidc_keys.load_or_create_key_set(Path(settings.saml_key_dir))
    app.state.clients = ClientRegistry(session_factory)
    app.state.grants = GrantStore(redis)
    app.state.pushed_requests = PushedRequestStore(redis)
    app.state.client_sessions = ClientSessionIndex(redis)
    # One client for the life of the process, so back-channel logout reuses
    # connections rather than paying a TLS handshake per notification — and so
    # a slow client cannot exhaust sockets by being notified often.
    logout_http = httpx.AsyncClient()
    app.state.logout_notifier = LogoutNotifier(issuer=settings.oidc_issuer, client=logout_http)
    app.state.policies = PolicyStore(Path(settings.policy_dir), default_scope=settings.scope)
    app.state.lifecycle_rules = RulesStore(Path(settings.lifecycle_rules_file))
    app.state.authorization = PolicyEngineStore(Path(settings.authorization_policy_file))
    app.state.roles = RoleStore(Path(settings.roles_file))
    app.state.role_assignments = RoleAssignmentStore(session_factory, catalogue=app.state.roles)
    app.state.decision_cache = DecisionCache(redis)
    app.state.decider = CachingDecider(app.state.authorization, app.state.decision_cache)
    app.state.mfa = FactorStore(session_factory, issuer=settings.service_name)
    app.state.mfa_challenges = ChallengeStore(redis)
    app.state.mfa_limiter = AttemptLimiter(redis)
    # Attempts per minute on the authentication endpoints (NFR-SEC-10). Distinct
    # from the second-factor limiter above, which counts failures: a failure
    # counter does not stop somebody hammering an endpoint with requests that
    # never reach a credential check.
    app.state.throttle = Throttle(redis)
    # One client for the life of the process, like the logout notifier's, so a
    # push does not pay a TCP handshake per poll.
    push_http = httpx.AsyncClient()
    # Fetching a partner's published metadata. Redirects are not followed: a
    # server-side fetch of an operator-supplied URL that chases redirects is how
    # an allowlisted address becomes an arbitrary one.
    app.state.metadata_http = httpx.AsyncClient(follow_redirects=False)
    app.state.push = (
        PushClient(settings.push_url, redis, client=push_http) if settings.push_url else None
    )
    app.state.lifecycle = LifecycleStore(session_factory)
    app.state.identity = IdentityRegistry(session_factory, scope=settings.scope)
    app.state.audit = AuditLog(session_factory)
    app.state.audit_query = AuditQueryStore(session_factory)
    app.state.dashboard = DashboardStore(session_factory)

    # The directory, when one is configured. Absent is a state an operator
    # chose, so it is not an error — but a *misconfigured* one is, which is why
    # the profile name is validated at startup rather than at first search.
    app.state.directory = _directory(settings, redis)
    app.state.directory_writer = _directory_writer(settings, app.state.directory)
    if app.state.directory is not None:
        # Reported rather than fatal. FR-DIR-08 asks that a directory outage
        # degrade to cached group data, and a readiness probe that failed on it
        # would take the broker out of rotation for something it can survive.
        app.state.readiness_probes["directory"] = app.state.directory.healthy

    app.state.dead_letters = DeadLetterQueue(session_factory)

    # Provisioning drives the lifecycle: a SCIM write is what makes somebody a
    # joiner, a mover or a leaver, and the store tells the orchestrator what
    # changed once the write has committed.
    app.state.lifecycle_orchestrator = LifecycleOrchestrator(
        rules=app.state.lifecycle_rules,
        lifecycle=app.state.lifecycle,
        sessions=app.state.sessions,
        grants=app.state.grants,
        audit=app.state.audit,
        identity=app.state.identity,
        # FR-LC-03's first step, which has been an empty slot since the leaver
        # sequence was written. A deployment with no directory still runs the
        # step and records that it had nothing to do.
        targets=(
            (LdapTarget(client=app.state.directory, writer=app.state.directory_writer),)
            if app.state.directory is not None
            else ()
        ),
        dead_letters=app.state.dead_letters,
        # Only an unreachable directory is worth retrying. A write it refuses on
        # its merits will be refused identically five times.
        transient=DirectoryUnavailable,
        # FR-AZ-08's other half. A transition changes what somebody is entitled
        # to, so every decision cached about them has to stop being reachable —
        # otherwise a deprovisioning takes up to a minute to reach the thing
        # actually enforcing it.
        decisions=app.state.decision_cache,
    )
    app.state.scim_users = UserStore(
        session_factory,
        issuer=settings.oidc_issuer,
        scope=settings.scope,
        on_transition=app.state.lifecycle_orchestrator.transitioned,
    )
    app.state.scim_groups = GroupStore(session_factory, issuer=settings.oidc_issuer)

    # Composed from the stores that own each fact rather than querying for
    # itself, so an administrator's view cannot be a second opinion about the
    # same rows (FR-ADM-04).
    app.state.people = PersonDirectory(
        identity=app.state.identity,
        lifecycle=app.state.lifecycle,
        roles=app.state.role_assignments,
        factors=app.state.mfa,
        sessions=app.state.sessions,
        audit=app.state.audit_query,
        groups=app.state.scim_groups,
    )

    # Reconciliation is on demand rather than on a timer. It walks every person
    # and asks the directory about each, which is a job an operator schedules
    # for a quiet hour rather than something the broker should decide to do to
    # itself while serving logins.
    app.state.reconciler = (
        Reconciler(
            session_factory,
            client=app.state.directory,
            target=LdapTarget(client=app.state.directory, writer=app.state.directory_writer),
        )
        if app.state.directory is not None
        else None
    )

    # What ends a grace period is somebody looking. The deadline is durable
    # because it is a column; this is the process that reads it.
    sweeper = GraceSweeper(app.state.lifecycle, decisions=app.state.decision_cache)
    app.state.grace_sweeper = sweeper
    sweeper.start()

    log.info(
        "broker.startup",
        environment=settings.environment.value,
        base_url=settings.base_url,
        version=__version__,
    )
    try:
        yield
    finally:
        # Ordered teardown so in-flight requests drain before the pool closes
        # (NFR-AVAIL-06). The sweep goes first: a cancelled task still holds a
        # connection until it unwinds, and disposing the pool underneath it is
        # how a clean shutdown produces an alarming traceback.
        await sweeper.stop()
        await logout_http.aclose()
        await push_http.aclose()
        await app.state.metadata_http.aclose()
        await redis.aclose()
        await engine.dispose()
        log.info("broker.shutdown")


def _directory(settings: Settings, redis: Any) -> DirectoryClient | None:
    """The directory client, or None when no directory is configured.

    None rather than a null object. A caller that has to ask whether there is a
    directory writes one `if`; a null object that answers "no groups" to every
    question would be indistinguishable from a directory in which nobody is a
    member of anything.
    """
    if not settings.ldap_enabled:
        return None
    return DirectoryClient(
        profile=directory_profile(settings.ldap_profile),
        url=settings.ldap_url,
        base_dn=settings.ldap_base_dn,
        bind_dn=settings.ldap_bind_dn,
        bind_password=settings.ldap_bind_password,
        start_tls=settings.ldap_start_tls,
        allow_plaintext=settings.ldap_allow_plaintext,
        cache=redis,
    )


def _directory_writer(settings: Settings, client: DirectoryClient | None) -> DirectoryWriter | None:
    """The write half, built only when there is a directory to write to."""
    if client is None:
        return None
    return DirectoryWriter(
        profile=directory_profile(settings.ldap_profile),
        base_dn=settings.ldap_base_dn,
        connector=Connector(
            url=settings.ldap_url,
            bind_dn=settings.ldap_bind_dn,
            bind_password=settings.ldap_bind_password,
            start_tls=settings.ldap_start_tls,
            allow_plaintext=settings.ldap_allow_plaintext,
        ),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Taking ``settings`` as an argument keeps the factory testable without
    mutating the process environment.
    """
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="CampusID Broker",
        version=__version__,
        description=(
            "SAML/OIDC identity broker with SCIM 2.0 provisioning and "
            "campus attribute-release policy."
        ),
        lifespan=lifespan,
        # Interactive API docs are an operator affordance, not a public one.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings
    app.state.readiness_probes = {}

    # Outermost, so the body cap applies before anything buffers the form.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Innermost of the three, so the correlation id is set before any handler
    # runs and cleared after the last one — including for a request the body cap
    # rejects, which is itself worth a correlated record.
    app.add_middleware(CorrelationMiddleware)
    app.include_router(health.router)
    app.include_router(saml_routes.router)
    app.include_router(disco_routes.router)
    app.include_router(oidc_routes.router)
    app.include_router(oauth2_routes.router)
    app.include_router(logout_routes.router)
    app.include_router(scim_routes.router)
    app.include_router(mfa_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(me_routes.router)

    return app
