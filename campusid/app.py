"""FastAPI application factory and lifespan management."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI

from campusid import __version__, health
from campusid.cache import check_redis, create_redis
from campusid.config import Settings, get_settings
from campusid.db import check_database, create_engine, create_session_factory
from campusid.federation.registry import FederationRegistry
from campusid.keys import load_or_create
from campusid.logging import configure_logging, get_logger
from campusid.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from campusid.oidc import keys as oidc_keys
from campusid.oidc.grants import GrantStore
from campusid.oidc.logout import ClientSessionIndex, LogoutNotifier
from campusid.oidc.par import PushedRequestStore
from campusid.oidc.registry import ClientRegistry
from campusid.policy.loader import PolicyStore
from campusid.routes import disco as disco_routes
from campusid.routes import logout as logout_routes
from campusid.routes import oauth2 as oauth2_routes
from campusid.routes import oidc as oidc_routes
from campusid.routes import saml as saml_routes
from campusid.saml.gate import AssertionGate, GatePolicy
from campusid.saml.metadata_sp import (
    DEFAULT_REQUESTED_ATTRIBUTES,
    ContactPerson,
    ServiceProviderDescription,
    build_sp_metadata,
)
from campusid.saml.stores import RedisReplayCache, RedisRequestStore
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
        # (NFR-AVAIL-06).
        await logout_http.aclose()
        await redis.aclose()
        await engine.dispose()
        log.info("broker.shutdown")


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
    app.include_router(health.router)
    app.include_router(saml_routes.router)
    app.include_router(disco_routes.router)
    app.include_router(oidc_routes.router)
    app.include_router(oauth2_routes.router)
    app.include_router(logout_routes.router)

    return app
