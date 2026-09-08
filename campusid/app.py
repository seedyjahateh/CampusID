"""FastAPI application factory and lifespan management."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from campusid import __version__, health
from campusid.cache import check_redis, create_redis
from campusid.config import Settings, get_settings
from campusid.db import check_database, create_engine, create_session_factory
from campusid.federation.registry import FederationRegistry
from campusid.keys import load_or_create
from campusid.logging import configure_logging, get_logger
from campusid.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
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

    return app
