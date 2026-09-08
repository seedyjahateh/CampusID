"""FastAPI application factory and lifespan management."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from campusid import __version__, health
from campusid.cache import check_redis, create_redis
from campusid.config import Settings, get_settings
from campusid.db import check_database, create_engine, create_session_factory
from campusid.logging import configure_logging, get_logger
from campusid.middleware import SecurityHeadersMiddleware

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open data-tier connections on startup and drain them on shutdown."""
    settings: Settings = app.state.settings

    engine = create_engine(settings)
    redis = create_redis(settings)

    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.redis = redis
    app.state.readiness_probes = {
        "database": functools.partial(check_database, engine),
        "redis": functools.partial(check_redis, redis),
    }

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

    app.add_middleware(SecurityHeadersMiddleware)
    app.include_router(health.router)

    return app
