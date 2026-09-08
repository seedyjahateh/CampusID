"""Shared test fixtures.

Unit tests exercise the ASGI app directly without running its lifespan, so no
Postgres or Redis is required. Readiness probes are injected per test. Tests
that need live dependencies carry the ``integration`` marker.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.app import create_app
from campusid.config import Environment, Settings
from tests.support.saml_forge import ForgedIdP


@pytest.fixture(scope="session")
def idp() -> ForgedIdP:
    """The trusted IdP. Session-scoped: RSA-2048 keygen costs ~100ms."""
    return ForgedIdP()


@pytest.fixture(scope="session")
def other_idp() -> ForgedIdP:
    """A second IdP, for signatures that verify against the wrong key.

    A separate entity rather than a stray keypair, because the realistic
    failure is a *registered* peer signing for someone else's entityID.
    """
    return ForgedIdP(entity_id="https://other-idp.test/saml")


@pytest.fixture
def settings() -> Settings:
    """Deterministic settings that never read the ambient environment."""
    return Settings(
        environment=Environment.CI,
        base_url="https://broker.test",
        log_format="console",
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    """An application instance with no dependency probes registered."""
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """HTTP client bound to the app in-process; lifespan is not run."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://broker.test") as http:
        yield http
