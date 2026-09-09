"""Application factory wiring."""

from __future__ import annotations

from campusid import __version__
from campusid.app import create_app
from campusid.config import Environment, Settings


def test_app_metadata(settings: Settings) -> None:
    app = create_app(settings)

    assert app.title == "CampusID Broker"
    assert app.version == __version__
    assert app.state.settings is settings


def test_probes_start_empty(settings: Settings) -> None:
    """Probes are registered by lifespan, not by the factory.

    This keeps the factory usable in unit tests without a data tier.
    """
    assert create_app(settings).state.readiness_probes == {}


def test_docs_are_available_outside_production(settings: Settings) -> None:
    app = create_app(settings)

    assert app.docs_url == "/docs"
    assert app.openapi_url == "/openapi.json"


def test_docs_are_disabled_in_production() -> None:
    """The schema enumerates every endpoint; it is an operator affordance."""
    app = create_app(Settings(environment=Environment.PRODUCTION, pairwise_salt="a-real-salt"))

    assert app.docs_url is None
    assert app.openapi_url is None
    assert app.redoc_url is None
