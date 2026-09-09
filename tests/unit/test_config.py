"""Configuration validation (NFR-OPS-02)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from campusid.config import Environment, Settings


def test_defaults_are_development() -> None:
    settings = Settings()

    assert settings.environment is Environment.DEV
    assert settings.is_production is False
    assert settings.service_name == "campusid-broker"


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAMPUSID_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("CAMPUSID_PORT", "9443")

    settings = Settings()

    assert settings.log_level == "DEBUG"
    assert settings.port == 9443


def test_unknown_setting_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo in a deployment variable must fail loudly, not be ignored."""
    monkeypatch.setenv("CAMPUSID_SAML_CLOCK_SKEW_SECOND", "180")  # missing trailing S

    with pytest.raises(ValidationError):
        Settings()


def test_base_url_trailing_slash_is_stripped() -> None:
    """The issuer and entityID must be byte-stable; a stray slash forks identity."""
    assert Settings(base_url="https://broker.test/").base_url == "https://broker.test"


@pytest.mark.parametrize("skew", [0, 180, 300])
def test_clock_skew_within_bounds_is_accepted(skew: int) -> None:
    assert Settings(saml_clock_skew_seconds=skew).saml_clock_skew_seconds == skew


@pytest.mark.parametrize("skew", [-1, 301, 600])
def test_clock_skew_outside_bounds_fails_at_startup(skew: int) -> None:
    """PRD test_skew_config_bounds: a widened acceptance window must not start.

    Generous skew is the quiet way a replay window becomes exploitable, so the
    ceiling is enforced by the schema rather than by review.
    """
    with pytest.raises(ValidationError):
        Settings(saml_clock_skew_seconds=skew)


def test_sync_database_url_drops_the_async_driver() -> None:
    settings = Settings(database_url="postgresql+asyncpg://u:p@db:5432/campusid")

    assert settings.sync_database_url.startswith("postgresql://")
    assert "asyncpg" not in settings.sync_database_url


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://u:p@db:5432/campusid",
        "postgresql+psycopg://u:p@db:5432/campusid",
        "sqlite+aiosqlite:///campusid.db",
    ],
)
def test_database_url_must_use_the_async_driver(url: str) -> None:
    """A sync driver blocks the event loop; the symptom is latency, not an error."""
    with pytest.raises(ValidationError):
        Settings(database_url=url)


@pytest.mark.parametrize("url", ["redis://cache:6379/0", "rediss://cache:6379/0"])
def test_redis_schemes_accepted(url: str) -> None:
    assert Settings(redis_url=url).redis_url == url


def test_redis_url_scheme_is_validated() -> None:
    with pytest.raises(ValidationError):
        Settings(redis_url="http://cache:6379/0")


def test_production_flag() -> None:
    settings = Settings(environment=Environment.PRODUCTION, pairwise_salt="a-real-salt")

    assert settings.is_production is True


def test_production_refuses_the_development_pairwise_salt() -> None:
    """Every deployment would derive the same identifiers from it, so one SP
    could compute another's identifier for a chosen user — which is the single
    property pairwise identifiers exist to provide. Checked at startup because
    there is no later moment anybody would notice."""
    with pytest.raises(ValidationError, match="pairwise_salt"):
        Settings(environment=Environment.PRODUCTION)


def test_development_keeps_its_default_salt() -> None:
    """The dev stack has to start without ceremony, or nobody runs it."""
    assert Settings().pairwise_salt.startswith("dev-only")


def test_the_pairwise_salt_is_available_as_bytes() -> None:
    """The derivation is an HMAC key, and encoding it at every call site is how
    two call sites end up disagreeing about the encoding."""
    assert Settings(pairwise_salt="salty").pairwise_salt_bytes == b"salty"


def test_settings_are_immutable() -> None:
    """Configuration must not drift at runtime."""
    settings = Settings()

    with pytest.raises(ValidationError):
        settings.port = 1234  # type: ignore[misc]
