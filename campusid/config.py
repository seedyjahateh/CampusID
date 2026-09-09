"""Application configuration.

All configuration arrives through the environment (NFR-OPS-02) so the same
image runs in every profile. There are no ``if ENV == "dev"`` branches outside
this module; behaviour differences are expressed as settings values.
"""

from __future__ import annotations

import os
from datetime import timedelta
from enum import StrEnum
from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "CAMPUSID_"
ASYNC_DB_SCHEME = "postgresql+asyncpg://"
REDIS_SCHEMES = ("redis://", "rediss://")


class Environment(StrEnum):
    """Deployment environment. Gates operator-only affordances."""

    DEV = "dev"
    CI = "ci"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Runtime settings, read from the environment.

    Field names map to ``CAMPUSID_``-prefixed environment variables, e.g.
    ``CAMPUSID_DATABASE_URL``.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=None,  # the container injects env directly; no dotenv in-process
        extra="forbid",
        frozen=True,
    )

    # --- Identity of this deployment -------------------------------------
    environment: Environment = Environment.DEV
    service_name: str = "campusid-broker"
    base_url: str = "https://broker.campus.test"

    # --- Data tier --------------------------------------------------------
    database_url: str = "postgresql+asyncpg://campusid:campusid@postgres:5432/campusid"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    redis_url: str = "redis://redis:6379/0"

    # --- HTTP -------------------------------------------------------------
    host: str = "0.0.0.0"  # noqa: S104 - bound inside a container network
    port: int = Field(default=8000, ge=1, le=65535)

    # --- Observability ----------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # --- SAML -------------------------------------------------------------
    saml_key_dir: str = "/var/lib/campusid/saml"
    """Where the SP keypair lives. A mounted volume, so the identity a peer
    trusts survives a restart."""

    saml_default_idp: str | None = None
    """entityID used by `/saml/sso` when the caller names none. Optional: with
    several IdPs registered, discovery (M1b) chooses instead."""

    # --- Protocol parameters (validated here, enforced in M1+) -----------
    saml_clock_skew_seconds: int = Field(default=180, ge=0, le=300)
    """Assertion time-condition tolerance.

    Bounded at 300s by the schema itself so a misconfiguration fails at
    startup rather than silently widening the acceptance window
    (PRD: ``test_skew_config_bounds.py``).
    """

    @field_validator("base_url")
    @classmethod
    def _no_trailing_slash(cls, value: str) -> str:
        """Entity IDs and issuer values must be byte-stable across restarts."""
        return value.rstrip("/")

    @field_validator("database_url")
    @classmethod
    def _require_async_driver(cls, value: str) -> str:
        """A sync driver here would block the event loop under load.

        Caught at startup because the symptom otherwise appears as unexplained
        latency under concurrency, not as an error.
        """
        if not value.startswith(ASYNC_DB_SCHEME):
            raise ValueError(f"database_url must start with {ASYNC_DB_SCHEME!r}")
        return value

    @field_validator("redis_url")
    @classmethod
    def _require_redis_scheme(cls, value: str) -> str:
        if not value.startswith(REDIS_SCHEMES):
            raise ValueError(f"redis_url must start with one of {REDIS_SCHEMES}")
        return value

    @model_validator(mode="after")
    def _reject_unknown_environment_variables(self) -> Self:
        """Fail startup on a prefixed variable that maps to no setting.

        ``extra="forbid"`` only rejects unknown *fields*; pydantic-settings
        silently ignores unknown *environment variables*. That silence is how a
        typo in ``CAMPUSID_SAML_CLOCK_SKEW_SECONDS`` becomes an afternoon spent
        wondering why the configured value has no effect. A misconfigured
        security parameter should refuse to boot, not quietly run on defaults.
        """
        known = {f"{ENV_PREFIX}{name.upper()}" for name in type(self).model_fields}
        unknown = sorted(
            name for name in os.environ if name.startswith(ENV_PREFIX) and name not in known
        )
        if unknown:
            raise ValueError(f"unknown {ENV_PREFIX}* environment variable(s): {', '.join(unknown)}")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    # All four derive from `base_url`, so there is exactly one place a
    # deployment's identity is configured. An entityID that drifted from the
    # ACS URL would break every registered peer at once, and silently.
    @property
    def saml_entity_id(self) -> str:
        """Our entityID. Also the URL our metadata is published at."""
        return f"{self.base_url}/saml/metadata"

    @property
    def saml_acs_url(self) -> str:
        return f"{self.base_url}/saml/acs"

    @property
    def saml_sso_url(self) -> str:
        return f"{self.base_url}/saml/sso"

    @property
    def saml_slo_url(self) -> str:
        return f"{self.base_url}/saml/sls"

    @property
    def saml_clock_skew(self) -> timedelta:
        return timedelta(seconds=self.saml_clock_skew_seconds)

    @property
    def sync_database_url(self) -> str:
        """Driver-neutral URL for tooling that cannot use asyncpg."""
        return self.database_url.replace("+asyncpg", "", 1)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
