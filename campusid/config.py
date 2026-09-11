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

    # --- Attribute release ------------------------------------------------
    policy_dir: str = "/app/policies"
    """Where the per-SP release policy files live (FR-ARP-01).

    A directory rather than a single file, so adding an SP is adding a file and
    a review diff shows one app's policy rather than every app's.
    """

    lifecycle_rules_file: str = "/app/config/lifecycle_rules.yaml"
    """Where the affiliation transition rules live (FR-LC-04).

    A single file rather than a directory, unlike release policy: policy is
    per-SP and adding an app means adding a file, while these rules describe the
    institution and there is only one of it.
    """

    authorization_policy_file: str = "/app/config/authorization.yaml"
    """Where the ABAC rules live (FR-AZ-03).

    One file, like the lifecycle rules and unlike the per-SP release policy: an
    authorization rule is about the institution's resources rather than about
    one federated application.
    """

    roles_file: str = "/app/config/roles.yaml"
    """Role definitions, their derivations, and the pairs that may not be held
    together (FR-AZ-01, FR-AZ-07)."""

    scope: str = "campus.test"
    """This deployment's own scope — the domain the campus IdP is authoritative
    for. Values scoped to anything else are dropped during normalisation, and
    it is the suffix on every subject identifier the broker issues."""

    pairwise_salt: str = "dev-only-pairwise-salt-replace-in-production"
    """Restore-critical. Changing it replaces every SP's entire user base with
    strangers simultaneously, so it is backed up with the database and rotating
    it is a coordinated migration rather than an operation. The default exists
    so the dev stack starts; production must override it."""

    # --- Second factors (FR-MFA-02) --------------------------------------
    webauthn_rp_id: str = "localhost"
    """The domain every credential is scoped to.

    This is the load-bearing WebAuthn setting. The browser refuses to use a
    credential from any origin outside it, which is where phishing resistance
    comes from — and changing it orphans every credential already registered,
    because the authenticator will not recognise the new relying party. It is a
    registrable domain with no scheme and no port, which is why it is not derived
    from `base_url`: `http://localhost:8000` is not a valid value and the
    difference is silent until the first enrolment fails.
    """

    webauthn_origin: str = "http://localhost:8000"
    """The exact origin the browser will report, scheme and port included.

    Separate from the relying-party id because they are different things that
    look alike, and because a deployment behind a proxy has an origin its own
    `base_url` may not describe.
    """

    impersonation_fixtures: str = ""
    """The ePPNs an administrator may act as for testing, comma-separated
    (FR-ADM-03).

    Enumerated rather than inferred. "A test account" is not a property anybody
    can read off a row, and a rule like "accounts whose name starts with test" is
    a rule somebody will eventually name a real person into.

    A comma-separated string rather than a list, because pydantic-settings reads
    a sequence field from the environment as JSON — so the natural empty value
    fails to parse and the operator's first encounter with this setting is a
    broker that will not start.

    Empty by default, so a deployment that has not chosen any has the capability
    switched off rather than pointed at whoever happens to match. The endpoint is
    absent in production regardless of what this holds.
    """

    push_url: str = ""
    """Where the push-approval service lives. Empty disables the push factor.

    Empty by default rather than pointing somewhere, for the reason `ldap_url` is:
    a broker configured with a service it cannot reach fails on every attempt,
    while a broker configured with none simply has no push factor.

    The service this talks to is a **simulator** (FR-MFA-03). It has no device
    registration and no cryptographic binding to a phone, and anybody who can
    reach it can approve anybody's request. The flow around it is real; the trust
    is not, and both the README and the simulator's own page say so.
    """

    # --- Directory (FR-DIR-01, FR-DIR-02, FR-DIR-03) ---------------------
    ldap_url: str = ""
    """`ldaps://host:636` or `ldap://host:389`. Empty disables the integration.

    Empty by default rather than pointing somewhere: a broker configured with a
    directory it cannot reach degrades on every login, and a broker configured
    with none simply has no directory. The second is a state an operator chose.
    """

    ldap_profile: str = "openldap"
    """Which attribute vocabulary this directory speaks (FR-DIR-03).

    Configured, never detected. Detection is a probe that succeeds against a
    hostile server too, and taking the attribute names an attacker's directory
    suggested is a strange place to end up.
    """

    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    """FR-DIR-02. Supplied by the secrets backend at deploy time, and empty here
    so nothing usable is committed. There is deliberately no development
    default: a directory bind that works out of the box is a credential
    somebody will find in the repository."""

    ldap_base_dn: str = ""
    ldap_start_tls: bool = True
    """Whether to negotiate StartTLS on a plain `ldap://` connection.

    On by default, so the insecure case is the one that has to be asked for.
    """

    ldap_allow_plaintext: bool = False
    """FR-DIR-01's escape hatch, for a development directory with no
    certificate.

    Refused in production by the validator below, and CI asserts the compose
    profile it uses does not set it. A bind sends the service account's password
    in the clear, so the only acceptable place for this is a laptop.
    """

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

    @model_validator(mode="after")
    def _require_a_real_pairwise_salt_in_production(self) -> Self:
        """The dev default must never reach production.

        Everyone would derive the same identifiers from it, so an SP could
        compute another SP's identifier for a chosen user — which is the single
        property pairwise identifiers exist to provide. Checked at startup
        because there is no later moment anybody would notice.
        """
        if self.environment is Environment.PRODUCTION and self.pairwise_salt.startswith("dev-only"):
            raise ValueError("pairwise_salt still holds its development default")
        return self

    @model_validator(mode="after")
    def _refuse_plaintext_ldap_in_production(self) -> Self:
        """FR-DIR-01. A plain bind sends the service account's password in the
        clear, and that account can usually read the whole directory.

        Two checks rather than one: the escape hatch is refused outright in
        production, and a plain `ldap://` URL is refused there even with StartTLS
        configured — because StartTLS on a URL that permits falling back is a
        downgrade an attacker on the path gets to choose.
        """
        if not self.is_production or not self.ldap_url:
            return self
        if self.ldap_allow_plaintext:
            raise ValueError("ldap_allow_plaintext cannot be set in production")
        if not self.ldap_url.startswith("ldaps://"):
            raise ValueError("ldap_url must use ldaps:// in production")
        return self

    @model_validator(mode="after")
    def _require_a_known_directory_profile(self) -> Self:
        """A typo would select the wrong attribute vocabulary and every search
        would return nothing, which reads as an empty directory rather than as a
        configuration error."""
        from campusid.directory.profiles import PROFILES

        if self.ldap_url and self.ldap_profile not in PROFILES:
            raise ValueError(
                f"unknown ldap_profile {self.ldap_profile!r}; known profiles are {sorted(PROFILES)}"
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def ldap_enabled(self) -> bool:
        """Whether a directory is configured at all."""
        return bool(self.ldap_url)

    @property
    def pairwise_salt_bytes(self) -> bytes:
        return self.pairwise_salt.encode("utf-8")

    @property
    def impersonation_fixture_set(self) -> frozenset[str]:
        """The fixture ePPNs, parsed once (FR-ADM-03).

        Blank entries are dropped rather than kept, because a trailing comma
        would otherwise put the empty string in the set — and a subject field
        nobody filled in would then match it.
        """
        return frozenset(
            entry.strip() for entry in self.impersonation_fixtures.split(",") if entry.strip()
        )

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
    def oidc_issuer(self) -> str:
        """The `iss` in every token and the base of every advertised endpoint.

        The base URL itself, with no path. An issuer that is a prefix of another
        issuer invites the mistake where a client validating by `startswith`
        accepts tokens from the wrong one, and OIDC Discovery derives the
        well-known path from the issuer anyway.
        """
        return self.base_url

    @property
    def sync_database_url(self) -> str:
        """Driver-neutral URL for tooling that cannot use asyncpg."""
        return self.database_url.replace("+asyncpg", "", 1)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
