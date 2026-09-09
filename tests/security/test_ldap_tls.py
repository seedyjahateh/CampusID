"""Refusing to bind to a directory in the clear (FR-DIR-01, FR-DIR-02).

An LDAP simple bind sends the password in the request. The account doing the
binding is a service account that can usually read the whole directory, so a
plain connection is one passive observer away from handing somebody every
attribute of every person at the institution.

Two checks, and the second is the one that gets missed. Refusing the explicit
plaintext escape hatch in production is obvious. Refusing a plain `ldap://` URL
there *even with StartTLS configured* is the less obvious half: StartTLS on a URL
that permits falling back is a downgrade an attacker on the path gets to choose,
and the bind that follows looks exactly like a successful one.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from campusid.config import Environment, Settings

pytestmark = pytest.mark.security

PRODUCTION = {
    "environment": Environment.PRODUCTION,
    "pairwise_salt": "a-real-production-salt-value-not-the-default",
}


def _settings(**overrides: object) -> Settings:
    return Settings(**overrides)  # type: ignore[arg-type]


def test_plaintext_is_refused_in_production() -> None:
    with pytest.raises(ValidationError, match="ldap_allow_plaintext"):
        _settings(**PRODUCTION, ldap_url="ldap://dir.campus.test", ldap_allow_plaintext=True)


def test_a_plain_url_is_refused_in_production_even_with_start_tls() -> None:
    """The downgrade an attacker chooses. A connection that *can* fall back is
    one that will, against somebody who can drop the StartTLS response."""
    with pytest.raises(ValidationError, match="ldaps://"):
        _settings(**PRODUCTION, ldap_url="ldap://dir.campus.test", ldap_start_tls=True)


def test_ldaps_is_accepted_in_production() -> None:
    settings = _settings(**PRODUCTION, ldap_url="ldaps://dir.campus.test:636")

    assert settings.ldap_enabled


def test_no_directory_at_all_is_a_valid_production_configuration() -> None:
    """A broker configured with a directory it cannot reach degrades on every
    login; one configured with none simply has no directory, and that is a state
    an operator chose."""
    settings = _settings(**PRODUCTION)

    assert not settings.ldap_enabled


def test_plaintext_is_allowed_outside_production() -> None:
    """The escape hatch exists for a development directory with no certificate.
    CI asserts the compose profile it uses does not set it."""
    settings = _settings(
        environment=Environment.DEV,
        ldap_url="ldap://openldap:389",
        ldap_allow_plaintext=True,
    )

    assert settings.ldap_allow_plaintext


def test_start_tls_is_on_by_default() -> None:
    """So the insecure case is the one that has to be asked for."""
    assert _settings().ldap_start_tls


def test_no_bind_credentials_are_committed() -> None:
    """FR-DIR-02. There is deliberately no development default: a directory bind
    that works out of the box is a credential somebody will find in the
    repository."""
    settings = _settings()

    assert settings.ldap_bind_dn == ""
    assert settings.ldap_bind_password == ""


def test_an_unknown_profile_refuses_to_boot() -> None:
    """Rather than searching with the wrong attribute names, which returns
    nothing and reads as an empty directory."""
    with pytest.raises(ValidationError, match="unknown ldap_profile"):
        _settings(ldap_url="ldap://openldap:389", ldap_profile="openldp")


def test_the_profile_is_only_checked_when_a_directory_is_configured() -> None:
    """A deployment with no directory should not have to hold a valid profile
    name for a thing it does not use."""
    assert not _settings(ldap_profile="anything").ldap_enabled
