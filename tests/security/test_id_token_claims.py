"""ID token, access token and logout token contents (FR-OP-10, FR-OP-12).

The claim set for scope `openid` alone is asserted *exactly*, not by
subset. "One extra claim slipped in" is how a token that was safe to log stops
being, and a subset assertion cannot see it happen.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from campusid.oidc import keys
from campusid.oidc.jwt import (
    TYPE_AT_JWT,
    TYPE_JWT,
    SigningKey,
    b64url_decode,
    decode,
)
from campusid.oidc.tokens import (
    ACCESS_TOKEN_TTL,
    ID_TOKEN_BASE_CLAIMS,
    ID_TOKEN_TTL,
    TokenContext,
    access_token,
    id_token,
    logout_token,
)

pytestmark = pytest.mark.security

ISSUER = "https://broker.campus.test"
CLIENT = "campus-portal"
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def key() -> SigningKey:
    return keys.generate(key_size=2048)


@pytest.fixture
def context() -> TokenContext:
    return TokenContext(
        issuer=ISSUER,
        client_id=CLIENT,
        subject="Ky7Qw2mVc1Zr@campus.test",
        sid="session-identifier",
        family_id="family-identifier",
        scopes=frozenset({"openid"}),
        auth_time=NOW - timedelta(minutes=2),
        nonce="n-0S6_WzA2Mj",
        acr="urn:campusid:aal1",
        amr=("pwd",),
    )


def _segment(token: str, index: int) -> dict[str, Any]:
    decoded: dict[str, Any] = json.loads(b64url_decode(token.split(".")[index]))
    return decoded


def _claims(token: str) -> dict[str, Any]:
    return _segment(token, 1)


def _header(token: str) -> dict[str, Any]:
    return _segment(token, 0)


# --- the ID token ----------------------------------------------------------


def test_the_openid_scope_alone_yields_exactly_the_required_claims(
    context: TokenContext, key: SigningKey
) -> None:
    """FR-OP-10's list, asserted as an equality.

    A client asking only to know who signed in learns who signed in. Every
    additional claim is personal data travelling somewhere it was not asked
    for, through a token that ends up in browser history and server logs.
    """
    claims = _claims(id_token(context, key, now=NOW))

    assert set(claims) == ID_TOKEN_BASE_CLAIMS


def test_requested_claims_are_added(context: TokenContext, key: SigningKey) -> None:
    with_email = TokenContext(
        issuer=context.issuer,
        client_id=context.client_id,
        subject=context.subject,
        sid=context.sid,
        family_id=context.family_id,
        scopes=frozenset({"openid", "email"}),
        auth_time=context.auth_time,
        nonce=context.nonce,
        acr=context.acr,
        amr=context.amr,
        claims={"email": "sam.obrien@campus.test"},
    )

    claims = _claims(id_token(with_email, key, now=NOW))

    assert claims["email"] == "sam.obrien@campus.test"
    assert set(claims) == ID_TOKEN_BASE_CLAIMS | {"email"}


def test_the_id_token_is_addressed_to_one_client(context: TokenContext, key: SigningKey) -> None:
    """A token naming several audiences is one the others can present as
    evidence of a login that was not theirs."""
    assert _claims(id_token(context, key, now=NOW))["aud"] == CLIENT


def test_the_id_token_lives_five_minutes(context: TokenContext, key: SigningKey) -> None:
    claims = _claims(id_token(context, key, now=NOW))

    assert claims["exp"] - claims["iat"] == ID_TOKEN_TTL.total_seconds()


def test_auth_time_is_when_the_user_authenticated_not_when_the_token_was_made(
    context: TokenContext, key: SigningKey
) -> None:
    """The distinction a client needs to enforce its own `max_age`. Setting
    `auth_time` to `iat` would report every token refresh as a fresh login."""
    claims = _claims(id_token(context, key, now=NOW))

    assert claims["auth_time"] == int(context.auth_time.timestamp())
    assert claims["auth_time"] != claims["iat"]


def test_absent_optional_claims_are_omitted_not_nulled(key: SigningKey) -> None:
    """A client comparing `nonce` against its stored value must fail on
    absence. A JSON null compares equal to nothing while still looking like an
    answer, and some client libraries read it as "checked"."""
    bare = TokenContext(
        issuer=ISSUER,
        client_id=CLIENT,
        subject="subject",
        sid="sid",
        family_id="fid",
        scopes=frozenset({"openid"}),
        auth_time=NOW,
    )

    claims = _claims(id_token(bare, key, now=NOW))

    assert "nonce" not in claims
    assert "acr" not in claims
    assert "amr" not in claims


def test_the_id_token_verifies(context: TokenContext, key: SigningKey) -> None:
    token = id_token(context, key, now=NOW)

    verified = decode(
        token,
        {key.kid: key.private_key.public_key()},
        issuer=ISSUER,
        audience=CLIENT,
        now=NOW,
        expected_typ=TYPE_JWT,
    )

    assert verified["sub"] == context.subject


# --- the access token ------------------------------------------------------


def test_the_access_token_declares_its_type(context: TokenContext, key: SigningKey) -> None:
    """RFC 9068. A resource server can refuse an ID token presented as a bearer
    credential by reading the header, without inspecting claims to guess."""
    token, _ = access_token(context, key, now=NOW)

    assert _header(token)["typ"] == TYPE_AT_JWT


def test_the_access_token_names_its_audience(context: TokenContext, key: SigningKey) -> None:
    """A token with no audience is one that any resource server trusting our
    JWKS will accept, which turns every client's token into a universal key."""
    token, _ = access_token(context, key, now=NOW)

    assert _claims(token)["aud"] == ISSUER


def test_the_access_token_carries_its_family(context: TokenContext, key: SigningKey) -> None:
    """The answer to "a JWT cannot be revoked". Introspection reads `fid` and
    consults the family's revocation marker, so reuse detection takes effect
    before the signature expires."""
    token, _ = access_token(context, key, now=NOW)

    assert _claims(token)["fid"] == context.family_id


def test_the_access_token_carries_a_unique_identifier(
    context: TokenContext, key: SigningKey
) -> None:
    first, first_jti = access_token(context, key, now=NOW)
    _, second_jti = access_token(context, key, now=NOW)

    assert _claims(first)["jti"] == first_jti
    assert first_jti != second_jti


def test_the_access_token_lifetime_is_the_revocation_window(
    context: TokenContext, key: SigningKey
) -> None:
    """Fifteen minutes is a security parameter, not a performance setting: it is
    how long a resource server that validates locally and never introspects will
    honour a token from a family that has already been revoked."""
    claims = _claims(access_token(context, key, now=NOW)[0])

    assert claims["exp"] - claims["iat"] == ACCESS_TOKEN_TTL.total_seconds()


def test_the_access_token_records_the_granted_scope(key: SigningKey) -> None:
    context = TokenContext(
        issuer=ISSUER,
        client_id=CLIENT,
        subject="subject",
        sid="sid",
        family_id="fid",
        scopes=frozenset({"openid", "email", "profile"}),
        auth_time=NOW,
    )

    assert _claims(access_token(context, key, now=NOW)[0])["scope"] == "email openid profile"


def test_the_access_token_carries_no_identity_claims(key: SigningKey) -> None:
    """It is a capability, not a description of a person. Attributes belong in
    the ID token or behind `/userinfo`, where the release decision is made once
    and can be changed without reissuing credentials."""
    context = TokenContext(
        issuer=ISSUER,
        client_id=CLIENT,
        subject="subject",
        sid="sid",
        family_id="fid",
        scopes=frozenset({"openid", "email"}),
        auth_time=NOW,
        claims={"email": "sam.obrien@campus.test"},
    )

    assert "email" not in _claims(access_token(context, key, now=NOW)[0])


# --- the logout token ------------------------------------------------------


def test_the_logout_token_carries_the_logout_event(context: TokenContext, key: SigningKey) -> None:
    claims = _claims(logout_token(context, key, now=NOW))

    assert claims["events"] == {"http://schemas.openid.net/event/backchannel-logout": {}}
    assert claims["sid"] == context.sid


def test_the_logout_token_has_no_nonce(context: TokenContext, key: SigningKey) -> None:
    """Back-Channel Logout 1.0 §2.4 forbids it, so a logout token can never be
    replayed into a client's login handler as proof that somebody signed in."""
    assert "nonce" not in _claims(logout_token(context, key, now=NOW))
