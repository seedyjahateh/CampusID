"""Authorization code and refresh token reuse (FR-OP-04, FR-OP-08).

Run against `fakeredis`, which implements real Redis semantics, so the `SET NX`
that makes single-use atomic is actually being exercised rather than mocked
away.

The interesting case in this file is never the honest client. It is always the
second presentation.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import aioredis

from campusid.errors import ReasonCode
from campusid.oidc.errors import INVALID_GRANT, OAuthError
from campusid.oidc.grants import (
    CODE_KEY_PREFIX,
    AuthorizationCode,
    GrantReuse,
    GrantStore,
    RefreshToken,
    new_family_id,
)

pytestmark = pytest.mark.security

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
CLIENT = "campus-portal"
REDIRECT = "https://portal.campus.test/oidc/callback"


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def store(redis: aioredis.FakeRedis) -> GrantStore:
    return GrantStore(redis)


@pytest.fixture
def family() -> str:
    return new_family_id()


@pytest.fixture
def grant(family: str) -> AuthorizationCode:
    return AuthorizationCode(
        client_id=CLIENT,
        redirect_uri=REDIRECT,
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes=("openid", "email"),
        subject="opaque-subject",
        sid="session-id",
        family_id=family,
        nonce="n-0S6_WzA2Mj",
        auth_time=NOW,
        acr="urn:campusid:aal1",
        amr=("pwd",),
    )


def _refresh(family: str, generation: int = 0) -> RefreshToken:
    return RefreshToken(
        client_id=CLIENT,
        scopes=("openid", "email"),
        subject="opaque-subject",
        sid="session-id",
        family_id=family,
        generation=generation,
        issued_at=NOW,
    )


# --- authorization codes ---------------------------------------------------


async def test_a_code_round_trips(store: GrantStore, grant: AuthorizationCode) -> None:
    code = await store.issue_code(grant)

    assert await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT) == grant


async def test_a_grant_round_trips_without_its_optional_claims(
    store: GrantStore, family: str
) -> None:
    """`nonce`, `auth_time`, `acr` and `amr` are absent for a plain OAuth grant.
    The record has to survive the trip through Redis without them rather than
    failing to deserialise at the token endpoint, an hour after the mistake."""
    minimal = AuthorizationCode(
        client_id=CLIENT,
        redirect_uri=REDIRECT,
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes=("openid",),
        subject="opaque-subject",
        sid="session-id",
        family_id=family,
    )
    code = await store.issue_code(minimal)

    assert await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT) == minimal


async def test_a_code_is_single_use(store: GrantStore, grant: AuthorizationCode) -> None:
    code = await store.issue_code(grant)
    await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    with pytest.raises(GrantReuse) as raised:
        await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    assert raised.value.reason is ReasonCode.GRANT_REUSE_DETECTED


async def test_reusing_a_code_revokes_the_family(
    store: GrantStore, grant: AuthorizationCode, family: str
) -> None:
    """FR-OP-04. The tokens already issued from the first redemption die with
    it: if the replay came from an attacker, the honest client's tokens are the
    ones that need cancelling, and there is no way to tell the two apart."""
    code = await store.issue_code(grant)
    await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)
    refresh = await store.issue_refresh_token(_refresh(family))

    with pytest.raises(GrantReuse):
        await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    assert await store.is_family_revoked(family)
    with pytest.raises(OAuthError, match="revoked"):
        await store.rotate_refresh_token(refresh, client_id=CLIENT)


async def test_reuse_is_distinguishable_from_expiry(
    store: GrantStore, grant: AuthorizationCode, redis: aioredis.FakeRedis
) -> None:
    """The reason consumption is a marker rather than a delete.

    Deleting the record on use is the obvious implementation, and it makes the
    second presentation look exactly like a timeout - so the one event that says
    a credential leaked gets logged as routine.
    """
    code = await store.issue_code(grant)
    await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    with pytest.raises(GrantReuse):
        await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    await redis.flushall()
    with pytest.raises(OAuthError) as expired:
        await store.redeem_code(code, client_id=CLIENT, redirect_uri=REDIRECT)

    assert expired.value.reason is ReasonCode.GRANT_INVALID
    assert not isinstance(expired.value, GrantReuse)


async def test_an_unknown_code_is_refused(store: GrantStore) -> None:
    with pytest.raises(OAuthError) as raised:
        await store.redeem_code("never-issued", client_id=CLIENT, redirect_uri=REDIRECT)

    assert raised.value.reason is ReasonCode.GRANT_INVALID
    assert raised.value.error == INVALID_GRANT


async def test_a_code_expires(grant: AuthorizationCode, redis: aioredis.FakeRedis) -> None:
    store = GrantStore(redis, code_ttl=timedelta(seconds=60))
    code = await store.issue_code(grant)

    assert 0 < await redis.ttl(f"{CODE_KEY_PREFIX}{_sha(code)}") <= 60


async def test_a_code_redeemed_by_another_client_revokes_the_family(
    store: GrantStore, grant: AuthorizationCode, family: str
) -> None:
    """Nobody reaches this by misconfiguration. A client presenting a code it
    was not issued is holding one it intercepted."""
    code = await store.issue_code(grant)

    with pytest.raises(OAuthError, match="another client"):
        await store.redeem_code(code, client_id="someone-else", redirect_uri=REDIRECT)

    assert await store.is_family_revoked(family)


async def test_a_code_is_bound_to_its_redirect_uri(
    store: GrantStore, grant: AuthorizationCode
) -> None:
    """Checked against the value recorded at issue time, not the one repeated on
    the token request - which is the parameter an attacker controls."""
    code = await store.issue_code(grant)

    with pytest.raises(OAuthError, match="redirect_uri"):
        await store.redeem_code(code, client_id=CLIENT, redirect_uri="https://evil.test/cb")


async def test_the_code_is_not_stored_in_redeemable_form(
    store: GrantStore, grant: AuthorizationCode, redis: aioredis.FakeRedis
) -> None:
    """A Redis dump, a monitoring exporter, a key that lands in a log line: none
    of them should yield anything anyone can spend."""
    code = await store.issue_code(grant)

    keys = await redis.keys("*")

    assert not any(code in key for key in keys)
    assert f"{CODE_KEY_PREFIX}{_sha(code)}" in keys


# --- refresh tokens --------------------------------------------------------


async def test_a_refresh_token_rotates(store: GrantStore, family: str) -> None:
    first = await store.issue_refresh_token(_refresh(family))

    second, record = await store.rotate_refresh_token(first, client_id=CLIENT, now=NOW)

    assert second != first
    assert record.generation == 1
    assert record.family_id == family


async def test_the_rotated_away_token_is_dead(store: GrantStore, family: str) -> None:
    first = await store.issue_refresh_token(_refresh(family))
    second, _ = await store.rotate_refresh_token(first, client_id=CLIENT, now=NOW)

    with pytest.raises(GrantReuse):
        await store.rotate_refresh_token(first, client_id=CLIENT, now=NOW)

    with pytest.raises(OAuthError, match="revoked"):
        await store.rotate_refresh_token(second, client_id=CLIENT, now=NOW)


async def test_reuse_revokes_the_whole_family_not_just_the_token(
    store: GrantStore, family: str
) -> None:
    """RFC 9700 §4.14.2. Revoking only the replayed token leaves whichever party
    rotated successfully holding a valid one - and if that is the attacker, the
    detection accomplished nothing.

    The honest user being signed out is the cost, and it is the point: the
    broker cannot tell the two presentations apart, so it stops trusting both.
    """
    first = await store.issue_refresh_token(_refresh(family))
    generation_two, _ = await store.rotate_refresh_token(first, client_id=CLIENT, now=NOW)
    generation_three, _ = await store.rotate_refresh_token(
        generation_two, client_id=CLIENT, now=NOW
    )

    with pytest.raises(GrantReuse) as raised:
        await store.rotate_refresh_token(first, client_id=CLIENT, now=NOW)

    assert raised.value.reason is ReasonCode.GRANT_REUSE_DETECTED
    assert await store.is_family_revoked(family)
    with pytest.raises(OAuthError) as latest:
        await store.rotate_refresh_token(generation_three, client_id=CLIENT, now=NOW)
    assert latest.value.reason is ReasonCode.GRANT_REVOKED


async def test_a_revoked_family_refuses_before_it_rotates(store: GrantStore, family: str) -> None:
    """Order matters: the revocation check runs before the spend marker, so a
    token in a dead family is refused rather than being consumed and its
    successor minted into a family nobody can use."""
    token = await store.issue_refresh_token(_refresh(family))
    await store.revoke_family(family)

    with pytest.raises(OAuthError) as raised:
        await store.rotate_refresh_token(token, client_id=CLIENT, now=NOW)

    assert raised.value.reason is ReasonCode.GRANT_REVOKED


async def test_an_unknown_refresh_token_is_refused(store: GrantStore) -> None:
    with pytest.raises(OAuthError) as raised:
        await store.rotate_refresh_token("never-issued", client_id=CLIENT)

    assert raised.value.reason is ReasonCode.GRANT_INVALID


async def test_a_refresh_token_is_bound_to_its_client(store: GrantStore, family: str) -> None:
    token = await store.issue_refresh_token(_refresh(family))

    with pytest.raises(OAuthError, match="another client"):
        await store.rotate_refresh_token(token, client_id="someone-else")

    assert await store.is_family_revoked(family)


async def test_the_refresh_token_is_not_stored_in_redeemable_form(
    store: GrantStore, family: str, redis: aioredis.FakeRedis
) -> None:
    token = await store.issue_refresh_token(_refresh(family))

    assert not any(token in key for key in await redis.keys("*"))


async def test_families_do_not_interfere(store: GrantStore) -> None:
    """Two logins by the same user are independent. Revoking one must not sign
    the other out - the blast radius is one authorization code's lineage."""
    doomed, survivor = new_family_id(), new_family_id()
    token = await store.issue_refresh_token(_refresh(survivor))
    await store.revoke_family(doomed)

    assert not await store.is_family_revoked(survivor)
    rotated, _ = await store.rotate_refresh_token(token, client_id=CLIENT, now=NOW)
    assert rotated


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()
