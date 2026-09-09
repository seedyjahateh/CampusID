"""The login-CSRF request binding (FR-SES, NFR-SEC-05).

An assertion is a statement about *someone*; it does not say who asked for it.
Without a binding, an attacker completes a login of their own, captures the
response, and feeds it to a victim's browser — the victim ends up signed in as
the attacker, which is how account-linking and stored-data attacks start.

The binding is a nonce the broker generates when it sends the `AuthnRequest`,
stored server-side under the `RelayState` and mirrored in a `SameSite=None`
cookie. Both halves must agree.
"""

from __future__ import annotations

from typing import Any

import pytest
from fakeredis import aioredis

from campusid.errors import ReasonCode, SamlRejected
from campusid.routes.saml import BINDING_KEY_PREFIX, assert_request_binding
from campusid.session.cookies import REQUEST_BINDING_COOKIE

pytestmark = pytest.mark.security

RELAY_STATE = "relay-token"
NONCE = "binding-nonce"


class _Request:
    """The two things the binding check reads off a request."""

    def __init__(self, redis: aioredis.FakeRedis, cookie: str | None) -> None:
        self.cookies = {REQUEST_BINDING_COOKIE: cookie} if cookie is not None else {}
        self.app = type("App", (), {"state": type("State", (), {"redis": redis})()})()


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


async def _store_nonce(redis: aioredis.FakeRedis, nonce: str = NONCE) -> None:
    await redis.set(f"{BINDING_KEY_PREFIX}{RELAY_STATE}", nonce, ex=300)


async def test_a_matching_binding_is_accepted(redis: aioredis.FakeRedis) -> None:
    await _store_nonce(redis)

    await assert_request_binding(_Request(redis, NONCE), RELAY_STATE)  # type: ignore[arg-type]


async def test_a_missing_cookie_is_refused(redis: aioredis.FakeRedis) -> None:
    """The attack itself: the victim's browser never received the nonce,
    because it never started this login."""
    await _store_nonce(redis)

    with pytest.raises(SamlRejected) as exc:
        await assert_request_binding(_Request(redis, None), RELAY_STATE)  # type: ignore[arg-type]

    assert exc.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_a_wrong_cookie_is_refused(redis: aioredis.FakeRedis) -> None:
    await _store_nonce(redis)

    with pytest.raises(SamlRejected) as exc:
        await assert_request_binding(_Request(redis, "guessed"), RELAY_STATE)  # type: ignore[arg-type]

    assert exc.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_a_missing_relay_state_is_refused(redis: aioredis.FakeRedis) -> None:
    with pytest.raises(SamlRejected) as exc:
        await assert_request_binding(_Request(redis, NONCE), None)  # type: ignore[arg-type]

    assert exc.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_an_unknown_relay_state_is_refused(redis: aioredis.FakeRedis) -> None:
    """Nothing stored: either the request expired or it was never made here."""
    with pytest.raises(SamlRejected) as exc:
        await assert_request_binding(_Request(redis, NONCE), RELAY_STATE)  # type: ignore[arg-type]

    assert exc.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_the_binding_is_consumed_on_use(redis: aioredis.FakeRedis) -> None:
    """Fetched and deleted in one step, so a captured RelayState and cookie
    pair cannot be replayed even inside the five-minute window."""
    await _store_nonce(redis)
    request: Any = _Request(redis, NONCE)

    await assert_request_binding(request, RELAY_STATE)

    with pytest.raises(SamlRejected):
        await assert_request_binding(request, RELAY_STATE)


async def test_the_binding_is_consumed_even_when_it_does_not_match(
    redis: aioredis.FakeRedis,
) -> None:
    """A failed attempt burns the nonce too.

    That is deliberate: leaving it in place would let an attacker brute-force
    the cookie value against a stored nonce that never expires early. The
    legitimate user simply starts again.
    """
    await _store_nonce(redis)

    with pytest.raises(SamlRejected):
        await assert_request_binding(_Request(redis, "wrong"), RELAY_STATE)  # type: ignore[arg-type]

    assert await redis.get(f"{BINDING_KEY_PREFIX}{RELAY_STATE}") is None
