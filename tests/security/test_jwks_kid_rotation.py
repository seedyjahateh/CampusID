"""Caching an upstream provider's keys (FR-RP-01).

Three sharp edges, and every test here is on one of them: a rotation must not
need a restart, the refresh that makes that true must not be a lever an
attacker can pull, and a JWK is untrusted input parsed before anything is
verified.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fakeredis import aioredis

from campusid.oidc import keys as oidc_keys
from campusid.oidc.keys import public_jwk
from campusid.rp.jwks import JwksCache, parse_jwks

pytestmark = pytest.mark.security

JWKS_URI = "https://partner.test/.well-known/jwks.json"


class _Provider:
    """A stand-in JWKS endpoint that counts what we ask of it."""

    def __init__(self, *keys: Any) -> None:
        self.published = list(keys)
        self.fetches = 0
        self.status = 200

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        if self.status >= 400:
            return httpx.Response(self.status)
        return httpx.Response(200, json={"keys": [public_jwk(key) for key in self.published]})


@pytest.fixture(scope="module")
def first() -> Any:
    return oidc_keys.generate(key_size=2048)


@pytest.fixture(scope="module")
def second() -> Any:
    return oidc_keys.generate(key_size=2048)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def provider(first: Any) -> _Provider:
    return _Provider(first)


@pytest.fixture
def cache(provider: _Provider, redis: aioredis.FakeRedis) -> JwksCache:
    return JwksCache(
        JWKS_URI,
        http=httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)),
        redis=redis,
    )


# --- the ordinary path ------------------------------------------------------


async def test_the_keys_are_fetched_on_first_use(cache: JwksCache, first: Any) -> None:
    keys = await cache.verification_keys(first.kid)

    assert set(keys) == {first.kid}


async def test_a_known_kid_does_not_refetch(
    cache: JwksCache, provider: _Provider, first: Any
) -> None:
    """Every ID token would otherwise cost a round trip to the provider, and the
    provider would be entitled to rate-limit us for it."""
    await cache.verification_keys(first.kid)
    await cache.verification_keys(first.kid)

    assert provider.fetches == 1


async def test_an_unknown_kid_triggers_a_refresh(
    cache: JwksCache, provider: _Provider, first: Any, second: Any
) -> None:
    """A provider rotates on its own schedule and does not tell us. Requiring a
    restart to notice would make every rotation an outage."""
    await cache.verification_keys(first.kid)
    provider.published = [first, second]

    keys = await cache.verification_keys(second.kid)

    assert second.kid in keys
    assert provider.fetches == 2


async def test_a_rotation_keeps_the_outgoing_key_while_it_is_published(
    cache: JwksCache, provider: _Provider, first: Any, second: Any
) -> None:
    """Both are in the document during the overlap, so a token signed a second
    before the rotation still verifies."""
    provider.published = [first, second]

    keys = await cache.verification_keys(second.kid)

    assert set(keys) == {first.kid, second.kid}


async def test_a_retired_key_disappears(
    cache: JwksCache, provider: _Provider, first: Any, second: Any
) -> None:
    await cache.verification_keys(first.kid)
    provider.published = [second]

    keys = await cache.verification_keys(second.kid)

    assert first.kid not in keys


# --- the refresh as a lever -------------------------------------------------


async def test_refreshes_are_rate_limited(
    cache: JwksCache, provider: _Provider, first: Any
) -> None:
    """Anyone who can reach our callback can present a token bearing a `kid` we
    have never seen. If every miss fetched, they could make us hammer the
    provider on demand — a denial of service we would be delivering on their
    behalf."""
    await cache.verification_keys(first.kid)

    for _ in range(20):
        await cache.verification_keys("never-published")

    assert provider.fetches == 2


async def test_a_throttled_miss_returns_what_is_cached(cache: JwksCache, first: Any) -> None:
    """Rather than raising. The caller then fails to verify the token, which is
    the same outcome by a safer route: a refusal we chose beats an exception
    thrown from inside a signature check."""
    await cache.verification_keys(first.kid)
    await cache.verification_keys("never-published")

    keys = await cache.verification_keys("also-never-published")

    assert set(keys) == {first.kid}


async def test_the_limiter_is_shared_across_replicas(
    provider: _Provider, redis: aioredis.FakeRedis, first: Any
) -> None:
    """A per-process limit multiplies by however many replicas are running,
    which is exactly the number an attacker would like to be large. Two caches
    over one Redis stand in for two replicas, both warm and both missing the
    same `kid`."""
    http = httpx.AsyncClient(transport=httpx.MockTransport(provider.handle))
    one = JwksCache(JWKS_URI, http=http, redis=redis)
    two = JwksCache(JWKS_URI, http=http, redis=redis)
    await one.verification_keys(first.kid)
    await two.verification_keys(first.kid)
    warm = provider.fetches

    await one.verification_keys("unknown")
    await two.verification_keys("unknown")

    assert provider.fetches == warm + 1


async def test_a_cold_cache_is_not_made_to_wait_for_the_rotation_limiter(
    provider: _Provider, redis: aioredis.FakeRedis, first: Any
) -> None:
    """Two limiters rather than one, because the situations differ.

    A rotation refresh can afford a minute — the keys we hold still verify
    almost everything. A cold cache verifies nothing, so charging its first
    fetch to the rotation budget would leave a genuine rotation moments later
    unable to fetch, and every token signed with the new key failing until the
    minute elapsed.
    """
    http = httpx.AsyncClient(transport=httpx.MockTransport(provider.handle))
    cache = JwksCache(JWKS_URI, http=http, redis=redis)

    await cache.verification_keys(first.kid)
    provider.published = [first, oidc_keys.generate(key_size=2048)]
    rotated = provider.published[1]

    assert rotated.kid in await cache.verification_keys(rotated.kid)


async def test_a_cold_cache_against_a_dead_provider_is_still_limited(
    provider: _Provider, redis: aioredis.FakeRedis
) -> None:
    """Otherwise every request retries a five-second timeout, and a provider
    outage becomes our own thundering herd."""
    provider.status = 503
    cache = JwksCache(
        JWKS_URI,
        http=httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)),
        redis=redis,
    )

    for _ in range(10):
        await cache.verification_keys("anything")

    assert provider.fetches == 1


# --- the provider misbehaving ----------------------------------------------


async def test_a_failed_fetch_keeps_the_previous_keys(
    cache: JwksCache, provider: _Provider, first: Any
) -> None:
    """Emptying the cache would turn one unreachable provider into every session
    failing, when the keys we already hold are almost certainly still right."""
    await cache.verification_keys(first.kid)
    provider.status = 503

    keys = await cache.verification_keys("unknown")

    assert set(keys) == {first.kid}


async def test_an_empty_document_keeps_the_previous_keys(
    cache: JwksCache, provider: _Provider, first: Any
) -> None:
    """A different problem from a network failure, and equally not a reason to
    discard keys that were working a minute ago."""
    await cache.verification_keys(first.kid)
    provider.published = []

    keys = await cache.verification_keys("unknown")

    assert set(keys) == {first.kid}


# --- a JWK is untrusted input ----------------------------------------------


@pytest.mark.parametrize("document", [[], {"keys": "not-a-list"}, "nonsense", None])
def test_a_document_that_is_not_a_key_set_is_refused(document: Any) -> None:
    with pytest.raises(ValueError, match="JWKS"):
        parse_jwks(document)


def test_one_bad_entry_does_not_spoil_the_document(first: Any) -> None:
    """An OP publishing junk alongside its real keys must not be able to take
    the integration down."""
    good = public_jwk(first)

    parsed = parse_jwks({"keys": ["not-a-dict", {"kty": "RSA"}, good, {}]})

    assert set(parsed) == {first.kid}


def test_a_non_rsa_key_is_skipped(first: Any) -> None:
    """Providers publish EC keys alongside RSA ones. Skipping is not a
    judgement about EC — it is that this verifier only does RS256."""
    parsed = parse_jwks({"keys": [{"kty": "EC", "kid": "ec-1", "crv": "P-256"}]})

    assert parsed == {}


def test_a_key_without_a_kid_is_skipped(first: Any) -> None:
    """It could never be selected during a rotation, which is the one situation
    the cache exists for."""
    entry = {k: v for k, v in public_jwk(first).items() if k != "kid"}

    assert parse_jwks({"keys": [entry]}) == {}


def test_an_encryption_key_is_skipped(first: Any) -> None:
    """Published in the same document and not ours to verify with."""
    entry = {**public_jwk(first), "use": "enc"}

    assert parse_jwks({"keys": [entry]}) == {}


def test_a_key_declaring_another_algorithm_is_skipped(first: Any) -> None:
    """`alg` is optional in a JWK. When present and not RS256, the provider is
    telling us what the key is for, and it is not us."""
    entry = {**public_jwk(first), "alg": "PS256"}

    assert parse_jwks({"keys": [entry]}) == {}


def test_a_key_without_a_declared_algorithm_is_accepted(first: Any) -> None:
    entry = {k: v for k, v in public_jwk(first).items() if k != "alg"}

    assert set(parse_jwks({"keys": [entry]})) == {first.kid}


def test_a_short_modulus_is_refused(first: Any) -> None:
    """Below the floor we hold our own keys to. A 1024-bit upstream key is one
    somebody can factor, and accepting it because a partner published it would
    make their mistake our compromise."""
    weak = public_jwk(oidc_keys.generate(key_size=1024))

    assert parse_jwks({"keys": [weak]}) == {}


def test_malformed_parameters_are_skipped(first: Any) -> None:
    for broken in ({"n": 12345}, {"n": "!!!not-base64!!!"}, {"e": None}):
        entry = {**public_jwk(first), **broken}
        assert parse_jwks({"keys": [entry]}) == {}
