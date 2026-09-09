"""Authenticating against an upstream provider (FR-RP-01).

The sceptical side of the relationship: every check here exists because
something upstream might be wrong, compromised, or lying. Most of the file is
about tokens that verify perfectly and still must not be accepted.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fakeredis import aioredis

from campusid.errors import BrokerError, ReasonCode
from campusid.oidc import keys as oidc_keys
from campusid.oidc.jwt import SigningKey, encode
from campusid.oidc.keys import public_jwk
from campusid.oidc.pkce import compute_challenge
from campusid.policy.attributes import EPPN, MAIL
from campusid.rp.client import PendingLogin, UpstreamClient, UpstreamProvider
from campusid.rp.jwks import JwksCache

pytestmark = pytest.mark.security

ISSUER = "https://partner.test"
CLIENT_ID = "campusid-broker"
REDIRECT = "https://broker.test/rp/callback"
NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def upstream_key() -> SigningKey:
    return oidc_keys.generate(key_size=2048)


@pytest.fixture(scope="module")
def stranger_key() -> SigningKey:
    """A key the provider does not publish. The realistic attacker is not one
    with no key but one with *a* key."""
    return oidc_keys.generate(key_size=2048)


class _Upstream:
    """A stand-in provider: a JWKS endpoint and a token endpoint."""

    def __init__(self, key: SigningKey) -> None:
        self.key = key
        self.id_token: str | None = None
        self.token_status = 200
        self.exchanges: list[dict[str, list[str]]] = []

    async def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("jwks.json"):
            return httpx.Response(200, json={"keys": [public_jwk(self.key)]})

        self.exchanges.append(dict(parse_qs(request.content.decode(), keep_blank_values=True)))
        if self.token_status >= 400:
            return httpx.Response(self.token_status, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "upstream-at", "id_token": self.id_token})


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def upstream(upstream_key: SigningKey) -> _Upstream:
    return _Upstream(upstream_key)


@pytest.fixture
def client(upstream: _Upstream, redis: aioredis.FakeRedis) -> UpstreamClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(upstream.handle))
    provider = UpstreamProvider(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",
        client_id=CLIENT_ID,
        client_secret="s" * 43,
        redirect_uri=REDIRECT,
    )
    return UpstreamClient(
        provider,
        http=http,
        redis=redis,
        jwks=JwksCache(provider.jwks_uri, http=http, redis=redis),
        now=lambda: NOW,
    )


def _id_token(key: SigningKey, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "248289761001",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "preferred_username": "sam.obrien@partner.test",
        "email": "sam.obrien@partner.test",
    }
    claims.update(overrides)
    return encode(claims, key)


async def _login(client: UpstreamClient) -> tuple[str, PendingLogin]:
    """Start a login and return the pending state the callback would consume."""
    url = await client.begin()
    state = parse_qs(urlsplit(url).query)["state"][0]
    return state, await client.consume_state(state)


# --- starting a login -------------------------------------------------------


async def test_the_authorization_url_carries_what_the_flow_needs(
    client: UpstreamClient,
) -> None:
    query = parse_qs(urlsplit(await client.begin()).query)

    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [REDIRECT]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] and query["nonce"] and query["code_challenge"]


async def test_pkce_is_used_upstream_too(client: UpstreamClient) -> None:
    """We are a confidential client here and could skip it. We do not: client
    authentication proves which application redeems the code, not which browser
    session it belongs to."""
    url = await client.begin()
    state = parse_qs(urlsplit(url).query)["state"][0]
    challenge = parse_qs(urlsplit(url).query)["code_challenge"][0]

    pending = await client.consume_state(state)

    assert compute_challenge(pending.code_verifier) == challenge


async def test_each_login_gets_fresh_state(client: UpstreamClient) -> None:
    first = parse_qs(urlsplit(await client.begin()).query)["state"][0]
    second = parse_qs(urlsplit(await client.begin()).query)["state"][0]

    assert first != second


# --- the callback's state ---------------------------------------------------


async def test_a_state_we_did_not_issue_is_refused(client: UpstreamClient) -> None:
    """This is what an attacker sends to complete *their* login in a victim's
    browser, so it is the first check and it is unconditional."""
    with pytest.raises(BrokerError) as raised:
        await client.consume_state("never-issued")

    assert raised.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_a_missing_state_is_refused(client: UpstreamClient) -> None:
    with pytest.raises(BrokerError, match="no state"):
        await client.consume_state(None)


async def test_state_is_single_use(client: UpstreamClient) -> None:
    """A captured callback URL cannot be replayed: the second attempt finds
    nothing."""
    state, _ = await _login(client)

    with pytest.raises(BrokerError):
        await client.consume_state(state)


# --- the ID token -----------------------------------------------------------


async def test_a_valid_login_yields_an_identity(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, nonce=pending.nonce)

    identity = await client.exchange("the-code", pending)

    assert identity.issuer == ISSUER
    assert identity.subject == "248289761001"
    assert identity.attributes[EPPN] == ["sam.obrien@partner.test"]
    assert identity.attributes[MAIL] == ["sam.obrien@partner.test"]


async def test_the_verifier_is_presented_at_the_token_endpoint(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, nonce=pending.nonce)

    await client.exchange("the-code", pending)

    assert upstream.exchanges[0]["code_verifier"] == [pending.code_verifier]


async def test_a_token_signed_by_a_stranger_is_refused(
    client: UpstreamClient, upstream: _Upstream, stranger_key: SigningKey
) -> None:
    """The realistic attacker is not one with no key but one with *a* key."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(stranger_key, nonce=pending.nonce)

    with pytest.raises(BrokerError) as raised:
        await client.exchange("the-code", pending)

    assert raised.value.reason is ReasonCode.SIGNATURE_INVALID


async def test_a_token_from_another_issuer_is_refused(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """Compared exactly, never by prefix. An issuer that is a prefix of another
    is how a multi-tenant provider's tenant A gets accepted as tenant B."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, iss=f"{ISSUER}/tenant-b", nonce=pending.nonce)

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


async def test_a_token_for_another_audience_is_refused(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, aud="somebody-else", nonce=pending.nonce)

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


async def test_an_expired_token_is_refused(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(
        upstream_key,
        exp=int((NOW - timedelta(hours=1)).timestamp()),
        nonce=pending.nonce,
    )

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


async def test_a_five_minute_clock_disagreement_is_tolerated(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """FR-RP-01's ceiling. Wider than the SAML gate's 180s because a five-minute
    disagreement between two organisations' clocks is ordinary, and we do not
    operate the other one."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(
        upstream_key,
        exp=int((NOW - timedelta(seconds=240)).timestamp()),
        nonce=pending.nonce,
    )

    assert await client.exchange("the-code", pending)


# --- the nonce --------------------------------------------------------------


async def test_a_token_answering_another_login_is_refused(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """The nonce is compared against the stored value, not merely required. An
    ID token stays replayable until its `exp`, and a presence check would accept
    one captured from another session at the same provider."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, nonce="a-different-login")

    with pytest.raises(BrokerError) as raised:
        await client.exchange("the-code", pending)

    assert raised.value.reason is ReasonCode.REQUEST_BINDING_INVALID


async def test_a_token_with_no_nonce_is_refused(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key)

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


# --- the authorized party ---------------------------------------------------


async def test_a_multi_audience_token_must_name_us_as_authorized_party(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """OIDC Core §3.1.3.7. Without the check, a provider that issues one token
    to several audiences hands any of them a token we would accept as ours."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(
        upstream_key,
        aud=[CLIENT_ID, "another-client"],
        azp="another-client",
        nonce=pending.nonce,
    )

    with pytest.raises(BrokerError) as raised:
        await client.exchange("the-code", pending)

    assert raised.value.reason is ReasonCode.AUDIENCE_MISMATCH


async def test_a_multi_audience_token_authorized_for_us_is_accepted(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(
        upstream_key,
        aud=[CLIENT_ID, "another-client"],
        azp=CLIENT_ID,
        nonce=pending.nonce,
    )

    assert await client.exchange("the-code", pending)


async def test_a_single_audience_token_needs_no_azp(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """The requirement applies only when the audience is multi-valued, and
    demanding `azp` universally would refuse most providers' tokens."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, aud=[CLIENT_ID], nonce=pending.nonce)

    assert await client.exchange("the-code", pending)


# --- the provider misbehaving ----------------------------------------------


async def test_a_refused_code_is_reported_without_the_providers_words(
    client: UpstreamClient, upstream: _Upstream
) -> None:
    """The provider's error text is written for us. A browser showing it would
    leak how this integration is configured."""
    _, pending = await _login(client)
    upstream.token_status = 400

    with pytest.raises(BrokerError) as raised:
        await client.exchange("the-code", pending)

    assert raised.value.reason is ReasonCode.GRANT_INVALID
    assert "invalid_grant" not in str(raised.value.detail)


async def test_a_response_without_an_id_token_is_refused(
    client: UpstreamClient, upstream: _Upstream
) -> None:
    """A plain OAuth response to an `openid` request. Continuing would mean
    treating an access token as proof somebody authenticated."""
    _, pending = await _login(client)
    upstream.id_token = None

    with pytest.raises(BrokerError) as raised:
        await client.exchange("the-code", pending)

    assert raised.value.reason is ReasonCode.SIGNATURE_MISSING


async def test_a_token_with_an_unknown_kid_is_refused_not_accepted(
    client: UpstreamClient, upstream: _Upstream, stranger_key: SigningKey
) -> None:
    """The refresh a missing `kid` triggers is rate-limited, so the interesting
    question is what happens when it cannot help: a refusal, never a fallback to
    trying every key we hold."""
    _, pending = await _login(client)
    upstream.id_token = _id_token(stranger_key, nonce=pending.nonce)

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


async def test_a_malformed_token_is_refused(client: UpstreamClient, upstream: _Upstream) -> None:
    _, pending = await _login(client)
    upstream.id_token = "not.a.token"

    with pytest.raises(BrokerError):
        await client.exchange("the-code", pending)


# --- what the identity carries ---------------------------------------------


async def test_the_authentication_instant_is_carried(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    """A client enforcing `max_age` downstream needs the upstream instant, not
    the moment we happened to process the callback."""
    _, pending = await _login(client)
    authenticated = NOW - timedelta(minutes=3)
    upstream.id_token = _id_token(
        upstream_key, auth_time=int(authenticated.timestamp()), nonce=pending.nonce
    )

    identity = await client.exchange("the-code", pending)

    assert identity.auth_time == authenticated


async def test_the_assurance_is_carried(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(
        upstream_key,
        acr="https://refeds.org/profile/mfa",
        amr=["pwd", "otp"],
        nonce=pending.nonce,
    )

    identity = await client.exchange("the-code", pending)

    assert identity.acr == "https://refeds.org/profile/mfa"
    assert identity.amr == ("pwd", "otp")


async def test_an_unmapped_claim_does_not_reach_the_attributes(
    client: UpstreamClient, upstream: _Upstream, upstream_key: SigningKey
) -> None:
    _, pending = await _login(client)
    upstream.id_token = _id_token(upstream_key, department="Computer Science", nonce=pending.nonce)

    identity = await client.exchange("the-code", pending)

    assert "department" not in identity.attributes
    assert "Computer Science" not in json.dumps(identity.attributes)
