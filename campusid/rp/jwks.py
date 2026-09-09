"""The upstream provider's verification keys (FR-RP-01).

Reading somebody else's JWKS is a small problem with three sharp edges, and the
whole module is about them.

**A key rotation must not need a restart.** An OP rotates on its own schedule
and does not tell us. So an unknown `kid` triggers a refresh — which is correct,
and is also the second edge.

**That refresh is an unauthenticated lever.** Anyone who can reach our callback
can present a token bearing a `kid` we have never seen, and if every miss
fetched the JWKS they could make us hammer the OP on demand: a denial of service
we would be delivering on their behalf. So refreshes are rate-limited to one a
minute, the limiter is in Redis so replicas share it, and a miss that arrives
while the limiter is closed is simply a verification failure. Refusing a token
we cannot verify is always safe; fetching on demand is not.

**A JWK is attacker-adjacent input.** It arrives over HTTPS from the OP, but the
parse happens before anything is verified, so it is treated as untrusted:
non-RSA keys, keys declaring an algorithm we do not accept, and malformed
parameters are skipped rather than raising, because one bad entry in an OP's
document must not make the other keys unusable.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any, Final

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from redis.asyncio import Redis

from campusid.logging import get_logger
from campusid.oidc.jwt import RS256

log = get_logger(__name__)

REFRESH_LIMIT_PREFIX: Final = "rp:jwks:refresh:"
REFRESH_INTERVAL_SECONDS: Final = 60
"""FR-RP-01's "1 refresh/min", governing refreshes prompted by an unknown `kid`.
Shared across replicas through Redis, because a per-process limit multiplies by
however many replicas are running — which is exactly the number an attacker
would like to be large."""

COLD_LIMIT_PREFIX: Final = "rp:jwks:cold:"
COLD_INTERVAL_SECONDS: Final = 5
"""A separate, much shorter limiter for the case where we hold *no* keys at all.

Two limiters rather than one, because the two situations differ. A rotation
refresh can afford to wait a minute: the keys we hold still verify almost
everything. A cold cache verifies nothing, so making it wait a minute turns a
brief provider outage into a full minute of refused logins *after* the provider
recovers. Five seconds is enough to stop a thundering herd — our own workers as
much as the provider's — without extending an outage past its cause.
"""

FETCH_TIMEOUT: Final = 5.0
MAX_DOCUMENT_BYTES: Final = 256 * 1024
"""A JWKS is a few kilobytes. The cap is here because the response comes from a
party we do not control, and an unbounded read is an unbounded allocation."""


@dataclass(frozen=True, slots=True)
class UpstreamKeys:
    """What we currently believe the provider's keys to be."""

    keys: dict[str, rsa.RSAPublicKey]

    def __contains__(self, kid: object) -> bool:
        return kid in self.keys


class JwksCache:
    """Caches one provider's keys, refreshing when a `kid` is missing."""

    def __init__(
        self,
        jwks_uri: str,
        *,
        http: httpx.AsyncClient,
        redis: Redis,
        refresh_interval: int = REFRESH_INTERVAL_SECONDS,
        cold_interval: int = COLD_INTERVAL_SECONDS,
    ) -> None:
        self._uri = jwks_uri
        self._http = http
        self._redis = redis
        self._interval = refresh_interval
        self._cold_interval = cold_interval
        self._keys: dict[str, rsa.RSAPublicKey] = {}

    @property
    def cached(self) -> dict[str, rsa.RSAPublicKey]:
        """What is held right now, without fetching."""
        return dict(self._keys)

    async def verification_keys(self, kid: str | None = None) -> dict[str, rsa.RSAPublicKey]:
        """The keys to verify with, refreshing if `kid` is one we do not hold.

        Returns whatever is cached when the limiter is closed rather than
        raising. The caller then fails to verify the token, which is the same
        outcome by a safer route: a refusal we chose beats an exception thrown
        from inside a signature check.
        """
        if self._keys and (kid is None or kid in self._keys):
            return dict(self._keys)

        # Which limiter applies depends on what we are missing. See the two
        # interval constants: a cold cache and a rotation are different
        # problems and deserve different patience.
        cold = not self._keys
        if await self._may_fetch(cold=cold):
            await self.refresh()
        else:
            log.warning("rp.jwks.refresh_throttled", jwks_uri=self._uri, kid=kid, cold=cold)

        return dict(self._keys)

    async def refresh(self) -> dict[str, rsa.RSAPublicKey]:
        """Fetch the document and replace the cache.

        A failed fetch keeps the previous keys. The alternative — emptying the
        cache — turns one unreachable OP into every session failing, when the
        keys we already hold are almost certainly still correct.
        """
        try:
            response = await self._http.get(self._uri, timeout=FETCH_TIMEOUT)
            response.raise_for_status()
            document = response.content[: MAX_DOCUMENT_BYTES + 1]
            if len(document) > MAX_DOCUMENT_BYTES:
                raise ValueError("JWKS document is implausibly large")
            parsed = parse_jwks(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            log.error("rp.jwks.fetch_failed", jwks_uri=self._uri, error=str(exc))
            return dict(self._keys)

        if not parsed:
            # An empty result means every entry was unusable, which is a
            # different problem from a network failure and equally not a reason
            # to discard keys that were working a minute ago.
            log.error("rp.jwks.no_usable_keys", jwks_uri=self._uri)
            return dict(self._keys)

        self._keys = parsed
        log.info("rp.jwks.refreshed", jwks_uri=self._uri, keys=len(parsed))
        return dict(self._keys)

    async def _may_fetch(self, *, cold: bool) -> bool:
        """Whether a fetch is allowed now, across every replica.

        `SET NX EX` rather than a counter: the question is "has anyone fetched
        recently", and the atomic answer is the same round trip that records it.
        """
        prefix = COLD_LIMIT_PREFIX if cold else REFRESH_LIMIT_PREFIX
        interval = self._cold_interval if cold else self._interval
        allowed = await self._redis.set(f"{prefix}{self._uri}", "1", nx=True, ex=interval)
        return bool(allowed)


def parse_jwks(document: Any) -> dict[str, rsa.RSAPublicKey]:
    """Turn a JWKS document into usable keys, skipping what we cannot use.

    Skipping rather than raising is deliberate. An OP that publishes an EC key
    alongside its RSA ones, or adds a key type we do not support, must not make
    its whole document unusable — and neither should one malformed entry, which
    would otherwise be a way to take the integration down by publishing junk.
    """
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS is not a document with a `keys` array")

    usable: dict[str, rsa.RSAPublicKey] = {}
    for entry in document["keys"]:
        key = _public_key(entry)
        if key is not None:
            usable[str(entry["kid"])] = key
    return usable


def _public_key(entry: Any) -> rsa.RSAPublicKey | None:
    """One JWK, or None if we cannot or should not use it."""
    if not isinstance(entry, dict):
        return None
    if entry.get("kty") != "RSA" or not isinstance(entry.get("kid"), str):
        # No `kid` means we could never select it during a rotation, which is
        # the one situation the cache exists for.
        return None
    if entry.get("use") not in (None, "sig"):
        # An encryption key is published in the same document and is not ours
        # to verify with.
        return None
    if entry.get("alg") not in (None, RS256):
        # `alg` is optional in a JWK. When present and not RS256 the OP is
        # telling us what this key is for, and it is not us.
        return None

    try:
        modulus = _to_int(entry["n"])
        exponent = _to_int(entry["e"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None

    if modulus.bit_length() < 2048:
        # Below the floor FR-OP-02 sets for our own keys. A 1024-bit upstream
        # key is a key somebody can factor, and accepting one because a partner
        # published it would make their mistake our compromise.
        return None

    try:
        return rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key()
    except ValueError:
        return None


def _to_int(value: Any) -> int:
    """Base64url-encoded big-endian integer, as JWA defines `n` and `e`."""
    if not isinstance(value, str):
        raise TypeError("expected a base64url string")
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")
