"""Caching authorization decisions (FR-AZ-08).

An authorization call happens on every request to a protected resource, and the
decision it makes is a pure function of things that change slowly. Sixty seconds
of caching turns a per-request evaluation into a per-minute one.

**Invalidation is by epoch, not by enumeration.** Each person has a counter;
every cache key carries its current value, and changing somebody's entitlements
increments it. Every decision cached under the old value becomes unreachable at
once, without knowing which keys exist. Enumerating keys to delete them would
mean either a scan of the keyspace — expensive, and racing the writes it is
trying to catch — or keeping an index of cached decisions per person, which is a
second cache with the same invalidation problem.

**The key includes everything the decision depended on.** Resource, action,
assurance, network, and the person's epoch. Leaving any of them out would serve
a decision made about a different question: the classic version of this bug
caches by person and resource, then serves a `read` permit to a `write`.

**A cache miss is not an error and a cache outage is not a denial.** Redis being
unavailable means every call evaluates, which is exactly what happened before
this module existed. An authorization layer that failed closed on a caching
problem would take the campus down to save some CPU.

**Time-dependent rules are cached too, and that is a deliberate rounding.** A
permit evaluated at 17:59:59 under an office-hours rule stays cached until
18:00:59. The requirement sets sixty seconds as the tolerance; this is what
spending it looks like.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final

from campusid.authz.engine import Decision, Effect, Request
from campusid.logging import get_logger

log = get_logger(__name__)

TTL: Final = timedelta(seconds=60)
"""FR-AZ-08's ceiling, used as the value rather than as a limit to stay under.

A shorter one would spend the invalidation machinery on nothing: the epoch makes
an entitlement change take effect immediately regardless, so the TTL only bounds
how long a decision survives a change the epoch does not cover — a policy file
edit, most of which are not urgent and all of which an operator can force by
touching the file.
"""

DECISION_PREFIX: Final = "authz:decision:"
EPOCH_PREFIX: Final = "authz:epoch:"


@dataclass(frozen=True, slots=True)
class CachedDecision:
    """A decision, plus whether it came from the cache.

    The flag is for the audit record. A dashboard counting denials wants to
    count decisions rather than evaluations, and one that could not tell them
    apart would report a quiet minute as a drop in traffic.
    """

    decision: Decision
    cached: bool


class DecisionCache:
    """Sixty seconds of memory for authorization decisions."""

    def __init__(self, redis: Any, *, ttl: timedelta = TTL) -> None:
        self._redis = redis
        self._ttl = ttl

    async def get(self, request: Request) -> Decision | None:
        """A previous decision about this exact question, if there is one."""
        if self._redis is None or request.subject.person_uuid is None:
            return None
        try:
            raw = await self._redis.get(await self._key(request))
        except Exception as exc:
            # A caching problem must not become an authorization failure.
            log.warning("authz.cache.unavailable", error=str(exc))
            return None
        return _decode(raw) if raw else None

    async def put(self, request: Request, decision: Decision) -> None:
        """Remember a decision for the life of the window."""
        if self._redis is None or request.subject.person_uuid is None:
            return
        try:
            await self._redis.set(
                await self._key(request),
                _encode(decision),
                ex=int(self._ttl.total_seconds()),
            )
        except Exception as exc:
            log.warning("authz.cache.unavailable", error=str(exc))

    async def invalidate(self, person_uuid: str) -> None:
        """Make every decision cached about this person unreachable (FR-AZ-08).

        One increment, whatever the number of cached decisions. Called when
        entitlements, roles or status change — anything the decision reads.
        """
        if self._redis is None:
            return
        try:
            epoch = await self._redis.incr(f"{EPOCH_PREFIX}{person_uuid}")
        except Exception as exc:
            # The failure direction that matters: an increment that did not
            # happen leaves stale permits readable for up to the TTL. Logged at
            # warning rather than swallowed, because it is the one cache error
            # with a security consequence.
            log.warning("authz.cache.invalidation_failed", person=person_uuid, error=str(exc))
            return
        log.info("authz.cache.invalidated", person=person_uuid, epoch=epoch)

    async def _key(self, request: Request) -> str:
        """A key naming everything the decision depended on.

        The person's epoch is part of it, which is what makes invalidation a
        single increment. Everything else is the question itself: serving a
        `read` permit to a `write` is the classic form of this bug, and it comes
        from a key that named the person and the resource and stopped there.
        """
        person = str(request.subject.person_uuid)
        epoch = await self._epoch(person)
        material = json.dumps(
            [
                person,
                epoch,
                request.resource.id,
                request.resource.classification,
                request.resource.requires_aal2,
                request.action,
                request.subject.assurance,
                request.environment.network,
            ],
            separators=(",", ":"),
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
        return f"{DECISION_PREFIX}{person}:{digest}"

    async def _epoch(self, person_uuid: str) -> int:
        raw = await self._redis.get(f"{EPOCH_PREFIX}{person_uuid}")
        try:
            return int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            return 0


def _encode(decision: Decision) -> str:
    return json.dumps(
        {
            "effect": decision.effect.value,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "required_assurance": decision.required_assurance,
        },
        separators=(",", ":"),
    )


def _decode(raw: str) -> Decision | None:
    """Read a cached decision, treating anything unreadable as a miss.

    A cache entry we cannot parse is a miss rather than an error: the policy
    engine is the source of truth and this is a shortcut, so a shortcut that
    raises is worse than no shortcut.
    """
    try:
        payload = json.loads(raw)
        return Decision(
            effect=Effect(payload["effect"]),
            rule_id=payload["rule_id"],
            reason=payload.get("reason", ""),
            required_assurance=payload.get("required_assurance"),
        )
    except (TypeError, ValueError, KeyError):
        return None


class CachingDecider:
    """A policy set with the cache in front of it.

    Wraps rather than extends, so the engine stays a pure function of its
    inputs and remains testable without Redis — which is what keeps the fifteen
    policy cases fast and honest.
    """

    def __init__(self, policies: Any, cache: DecisionCache) -> None:
        self._policies = policies
        self._cache = cache

    async def decide(self, request: Request) -> CachedDecision:
        cached = await self._cache.get(request)
        if cached is not None:
            return CachedDecision(decision=cached, cached=True)

        decision = self._policies.current.decide(request)
        await self._cache.put(request, decision)
        return CachedDecision(decision=decision, cached=False)
