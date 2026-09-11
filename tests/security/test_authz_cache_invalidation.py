"""Caching authorization decisions, and unmaking them (FR-AZ-08).

An authorization decision cached for sixty seconds is a performance feature; one
that survives a revocation is a security bug. The requirement asks for both
halves and the second is the one these tests are mostly about.

The design worth reading is the epoch. Each person has a counter carried in every
cache key, and a revocation increments it — so every decision cached about them
becomes unreachable at once, without anybody having to know which keys exist.
Enumerating keys instead would mean scanning the keyspace, racing the writes it
is trying to catch.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fakeredis import aioredis

from campusid.authz.cache import TTL, CachingDecider, DecisionCache
from campusid.authz.engine import (
    Decision,
    Effect,
    Environment,
    PolicySet,
    Request,
    Resource,
    Rule,
    Subject,
)

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
OTHER = "c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b"

PERMIT = Decision(effect=Effect.PERMIT, rule_id="a-rule", reason="permitted")
DENY = Decision(effect=Effect.DENY, rule_id="another-rule", reason="denied")


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def cache(redis: aioredis.FakeRedis) -> DecisionCache:
    return DecisionCache(redis)


def _ask(
    *,
    person: str | None = PERSON,
    resource: str = "lms:course/101",
    action: str = "read",
    assurance: str = "urn:campusid:aal1",
    network: str = "campus",
) -> Request:
    return Request(
        subject=Subject(person_uuid=person, assurance=assurance),
        resource=Resource(id=resource),
        action=action,
        environment=Environment(network=network),
    )


# --- remembering ------------------------------------------------------------


async def test_a_decision_is_remembered(cache: DecisionCache) -> None:
    await cache.put(_ask(), PERMIT)

    remembered = await cache.get(_ask())

    assert remembered is not None
    assert remembered.effect is Effect.PERMIT
    assert remembered.rule_id == "a-rule"


async def test_nothing_is_remembered_before_it_is_asked(cache: DecisionCache) -> None:
    assert await cache.get(_ask()) is None


async def test_a_challenge_survives_the_round_trip(cache: DecisionCache) -> None:
    """Including what it asked for. A challenge that lost its required assurance
    would leave the caller guessing at the strongest thing it supports."""
    challenge = Decision(
        effect=Effect.CHALLENGE,
        rule_id="hr",
        reason="stronger authentication required",
        required_assurance="urn:campusid:aal2",
    )
    await cache.put(_ask(), challenge)

    remembered = await cache.get(_ask())

    assert remembered is not None
    assert remembered.effect is Effect.CHALLENGE
    assert remembered.required_assurance == "urn:campusid:aal2"


# --- the key names the whole question ---------------------------------------


async def test_a_different_action_is_a_different_question(cache: DecisionCache) -> None:
    """The classic form of this bug: a key naming the person and the resource
    and stopping there, which serves a read permit to a write."""
    await cache.put(_ask(action="read"), PERMIT)

    assert await cache.get(_ask(action="write")) is None


async def test_a_different_resource_is_a_different_question(cache: DecisionCache) -> None:
    await cache.put(_ask(resource="lms:course/101"), PERMIT)

    assert await cache.get(_ask(resource="hr:payslips")) is None


async def test_a_different_person_is_a_different_question(cache: DecisionCache) -> None:
    await cache.put(_ask(person=PERSON), PERMIT)

    assert await cache.get(_ask(person=OTHER)) is None


async def test_a_stronger_session_is_a_different_question(cache: DecisionCache) -> None:
    """Otherwise a challenge cached for a single-factor session would be served
    back to the same person after they completed the step-up, and they would be
    challenged in a loop."""
    await cache.put(_ask(assurance="urn:campusid:aal1"), DENY)

    assert await cache.get(_ask(assurance="urn:campusid:aal2")) is None


async def test_a_different_network_is_a_different_question(cache: DecisionCache) -> None:
    """A permit earned on the campus network must not be served to the same
    person on the public one."""
    await cache.put(_ask(network="campus"), PERMIT)

    assert await cache.get(_ask(network="public")) is None


# --- invalidation -----------------------------------------------------------


async def test_invalidating_unmakes_every_decision_about_a_person(
    cache: DecisionCache,
) -> None:
    """One increment, whatever the number of cached decisions — which is what
    makes this work without knowing which keys exist."""
    await cache.put(_ask(resource="lms:one"), PERMIT)
    await cache.put(_ask(resource="lms:two"), PERMIT)
    await cache.put(_ask(resource="library:journals"), PERMIT)

    await cache.invalidate(PERSON)

    assert await cache.get(_ask(resource="lms:one")) is None
    assert await cache.get(_ask(resource="lms:two")) is None
    assert await cache.get(_ask(resource="library:journals")) is None


async def test_invalidating_one_person_leaves_everybody_else_alone(
    cache: DecisionCache,
) -> None:
    """A revocation is about one person. Emptying the cache for the campus would
    work and would also make every revocation a performance incident."""
    await cache.put(_ask(person=PERSON), PERMIT)
    await cache.put(_ask(person=OTHER), PERMIT)

    await cache.invalidate(PERSON)

    assert await cache.get(_ask(person=PERSON)) is None
    assert await cache.get(_ask(person=OTHER)) is not None


async def test_decisions_made_after_an_invalidation_are_kept(
    cache: DecisionCache,
) -> None:
    """The epoch moves forward rather than switching the cache off."""
    await cache.invalidate(PERSON)
    await cache.put(_ask(), DENY)

    remembered = await cache.get(_ask())

    assert remembered is not None
    assert remembered.effect is Effect.DENY


async def test_invalidating_twice_is_harmless(cache: DecisionCache) -> None:
    await cache.put(_ask(), PERMIT)
    await cache.invalidate(PERSON)
    await cache.invalidate(PERSON)

    assert await cache.get(_ask()) is None


# --- the window -------------------------------------------------------------


async def test_a_decision_expires(redis: aioredis.FakeRedis) -> None:
    """Sixty seconds is the requirement's ceiling, used as the value. The epoch
    already makes an entitlement change immediate, so the window only bounds how
    long a decision survives a change the epoch does not cover."""
    cache = DecisionCache(redis, ttl=timedelta(seconds=60))
    await cache.put(_ask(), PERMIT)

    ttl = await redis.ttl(next(iter(await redis.keys("authz:decision:*"))))

    assert 0 < ttl <= 60


def test_the_window_is_not_longer_than_the_requirement_allows() -> None:
    assert timedelta(seconds=60) >= TTL


# --- failing open -----------------------------------------------------------


async def test_a_cache_outage_is_a_miss_rather_than_a_denial() -> None:
    """Redis being unavailable means every call evaluates, which is what
    happened before this module existed. An authorization layer that failed
    closed on a caching problem would take the campus down to save some CPU."""

    class _Broken:
        async def get(self, key: str) -> str:
            raise ConnectionError("redis is gone")

        async def set(self, key: str, value: str, ex: int | None = None) -> None:
            raise ConnectionError("redis is gone")

    cache = DecisionCache(_Broken())

    await cache.put(_ask(), PERMIT)

    assert await cache.get(_ask()) is None


async def test_an_unreadable_entry_is_a_miss(redis: aioredis.FakeRedis) -> None:
    """The policy engine is the source of truth and this is a shortcut. A
    shortcut that raises is worse than no shortcut."""
    cache = DecisionCache(redis)
    await cache.put(_ask(), PERMIT)
    key = next(iter(await redis.keys("authz:decision:*")))
    await redis.set(key, "not json")

    assert await cache.get(_ask()) is None


async def test_a_subject_with_no_person_is_never_cached(cache: DecisionCache) -> None:
    """There is nothing to invalidate against. Caching under a null key would
    mean one anonymous decision serving every anonymous caller."""
    await cache.put(_ask(person=None), PERMIT)

    assert await cache.get(_ask(person=None)) is None


async def test_no_cache_at_all_still_decides() -> None:
    cache = DecisionCache(None)

    await cache.put(_ask(), PERMIT)

    assert await cache.get(_ask()) is None


# --- the decider ------------------------------------------------------------


class _Policies:
    def __init__(self, policies: PolicySet) -> None:
        self.current = policies
        self.evaluations = 0

    def decide(self, request: Request) -> Decision:  # pragma: no cover - not the path used
        raise AssertionError("the decider reads `.current`")


class _Counting(PolicySet):
    def __init__(self, rules: tuple[Rule, ...]) -> None:
        super().__init__(rules)
        self.evaluations = 0

    def decide(self, request: Request) -> Decision:
        self.evaluations += 1
        return super().decide(request)


async def test_the_second_identical_request_is_not_evaluated(
    cache: DecisionCache,
) -> None:
    policies = _Counting((Rule(id="open", effect=Effect.PERMIT, resource_prefix="lms:"),))
    decider = CachingDecider(_Policies(policies), cache)

    first = await decider.decide(_ask())
    second = await decider.decide(_ask())

    assert policies.evaluations == 1
    assert not first.cached
    assert second.cached
    assert second.decision.effect is Effect.PERMIT


async def test_a_revocation_sends_the_next_request_back_to_the_engine(
    cache: DecisionCache,
) -> None:
    """The whole point of the epoch, end to end."""
    policies = _Counting((Rule(id="open", effect=Effect.PERMIT, resource_prefix="lms:"),))
    decider = CachingDecider(_Policies(policies), cache)

    await decider.decide(_ask())
    await cache.invalidate(PERSON)
    again = await decider.decide(_ask())

    assert policies.evaluations == 2
    assert not again.cached


async def test_whether_a_decision_was_cached_is_reported(cache: DecisionCache) -> None:
    """A dashboard counting denials wants decisions rather than evaluations, and
    one that could not tell them apart would report a quiet minute as a drop in
    traffic."""
    policies = _Counting((Rule(id="open", effect=Effect.PERMIT, resource_prefix="lms:"),))
    decider = CachingDecider(_Policies(policies), cache)

    assert not (await decider.decide(_ask())).cached
    assert (await decider.decide(_ask())).cached
