"""Server-side session storage (FR-SES-01/02/03/06).

Run against fakeredis, so TTL and expiry behave as they will in production.
Time is injected rather than slept through — a test that waits 30 minutes to
prove an idle timeout is a test nobody runs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import aioredis

from campusid.session.store import (
    ABSOLUTE_TIMEOUT,
    IDLE_TIMEOUT,
    SESSION_KEY_PREFIX,
    Session,
    SessionStore,
    new_sid,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def store(redis: aioredis.FakeRedis) -> SessionStore:
    return SessionStore(redis)


async def _session(store: SessionStore, now: datetime = NOW) -> Session:
    return await store.create(
        idp_entity_id="https://idp.test/saml",
        name_id="sam.obrien@campus.edu",
        acr="urn:campusid:aal1",
        amr=("pwd",),
        session_index="_session1",
        attributes={"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": ["student@campus.edu"]},
        now=now,
    )


async def test_a_session_round_trips(store: SessionStore) -> None:
    created = await _session(store)

    loaded = await store.load(created.sid, now=NOW)

    assert loaded is not None
    assert loaded.name_id == "sam.obrien@campus.edu"
    assert loaded.amr == ("pwd",)
    assert loaded.attributes == {"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": ["student@campus.edu"]}


async def test_an_unknown_identifier_loads_nothing(store: SessionStore) -> None:
    assert await store.load(new_sid(), now=NOW) is None


async def test_the_subject_key_is_scoped_to_the_issuing_idp(store: SessionStore) -> None:
    """A `NameID` is only meaningful within the IdP that minted it. Keying on
    it alone would let two federated IdPs collide into one identity."""
    created = await _session(store)

    assert created.subject_key == "https://idp.test/saml|sam.obrien@campus.edu"


# --- timeouts, enforced server-side ---------------------------------------


async def test_a_session_just_inside_the_idle_window_loads(store: SessionStore) -> None:
    created = await _session(store)

    assert await store.load(created.sid, now=NOW + IDLE_TIMEOUT - timedelta(seconds=1))


async def test_idle_expiry_is_enforced(store: SessionStore) -> None:
    """Loaded only once: a load inside the window refreshes `last_seen_at`, so
    checking the boundary after a successful load would be measuring the wrong
    interval — and would pass whatever the timeout was set to."""
    created = await _session(store)

    assert await store.load(created.sid, now=NOW + IDLE_TIMEOUT) is None


async def test_activity_refreshes_the_idle_window(store: SessionStore) -> None:
    """Idle means idle. A session used every 20 minutes must not die at 30."""
    created = await _session(store)
    later = NOW + timedelta(minutes=20)

    assert await store.load(created.sid, now=later) is not None
    assert await store.load(created.sid, now=later + timedelta(minutes=20)) is not None


async def test_the_absolute_deadline_cannot_be_refreshed(store: SessionStore) -> None:
    """Activity extends the idle window but never the absolute one, so a
    continuously-used session still ends after twelve hours."""
    created = await _session(store)

    moment = NOW
    while moment < NOW + ABSOLUTE_TIMEOUT - timedelta(minutes=10):
        moment += timedelta(minutes=10)
        assert await store.load(created.sid, now=moment) is not None

    assert await store.load(created.sid, now=NOW + ABSOLUTE_TIMEOUT) is None


async def test_an_expired_session_is_deleted_not_merely_hidden(
    store: SessionStore, redis: aioredis.FakeRedis
) -> None:
    """So a clock adjustment cannot resurrect it."""
    created = await _session(store)

    await store.load(created.sid, now=NOW + ABSOLUTE_TIMEOUT)

    assert await redis.get(f"{SESSION_KEY_PREFIX}{created.sid}") is None
    assert await store.load(created.sid, now=NOW) is None


async def test_redis_ttl_is_bounded_by_the_idle_window(
    store: SessionStore, redis: aioredis.FakeRedis
) -> None:
    """An abandoned session must expire on its own rather than accumulate."""
    created = await _session(store)

    ttl = await redis.ttl(f"{SESSION_KEY_PREFIX}{created.sid}")

    assert 0 < ttl <= IDLE_TIMEOUT.total_seconds()


# --- rotation --------------------------------------------------------------


async def test_rotation_issues_a_new_identifier_and_kills_the_old(
    store: SessionStore,
) -> None:
    """FR-SES-03. An attacker who fixed the pre-authentication identifier is
    left holding a value that addresses nothing."""
    created = await _session(store)

    rotated = await store.rotate(created.sid, now=NOW)

    assert rotated is not None
    assert rotated.sid != created.sid
    assert await store.load(created.sid, now=NOW) is None
    assert await store.load(rotated.sid, now=NOW) is not None


async def test_rotation_preserves_the_session_contents(store: SessionStore) -> None:
    created = await _session(store)

    rotated = await store.rotate(created.sid, now=NOW)

    assert rotated is not None
    assert rotated.name_id == created.name_id
    assert rotated.created_at == created.created_at
    assert rotated.absolute_expiry == created.absolute_expiry


async def test_rotating_an_expired_session_yields_nothing(store: SessionStore) -> None:
    created = await _session(store)

    assert await store.rotate(created.sid, now=NOW + ABSOLUTE_TIMEOUT) is None


# --- elevation (used by step-up in M4) ------------------------------------


async def test_elevation_raises_assurance_and_rotates(store: SessionStore) -> None:
    """Assurance changing is a privilege change, so the identifier changes too:
    a session captured at the lower level must not be replayable at the
    higher one."""
    created = await _session(store)
    later = NOW + timedelta(minutes=5)

    elevated = await store.elevate(
        created.sid, acr="urn:campusid:aal2", amr=("pwd", "hwk"), now=later
    )

    assert elevated is not None
    assert elevated.sid != created.sid
    assert elevated.acr == "urn:campusid:aal2"
    assert elevated.amr == ("pwd", "hwk")
    assert elevated.auth_time == later
    assert await store.load(created.sid, now=later) is None


async def test_elevating_an_unknown_session_yields_nothing(store: SessionStore) -> None:
    assert await store.elevate(new_sid(), acr="x", amr=(), now=NOW) is None


# --- termination -----------------------------------------------------------


async def test_destroy_is_immediate(store: SessionStore) -> None:
    """The reason session state is server-side: a self-contained signed cookie
    could not be revoked before it expired."""
    created = await _session(store)

    await store.destroy(created.sid)

    assert await store.load(created.sid, now=NOW) is None


# --- the identifier --------------------------------------------------------


async def test_identifiers_are_unguessable() -> None:
    """NFR-SEC-02: 256 bits from a CSPRNG. The identifier is all that stands
    between an attacker and someone else's session."""
    identifiers = {new_sid() for _ in range(200)}

    assert len(identifiers) == 200
    assert all(len(sid) >= 43 for sid in identifiers)  # 32 bytes, urlsafe-base64


async def test_the_cookie_value_carries_no_identity(store: SessionStore) -> None:
    """FR-SES-06: the cookie is an opaque handle, not a container."""
    created = await _session(store)

    assert "sam.obrien" not in created.sid
    assert "idp.test" not in created.sid
