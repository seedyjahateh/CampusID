"""Data-tier client construction.

Building an engine or a Redis client performs no I/O, so these assertions run
without containers. The probes themselves (``check_database``, ``check_redis``)
are exercised by the integration suite.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from campusid.cache import create_redis
from campusid.config import Settings
from campusid.db import create_engine, create_session_factory


def test_engine_uses_the_configured_pool_size() -> None:
    settings = Settings(database_pool_size=7)

    engine = create_engine(settings)

    assert isinstance(engine, AsyncEngine)
    # size() is a QueuePool accessor; engine.pool is typed as the Pool base.
    assert engine.pool.size() == 7  # type: ignore[attr-defined]


def test_engine_pre_pings() -> None:
    """A broker idle overnight must not fail the first login of the morning."""
    engine = create_engine(Settings())

    assert getattr(engine.pool, "_pre_ping", False) is True


def test_session_factory_is_bound_to_the_engine() -> None:
    engine = create_engine(Settings())

    factory = create_session_factory(engine)

    assert factory.kw["bind"] is engine
    assert factory.kw["expire_on_commit"] is False


def test_redis_client_uses_the_configured_url() -> None:
    settings = Settings(redis_url="redis://cache:6380/3")

    client = create_redis(settings)

    kwargs = client.connection_pool.connection_kwargs
    assert kwargs["host"] == "cache"
    assert kwargs["port"] == 6380
    assert kwargs["db"] == 3


def test_redis_client_has_bounded_timeouts() -> None:
    """An unresponsive Redis must fail the readiness probe, not hang it."""
    kwargs = create_redis(Settings()).connection_pool.connection_kwargs

    assert kwargs["socket_connect_timeout"] == 2
    assert kwargs["socket_timeout"] == 2
