"""Startup and shutdown wiring.

The data-tier clients are stubbed so this runs without containers; what is
under test is the wiring — that probes get registered and that both clients are
released on shutdown (NFR-AVAIL-06).
"""

from __future__ import annotations

import pytest

from campusid.app import create_app, lifespan
from campusid.config import Settings


class _FakeEngine:
    def __init__(self) -> None:
        self.disposed = False

    async def dispose(self) -> None:
        self.disposed = True


class _FakeRedis:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> tuple[_FakeEngine, _FakeRedis]:
    engine = _FakeEngine()
    redis = _FakeRedis()
    monkeypatch.setattr("campusid.app.create_engine", lambda _settings: engine)
    monkeypatch.setattr("campusid.app.create_redis", lambda _settings: redis)
    monkeypatch.setattr("campusid.app.create_session_factory", lambda _engine: object())
    return engine, redis


async def test_lifespan_registers_dependency_probes(
    settings: Settings,
    stubs: tuple[_FakeEngine, _FakeRedis],
) -> None:
    app = create_app(settings)

    async with lifespan(app):
        assert set(app.state.readiness_probes) == {"database", "redis"}
        assert app.state.engine is stubs[0]
        assert app.state.redis is stubs[1]


async def test_lifespan_releases_clients_on_shutdown(
    settings: Settings,
    stubs: tuple[_FakeEngine, _FakeRedis],
) -> None:
    engine, redis = stubs
    app = create_app(settings)

    # Sampled into tuples rather than asserted in place: asserting
    # `not engine.disposed` would narrow the attribute to False for the rest of
    # the function, and mypy would call every later assertion unreachable.
    async with lifespan(app):
        during = (engine.disposed, redis.closed)
    after = (engine.disposed, redis.closed)

    assert during == (False, False)
    assert after == (True, True)


async def test_clients_are_released_even_when_startup_raises(
    settings: Settings,
    stubs: tuple[_FakeEngine, _FakeRedis],
) -> None:
    """A failure during serving must not leak connections."""
    engine, redis = stubs
    app = create_app(settings)

    with pytest.raises(RuntimeError, match="boom"):
        async with lifespan(app):
            raise RuntimeError("boom")

    assert engine.disposed
    assert redis.closed
