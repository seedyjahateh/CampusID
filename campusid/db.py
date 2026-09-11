"""Database engine lifecycle and connectivity probe."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from campusid.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Build the application's async engine.

    ``pool_pre_ping`` matters here: a broker that has been idle overnight must
    not fail the first login of the morning on a stale connection.

    Connects as the least-privilege application role when one is configured
    (FR-AUD-04) and as the schema owner otherwise. Falling back rather than
    refusing keeps a development stack that has not been reconfigured working,
    and the difference is visible in one place instead of being a branch every
    caller has to know about.
    """
    return create_async_engine(
        settings.app_database_url or settings.database_url,
        pool_size=settings.database_pool_size,
        pool_pre_ping=True,
        echo=False,
    )


def create_owner_engine(settings: Settings) -> AsyncEngine:
    """An engine for the role that owns the schema.

    Used by migrations and by nothing else. Separate from `create_engine` so the
    application cannot reach it by accident: the whole point of the split is that
    the code handling requests holds no DDL rights, and a single function with a
    flag would make that one wrong argument away.
    """
    return create_async_engine(settings.database_url, pool_pre_ping=True, echo=False)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build a session factory bound to ``engine``."""
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def check_database(engine: AsyncEngine) -> None:
    """Raise if the database is not reachable. Used by the readiness probe."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
