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
    """
    return create_async_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        pool_pre_ping=True,
        echo=False,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build a session factory bound to ``engine``."""
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def check_database(engine: AsyncEngine) -> None:
    """Raise if the database is not reachable. Used by the readiness probe."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
