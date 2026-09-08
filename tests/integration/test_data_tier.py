"""Live data-tier checks. Requires the compose stack to be running.

Bring it up with ``docker compose up -d --wait``, then run these with
``docker compose run --rm tests``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from campusid.cache import check_redis, create_redis
from campusid.config import get_settings
from campusid.db import check_database, create_engine

pytestmark = pytest.mark.integration


async def test_database_is_reachable() -> None:
    engine = create_engine(get_settings())
    try:
        await check_database(engine)
    finally:
        await engine.dispose()


async def test_redis_is_reachable() -> None:
    client = create_redis(get_settings())
    try:
        await check_redis(client)
    finally:
        await client.aclose()


async def test_baseline_migration_has_been_applied() -> None:
    """The entrypoint runs `alembic upgrade head` before serving (NFR-OPS-03)."""
    engine = create_engine(get_settings())
    try:
        async with engine.connect() as connection:
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
            extensions = await connection.scalars(
                text("SELECT extname FROM pg_extension ORDER BY extname")
            )
            installed = set(extensions.all())
    finally:
        await engine.dispose()

    assert revision == "0001_baseline"
    assert {"pgcrypto", "citext"} <= installed
