"""Alembic environment.

Two decisions worth noting:

1. The database URL comes from ``CAMPUSID_DATABASE_URL``, never from
   ``alembic.ini``, so no credential is ever committed (NFR-SEC-07).

2. Migrations take a Postgres session-level advisory lock before running
   (NFR-OPS-03). Every broker replica runs ``alembic upgrade head`` at startup;
   without the lock, a rolling deploy races several instances through the same
   DDL and the loser crash-loops.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

# Imported for their side effect: each module registers its tables on the shared
# `metadata`, which is what autogenerate and the schema test compare against. A
# table whose module is not imported here is invisible to both.
import campusid.audit.models
import campusid.federation.models
import campusid.identity.models
import campusid.lifecycle.models
import campusid.oidc.models
import campusid.scim.models  # noqa: F401
from campusid.config import get_settings
from campusid.models import metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", str(get_settings().database_url))

target_metadata = metadata

MIGRATION_LOCK_ID = 8_845_213_007
"""Arbitrary but stable key. Any value works; it must not change."""


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        # Forward-only: Alembic must never invent a downgrade for us.
        render_as_batch=False,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting. Used for review of pending DDL."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        # The lock is taken and committed *outside* the migration run. Leaving
        # its transaction open would make Alembic's own begin_transaction() a
        # nested no-op, so the DDL would be rolled back when the connection
        # closed — while still logging "Running upgrade" as if it had applied.
        await connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": MIGRATION_LOCK_ID})
        await connection.commit()
        try:
            await connection.run_sync(do_run_migrations)
            await connection.commit()
        finally:
            # Session-level lock: released explicitly, not by transaction end.
            await connection.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_ID}
            )
            await connection.commit()
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
