"""A least-privilege role for the application (FR-AUD-04).

Until now the broker has connected as the database owner, which means the
application-side promise that the audit trail is append-only rested entirely on
there being no code that writes an UPDATE. That is a real protection against the
ordinary bug and no protection at all against a compromised process — and a
compromised process is the case an audit trail exists for.

This creates `campusid_app` and grants it what the application actually needs:
read and write on every table, and on `audit_event` only SELECT and INSERT. An
UPDATE or DELETE against the trail from the application's connection is then
refused by Postgres rather than by convention.

**Schema ownership stays with the migration role.** The application role owns
nothing and has no CREATE on the schema, so it cannot add a table, drop one, or
alter `audit_event` into something writable. An append-only grant that the
grantee can ALTER away is decoration.

**Default privileges are set for future tables.** Without them a later migration
creates a table the application cannot read, and the failure appears at runtime
in whatever code first touches it rather than during the migration — which is a
long way from the cause.

**The role is created without a password unless one is configured.** A role that
cannot log in still carries the grants, so the privilege model is present in
every database and whether the application uses it is a deployment choice. That
keeps this migration safe to run on a stack that has not been reconfigured yet.

Revision ID: 0015_least_privilege_app_role
Revises: 0014_audit_hash_chain
Created: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from campusid.config import get_settings

revision: str = "0015_least_privilege_app_role"
down_revision: str | None = "0014_audit_hash_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "campusid_app"

APPEND_ONLY = "audit_event"
"""The one table the application may not modify.

Named as a constant so the revoke below and the test that proves it are talking
about the same thing.
"""


def upgrade() -> None:
    bind = op.get_bind()
    password = get_settings().app_db_password

    _create_role(bind, password)
    _grant_baseline(bind)
    _restrict_the_audit_trail(bind)
    _set_default_privileges(bind)


def _create_role(bind: sa.engine.Connection, password: str) -> None:
    """Create the role, or set its password if it is already there.

    Idempotent because a migration that fails halfway must be re-runnable, and
    `CREATE ROLE` has no `IF NOT EXISTS`.

    `CREATE ROLE` is a utility statement and takes no bind parameters, so the
    password has to be interpolated. It is quoted by `quote_literal` — Postgres's
    own escaping rather than something hand-rolled here — and the value is read
    from configuration, so it is not in this file. It *does* reach the server as
    statement text, which means a database with `log_statement = ddl` records it;
    that is a known property of creating roles anywhere, and the answer is to
    rotate the password after provisioning rather than to pretend otherwise.
    """
    exists = bind.scalar(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": APP_ROLE}
    )
    if not exists:
        # NOLOGIN when nothing is configured: the grants still apply, so the
        # privilege model is present even on a stack that has not been pointed
        # at it yet.
        clause = f"LOGIN PASSWORD {_literal(bind, password)}" if password else "NOLOGIN"
        bind.execute(sa.text(f"CREATE ROLE {APP_ROLE} {clause}"))
        return

    if password:
        bind.execute(sa.text(f"ALTER ROLE {APP_ROLE} LOGIN PASSWORD {_literal(bind, password)}"))


def _literal(bind: sa.engine.Connection, value: str) -> str:
    """A value quoted the way Postgres quotes it.

    Asked of the server rather than escaped here, because the one thing worse
    than interpolating into DDL is interpolating into DDL with an escaping rule
    somebody wrote from memory.
    """
    return str(bind.scalar(sa.text("SELECT quote_literal(:value)"), {"value": value}))


def _grant_baseline(bind: sa.engine.Connection) -> None:
    """Everything the application needs on what exists today."""
    database = bind.scalar(sa.text("SELECT current_database()"))
    bind.execute(sa.text(f'GRANT CONNECT ON DATABASE "{database}" TO {APP_ROLE}'))
    bind.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))
    bind.execute(
        sa.text(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}"
        )
    )
    # Identity and serial columns read their sequence on every insert, so a role
    # that can insert but not use the sequence can insert nothing.
    bind.execute(sa.text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}"))
    # Older Postgres grants CREATE on `public` to everybody. An append-only grant
    # is decoration if the grantee can create a table, or alter one.
    bind.execute(sa.text(f"REVOKE CREATE ON SCHEMA public FROM {APP_ROLE}"))
    bind.execute(sa.text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))


def _restrict_the_audit_trail(bind: sa.engine.Connection) -> None:
    """FR-AUD-04, enforced by the database rather than by convention.

    Revoked then granted rather than granted alone: the baseline above handed
    out UPDATE and DELETE on every table, and a grant that does not take
    something away leaves them.
    """
    bind.execute(sa.text(f"REVOKE ALL ON {APPEND_ONLY} FROM {APP_ROLE}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT ON {APPEND_ONLY} TO {APP_ROLE}"))
    bind.execute(
        sa.text(
            "GRANT USAGE, SELECT ON SEQUENCE "
            f"{pg_sequence_name(bind, APPEND_ONLY, 'seq')} TO {APP_ROLE}"
        )
    )


def pg_sequence_name(bind: sa.engine.Connection, table: str, column: str) -> str:
    """The sequence behind an identity column, as Postgres names it.

    Looked up rather than assumed: the conventional `table_column_seq` is a
    convention, and a migration that guessed wrong would grant nothing and fail
    at the first insert instead of here.
    """
    name = bind.scalar(
        sa.text("SELECT pg_get_serial_sequence(:table, :column)"),
        {"table": table, "column": column},
    )
    if not name:  # pragma: no cover - the column is an identity column
        raise RuntimeError(f"{table}.{column} has no sequence")
    return str(name)


def _set_default_privileges(bind: sa.engine.Connection) -> None:
    """So a table added by a later migration is readable without a second grant.

    Without this the failure appears at runtime in whatever code first touches
    the new table, which is a long way from the cause.
    """
    owner = bind.scalar(sa.text("SELECT current_user"))
    bind.execute(
        sa.text(
            f'ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA public '
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}"
        )
    )
    bind.execute(
        sa.text(
            f'ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA public '
            f"GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}"
        )
    )


def downgrade() -> None:
    raise NotImplementedError("CampusID migrations are forward-only")
