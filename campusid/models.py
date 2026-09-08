"""Declarative base and shared metadata.

The naming convention is set before the first table exists on purpose. Without
it, Alembic autogenerate emits constraint names the database chose for us, and
a later migration that needs to drop a constraint has nothing stable to name.
Retrofitting a convention means renaming every constraint in a live schema.

Domain tables arrive with the identity registry in M1-M3; see PRD section 8.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Base class for every ORM model in the broker."""

    metadata = metadata
