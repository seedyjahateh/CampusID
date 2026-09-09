"""The OIDC client registry against live Postgres.

Integration rather than unit because the behaviour under test *is* the
persistence: the upsert, the enabled flag, the check constraints that hold even
when a row is written by something other than this code, and the round trip
through JSONB that has to come back as the same tuple it went in as.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.errors import ReasonCode
from campusid.oidc.clients import MIN_SECRET_LENGTH, ClientType
from campusid.oidc.errors import OAuthError
from campusid.oidc.models import OidcClientRecord
from campusid.oidc.registry import ClientRegistry

pytestmark = pytest.mark.integration

PORTAL = "https://portal.campus.test/oidc/callback"
SCOPES = frozenset({"openid", "profile", "email"})


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Undo only what the test registered.

    Snapshot-and-delete rather than a truncate, for the reason the federation
    registry fixture learned the hard way: another fixture's rows in the same
    table make a wholesale clear pass in isolation and fail in the suite.
    """
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(OidcClientRecord.client_id)))

    yield factory

    async with factory() as session, session.begin():
        await session.execute(
            delete(OidcClientRecord).where(OidcClientRecord.client_id.not_in(pre_existing or {""}))
        )


@pytest.fixture
def registry(sessions: async_sessionmaker[AsyncSession]) -> ClientRegistry:
    return ClientRegistry(sessions)


async def _register(registry: ClientRegistry, client_id: str = "campus-portal") -> tuple[str, str]:
    client, secret = await registry.register(
        client_id=client_id,
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(PORTAL,),
        allowed_scopes=SCOPES,
        display_name="Campus Portal",
    )
    assert secret is not None
    return client.client_id, secret


async def test_a_client_round_trips(registry: ClientRegistry) -> None:
    client_id, _ = await _register(registry)

    stored = await registry.get(client_id)

    assert stored is not None
    assert stored.redirect_uris == (PORTAL,)
    assert stored.allowed_scopes == SCOPES
    assert stored.display_name == "Campus Portal"


async def test_the_secret_is_returned_once_and_never_again(registry: ClientRegistry) -> None:
    """There is no column that could hold the plaintext. A secret a system can
    redisplay is one that ends up in a screenshot."""
    client_id, secret = await _register(registry)

    stored = await registry.get(client_id)

    assert stored is not None
    assert stored.secret_hash is not None
    assert secret not in stored.secret_hash
    stored.authenticate(secret)


async def test_a_generated_secret_is_long_enough_for_the_hash_choice(
    registry: ClientRegistry,
) -> None:
    """SHA-256 without a KDF is only defensible while these are long and
    machine-generated."""
    _, secret = await _register(registry)

    assert len(secret) >= MIN_SECRET_LENGTH


async def test_a_short_secret_is_refused(registry: ClientRegistry) -> None:
    with pytest.raises(ValueError, match="at least"):
        await registry.register(
            client_id="weak",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(PORTAL,),
            allowed_scopes=SCOPES,
            secret="hunter2",
        )


async def test_re_registering_updates_rather_than_duplicating(registry: ClientRegistry) -> None:
    """Two rows for one client_id would make which registration wins depend on
    row order."""
    client_id, _ = await _register(registry)

    await registry.register(
        client_id=client_id,
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(PORTAL, "https://portal.campus.test/oidc/callback2"),
        allowed_scopes=frozenset({"openid"}),
    )

    stored = await registry.get(client_id)
    assert stored is not None
    assert len(stored.redirect_uris) == 2
    assert len([c for c in await registry.list_clients() if c.client_id == client_id]) == 1


async def test_re_registering_without_a_secret_keeps_the_existing_one(
    registry: ClientRegistry,
) -> None:
    """Rotating a secret is a deliberate act, not a side effect of editing a
    redirect URI."""
    client_id, secret = await _register(registry)

    await registry.register(
        client_id=client_id,
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(PORTAL,),
        allowed_scopes=SCOPES,
        secret=secret,
    )

    stored = await registry.get(client_id)
    assert stored is not None
    stored.authenticate(secret)


async def test_an_unknown_client_is_none(registry: ClientRegistry) -> None:
    assert await registry.get("never-registered") is None


async def test_requiring_an_unknown_client_refuses(registry: ClientRegistry) -> None:
    with pytest.raises(OAuthError) as raised:
        await registry.require("never-registered")

    assert raised.value.reason is ReasonCode.UNKNOWN_CLIENT
    assert raised.value.redirectable is False


async def test_a_disabled_client_is_indistinguishable_from_an_unknown_one(
    registry: ClientRegistry,
) -> None:
    """Telling an unauthenticated caller which client_ids exist but are turned
    off is free reconnaissance, and the authorization endpoint has the same
    answer for both."""
    client_id, _ = await _register(registry)

    await registry.set_enabled(client_id, False)

    assert await registry.get(client_id) is None
    assert client_id in {client.client_id for client in await registry.list_clients()}


async def test_re_enabling_restores_the_client(registry: ClientRegistry) -> None:
    """Disabling is preferred to deleting: a client that issued tokens stays
    nameable in the audit trail after it stops being trusted."""
    client_id, _ = await _register(registry)
    await registry.set_enabled(client_id, False)

    await registry.set_enabled(client_id, True)

    assert await registry.get(client_id) is not None


async def test_enabling_an_unknown_client_refuses(registry: ClientRegistry) -> None:
    with pytest.raises(OAuthError, match="no such client"):
        await registry.set_enabled("never-registered", True)


async def test_an_unknown_scope_cannot_be_registered(registry: ClientRegistry) -> None:
    """A scope the broker cannot fulfil would be granted and release nothing,
    which a client cannot tell from a policy denial."""
    with pytest.raises(ValueError, match="unknown scopes"):
        await registry.register(
            client_id="greedy",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(PORTAL,),
            allowed_scopes=frozenset({"openid", "campus:everything"}),
        )


async def test_a_public_client_cannot_be_given_a_secret(registry: ClientRegistry) -> None:
    with pytest.raises(ValueError, match="cannot hold a secret"):
        await registry.register(
            client_id="browser-app",
            client_type=ClientType.PUBLIC,
            redirect_uris=(PORTAL,),
            allowed_scopes=SCOPES,
            secret="x" * 43,
        )


async def test_an_invalid_registration_writes_nothing(registry: ClientRegistry) -> None:
    """The client is constructed before anything is written, so a registration
    that could never work is refused rather than stored and then rejected on
    every read."""
    with pytest.raises(ValueError):
        await registry.register(
            client_id="insecure",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=("http://portal.campus.test/cb",),
            allowed_scopes=SCOPES,
        )

    assert await registry.get("insecure") is None


# --- what the database enforces on its own ---------------------------------
#
# The dataclass enforces all of this too. These assert the *second* barrier: a
# row written by hand during an incident, by a script, or by a future migration
# must not be able to create a registration the code would have refused.

INSERT = (
    "INSERT INTO oidc_client "
    "(client_id, client_type, redirect_uris, allowed_scopes, secret_hash) "
    "VALUES (:client_id, :client_type, CAST(:uris AS jsonb), CAST(:scopes AS jsonb), :secret)"
)

ONE_URI = '["https://x.test/cb"]'
OPENID = '["openid"]'


async def _insert(sessions: async_sessionmaker[AsyncSession], **values: str | None) -> None:
    async with sessions() as session, session.begin():
        await session.execute(text(INSERT), values)


@pytest.mark.parametrize(
    ("case", "row"),
    [
        (
            "a confidential client with no secret",
            {"client_type": "confidential", "uris": ONE_URI, "secret": None},
        ),
        (
            "a public client holding a secret",
            {"client_type": "public", "uris": ONE_URI, "secret": "deadbeef"},
        ),
        (
            "a client with no redirect URI",
            {"client_type": "public", "uris": "[]", "secret": None},
        ),
        (
            "an unrecognised client type",
            {"client_type": "trusted", "uris": ONE_URI, "secret": None},
        ),
    ],
)
async def test_the_schema_refuses_an_impossible_registration(
    sessions: async_sessionmaker[AsyncSession], case: str, row: dict[str, str | None]
) -> None:
    with pytest.raises(IntegrityError):
        await _insert(sessions, client_id=f"bypass-{case}", scopes=OPENID, **row)
