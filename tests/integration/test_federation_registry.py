"""The federation registry against live Postgres (FR-FED-02/03).

Integration rather than unit because the behaviour under test *is* the
persistence: upsert on entityID, the enabled flag, and the round trip from a
stored document back to a certificate that verifies a real assertion.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.errors import MetadataRejected, ReasonCode
from campusid.federation.models import FederationEntity
from campusid.federation.registry import FederationRegistry
from campusid.saml.gate import AssertionGate, GatePolicy
from campusid.saml.stores import OutstandingRequest
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore

pytestmark = pytest.mark.integration


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Undo only what the test registered.

    Deliberately *not* a truncate. The same database holds the Keycloak
    registration that `federation-init` created, and clearing the table
    wholesale left the federation tests unable to resolve their IdP — passing
    in isolation and failing in the suite, which is the worst way for a test to
    be wrong. Snapshotting first means the cleanup is precise without depending
    on how entities happen to be named.
    """
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(FederationEntity.entity_id)))

    yield factory

    async with factory() as session, session.begin():
        await session.execute(
            delete(FederationEntity).where(FederationEntity.entity_id.not_in(pre_existing or {""}))
        )


@pytest.fixture
def registry(sessions: async_sessionmaker[AsyncSession]) -> FederationRegistry:
    return FederationRegistry(sessions)


async def _registered_ids(registry: FederationRegistry) -> list[str]:
    """Entity ids currently registered.

    Assertions are made against membership rather than the whole list: the
    federation profile registers Keycloak into the same table, so a test that
    expected to be alone would pass by itself and fail in the suite.
    """
    return [entity.entity_id for entity in await registry.list_idps()]


async def test_registering_an_idp_makes_it_resolvable(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    descriptor = await registry.register_idp(idp.metadata(), display_name="Campus IdP")

    assert descriptor.entity_id == idp.entity_id

    trusted = await registry.resolve_trusted_idp(idp.entity_id)
    assert trusted is not None
    assert trusted.signing_certificates == (idp.key.certificate_pem,)


async def test_an_unregistered_issuer_resolves_to_nothing(
    registry: FederationRegistry,
) -> None:
    assert await registry.resolve_trusted_idp("https://stranger.test/saml") is None


async def test_invalid_metadata_is_refused_at_registration(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """Refused where an operator can act on it, rather than at 3am when a
    login fails."""
    with pytest.raises(MetadataRejected) as exc:
        await registry.register_idp(idp.metadata(include_key=False))

    assert exc.value.reason is ReasonCode.METADATA_INVALID
    assert idp.entity_id not in await _registered_ids(registry)


async def test_re_registering_replaces_rather_than_duplicates(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """A key rollover re-registers the same entityID. A second row would leave
    which certificate wins a matter of row order."""
    rolled = ForgedIdP(entity_id=idp.entity_id)

    await registry.register_idp(idp.metadata())
    await registry.register_idp(rolled.metadata())

    registered = await _registered_ids(registry)
    assert list(registered).count(idp.entity_id) == 1

    trusted = await registry.resolve_trusted_idp(idp.entity_id)
    assert trusted is not None
    assert trusted.signing_certificates == (rolled.key.certificate_pem,)


async def test_a_disabled_entity_stops_being_trusted(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """Disabling rather than deleting: an entity that authenticated people
    must stay nameable in the audit trail after trust is withdrawn."""
    await registry.register_idp(idp.metadata())

    await registry.set_enabled(idp.entity_id, False)

    assert await registry.resolve_trusted_idp(idp.entity_id) is None
    assert idp.entity_id in await _registered_ids(registry)  # listed, just not trusted


async def test_re_enabling_restores_trust(registry: FederationRegistry, idp: ForgedIdP) -> None:
    await registry.register_idp(idp.metadata())
    await registry.set_enabled(idp.entity_id, False)

    await registry.set_enabled(idp.entity_id, True)

    assert await registry.resolve_trusted_idp(idp.entity_id) is not None


async def test_disabling_an_unknown_entity_is_an_error(
    registry: FederationRegistry,
) -> None:
    with pytest.raises(MetadataRejected):
        await registry.set_enabled("https://nobody.test/saml", False)


async def test_metadata_that_expires_after_registration_stops_resolving(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """The point of `validUntil`: trust lapses on its own.

    `resolve_trusted_idp` returns None so the gate reports `unknown_issuer`,
    which is the honest description — the entity is no longer trusted.
    `describe` raises, so an operator looking at the same entity is told *why*.
    """
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    await registry.register_idp(idp.metadata(valid_until=expires))

    assert await registry.resolve_trusted_idp(idp.entity_id) is not None

    later = expires + dt.timedelta(minutes=1)
    with pytest.raises(MetadataRejected) as exc:
        await registry.describe(idp.entity_id, now=later)
    assert exc.value.reason is ReasonCode.METADATA_EXPIRED


async def test_the_stored_document_is_kept_verbatim(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """Only the raw descriptor is stored, so every trust decision is made by
    the current parser rather than by values extracted under older rules."""
    document = idp.metadata()
    await registry.register_idp(document, metadata_url="http://keycloak:8080/descriptor")

    stored = next(
        entity for entity in await registry.list_idps() if entity.entity_id == idp.entity_id
    )

    assert stored.metadata_document.encode("utf-8") == document
    assert stored.metadata_url == "http://keycloak:8080/descriptor"


async def test_the_gate_authenticates_against_a_registered_idp(
    registry: FederationRegistry, idp: ForgedIdP
) -> None:
    """The whole point of the registry, end to end.

    An assertion is accepted using only a certificate recovered from metadata
    that was stored, retrieved and re-parsed — the path a real login takes.
    """
    await registry.register_idp(idp.metadata())

    store = InMemoryRequestStore()
    store.requests["_request1"] = OutstandingRequest(
        request_id="_request1",
        idp_entity_id=idp.entity_id,
        relay_state="relay-token",
        created_at=dt.datetime.now(dt.UTC),
    )
    gate = AssertionGate(
        policy=GatePolicy(audience=idp.default_audience, destination=idp.default_destination),
        resolve_idp=registry.resolve_trusted_idp,
        replay_cache=InMemoryReplayCache(),
        request_store=store,
    )

    facts = await gate.validate(idp.response())

    assert facts.issuer == idp.entity_id
    assert facts.name_id == "sam.obrien@campus.edu"
