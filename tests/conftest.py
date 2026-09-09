"""Shared test fixtures.

Unit tests exercise the ASGI app directly without running its lifespan, so no
Postgres or Redis is required. Readiness probes are injected per test. Tests
that need live dependencies carry the ``integration`` marker.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import structlog
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.app import create_app
from campusid.config import Environment, Settings
from campusid.keys import SigningMaterial, generate_self_signed
from campusid.oidc import keys as oidc_keys
from campusid.oidc.keys import KeySet
from campusid.saml.gate import AssertionGate, GatePolicy, IdPResolver, TrustedIdP
from campusid.saml.stores import OutstandingRequest
from tests.support.audit import RecordingAuditLog
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    """Undo any logging configuration a test left behind.

    `configure_logging` builds a logger bound to `sys.stdout` *as it is at that
    moment* and caches it. Under pytest that is the capture buffer for whichever
    test called it, and the buffer is closed when that test ends — so the next
    test in the session that logs a warning raises `ValueError: I/O operation on
    closed file` from inside structlog, several files away from the cause.

    Resetting to structlog's defaults after every test confines that to the
    tests about logging, which is where it belongs.
    """
    yield
    structlog.reset_defaults()


@pytest.fixture(scope="session")
def idp() -> ForgedIdP:
    """The trusted IdP. Session-scoped: RSA-2048 keygen costs ~100ms."""
    return ForgedIdP()


@pytest.fixture(scope="session")
def other_idp() -> ForgedIdP:
    """A second IdP, for signatures that verify against the wrong key.

    A separate entity rather than a stray keypair, because the realistic
    failure is a *registered* peer signing for someone else's entityID.
    """
    return ForgedIdP(entity_id="https://other-idp.test/saml")


@pytest.fixture
def replay_cache() -> InMemoryReplayCache:
    return InMemoryReplayCache()


@pytest.fixture
def request_store(idp: ForgedIdP) -> InMemoryRequestStore:
    """Seeded with the request the forge answers by default."""
    store = InMemoryRequestStore()
    store.requests["_request1"] = OutstandingRequest(
        request_id="_request1",
        idp_entity_id=idp.entity_id,
        relay_state="relay-token",
        created_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
    )
    return store


@pytest.fixture
def gate_policy(idp: ForgedIdP) -> GatePolicy:
    return GatePolicy(audience=idp.default_audience, destination=idp.default_destination)


@pytest.fixture
def trusted_idps(idp: ForgedIdP, other_idp: ForgedIdP) -> dict[str, TrustedIdP]:
    """Both forge IdPs registered, each pinned to its own certificate.

    `other_idp` is registered deliberately: the interesting failure is not an
    unknown stranger but a *trusted peer* signing for someone else's entityID.
    """
    return {
        idp.entity_id: TrustedIdP(
            entity_id=idp.entity_id,
            signing_certificates=(idp.key.certificate_pem,),
        ),
        other_idp.entity_id: TrustedIdP(
            entity_id=other_idp.entity_id,
            signing_certificates=(other_idp.key.certificate_pem,),
        ),
    }


@pytest.fixture
def resolve_idp(trusted_idps: dict[str, TrustedIdP]) -> IdPResolver:
    """The gate's resolver is async because the real one queries Postgres."""

    async def resolve(entity_id: str) -> TrustedIdP | None:
        return trusted_idps.get(entity_id)

    return resolve


@pytest.fixture
def gate(
    gate_policy: GatePolicy,
    resolve_idp: IdPResolver,
    replay_cache: InMemoryReplayCache,
    request_store: InMemoryRequestStore,
) -> AssertionGate:
    return AssertionGate(
        policy=gate_policy,
        resolve_idp=resolve_idp,
        replay_cache=replay_cache,
        request_store=request_store,
    )


@pytest.fixture(scope="session")
def sp_material() -> SigningMaterial:
    """The broker's own keypair, 2048-bit for speed.

    Production uses 3072 (PRD 11.2); generating that per test would cost
    seconds each for no additional coverage.
    """
    return generate_self_signed("https://broker.test", key_size=2048)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Deterministic settings that never read the ambient environment."""
    return Settings(
        environment=Environment.CI,
        base_url="https://broker.test",
        log_format="console",
        saml_key_dir=str(tmp_path / "saml"),
        policy_dir=str(tmp_path / "policies"),
        scope="campus.test",
    )


@pytest.fixture(scope="session")
def oidc_key_set() -> KeySet:
    """The broker's token-signing keys. Session-scoped for the same reason as
    the forge's: RSA keygen costs more than every test using it."""
    return KeySet(active=oidc_keys.generate(key_size=2048))


@pytest.fixture
def audit() -> RecordingAuditLog:
    """The audit trail, in memory.

    Attached to every app fixture, so a route that emits an event never blows up
    for want of a database and any test can assert on what was recorded.
    """
    return RecordingAuditLog()


@pytest.fixture
def app(settings: Settings, oidc_key_set: KeySet, audit: RecordingAuditLog) -> FastAPI:
    """An application instance with no dependency probes registered.

    The lifespan does not run, so anything it would normally put on
    ``app.state`` is injected here instead. That is the same substitutability
    the gate's stores have, and for the same reason: the HTTP surface has to be
    exhaustively testable without containers.
    """
    app = create_app(settings)
    app.state.oidc_keys = oidc_key_set
    app.state.audit = audit
    return app


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """HTTP client bound to the app in-process; lifespan is not run."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://broker.test") as http:
        yield http
