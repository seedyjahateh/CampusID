"""Registering and disabling federation partners (FR-ADM-02, FR-ADM-07).

The guard is tested next door; these are about what the endpoints do once
somebody is through it. Two things matter more than the CRUD.

Metadata goes through the same parser the gate uses, so an entity that would not
work cannot be registered. The alternative is a console that accepts anything and
a login that fails an hour later with a reason code nobody connects to this
action.

Every mutation carries a reason, refused before the change rather than defaulted,
because a default reason is a field everybody stops reading.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from campusid.audit.events import EventType
from campusid.authz.engine import AAL2
from campusid.errors import MetadataRejected, ReasonCode
from campusid.mfa.assurance import MFA, OTP, PWD
from campusid.routes.admin import ADMIN_ROLE, MAX_METADATA
from campusid.session.cookies import SESSION_COOKIE
from campusid.session.store import Session, SessionStore
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

BASE = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
ENTITY = "https://idp.partner.test/saml"
VALID_UNTIL = datetime(2027, 1, 1, tzinfo=UTC)

CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBCgKCAQEAtest
-----END CERTIFICATE-----"""


@dataclass
class _Entity:
    entity_id: str
    display_name: str | None
    role: str
    enabled: bool
    metadata_url: str | None
    valid_until: datetime | None
    last_refreshed_at: datetime | None


@dataclass
class _Endpoint:
    binding: str
    location: str


@dataclass
class _Descriptor:
    entity_id: str
    valid_until: datetime | None
    sso_endpoints: tuple[_Endpoint, ...]
    signing_certificates: tuple[str, ...]


class _Registry:
    def __init__(self) -> None:
        self.entities: list[_Entity] = []
        self.registered: list[dict[str, Any]] = []
        self.switched: list[tuple[str, bool]] = []
        self.descriptor: _Descriptor | None = None
        self.register_raises: Exception | None = None
        self.describe_raises: Exception | None = None
        self.enable_raises: Exception | None = None

    async def list_idps(self) -> list[_Entity]:
        return list(self.entities)

    async def describe(self, entity_id: str) -> _Descriptor | None:
        if self.describe_raises is not None:
            raise self.describe_raises
        return self.descriptor

    async def register_idp(self, document: bytes, **kwargs: Any) -> _Descriptor:
        if self.register_raises is not None:
            raise self.register_raises
        self.registered.append({"document": document, **kwargs})
        return _Descriptor(
            entity_id=ENTITY, valid_until=VALID_UNTIL, sso_endpoints=(), signing_certificates=()
        )

    async def set_enabled(self, entity_id: str, enabled: bool) -> None:
        if self.enable_raises is not None:
            raise self.enable_raises
        self.switched.append((entity_id, enabled))


@pytest.fixture
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def registry() -> _Registry:
    return _Registry()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


class _Assignments:
    async def roles_for(self, person_uuid: str) -> set[str]:
        return {ADMIN_ROLE}


def _fetching(response: httpx.Response) -> httpx.AsyncClient:
    """A client that answers every fetch with one canned response.

    `follow_redirects=False`, matching the application's, so a 302 arrives here
    as a 302 rather than as whatever it points at.
    """
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: response), follow_redirects=False
    )


@pytest.fixture
def wired(
    app: FastAPI, redis: aioredis.FakeRedis, registry: _Registry, audit: RecordingAuditLog
) -> FastAPI:
    app.state.redis = redis
    app.state.sessions = SessionStore(redis)
    app.state.role_assignments = _Assignments()
    app.state.registry = registry
    app.state.audit = audit
    return app


@pytest.fixture
async def http(wired: FastAPI) -> Any:
    transport = ASGITransport(app=wired)
    async with AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as client:
        yield client


@pytest.fixture
async def admin(wired: FastAPI) -> dict[str, str]:
    session: Session = await wired.state.sessions.create(
        idp_entity_id="https://idp.campus.test/saml",
        name_id="marcus.reed@campus.test",
        auth_time=datetime.now(UTC) - timedelta(minutes=1),
        acr=AAL2,
        amr=(PWD, OTP, MFA),
        person_uuid=PERSON,
    )
    return {SESSION_COOKIE: session.sid}


# --- listing ----------------------------------------------------------------


async def test_the_listing_shows_disabled_entities_too(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """An operator asking why a login fails needs to see that the entity is
    registered and switched off, which is a different problem from it never
    having been registered."""
    registry.entities = [_Entity(ENTITY, "Partner College", "idp", False, None, VALID_UNTIL, None)]

    body = (await http.get("/admin/entities", cookies=admin)).json()

    assert body["entities"][0]["entity_id"] == ENTITY
    assert body["entities"][0]["enabled"] is False


async def test_an_empty_registry_lists_nothing(http: AsyncClient, admin: dict[str, str]) -> None:
    assert (await http.get("/admin/entities", cookies=admin)).json() == {"entities": []}


# --- describing -------------------------------------------------------------


async def test_an_entity_is_described_from_its_document(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """Parsed on read rather than served from stored columns, so what an
    administrator sees is what the gate will actually use."""
    registry.descriptor = _Descriptor(
        entity_id=ENTITY,
        valid_until=VALID_UNTIL,
        sso_endpoints=(_Endpoint("urn:binding:redirect", "https://idp.partner.test/sso"),),
        signing_certificates=(CERTIFICATE,),
    )

    body = (await http.get(f"/admin/entities/{ENTITY}", cookies=admin)).json()

    assert body["entity_id"] == ENTITY
    assert body["sso_endpoints"][0]["location"] == "https://idp.partner.test/sso"


async def test_certificates_are_shown_as_fingerprints(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """An administrator comparing a key rollover against what the partner sent
    needs to tell two apart, and a page of base64 is not how anybody does that."""
    registry.descriptor = _Descriptor(ENTITY, VALID_UNTIL, (), (CERTIFICATE,))

    body = (await http.get(f"/admin/entities/{ENTITY}", cookies=admin)).json()

    fingerprint = body["signing_certificates"][0]
    assert fingerprint.count(":") == 31
    assert "BEGIN CERTIFICATE" not in str(body)


async def test_an_unregistered_entity_is_not_found(
    http: AsyncClient, admin: dict[str, str]
) -> None:
    assert (await http.get(f"/admin/entities/{ENTITY}", cookies=admin)).status_code == 404


async def test_a_document_that_has_become_unusable_is_surfaced(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """Exactly what an operator is looking for when logins from one partner stop
    working. Hiding it behind a 404 would send them looking for a registration
    that is right there."""
    registry.describe_raises = MetadataRejected(ReasonCode.METADATA_EXPIRED, "validUntil passed")

    response = await http.get(f"/admin/entities/{ENTITY}", cookies=admin)

    assert response.status_code == 409
    assert response.json()["reason"] == ReasonCode.METADATA_EXPIRED.value


# --- registering ------------------------------------------------------------


async def test_pasted_metadata_registers(
    http: AsyncClient, admin: dict[str, str], registry: _Registry, audit: RecordingAuditLog
) -> None:
    response = await http.post(
        "/admin/entities",
        json={"metadata": "<EntityDescriptor/>", "reason": "onboarding Partner College"},
        cookies=admin,
    )

    assert response.status_code == 201
    assert response.json()["entity_id"] == ENTITY
    assert registry.registered[0]["document"] == b"<EntityDescriptor/>"
    assert EventType.ADMIN_ACTION in audit.types


async def test_metadata_the_parser_refuses_is_not_registered(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """The same parser the gate uses. A console that accepted anything would
    turn this into a login failing an hour later for a reason nobody connects to
    this action."""
    registry.register_raises = MetadataRejected(ReasonCode.METADATA_INVALID, "no EntityDescriptor")

    response = await http.post(
        "/admin/entities", json={"metadata": "<nonsense/>", "reason": "why not"}, cookies=admin
    )

    assert response.status_code == 400
    assert response.json()["reason"] == ReasonCode.METADATA_INVALID.value


async def test_a_refused_registration_is_still_audited(
    http: AsyncClient, admin: dict[str, str], registry: _Registry, audit: RecordingAuditLog
) -> None:
    """A trail that records only what worked cannot answer "who kept trying to
    register this"."""
    registry.register_raises = MetadataRejected(ReasonCode.METADATA_INVALID, "no")

    await http.post(
        "/admin/entities", json={"metadata": "<nonsense/>", "reason": "why not"}, cookies=admin
    )

    assert EventType.ADMIN_ACTION in audit.types


async def test_an_oversized_paste_never_reaches_the_route(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """The body-size middleware refuses it while it is still being received,
    which is the right place for that check — so the answer is 413 rather than
    the route's own 400, and nothing buffered the document."""
    response = await http.post(
        "/admin/entities",
        json={"metadata": "x" * (MAX_METADATA + 1), "reason": "large"},
        cookies=admin,
    )

    assert response.status_code == 413
    assert registry.registered == []


async def test_an_oversized_fetch_is_refused(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str], registry: _Registry
) -> None:
    """The fetched path is where the route's own cap matters: those bytes arrive
    from a server the middleware never sees."""
    wired.state.metadata_http = _fetching(httpx.Response(200, content=b"x" * (MAX_METADATA + 1)))

    response = await http.post(
        "/admin/entities",
        json={"metadata_url": "https://partner.test/metadata", "reason": "onboarding"},
        cookies=admin,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "metadata_too_large"
    assert registry.registered == []


async def test_a_fetched_document_registers(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str], registry: _Registry
) -> None:
    """Registering a partner by their published metadata URL is the normal way
    federation works."""
    wired.state.metadata_http = _fetching(httpx.Response(200, content=b"<EntityDescriptor/>"))

    response = await http.post(
        "/admin/entities",
        json={"metadata_url": "https://partner.test/metadata", "reason": "onboarding"},
        cookies=admin,
    )

    assert response.status_code == 201
    assert registry.registered[0]["document"] == b"<EntityDescriptor/>"


async def test_a_fetch_that_fails_is_reported_as_such(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str], registry: _Registry
) -> None:
    """Distinct from metadata the parser refused: one is the partner's server
    being down, the other is their document being wrong, and an operator chases
    them differently."""
    wired.state.metadata_http = _fetching(httpx.Response(404))

    response = await http.post(
        "/admin/entities",
        json={"metadata_url": "https://partner.test/metadata", "reason": "onboarding"},
        cookies=admin,
    )

    assert response.json()["error"] == "metadata_unreachable"
    assert registry.registered == []


async def test_a_fetch_does_not_follow_redirects(
    http: AsyncClient, wired: FastAPI, admin: dict[str, str], registry: _Registry
) -> None:
    """A server-side fetch of an operator-supplied URL that chases redirects is
    how one address becomes an arbitrary one."""
    wired.state.metadata_http = _fetching(
        httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
    )

    response = await http.post(
        "/admin/entities",
        json={"metadata_url": "https://partner.test/metadata", "reason": "onboarding"},
        cookies=admin,
    )

    assert response.json()["error"] == "metadata_unreachable"
    assert registry.registered == []


async def test_a_registration_with_no_document_is_refused(
    http: AsyncClient, admin: dict[str, str]
) -> None:
    response = await http.post("/admin/entities", json={"reason": "nothing here"}, cookies=admin)

    assert response.status_code == 400
    assert response.json()["error"] == "metadata_required"


async def test_a_url_that_is_not_http_is_refused(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """A fetch is a server-side request to an operator-supplied address, so the
    scheme is not somebody else's to choose."""
    response = await http.post(
        "/admin/entities",
        json={"metadata_url": "file:///etc/passwd", "reason": "look at this"},
        cookies=admin,
    )

    assert response.status_code == 400
    assert registry.registered == []


# --- the reason (FR-ADM-07) -------------------------------------------------


@pytest.mark.parametrize("body", [{}, {"reason": ""}, {"reason": "   "}, {"reason": "x" * 513}])
async def test_a_mutation_without_a_usable_reason_is_refused(
    http: AsyncClient, admin: dict[str, str], registry: _Registry, body: dict[str, Any]
) -> None:
    """Refused before the change rather than defaulted, because a default reason
    is a field everybody stops reading."""
    response = await http.post("/admin/entities", json={**body, "metadata": "<x/>"}, cookies=admin)

    assert response.status_code == 400
    assert response.json()["error"] == "reason_required"
    assert registry.registered == []


async def test_the_reason_reaches_the_audit_record(
    http: AsyncClient, admin: dict[str, str], audit: RecordingAuditLog
) -> None:
    """In the column the schema has for it, so "every administrative change and
    why" is a column read rather than a search through JSON."""
    await http.post(
        "/admin/entities",
        json={"metadata": "<x/>", "reason": "onboarding Partner College"},
        cookies=admin,
    )

    recorded = audit.of_type(EventType.ADMIN_ACTION)[0]
    assert recorded.reason == "onboarding Partner College"
    assert recorded.actor == PERSON


# --- enabling and disabling -------------------------------------------------


async def test_an_entity_can_be_disabled(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    """Disabling rather than deleting, so the reason a partner was cut off stays
    answerable and turning them back on is one call rather than a metadata
    exchange arranged again during an incident."""
    response = await http.post(
        f"/admin/entities/{ENTITY}/enabled",
        json={"enabled": False, "reason": "suspected key compromise"},
        cookies=admin,
    )

    assert response.status_code == 200
    assert registry.switched == [(ENTITY, False)]


async def test_an_entity_can_be_re_enabled(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    await http.post(
        f"/admin/entities/{ENTITY}/enabled",
        json={"enabled": True, "reason": "key rotated, partner confirmed"},
        cookies=admin,
    )

    assert registry.switched == [(ENTITY, True)]


async def test_switching_an_unregistered_entity_is_not_found(
    http: AsyncClient, admin: dict[str, str], registry: _Registry
) -> None:
    registry.enable_raises = MetadataRejected(ReasonCode.METADATA_INVALID, "not registered")

    response = await http.post(
        f"/admin/entities/{ENTITY}/enabled",
        json={"enabled": False, "reason": "tidying up"},
        cookies=admin,
    )

    assert response.status_code == 404


@pytest.mark.parametrize("value", [None, "false", 0, "yes"])
async def test_a_switch_that_does_not_say_which_way_is_refused(
    http: AsyncClient, admin: dict[str, str], registry: _Registry, value: Any
) -> None:
    """A string "false" is true to anybody reading it loosely, and this is the
    one field where reading it loosely turns trust on."""
    response = await http.post(
        f"/admin/entities/{ENTITY}/enabled",
        json={"enabled": value, "reason": "a reason"},
        cookies=admin,
    )

    assert response.status_code == 400
    assert registry.switched == []


async def test_switching_is_audited_with_the_entity_and_the_reason(
    http: AsyncClient, admin: dict[str, str], audit: RecordingAuditLog
) -> None:
    await http.post(
        f"/admin/entities/{ENTITY}/enabled",
        json={"enabled": False, "reason": "suspected key compromise"},
        cookies=admin,
    )

    recorded = audit.of_type(EventType.ADMIN_ACTION)[0]
    assert recorded.target == ENTITY
    assert recorded.reason == "suspected key compromise"
    assert recorded.detail["enabled"] is False
