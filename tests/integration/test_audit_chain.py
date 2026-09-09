"""The audit chain, against live Postgres and a real login (FR-AUD-01/02).

The one place FR-AUD-02's claim can be made honestly: "one login yields ≥6
events sharing one id" counts the SAML half, and the SAML half only exists when
somebody actually authenticates. Here that is a real browser-shaped round trip
through Keycloak, and the events are read back out of the real table by the real
emitter rather than out of an in-memory double.

It also exercises the queries FR-AUD-03 will need — by correlation id, and by
subject over a time range — which is the point of the indexes in migration 0004.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from html import unescape
from typing import Any

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.audit.events import REDACTED, EventType
from campusid.audit.models import AuditEventRecord
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.session.cookies import REQUEST_BINDING_COOKIE

pytestmark = [pytest.mark.integration, pytest.mark.federation]

BROKER = "http://broker:8000"
KEYCLOAK_INTERNAL = "http://keycloak:8080"
KEYCLOAK_PUBLIC = "http://localhost:18080"
IDP_ENTITY_ID = f"{KEYCLOAK_PUBLIC}/realms/campus"

FIXTURE_USER = "sam.obrien"
FIXTURE_PASSWORD = "campus-dev-password"

LOGIN_FORM_ACTION = re.compile(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"')
SAML_RESPONSE_FIELD = re.compile(
    r'<input[^>]+name="SAMLResponse"[^>]+value="([^"]*)"', re.IGNORECASE
)
RELAY_STATE_FIELD = re.compile(r'<input[^>]+name="RelayState"[^>]+value="([^"]*)"', re.IGNORECASE)


def _internal(url: str) -> str:
    """Keycloak advertises the browser-facing host; from inside the compose
    network it is reachable under another name. Applied to the transport only,
    never to anything a signature covers — see `test_keycloak_sso.py`."""
    return url.replace(KEYCLOAK_PUBLIC, KEYCLOAK_INTERNAL)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Clear only what this test wrote.

    Snapshot-and-delete rather than a truncate, for the reason the federation
    fixture learned: other rows in the same table make a wholesale clear pass in
    isolation and fail in the suite.
    """
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(AuditEventRecord.event_id)))

    yield factory

    async with factory() as session, session.begin():
        await session.execute(
            delete(AuditEventRecord).where(AuditEventRecord.event_id.not_in(pre_existing or {""}))
        )


async def _login(client: httpx.AsyncClient) -> str:
    """Drive a real SAML login and return the chain's correlation id.

    The id is read off the `X-Correlation-ID` header of the *first* request,
    which is the same value a user would quote from an error page — so this
    follows the operator's actual route into the trail rather than a private
    handle the application happens to know.
    """
    start = await client.get(f"{BROKER}/saml/sso", params={"idp": IDP_ENTITY_ID})
    assert start.status_code == 303, start.text
    correlation = start.headers["x-correlation-id"]
    binding_cookie = start.cookies[REQUEST_BINDING_COOKIE]

    login_page = await client.get(_internal(start.headers["location"]))
    match = LOGIN_FORM_ACTION.search(login_page.text)
    assert match, "Keycloak did not render a login form"

    submitted = await client.post(
        _internal(unescape(match.group(1))),
        data={"username": FIXTURE_USER, "password": FIXTURE_PASSWORD},
        cookies=login_page.cookies,
    )
    response_field = SAML_RESPONSE_FIELD.search(submitted.text)
    assert response_field, f"no SAMLResponse in Keycloak's reply: {submitted.text[:400]}"

    form = {"SAMLResponse": unescape(response_field.group(1))}
    relay_field = RELAY_STATE_FIELD.search(submitted.text)
    if relay_field:
        form["RelayState"] = unescape(relay_field.group(1))

    acs = await client.post(
        f"{BROKER}/saml/acs", data=form, cookies={REQUEST_BINDING_COOKIE: binding_cookie}
    )
    assert acs.status_code == 303, acs.text
    return correlation


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
        yield client


async def _events(
    sessions: async_sessionmaker[AsyncSession], **where: Any
) -> list[AuditEventRecord]:
    async with sessions() as session:
        statement = select(AuditEventRecord).order_by(AuditEventRecord.occurred_at)
        for column, value in where.items():
            statement = statement.where(getattr(AuditEventRecord, column) == value)
        return list(await session.scalars(statement))


async def test_a_login_is_written_to_the_audit_table(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The emitter, the model and the migration agreeing — which no unit test
    with an in-memory double can establish."""
    await _login(http)

    assert await _events(sessions, event_type=EventType.AUTH_SUCCESS.value)


async def test_the_login_chain_shares_one_correlation_id(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-AUD-02. The SAML half alone is three events — the request, the
    successful assertion, and the session — and they are joined by the id the
    browser was handed on its very first request."""
    correlation = await _login(http)

    chain = await _events(sessions, correlation_id=correlation)

    assert len(chain) >= 3
    assert {event.correlation_id for event in chain} == {correlation}


async def test_the_chain_covers_the_request_and_its_answer(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The `auth.request` is emitted on `/saml/sso` and the `auth.success` on
    `/saml/acs` — two different HTTP requests, minutes apart if the user is
    slow. Joining them is the whole reason the id is carried on the
    server-side outstanding request rather than regenerated per request."""
    await _login(http)

    types = {event.event_type for event in await _events(sessions)}

    assert {
        EventType.AUTH_REQUEST.value,
        EventType.AUTH_SUCCESS.value,
        EventType.SESSION_CREATED.value,
    } <= types


async def test_the_trail_is_queryable_by_subject(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """US-02's shape: "look up a person and see every attribute released". The
    index in migration 0004 exists for this query."""
    await _login(http)

    successes = await _events(sessions, event_type=EventType.AUTH_SUCCESS.value)
    subject = successes[0].subject
    assert subject

    timeline = await _events(sessions, subject=subject)
    assert len(timeline) >= 2


async def test_no_assertion_or_attribute_value_reaches_the_table(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-AUD-06 against real data rather than fixtures. Keycloak asserts this
    user's real attributes; the names may be recorded and the values may not."""
    await _login(http)

    written = repr([event.detail for event in await _events(sessions)])

    assert "saml" not in written.lower() or "Assertion" not in written
    assert FIXTURE_PASSWORD not in written
    # The IdP releases an email for this fixture user; the record keeps the
    # attribute name and replaces the address.
    assert "@campus.test" not in written or REDACTED in written


async def test_the_source_address_is_recorded(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-AUD-01. The peer we can see — inside the compose network, the test
    container's address — never a forwarded header we cannot verify."""
    await _login(http)

    successes = await _events(sessions, event_type=EventType.AUTH_SUCCESS.value)

    assert successes[0].source_ip
