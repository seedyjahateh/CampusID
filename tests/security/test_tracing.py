"""One login produces one connected trace (NFR-OBS-02).

The requirement asks for at least five spans in a single trace. That number is
the interesting part: it rules out the implementation where a request is one span
with a duration, which tells you a login took eleven seconds and not where the
eleven seconds went.

Spans are captured with an in-memory exporter rather than a collector. A test
that needed one would be an integration test, would be skipped whenever the
collector was not up, and would be measuring the collector.

**What is asserted is the shape, not the timings.** That every span shares one
trace id, that they nest rather than sit in a row, that each carries the
correlation id joining it to the audit trail, and — the one nobody writes — that
no span carries a person.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from httpx import AsyncClient
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from campusid.identity.registry import STATUS_ACTIVE
from campusid.observability.tracing import CORRELATION_ATTRIBUTE
from campusid.routes.saml import BINDING_KEY_PREFIX
from campusid.saml.gate import AssertionGate
from campusid.session.cookies import REQUEST_BINDING_COOKIE
from campusid.session.store import SessionStore
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryRequestStore

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"

NAME_ID = "sam.obrien@campus.edu"
"""The subject the forge asserts. Searched for in every span attribute, because
the rule a trace has to keep is that it never carries one."""


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    """A provider installed for one test and removed afterwards.

    OpenTelemetry refuses to replace a provider once set and warns rather than
    raising, so this reaches past the guard deliberately. The alternative is a
    session-wide provider that accumulates every span every test produces, which
    would make an assertion about *this* login's spans depend on test ordering.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # The module global, not `get_tracer_provider()`. That returns the *proxy*
    # provider, whose whole job is to delegate to this global — so restoring its
    # return value here makes the proxy delegate to itself, and the next span
    # opened anywhere in the session recurses until the stack runs out. It fails
    # in every file that runs after this one and in none that run alone, which is
    # the most expensive shape a test-isolation bug can take.
    previous = trace._TRACER_PROVIDER
    trace._TRACER_PROVIDER = provider
    try:
        yield exporter
    finally:
        trace._TRACER_PROVIDER = previous
        provider.shutdown()


class _Person:
    edu_person_unique_id = "opaque@campus.test"
    status = STATUS_ACTIVE


class _Identifier:
    def __init__(self, id_type: str, value: str) -> None:
        self.id_type = id_type
        self.value = value
        self.released_at = None
        self.is_primary = True


class _Identity:
    """The registry, reduced to what a completed login asks of it."""

    async def resolve(self, assertion: Any) -> Any:
        return SimpleNamespace(linked=True, person_uuid=uuid.UUID(PERSON))

    async def get(self, person_uuid: str) -> _Person:
        return _Person()

    async def identifiers(self, person_uuid: str) -> list[_Identifier]:
        return [_Identifier("eppn", "sam.obrien@campus.test")]

    async def affiliations_on(self, person_uuid: str, on: Any) -> set[str]:
        return {"student"}


class _Lifecycle:
    async def held(self, person_uuid: Any, *, on: Any = None) -> set[str]:
        return {"urn:mace:campus.edu:entitlement:lms:access"}


@pytest.fixture
def traced_app(app: FastAPI, gate: AssertionGate, request_store: InMemoryRequestStore) -> FastAPI:
    """Enough of the application for one login to complete.

    A successful login is what the requirement is about: a refused one stops at
    the first check and produces two spans, which would let this file assert a
    number it had arranged to be small.
    """
    app.state.redis = aioredis.FakeRedis(decode_responses=True)
    app.state.gate = gate
    app.state.request_store = request_store
    app.state.sessions = SessionStore(aioredis.FakeRedis(decode_responses=True))
    app.state.identity = _Identity()
    app.state.lifecycle = _Lifecycle()
    return app


async def _complete_a_login(app: FastAPI, client: AsyncClient, idp: ForgedIdP) -> None:
    """One SSO, end to end, through the real ACS.

    The binding nonce is seeded directly rather than by driving `/saml/sso`
    first: that leg has its own tests, and starting there would put its spans in
    a different trace and make the count below ambiguous.
    """
    nonce = "a-binding-nonce"
    await app.state.redis.set(f"{BINDING_KEY_PREFIX}relay-token", nonce)

    response = await client.post(
        "/saml/acs",
        data={
            "SAMLResponse": base64.b64encode(idp.response()).decode("ascii"),
            "RelayState": "relay-token",
        },
        cookies={REQUEST_BINDING_COOKIE: nonce},
    )
    assert response.status_code == 303, response.text


async def _post_a_bad_assertion(client: AsyncClient) -> None:
    """A refused login, for the tests about what a failure looks like."""
    await client.post("/saml/acs", data={"SAMLResponse": "not-base64", "RelayState": "x"})


def _finished(exporter: InMemorySpanExporter) -> list[ReadableSpan]:
    return list(exporter.get_finished_spans())


async def test_one_login_produces_at_least_five_connected_spans(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter, idp: ForgedIdP
) -> None:
    """The requirement's own acceptance criterion.

    Five is the number that rules out the implementation where a request is one
    span with a duration — which says a login took eleven seconds and not where
    the eleven seconds went.

    One trace id across all of them, because spans sharing a name and not a trace
    look right in a list and are useless in a viewer.
    """
    await _complete_a_login(traced_app, client, idp)

    finished = _finished(spans)
    assert len(finished) >= 5, [span.name for span in finished]
    assert len({span.context.trace_id for span in finished if span.context}) == 1


async def test_the_trace_names_each_phase_of_the_login(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter, idp: ForgedIdP
) -> None:
    """Named for the work rather than for the function.

    `saml.verify_signature` is worth its own span because it is an RSA operation
    next to microseconds of parsing; `session.create` because it is the first
    write. A reader looking for eleven seconds finds it in one of these or not at
    all.
    """
    await _complete_a_login(traced_app, client, idp)

    names = {span.name for span in _finished(spans)}
    assert {
        "POST /saml/acs",
        "saml.parse",
        "saml.verify_signature",
        "saml.check_conditions",
        "identity.resolve",
        "session.create",
    } <= names


async def test_the_spans_nest_rather_than_sit_in_a_row(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter, idp: ForgedIdP
) -> None:
    """The parse happens *inside* the ACS, and the trace has to say so.

    A flat list of sibling spans is what an implementation produces when each one
    opens its own root, and it loses the only thing a trace adds over five log
    lines: which work was part of which.
    """
    await _complete_a_login(traced_app, client, idp)

    by_name = {span.name: span for span in _finished(spans)}
    parse, acs = by_name["saml.parse"], by_name["POST /saml/acs"]
    assert parse.parent is not None, "the parse span opened its own trace"
    assert acs.context is not None
    assert parse.parent.span_id == acs.context.span_id


async def test_every_span_carries_the_correlation_id(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter
) -> None:
    """What joins a trace to the audit events for the same request.

    The trace id would be the natural key and does not exist in the audit trail,
    which predates this by four milestones and is written by code that has no
    tracer. So the join runs the other way.
    """
    await _post_a_bad_assertion(client)

    for span in _finished(spans):
        attributes: dict[str, Any] = dict(span.attributes or {})
        assert attributes.get(CORRELATION_ATTRIBUTE), f"{span.name} carries no correlation id"


async def test_no_span_carries_a_person(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter, idp: ForgedIdP
) -> None:
    """The rule the attribute choices are built around, asserted rather than
    assumed.

    A trace is shipped to a system outside this one, kept for as long as that
    system keeps things, and read by people who were never granted the identity
    registry. A subject in a span attribute is a disclosure that no access
    control in this project touches.

    Driven through a *successful* login, because that is the path with something
    to leak: a refusal never reaches the attributes.
    """
    await _complete_a_login(traced_app, client, idp)

    for span in _finished(spans):
        rendered = " ".join(str(value) for value in (span.attributes or {}).values())
        assert NAME_ID not in rendered, f"{span.name} carries a subject"
        assert "@campus" not in rendered, f"{span.name} carries something that looks like one"


async def test_a_refusal_marks_its_span_as_an_error(
    traced_app: FastAPI, client: AsyncClient, spans: InMemorySpanExporter
) -> None:
    """A span that swallowed the exception would make the trace say the work
    succeeded, which is worse than having no trace of it."""
    await _post_a_bad_assertion(client)

    statuses = [span.status.status_code for span in _finished(spans)]
    assert trace.StatusCode.ERROR in statuses


def test_tracing_is_off_without_an_endpoint() -> None:
    """A deployment with no collector pays nothing.

    Not a performance nicety: with tracing on by default, every test run would
    accumulate spans nobody reads, and the SDK would be installed in processes
    that have no use for it.
    """
    from campusid.observability.tracing import configure

    assert configure("") is False
    assert configure(None) is False
