"""Distributed tracing (NFR-OBS-02).

A trace answers a question the audit trail and the metrics both refuse to. The
trail says what happened and in what order; the metrics say how often and how
long in aggregate. Neither says *where the eleven seconds went* in the one login
that took eleven seconds, and that is the question somebody has at the time.

**Spans are named by hand, not by auto-instrumentation.** The
`opentelemetry-instrumentation-*` packages wrap every database call, every
outbound request and every ASGI message, which produces a trace with four hundred
spans in it — technically complete and unreadable, and coupled to the internals
of three libraries that change. The six spans here are the six places a login
actually passes through, and a reader can hold all of them in their head.

**Nothing is traced unless an endpoint is configured.** With no collector the SDK
is never installed and every span comes from the API's no-op implementation,
which costs a function call and allocates nothing. A deployment that does not
want tracing does not pay for it, and — more to the point — a *test* run does not
accumulate spans nobody reads.

**A span carries no personal data, for the reason the metrics carry none.** A
trace is shipped to a system outside this one, kept for as long as that system
keeps things, and read by people who were never granted access to the identity
registry. Subject identifiers, attribute values and entity IDs of the person's
choosing stay out; what goes in is the shape of the work — which check refused,
how many attributes were considered, whether the directory answered from cache.

**The correlation id is the join.** Every span carries it as an attribute, so a
trace and the audit events for the same request can be put side by side. That is
deliberate rather than automatic: the trace id would be the natural key and it
does not exist in the audit trail, which predates this by four milestones and is
written by code that has no tracer.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

from opentelemetry import trace
from opentelemetry.trace import Span, Tracer

from campusid.audit.log import correlation_id

SERVICE_NAME: Final = "campusid-broker"

CORRELATION_ATTRIBUTE: Final = "campusid.correlation_id"
"""What joins a span to the audit events for the same request."""


def configure(endpoint: str | None, *, service_name: str = SERVICE_NAME) -> bool:
    """Install the tracer provider, if there is anywhere to send spans.

    Returns whether tracing was actually enabled, so the caller can log the fact
    rather than leaving an operator to guess from the absence of traces.

    Idempotent in the way that matters: OpenTelemetry refuses a second provider
    and warns, so calling this twice in one process is harmless and calling it
    once per test would be noisy. Tests install their own provider directly.
    """
    if not endpoint:
        return False

    # Imported here rather than at module scope. The exporter pulls in gRPC or
    # HTTP machinery depending on the protocol, and a deployment with no
    # collector should not pay for importing it.
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    # Console rather than OTLP, and that is a real limitation stated plainly: a
    # deployment that wants OTLP adds `opentelemetry-exporter-otlp` and swaps
    # this line. Shipping the exporter would mean shipping gRPC to every
    # deployment for the benefit of the ones that collect traces.
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return True


def tracer(name: str = "campusid") -> Tracer:
    """The tracer for a module.

    Fetched per call rather than cached at import. A module-level tracer is
    bound to whichever provider existed when the module was first imported,
    which in a test run is the no-op one — so the spans a test installs a
    provider to capture would go to the provider it replaced.
    """
    return trace.get_tracer(name)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Span]:
    """One span, carrying the correlation id and whatever else is safe to say.

    Attributes are passed by the caller and are the caller's responsibility, but
    the rule is short enough to restate: nothing that names a person. A reason
    code, a count, a boolean, an algorithm URI — yes. A subject, an email, an
    attribute value — no.

    Exceptions are recorded and re-raised. A span that swallowed one would make
    the trace say the work succeeded, which is worse than no trace.
    """
    with tracer().start_as_current_span(name) as current:
        current.set_attribute(CORRELATION_ATTRIBUTE, correlation_id())
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        try:
            yield current
        except Exception as exc:
            current.record_exception(exc)
            current.set_status(trace.Status(trace.StatusCode.ERROR, type(exc).__name__))
            raise
