"""Emitting audit events (FR-AUD-01, FR-AUD-02).

The correlation id is the load-bearing part. FR-AUD-02 asks that one login
produce a chain of events sharing a single id — the authorization request, the
upstream SSO, the attribute release, the token issuance — because the question
an investigator asks is never "did this event happen" but "what else happened
around it".

It lives in a `contextvar` set once per request rather than being threaded
through every function signature. That is not convenience: a parameter that has
to be passed through fifteen call sites is a parameter somebody will forget at
the sixteenth, and a missing correlation id produces an event that is present
but unjoinable — the worst of both.

**Emission never fails a request.** An audit write that raises would turn a
database hiccup into a failed login, and a broker that stops authenticating
because it cannot write history has chosen the wrong thing to protect. Failures
are logged loudly instead. That is a real trade — a determined attacker who can
break the audit database can act unlogged — and M5's answer is the hash chain
plus alerting on the gap, not making the request fail.
"""

from __future__ import annotations

import contextvars
import secrets
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.events import AuditEvent, EventType, Outcome, redact
from campusid.audit.models import AuditEventRecord
from campusid.logging import get_logger
from campusid.saml.stores import utcnow

log = get_logger(__name__)

_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id")


def new_correlation_id() -> str:
    """A fresh id for one chain of events.

    Short enough for a user to read back over the phone — it is the same value
    the error page shows as a reference, so an operator searching the audit
    trail for what a caller quotes finds the whole chain rather than one
    rejection.
    """
    return secrets.token_hex(8)


def set_correlation_id(value: str) -> None:
    _correlation_id.set(value)


def correlation_id() -> str:
    """The current chain's id, minting one if this is the start of a chain."""
    try:
        return _correlation_id.get()
    except LookupError:
        fresh = new_correlation_id()
        _correlation_id.set(fresh)
        return fresh


class AuditLog:
    """Writes audit events to Postgres."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def record(
        self,
        event_type: EventType,
        outcome: Outcome,
        *,
        actor: str | None = None,
        subject: str | None = None,
        target: str | None = None,
        reason: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        detail: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> AuditEvent:
        """Record one event and return it.

        The event is returned so a caller can assert on it in a test without
        reading the database back, and so the emitter stays the only thing that
        knows how a field is populated.
        """
        event = AuditEvent(
            event_type=event_type,
            outcome=outcome,
            timestamp=now or utcnow(),
            correlation_id=correlation_id(),
            actor=actor,
            subject=subject,
            target=target,
            reason=reason,
            source_ip=source_ip,
            user_agent=user_agent,
            session_id=session_id,
            # Redacted here rather than at the call site. A rule enforced in one
            # place is a rule; enforced at forty call sites it is a convention.
            detail=redact(detail or {}),
        )
        await self._write(event)
        return event

    async def _write(self, event: AuditEvent) -> None:
        try:
            async with self._sessions() as session, session.begin():
                session.add(
                    AuditEventRecord(
                        event_id=event.event_id,
                        event_type=event.event_type.value,
                        outcome=event.outcome.value,
                        occurred_at=event.timestamp,
                        correlation_id=event.correlation_id,
                        actor=event.actor,
                        subject=event.subject,
                        target=event.target,
                        reason=event.reason,
                        source_ip=event.source_ip,
                        user_agent=event.user_agent,
                        session_id=event.session_id,
                        detail=event.detail,
                    )
                )
        except Exception as exc:
            # Deliberately swallowed. An audit write that raises turns a
            # database hiccup into a failed login, and a broker that stops
            # authenticating because it cannot write history has chosen the
            # wrong thing to protect. Logged at error so the gap is visible.
            log.error(
                "audit.write_failed",
                event_type=event.event_type.value,
                correlation_id=event.correlation_id,
                error=str(exc),
            )
