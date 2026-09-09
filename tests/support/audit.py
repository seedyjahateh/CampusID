"""An audit log that keeps its events in memory.

Subclasses the real `AuditLog` and replaces only `_write`, so everything the
tests care about — the correlation id from the contextvar, the field mapping,
and above all the redaction — is the production code path rather than a
reimplementation of it. A double that built its own events could pass while the
real emitter leaked a student number.
"""

from __future__ import annotations

from campusid.audit.events import AuditEvent, EventType
from campusid.audit.log import AuditLog


class RecordingAuditLog(AuditLog):
    """Collects events instead of writing them."""

    def __init__(self) -> None:
        # Deliberately no session factory: reaching for one would be a bug, and
        # `None` makes that bug an immediate AttributeError rather than a
        # mysterious connection attempt in a unit test.
        self.events: list[AuditEvent] = []

    async def _write(self, event: AuditEvent) -> None:
        self.events.append(event)

    def of_type(self, event_type: EventType) -> list[AuditEvent]:
        return [event for event in self.events if event.event_type is event_type]

    @property
    def types(self) -> list[EventType]:
        return [event.event_type for event in self.events]
