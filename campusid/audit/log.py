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

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.chain import GENESIS, Broken, link, verify_from
from campusid.audit.events import AuditEvent, EventType, Outcome, redact
from campusid.audit.models import AuditEventRecord, AuditRetentionAnchor
from campusid.logging import get_logger
from campusid.saml.stores import utcnow

log = get_logger(__name__)

CHAIN_LOCK = 0x43414944
"""The advisory-lock key the chain writer holds, as a constant.

A fixed number rather than a hash of a string, so it is greppable and cannot
collide with the migration lock by accident — two locks that happen to agree
would deadlock a migration against a login.
"""


def _verifiable(record: AuditEventRecord) -> dict[str, Any]:
    """A stored row in the shape the verifier hashes.

    The chain's own columns are carried alongside the covered fields rather than
    inside them: `verify` reads `seq`, `prev_hash` and `hash` to check the links
    and ignores them when recomputing the digest, which is what makes a row that
    was edited *and* rehashed still detectable at the link before it.
    """
    return {
        "seq": record.seq,
        "prev_hash": record.prev_hash,
        "hash": record.hash,
        "event_id": record.event_id,
        "event_type": record.event_type,
        "outcome": record.outcome,
        "occurred_at": record.occurred_at,
        "correlation_id": record.correlation_id,
        "actor": record.actor,
        "subject": record.subject,
        "target": record.target,
        "reason": record.reason,
        "source_ip": record.source_ip,
        "user_agent": record.user_agent,
        "session_id": record.session_id,
        "detail": record.detail,
    }


def _row(event: AuditEvent) -> dict[str, object]:
    """The event as columns, in one place.

    Shared with the hash so the bytes that are stored and the bytes that are
    hashed cannot drift: a field added to the insert and forgotten in the digest
    is a field an attacker may edit freely.
    """
    return {
        "event_id": event.event_id,
        "event_type": event.event_type.value,
        "outcome": event.outcome.value,
        "occurred_at": event.timestamp,
        "correlation_id": event.correlation_id,
        "actor": event.actor,
        "subject": event.subject,
        "target": event.target,
        "reason": event.reason,
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "session_id": event.session_id,
        "detail": event.detail,
    }


_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id")

_impersonator: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "impersonator", default=None
)
"""Who is acting as somebody else on this request, if anybody (FR-ADM-03).

A contextvar for the same reason the correlation id is one, and the argument is
stronger here. The requirement is that *every* downstream event carries the
marker, and a parameter threaded through forty call sites is a parameter somebody
forgets at the forty-first — producing exactly the event an investigation needs
and cannot find. Set once, where the session is loaded, and read once, where the
event is written.
"""


def set_impersonator(value: str | None) -> None:
    """Record that this request is being made by somebody acting as another.

    Called by the session store on every load, with `None` for an ordinary
    session — so the marker cannot leak from one request to the next on a reused
    worker, which is the failure mode that would attach an administrator's name
    to a stranger's login.
    """
    _impersonator.set(value)


def impersonator() -> str | None:
    return _impersonator.get()


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
        acting_as = impersonator()
        if acting_as is not None:
            # FR-ADM-03. Merged here rather than at the call site, for the same
            # reason redaction is: a rule enforced in one place is a rule, and
            # this one has to hold for *every* downstream event or the trail
            # quietly credits an administrator's actions to the person they were
            # impersonating.
            detail = {**(detail or {}), "impersonation": True, "impersonated_by": acting_as}

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

    async def verify_chain(self, *, batch: int = 5000) -> Broken | None:
        """Walk the whole trail and report the first break (FR-AUD-05).

        Read in batches rather than all at once, because a year of a real
        deployment's events does not fit in memory and a verifier that only works
        on a small trail is one nobody runs on a large one.

        The batches are stitched by carrying the expected hash across, so the
        boundary between two batches is checked exactly like any other link.

        Starts from the last retention anchor rather than from the genesis
        constant when the trail has been pruned (FR-AUD-08). A verifier that
        assumed genesis after a prune would report the whole surviving trail as
        broken; one that skipped the first link entirely would let a deletion
        pass unnoticed. The anchor is what makes the third option possible.
        """
        expected = await self._starting_hash()
        last_seq = 0

        while True:
            async with self._sessions() as session:
                rows = list(
                    await session.execute(
                        select(AuditEventRecord)
                        .where(AuditEventRecord.seq > last_seq)
                        .order_by(AuditEventRecord.seq)
                        .limit(batch)
                    )
                )
            if not rows:
                return None

            events = [_verifiable(row[0]) for row in rows]
            # The carried hash is spliced onto the front as a sentinel the
            # verifier can start from, so `verify` needs no notion of resuming.
            broken = verify_from(expected, events)
            if broken is not None:
                return broken

            expected = str(events[-1]["hash"])
            last_seq = int(events[-1]["seq"])

    async def _starting_hash(self) -> str:
        """Where the surviving chain legitimately begins.

        The genesis constant when nothing has been pruned, the newest retention
        anchor's hash when something has. Read here rather than taken as an
        argument so a caller cannot verify against the wrong origin by accident,
        and so the verification command needs to know nothing about retention.
        """
        async with self._sessions() as session:
            anchor = await session.scalar(
                select(AuditRetentionAnchor.removed_through_hash)
                .order_by(AuditRetentionAnchor.removed_through_seq.desc())
                .limit(1)
            )
        return str(anchor) if anchor else GENESIS

    async def chain_head(self) -> str:
        """The hash the trail currently ends on.

        Worth publishing somewhere the database's owner does not control. That is
        what turns "partial tampering is detectable" into "tampering is
        detectable", and it is the one part of this that cannot live in code.
        """
        async with self._sessions() as session:
            tail = await session.scalar(
                select(AuditEventRecord.hash).order_by(AuditEventRecord.seq.desc()).limit(1)
            )
        # Falls back to the anchor rather than to genesis, so a trail pruned down
        # to nothing still reports the value its last event hashed to — otherwise
        # a published head would appear to reset, which is what a trail somebody
        # had emptied would also look like.
        return str(tail) if tail else await self._starting_hash()

    async def _write(self, event: AuditEvent) -> None:
        try:
            async with self._sessions() as session, session.begin():
                # One writer at a time, for the life of this transaction. The
                # chain is a linked list built from its own tail, so two writers
                # reading the same tail would produce two events claiming the
                # same predecessor — a fork, which a verifier reports as tampering
                # because from the outside it is indistinguishable from one.
                #
                # This serialises audit writes. That caps audit throughput at a
                # few thousand a second, which is far above what this broker
                # emits, and buys a chain with no unsealed tail and therefore no
                # special case for the verifier to be fooled at.
                await session.execute(select(func.pg_advisory_xact_lock(CHAIN_LOCK)))

                tail = await session.scalar(
                    select(AuditEventRecord.hash).order_by(AuditEventRecord.seq.desc()).limit(1)
                )
                if tail is None:
                    # An empty table is not necessarily a new one: a retention
                    # pass can remove every surviving event. Linking to the
                    # genesis constant then would start a second chain the
                    # verifier — which resumes from the anchor — reads as a break
                    # at the very first row after the prune.
                    anchor = await session.scalar(
                        select(AuditRetentionAnchor.removed_through_hash)
                        .order_by(AuditRetentionAnchor.removed_through_seq.desc())
                        .limit(1)
                    )
                    previous = str(anchor) if anchor else GENESIS
                else:
                    previous = str(tail)

                row = _row(event)
                session.add(
                    AuditEventRecord(
                        **row,
                        prev_hash=previous,
                        hash=link(previous, row),
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
