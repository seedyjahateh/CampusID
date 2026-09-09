"""Applying a lifecycle transition to the registry (FR-LC-05, FR-LC-06).

Where a `Delta` from the rules becomes rows: grants written with their
justification, revocations either done now or scheduled, and a timeline event
recording both sides of the change.

**A deferred revocation is a row, not a timer.** A thirty-day grace period
outlives any process, so `revoke_at` is stored and a sweep picks it up. An access
that ends only if a particular container stays alive does not end, and that is
the failure FR-LC-05's "durable across restarts" is about.

**Revoking means setting `revoked_at`, never deleting.** "This person had LMS
access until August" is a question an auditor asks, and a deleted row cannot
answer it. The same reason identifiers are tombstoned rather than freed.

**A grant is keyed by its justification.** Somebody who is both student and
faculty holds the LMS twice, and losing one affiliation must leave the other
grant standing. Writing one row per (person, entitlement) instead would make the
mover case silently wrong in the direction of removing access somebody still has
a reason to hold.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.audit.log import correlation_id
from campusid.lifecycle.models import EntitlementGrant, LifecycleEvent
from campusid.lifecycle.rules import Delta, Grant
from campusid.logging import get_logger

log = get_logger(__name__)

JOINER = "joiner"
MOVER = "mover"
LEAVER = "leaver"
GRACE_EXPIRY = "grace_expiry"

SOURCE_SCIM = "scim"
SOURCE_SCHEDULER = "scheduler"


def justification_ref(grant: Grant) -> str:
    """How a grant's reason is written down.

    Rule and affiliation together, because the rule alone cannot distinguish the
    student justification from the faculty one when a person holds both — and
    that distinction is exactly what a mover transition turns on.
    """
    return f"{grant.rule_id}:{grant.affiliation}"


def event_type(before: set[str], after: set[str]) -> str:
    """Which of the three transitions this is.

    Named from the affiliations rather than from what the caller thinks it is
    doing, so a SCIM update that happens to remove somebody's last affiliation
    is recorded as the leaver it is.
    """
    if not before:
        return JOINER
    if not after:
        return LEAVER
    return MOVER


class LifecycleStore:
    """Reads and writes the entitlement grants and the timeline."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def apply(
        self,
        person_uuid: uuid.UUID,
        delta: Delta,
        *,
        before: set[str],
        after: set[str],
        source: str = SOURCE_SCIM,
    ) -> None:
        """Write a transition: grants, revocations, and one timeline event."""
        async with self._sessions() as session, session.begin():
            await self._grant(session, person_uuid, delta.granted)
            await self._revoke(session, person_uuid, delta)

            session.add(
                LifecycleEvent(
                    person_uuid=person_uuid,
                    event_type=event_type(before, after),
                    source=source,
                    before_state=_state(before, delta.granted, delta.retained, delta.revoked),
                    after_state={
                        "affiliations": sorted(after),
                        "entitlements": sorted(
                            {grant.urn for grant in delta.granted + delta.retained}
                        ),
                    },
                    correlation_id=correlation_id(),
                )
            )

        log.info(
            "lifecycle.transition",
            person_uuid=str(person_uuid),
            event_type=event_type(before, after),
            granted=len(delta.granted),
            revoked=len(delta.revoked),
            deferred=len(delta.deferred),
        )

    async def held(self, person_uuid: uuid.UUID, *, on: date | None = None) -> set[str]:
        """The entitlements this person actually holds right now.

        Reads the grants rather than recomputing from the rules, because the two
        can legitimately differ: a grant inside its grace period is still held
        even though no current affiliation justifies it any more. Recomputing
        would report the access as gone while it is still working.
        """
        today = on or date.today()
        async with self._sessions() as session:
            rows = await session.scalars(
                select(EntitlementGrant).where(
                    EntitlementGrant.person_uuid == person_uuid,
                    EntitlementGrant.revoked_at.is_(None),
                )
            )
            return {
                grant.entitlement_urn
                for grant in rows
                if grant.revoke_at is None or grant.revoke_at > today
            }

    async def timeline(self, person_uuid: uuid.UUID) -> list[LifecycleEvent]:
        """Every transition this person has been through, oldest first (FR-LC-06)."""
        async with self._sessions() as session:
            return list(
                await session.scalars(
                    select(LifecycleEvent)
                    .where(LifecycleEvent.person_uuid == person_uuid)
                    .order_by(LifecycleEvent.occurred_at)
                )
            )

    async def expire_due(self, *, on: date | None = None) -> int:
        """Revoke every grant whose grace period has ended (FR-LC-05).

        The durable half. A broker that was not running when a grace period
        expired revokes on its next sweep rather than never — which is the whole
        reason the deadline is a column instead of a timer.
        """
        today = on or date.today()
        expired = 0

        async with self._sessions() as session, session.begin():
            due = list(
                await session.scalars(
                    select(EntitlementGrant).where(
                        EntitlementGrant.revoked_at.is_(None),
                        EntitlementGrant.revoke_at.is_not(None),
                        EntitlementGrant.revoke_at <= today,
                    )
                )
            )
            for grant in due:
                grant.revoked_at = datetime.now(UTC)
                session.add(
                    LifecycleEvent(
                        person_uuid=grant.person_uuid,
                        event_type=GRACE_EXPIRY,
                        source=SOURCE_SCHEDULER,
                        before_state={"entitlement": grant.entitlement_urn, "held": True},
                        after_state={"entitlement": grant.entitlement_urn, "held": False},
                        correlation_id=correlation_id(),
                    )
                )
                expired += 1

        if expired:
            log.info("lifecycle.grace.expired", count=expired, on=today.isoformat())
        return expired

    # --- helpers ----------------------------------------------------------

    async def _grant(
        self, session: AsyncSession, person_uuid: uuid.UUID, grants: tuple[Grant, ...]
    ) -> None:
        """Write new grants, ignoring ones already recorded.

        `ON CONFLICT DO NOTHING` against the justification key, so a replayed
        SIS message does not double-grant and does not fail either — a
        provisioning client that retries is the ordinary case.
        """
        if not grants:
            return
        await session.execute(
            pg_insert(EntitlementGrant)
            .values(
                [
                    {
                        "person_uuid": person_uuid,
                        "entitlement_urn": grant.urn,
                        "justification_kind": "affiliation",
                        "justification_ref": justification_ref(grant),
                        "granted_at": datetime.now(UTC),
                    }
                    for grant in grants
                ]
            )
            .on_conflict_do_nothing(
                index_elements=["person_uuid", "entitlement_urn", "justification_ref"]
            )
        )

    async def _revoke(self, session: AsyncSession, person_uuid: uuid.UUID, delta: Delta) -> None:
        """End the grants a transition took away.

        Immediately when there is no grace period, and by deadline when there
        is. A grant already carrying an earlier deadline keeps it: a second
        transition must not extend an access that is already counting down.
        """
        if not delta.revoked:
            return

        deadlines = {revocation.urn: revocation for revocation in delta.revoked}
        rows = await session.scalars(
            select(EntitlementGrant).where(
                EntitlementGrant.person_uuid == person_uuid,
                EntitlementGrant.entitlement_urn.in_(deadlines),
                EntitlementGrant.revoked_at.is_(None),
            )
        )

        now = datetime.now(UTC)
        for grant in rows:
            revocation = deadlines[grant.entitlement_urn]
            if revocation.grace_days == 0:
                grant.revoked_at = now
                grant.revoke_at = revocation.effective
                continue
            if grant.revoke_at is None or revocation.effective < grant.revoke_at:
                grant.revoke_at = revocation.effective


def _state(
    affiliations: set[str],
    granted: tuple[Grant, ...],
    retained: tuple[Grant, ...],
    revoked: tuple[Any, ...],
) -> dict[str, Any]:
    """The `before_state` of a transition, reconstructed from the delta.

    Both sides are recorded rather than a diff, because a diff is derivable from
    the states and the states are not derivable from the diff — and the question
    an auditor asks a year later is what the record actually said.
    """
    return {
        "affiliations": sorted(affiliations),
        "entitlements": sorted(
            {grant.urn for grant in retained} | {revocation.urn for revocation in revoked}
        ),
    }
