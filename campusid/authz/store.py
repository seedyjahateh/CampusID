"""Reading and writing role assignments (FR-AZ-01, FR-AZ-06, FR-AZ-07).

Where a derivation becomes rows, and where an administrator's grant is refused
if it would break separation of duties.

**Reconciling derived roles is a diff, not an append.** Every login derives what
somebody's affiliations and groups say they are; the store adds what is new and
*ends* what no longer applies. An append-only derivation would leave a graduate
holding `student` until somebody noticed.

**Only derived assignments are reconciled.** A direct grant is a decision
somebody made, and a derivation run that quietly removed it would be the system
overruling a human without telling them. Direct grants end when an administrator
ends them or when their window closes.

**Validity is checked when the question is asked.** FR-AZ-06: an assignment that
expired last night is still in the table this morning, and a system that only
checked on the way in would honour it forever.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.authz.models import RoleAssignment
from campusid.authz.roles import Assignment, Origin, RoleCatalogue, RoleError
from campusid.logging import get_logger

log = get_logger(__name__)

DERIVED: tuple[str, ...] = (Origin.AFFILIATION.value, Origin.GROUP.value)
"""The origins a derivation run owns. Everything else is somebody's decision."""


class RoleAssignmentStore:
    """Role assignments for one deployment."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], *, catalogue: Any
    ) -> None:
        self._sessions = session_factory
        self._catalogue = catalogue

    def _rules(self) -> RoleCatalogue:
        current: RoleCatalogue = self._catalogue.current
        return current

    async def roles_for(self, person_uuid: str, *, on: date | None = None) -> set[str]:
        """Which roles this person holds, as of a date (FR-AZ-06).

        A date rather than "now" so the question "was this person an approver in
        March?" is the same query as "are they one today" — which is what makes
        an access review possible at all.
        """
        when = on or date.today()
        async with self._sessions() as session:
            rows = await session.scalars(
                select(RoleAssignment).where(RoleAssignment.person_uuid == uuid.UUID(person_uuid))
            )
            return {row.role for row in rows if _live(row, when)}

    async def assignments_for(self, person_uuid: str) -> list[RoleAssignment]:
        """Every assignment, live or not, so a review can see the history."""
        async with self._sessions() as session:
            return list(
                await session.scalars(
                    select(RoleAssignment)
                    .where(RoleAssignment.person_uuid == uuid.UUID(person_uuid))
                    .order_by(RoleAssignment.granted_at)
                )
            )

    async def reconcile_derived(
        self,
        person_uuid: str,
        derived: tuple[Assignment, ...],
        *,
        on: date | None = None,
    ) -> tuple[int, int]:
        """Make the derived assignments match what the facts now say.

        Returns `(added, ended)`. A diff rather than an append: a derivation run
        that only added would leave a graduate holding `student` until somebody
        noticed, which is the failure this whole module exists to avoid.
        """
        today = on or date.today()
        wanted = {(item.role, item.origin.value, item.reference) for item in derived}
        added = ended = 0

        async with self._sessions() as session, session.begin():
            rows = list(
                await session.scalars(
                    select(RoleAssignment).where(
                        RoleAssignment.person_uuid == uuid.UUID(person_uuid),
                        RoleAssignment.origin_kind.in_(DERIVED),
                    )
                )
            )

            existing: set[tuple[str, str, str]] = set()
            for row in rows:
                key = (row.role, row.origin_kind, row.origin_ref)
                if key in wanted:
                    existing.add(key)
                    if row.valid_until is not None and row.valid_until < today:
                        # The fact is true again: somebody re-enrolled. Reopen
                        # rather than insert, because the unique index is on the
                        # origin and a second row would be refused anyway.
                        row.valid_until = None
                elif _live(row, today):
                    # The fact stopped being true. Ended rather than deleted, so
                    # "they were an instructor until June" stays answerable.
                    row.valid_until = today
                    ended += 1

            for role, origin_kind, reference in sorted(wanted - existing):
                session.add(
                    RoleAssignment(
                        person_uuid=uuid.UUID(person_uuid),
                        role=role,
                        origin_kind=origin_kind,
                        origin_ref=reference,
                        valid_from=today,
                    )
                )
                added += 1

        if added or ended:
            log.info(
                "authz.roles.reconciled",
                person_uuid=person_uuid,
                added=added,
                ended=ended,
            )
        return added, ended

    async def grant(
        self,
        person_uuid: str,
        role: str,
        *,
        granted_by: str,
        valid_from: date | None = None,
        valid_until: date | None = None,
    ) -> bool:
        """Assign a role directly, refusing a combination that breaks the rules.

        Refused *before* the write, with the conflict named. Recording it and
        alerting afterwards would mean the control exists only in a report, and
        the person doing the assigning is the one who can undo it.
        """
        catalogue = self._rules()
        if role not in catalogue.roles:
            raise RoleError(f"no such role {role!r}")

        today = valid_from or date.today()
        held = await self.roles_for(person_uuid, on=today)
        catalogue.assert_compatible(held | {role})

        async with self._sessions() as session, session.begin():
            existing = await session.scalar(
                select(RoleAssignment).where(
                    RoleAssignment.person_uuid == uuid.UUID(person_uuid),
                    RoleAssignment.role == role,
                    RoleAssignment.origin_kind == Origin.DIRECT.value,
                    RoleAssignment.origin_ref == granted_by,
                )
            )
            if existing is not None:
                # The same grant from the same person. Extending the window is
                # the intent; a second row would be refused by the index.
                existing.valid_until = valid_until
                return False

            session.add(
                RoleAssignment(
                    person_uuid=uuid.UUID(person_uuid),
                    role=role,
                    origin_kind=Origin.DIRECT.value,
                    origin_ref=granted_by,
                    valid_from=today,
                    valid_until=valid_until,
                    granted_by=granted_by,
                )
            )

        log.info("authz.roles.granted", person_uuid=person_uuid, role=role, by=granted_by)
        return True

    async def revoke(self, person_uuid: str, role: str, *, on: date | None = None) -> int:
        """End every live assignment of one role to one person.

        Ended rather than deleted, and every origin at once: revoking a role
        from somebody who holds it twice and leaving one reason standing is the
        revocation that does not revoke.
        """
        today = on or date.today()
        ended = 0

        async with self._sessions() as session, session.begin():
            rows = await session.scalars(
                select(RoleAssignment).where(
                    RoleAssignment.person_uuid == uuid.UUID(person_uuid),
                    RoleAssignment.role == role,
                )
            )
            for row in rows:
                if _live(row, today):
                    row.valid_until = today
                    ended += 1

        if ended:
            log.info("authz.roles.revoked", person_uuid=person_uuid, role=role, origins=ended)
        return ended


def _live(row: RoleAssignment, when: date) -> bool:
    """Whether an assignment is in force on a date (FR-AZ-06).

    Half-open: `valid_from` is included and `valid_until` is not. The same
    convention the affiliation table already uses, and the reason is the same —
    a revocation taking effect today sets `valid_until` to today and the role is
    gone today. With an inclusive bound, revoking somebody would leave them
    holding the role for the rest of the day, which is precisely the window an
    immediate revocation exists to close.

    It also composes: an assignment ending on the first of July and another
    starting the same day describe a handover with no gap and no overlap.
    """
    if row.valid_from > when:
        return False
    return row.valid_until is None or row.valid_until > when
