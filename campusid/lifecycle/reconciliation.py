"""Comparing what the broker believes to what the directory does (FR-LC-07).

Provisioning is a sequence of writes to systems that can each fail
independently, so the two ends drift. A dead letter catches the failures we saw;
reconciliation catches the ones we did not — an administrator who re-enabled an
account by hand, a write that succeeded and was then undone by a restore, a
person created before the integration existed.

**Dry run is the default, and that is the whole shape of the feature.** A job
that compares and reports is something an operator runs on a Tuesday to find
out. A job that fixes things is something they run once they have read the
report and agree with it. Making the safe one the default is what lets the
first happen at all.

**Not every drift is remediable, and the unremediable one is the interesting
one.** An account in the directory that the broker has never heard of is a
finding, not a task: it might be a service account, a contractor provisioned by
somebody else, or the only administrator account on the box. Disabling it
automatically is how a reconciliation job takes down a campus, so orphans are
reported and never touched.

**The remediation is the ordinary write, not a special one.** Drift is closed by
the same disable the leaver path uses, which means it inherits the retries, the
idempotency and the dead letter. A reconciler with its own writes would be a
second provisioning implementation that only runs when something is already
wrong.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.directory.client import DirectoryUnavailable
from campusid.identity.models import Identifier, Person
from campusid.identity.registry import ID_EPPN, STATUS_ACTIVE
from campusid.logging import get_logger

log = get_logger(__name__)


class DriftKind(StrEnum):
    """What kind of disagreement this is.

    Separate values rather than a message, because what an operator does about
    each is different and a report they have to read prose to triage is a report
    they stop running.
    """

    SHOULD_BE_DISABLED = "should_be_disabled"
    """The broker says this person has left; the directory still lets them in.
    The security finding, and the only kind this job will fix on its own."""

    MISSING_DOWNSTREAM = "missing_downstream"
    """An active person with no directory account. Usually somebody created
    just-in-time by a federated login who was never provisioned downstream —
    a gap rather than a hazard, and creating an account is a decision with a
    password policy attached, so it is reported rather than done."""

    ORPHANED = "orphaned"
    """A directory account the broker has never heard of. Reported and never
    touched: it might be a service account, a contractor somebody else
    provisioned, or the only administrator account on the box."""

    UNREACHABLE = "unreachable"
    """The directory could not be asked about this person. Not drift — an
    absence of evidence — and recorded as such so a run during an outage does
    not read as a clean bill of health."""


@dataclass(frozen=True, slots=True)
class Drift:
    """One disagreement between the broker and a downstream system."""

    kind: DriftKind
    person_uuid: str | None
    login: str | None
    detail: str = ""

    @property
    def remediable(self) -> bool:
        """Whether this job will close it without being asked twice."""
        return self.kind is DriftKind.SHOULD_BE_DISABLED


@dataclass(frozen=True, slots=True)
class Report:
    """What one reconciliation run found and did."""

    drifts: tuple[Drift, ...] = ()
    remediated: tuple[Drift, ...] = ()
    failed: tuple[Drift, ...] = ()
    applied: bool = False
    """False for a dry run. Carried on the report so a reader cannot mistake a
    list of findings for a list of fixes."""

    scanned: int = 0

    def of_kind(self, kind: DriftKind) -> tuple[Drift, ...]:
        return tuple(drift for drift in self.drifts if drift.kind is kind)

    @property
    def clean(self) -> bool:
        """Whether the two ends agree, with no unreachable gaps.

        An unreachable person counts against this deliberately: a run that could
        not ask is not a run that found nothing.
        """
        return not self.drifts


def classify(*, person_uuid: str, login: str, status: str, entry: Any) -> Drift | None:
    """Decide what one person's two records disagree about, if anything.

    Separated from the walk because this is the judgement and the walk is
    plumbing. Four states, and the pair that looks alike is the pair that
    matters: a deactivated person with no directory account is two systems
    agreeing that somebody has gone, while an *active* person with no account is
    a provisioning gap.
    """
    active = status == STATUS_ACTIVE

    if entry is None:
        if not active:
            # Gone from the directory and gone here. The two ends agree.
            return None
        return Drift(
            kind=DriftKind.MISSING_DOWNSTREAM,
            person_uuid=person_uuid,
            login=login,
            detail="active here, no directory account",
        )

    if not active and not entry.disabled:
        return Drift(
            kind=DriftKind.SHOULD_BE_DISABLED,
            person_uuid=person_uuid,
            login=login,
            detail=f"status {status} here, enabled in the directory",
        )
    return None


@dataclass
class _Scan:
    drifts: list[Drift] = field(default_factory=list)
    scanned: int = 0


class Reconciler:
    """Compares the registry to the directory, and closes what it safely can."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        client: Any,
        target: Any,
    ) -> None:
        self._sessions = session_factory
        self._client = client
        self._target = target

    async def run(self, *, apply: bool = False, limit: int = 5000) -> Report:
        """Compare, and remediate only if asked.

        `apply` defaults to False because a reconciliation that fixes things by
        default is one nobody dares run. The report is the product; the fixing
        is what an operator does after reading it.
        """
        report = await self.compare(limit=limit)
        if not apply:
            return report
        return await self.remediate(report)

    async def compare(self, *, limit: int = 5000) -> Report:
        """Walk every person and ask the directory about each.

        Separate from `remediate` so an operator tool can compare once, put the
        report in front of somebody, and act on it afterwards — which is the
        workflow the dry-run default is there to support.
        """
        scan = await self._scan(limit=limit)
        log.info(
            "reconciliation.reported",
            scanned=scan.scanned,
            drifts=len(scan.drifts),
            applied=False,
        )
        return Report(drifts=tuple(scan.drifts), scanned=scan.scanned)

    async def remediate(self, report: Report) -> Report:
        """Close what this job is willing to close, and say what it did not.

        Takes a report rather than re-comparing, so what gets fixed is what
        somebody read. Re-comparing here would mean the thing acted on is not
        the thing approved.
        """
        remediated: list[Drift] = []
        failed: list[Drift] = []
        for drift in report.drifts:
            if not drift.remediable:
                continue
            if await self._remediate(drift):
                remediated.append(drift)
            else:
                failed.append(drift)

        log.info(
            "reconciliation.applied",
            scanned=report.scanned,
            drifts=len(report.drifts),
            remediated=len(remediated),
            failed=len(failed),
        )
        return Report(
            drifts=report.drifts,
            remediated=tuple(remediated),
            failed=tuple(failed),
            applied=True,
            scanned=report.scanned,
        )

    # --- comparing --------------------------------------------------------

    async def _scan(self, *, limit: int) -> _Scan:
        scan = _Scan()

        async with self._sessions() as session:
            people = list(
                await session.scalars(select(Person).order_by(Person.created_at).limit(limit))
            )
            logins = await self._logins(session, [person.person_uuid for person in people])

        for person in people:
            scan.scanned += 1
            login = logins.get(person.person_uuid)
            if login is None:
                # Nothing downstream can be addressed without one. Not drift:
                # there is no account we could be disagreeing about.
                continue
            drift = await self._compare_one(person, login)
            if drift is not None:
                scan.drifts.append(drift)

        return scan

    async def _compare_one(self, person: Person, login: str) -> Drift | None:
        try:
            entry = await self._client.find_user(login)
        except DirectoryUnavailable as exc:
            # An absence of evidence rather than a finding. Recording it as
            # clean would let a run during an outage read as a bill of health.
            return Drift(
                kind=DriftKind.UNREACHABLE,
                person_uuid=str(person.person_uuid),
                login=login,
                detail=str(exc),
            )

        return classify(
            person_uuid=str(person.person_uuid),
            login=login,
            status=person.status,
            entry=entry,
        )

    async def _logins(self, session: AsyncSession, people: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        """The principal name each person is known by downstream.

        Released ones count. A leaver's ePPN is tombstoned the moment they are
        deprovisioned, and this job exists precisely to check what happened to
        *them* — looking only at live identifiers would make the population it
        cares about invisible to it.
        """
        if not people:
            return {}

        rows = await session.scalars(
            select(Identifier).where(
                Identifier.person_uuid.in_(people), Identifier.id_type == ID_EPPN
            )
        )
        best: dict[uuid.UUID, Identifier] = {}
        for row in rows:
            current = best.get(row.person_uuid)
            if current is None or (current.released_at is not None and row.released_at is None):
                best[row.person_uuid] = row
        return {person: row.value for person, row in best.items()}

    # --- remediating ------------------------------------------------------

    async def _remediate(self, drift: Drift) -> bool:
        """Close one drift with the ordinary write.

        The same disable the leaver path uses, so this inherits its retries, its
        idempotency and its dead letter. A reconciler with its own writes would
        be a second provisioning implementation that only runs when something is
        already wrong.
        """
        assert drift.login is not None
        try:
            await self._target.disable(drift.login)
        except Exception as exc:
            log.warning("reconciliation.remediation_failed", login=drift.login, error=str(exc))
            return False
        log.info("reconciliation.remediated", login=drift.login, kind=drift.kind.value)
        return True
