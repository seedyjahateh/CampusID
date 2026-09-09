"""Joiner, mover and leaver (FR-LC-01, FR-LC-02, FR-LC-03).

What actually happens when somebody's relationship to the institution changes.
The rules decide *what* changes and the store writes it down; this decides in
what order the consequences are applied, and the order is the requirement.

**Deprovisioning is ordered, and the order is not arbitrary.** FR-LC-03 fixes
it: disable the account, terminate every session, revoke every refresh token,
then revoke the entitlements. Read backwards it is obvious — revoking
entitlements first while a live session still holds an access token means the
person keeps working for as long as that token lasts, and the audit trail says
they were deprovisioned. Each step is recorded as it completes, so a run that
fails halfway shows which step it reached instead of simply being absent.

**Sessions are terminated by person, not by identifier.** That is why the session
store is keyed on `person_uuid`: somebody who logged in through two IdPs has two
subjects under the older key, and ending half of them is the failure this whole
sequence exists to prevent.

**A downstream target is a step with nobody in it yet.** LDAP and the portal are
M4; the slot is here, ordered first, because putting it in later would mean
re-deciding an order that is already the requirement. Until then the step
records that it had nothing to do rather than being silently skipped — an empty
step and a missing step read very differently a year later.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import date
from typing import Any, Protocol

from campusid.audit.events import EventType, Outcome
from campusid.lifecycle.rules import Delta, LifecycleRules
from campusid.lifecycle.store import LEAVER, LifecycleStore, event_type
from campusid.logging import get_logger

log = get_logger(__name__)

DISABLE_ACCOUNTS = "disable_accounts"
TERMINATE_SESSIONS = "terminate_sessions"
REVOKE_TOKENS = "revoke_tokens"
REVOKE_ENTITLEMENTS = "revoke_entitlements"

DEPROVISION_ORDER: tuple[str, ...] = (
    DISABLE_ACCOUNTS,
    TERMINATE_SESSIONS,
    REVOKE_TOKENS,
    REVOKE_ENTITLEMENTS,
)
"""FR-LC-03's sequence, written down so a test can assert it rather than infer
it from the order of statements in a function."""

EVENT_FOR = {
    "joiner": EventType.LIFECYCLE_JOINER,
    "mover": EventType.LIFECYCLE_MOVER,
    "leaver": EventType.LIFECYCLE_LEAVER,
}


class ProvisioningTarget(Protocol):
    """A downstream system a person's account exists in.

    Named as a protocol now, with no implementations, because the *order* it
    occupies in a deprovisioning is a requirement and deciding it later would
    mean re-deciding it. LDAP and the campus portal arrive in M4.
    """

    name: str

    async def disable(self, person_uuid: str) -> None: ...


class LifecycleOrchestrator:
    """Applies a transition and everything that follows from it."""

    def __init__(
        self,
        *,
        rules: Any,
        lifecycle: LifecycleStore,
        sessions: Any,
        grants: Any,
        audit: Any,
        targets: Sequence[ProvisioningTarget] = (),
    ) -> None:
        self._rules = rules
        self._lifecycle = lifecycle
        self._sessions = sessions
        self._grants = grants
        self._audit = audit
        self._targets = tuple(targets)

    # --- joiner and mover -------------------------------------------------

    async def transitioned(
        self,
        person_uuid: str,
        before: set[str],
        after: set[str],
        *,
        source: str = "scim",
        on: date | None = None,
    ) -> Delta:
        """Apply an affiliation change (FR-LC-01, FR-LC-02).

        A transition to no affiliations at all is a leaver and is routed as one,
        because "the SIS removed their last affiliation" and "the SIS set active
        to false" are the same event to everybody downstream and should not
        depend on which field the SIS happened to change.
        """
        if after == set() and before:
            return await self.deprovision(person_uuid, before, source=source, on=on)

        rules: LifecycleRules = self._current_rules()
        delta = rules.transition(before, after, on=on)
        await self._lifecycle.apply(
            uuid.UUID(person_uuid), delta, before=before, after=after, source=source
        )
        await self._record_delta(person_uuid, before, after, delta, source)
        return delta

    # --- leaver -----------------------------------------------------------

    async def deprovision(
        self,
        person_uuid: str,
        before: set[str],
        *,
        source: str = "scim",
        on: date | None = None,
    ) -> Delta:
        """FR-LC-03, in the order the requirement gives.

        Returns the delta so a caller can report what was taken away, but the
        return value is not the point — the point is that by the time it returns
        the person cannot reach anything, and the trail says in what order they
        stopped being able to.
        """
        rules: LifecycleRules = self._current_rules()
        delta = rules.transition(before, set(), on=on)

        # 1. The account in every downstream system. First, because a directory
        #    that still authenticates is a way back in that revoking our own
        #    tokens does nothing about.
        disabled = await self._disable_accounts(person_uuid)

        # 2. Every session, by person. The store is keyed on `person_uuid`
        #    precisely so this means every session rather than every session
        #    from one IdP.
        sids = await self._sessions.terminate_subject(person_uuid)
        await self._step(person_uuid, TERMINATE_SESSIONS, {"sessions": len(sids)})

        # 3. Every refresh token those sessions produced. Destroying a session
        #    stops `/userinfo`; it does not stop a refresh token rotating
        #    happily against a session that no longer exists.
        families = 0
        for sid in sids:
            families += len(await self._grants.revoke_session_families(sid))
        await self._step(person_uuid, REVOKE_TOKENS, {"families": families})

        # 4. The entitlements, last. Doing this first while a live session still
        #    held an access token would let the person go on working while the
        #    trail said they were deprovisioned.
        await self._lifecycle.apply(
            uuid.UUID(person_uuid), delta, before=before, after=set(), source=source
        )
        await self._step(
            person_uuid,
            REVOKE_ENTITLEMENTS,
            {"immediate": len(delta.immediate), "deferred": len(delta.deferred)},
        )

        await self._audit.record(
            EventType.LIFECYCLE_LEAVER,
            Outcome.SUCCESS,
            subject=person_uuid,
            detail={
                "affiliations_ended": sorted(before),
                "sessions_terminated": len(sids),
                # Named without the word the redactor keys on. It is a count,
                # not a credential, but the redactor is deliberately about
                # *shapes of secret* rather than exact names and weakening it to
                # let one count through would be the wrong trade.
                "families_revoked": families,
                "targets_disabled": disabled,
            },
        )
        log.info(
            "lifecycle.deprovisioned",
            person_uuid=person_uuid,
            sessions=len(sids),
            families=families,
        )
        return delta

    # --- helpers ----------------------------------------------------------

    def _current_rules(self) -> LifecycleRules:
        """The rules as of now, so an edit takes effect without a restart."""
        current: LifecycleRules = self._rules.current
        return current

    async def _disable_accounts(self, person_uuid: str) -> list[str]:
        """Step one, which currently has nothing to do.

        Recorded anyway. An empty step and a missing step read very differently
        a year later, and the difference is exactly the question "did we ever
        disable the directory account?".
        """
        disabled: list[str] = []
        for target in self._targets:
            await target.disable(person_uuid)
            disabled.append(target.name)
        await self._step(person_uuid, DISABLE_ACCOUNTS, {"targets": disabled})
        return disabled

    async def _step(self, person_uuid: str, step: str, detail: dict[str, Any]) -> None:
        await self._audit.record(
            EventType.DEPROVISION_STEP,
            Outcome.SUCCESS,
            subject=person_uuid,
            detail={"step": step, **detail},
        )

    async def _record_delta(
        self,
        person_uuid: str,
        before: set[str],
        after: set[str],
        delta: Delta,
        source: str,
    ) -> None:
        """One event per entitlement, plus one for the transition itself.

        Per entitlement because "when did they get it" is the question an access
        review asks about one grant, and a single event carrying a list makes
        that a search through JSON rather than a filter.
        """
        for grant in delta.granted:
            await self._audit.record(
                EventType.ENTITLEMENT_GRANTED,
                Outcome.SUCCESS,
                subject=person_uuid,
                target=grant.urn,
                detail={"rule": grant.rule_id, "affiliation": grant.affiliation},
            )
        for revocation in delta.revoked:
            await self._audit.record(
                EventType.ENTITLEMENT_REVOKED,
                Outcome.SUCCESS,
                subject=person_uuid,
                target=revocation.urn,
                detail={
                    "effective": revocation.effective.isoformat(),
                    "grace_days": revocation.grace_days,
                },
            )

        kind = event_type(before, after)
        await self._audit.record(
            EVENT_FOR.get(kind, EventType.LIFECYCLE_MOVER),
            Outcome.SUCCESS,
            subject=person_uuid,
            detail={
                "source": source,
                "before": sorted(before),
                "after": sorted(after),
                "granted": [grant.urn for grant in delta.granted],
                "revoked": [revocation.urn for revocation in delta.revoked],
            },
        )
        if kind == LEAVER:  # pragma: no cover - routed to deprovision above
            log.warning("lifecycle.leaver_not_deprovisioned", person_uuid=person_uuid)
