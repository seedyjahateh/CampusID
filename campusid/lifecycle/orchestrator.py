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
from campusid.lifecycle.retry import RetriesExhausted, with_retries
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

    Addressed by login rather than by `person_uuid`, because no downstream
    system has heard of ours. Resolving the two is this module's job: it is the
    half of the problem that needs the identity registry, and a target that had
    to reach for one would be a target coupled to our storage.
    """

    name: str

    async def disable(self, login: str) -> None: ...


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
        identity: Any = None,
        dead_letters: Any = None,
        transient: type[Exception] | tuple[type[Exception], ...] = Exception,
        retry_sleep: Any = None,
        decisions: Any = None,
    ) -> None:
        self._rules = rules
        self._lifecycle = lifecycle
        self._sessions = sessions
        self._grants = grants
        self._audit = audit
        self._targets = tuple(targets)
        self._identity = identity
        self._dead_letters = dead_letters
        self._transient = transient
        """What is worth retrying. Narrowed by the caller, because a directory
        refusing a write it will refuse identically five times buys nothing but
        five multiples of the backoff before the same dead letter."""

        self._retry_sleep = retry_sleep
        """Injected so a test can exercise the retry path without waiting out
        thirty seconds of backoff to prove it."""

        self._decisions = decisions
        """The authorization decision cache, told when a transition changes what
        somebody is entitled to (FR-AZ-08). Without it, a deprovisioning would
        take up to a minute to reach whatever is enforcing access."""

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
        await self._invalidate_decisions(person_uuid)
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

        # 5. Every authorization decision cached about them. Steps 1-4 change
        #    what the answer would be; this is what stops the old answer being
        #    served for the rest of the caching window (FR-AZ-08).
        await self._invalidate_decisions(person_uuid)

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

    async def _invalidate_decisions(self, person_uuid: str) -> None:
        """Unmake every authorization decision cached about this person.

        Entitlements are the input to those decisions, so a transition that does
        not say so leaves a permit readable for the rest of the caching window —
        which is the whole of the delay between deprovisioning somebody and the
        thing enforcing access noticing.

        Optional because most of the lifecycle tests have no Redis and should not
        need one to assert what the lifecycle does.
        """
        if self._decisions is None:
            return
        await self._decisions.invalidate(person_uuid)

    def _current_rules(self) -> LifecycleRules:
        """The rules as of now, so an edit takes effect without a restart."""
        current: LifecycleRules = self._rules.current
        return current

    async def _disable_accounts(self, person_uuid: str) -> list[str]:
        """Step one: the account in every downstream system.

        Recorded even when there are no targets. An empty step and a missing
        step read very differently a year later, and the difference is exactly
        the question "did we ever disable the directory account?".

        A failure here is not swallowed. The retry and dead-letter machinery
        exists for an unreachable downstream, and a step that absorbed the error
        would leave an enabled account behind with a trail saying it was
        disabled — which is worse than a visible failure by the whole width of
        the audit trail.
        """
        if not self._targets:
            await self._step(person_uuid, DISABLE_ACCOUNTS, {"targets": []})
            return []

        login = await self._login_for(person_uuid)
        if login is None:
            # Nothing downstream can be addressed without one, and inventing a
            # login to try would be guessing at somebody else's namespace.
            log.warning("lifecycle.no_login_for_targets", person_uuid=person_uuid)
            await self._step(person_uuid, DISABLE_ACCOUNTS, {"targets": [], "reason": "no login"})
            return []

        disabled: list[str] = []
        failed: list[str] = []
        for target in self._targets:
            if await self._disable_one(target, person_uuid, login):
                disabled.append(target.name)
            else:
                failed.append(target.name)

        await self._step(
            person_uuid,
            DISABLE_ACCOUNTS,
            {"targets": disabled, "dead_lettered": failed} if failed else {"targets": disabled},
        )
        return disabled

    async def _disable_one(self, target: ProvisioningTarget, person_uuid: str, login: str) -> bool:
        """One target, retried and then dead-lettered (FR-LC-09).

        A failure here does not stop the sequence, and that is the deliberate
        part. The remaining steps — terminating sessions, revoking tokens,
        ending entitlements — are ours to do and they still reduce what the
        person can reach. Abandoning them because a directory was unreachable
        would leave somebody with live sessions *and* an enabled account, which
        is strictly worse than one of the two.

        Without a queue to file it in, the failure propagates: dropping it would
        leave an enabled account with a trail saying it was disabled, and that is
        worse than a visible failure by the whole width of the audit trail.
        """
        try:
            await with_retries(
                lambda: target.disable(login),
                retry_on=self._transient,
                sleep=self._retry_sleep,
                description=f"{target.name}.disable",
            )
            return True
        except RetriesExhausted as exc:
            if self._dead_letters is None:
                raise
            await self._dead_letters.record(
                person_uuid=person_uuid,
                target=target.name,
                operation="disable",
                # The login is carried because by the time somebody replays
                # this, the person's identifiers may have been released and the
                # registry would no longer volunteer one.
                payload={"login": login},
                attempts=exc.attempts,
            )
            await self._audit.record(
                EventType.DEPROVISION_STEP,
                Outcome.FAILURE,
                subject=person_uuid,
                detail={
                    "step": DISABLE_ACCOUNTS,
                    "target": target.name,
                    "attempts": len(exc.attempts),
                },
            )
            return False

    async def _login_for(self, person_uuid: str) -> str | None:
        """The principal name a downstream system knows this person by.

        The live ePPN when there is one, and the tombstoned one when there is
        not — which is the ordinary case for a leaver, because provisioning
        releases a person's identifiers before this runs. Using a released value
        is safe here and nowhere else: FR-LC-08 guarantees an ePPN is never
        reassigned, so the tombstone still names exactly one person. Without the
        fallback, a SCIM delete would leave the directory account enabled and
        the trail would say the step ran with nothing to do.
        """
        if self._identity is None:
            return None

        identifiers = await self._identity.identifiers(person_uuid, include_released=True)
        eppns = [identifier for identifier in identifiers if identifier.id_type == "eppn"]
        live = [identifier for identifier in eppns if identifier.released_at is None]
        for candidate in (live, eppns):
            if candidate:
                value: str = candidate[0].value
                return value
        return None

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
