"""Deprovisioning, in order (FR-LC-03).

The requirement fixes a sequence — disable the account, terminate every session,
revoke every refresh token, revoke the entitlements — and the order is the whole
point. Read backwards it is obvious: revoking entitlements first while a live
session still holds an access token means the person goes on working for as long
as that token lasts, and the audit trail says they were deprovisioned.

So these tests assert the order, not just the outcome. A run that does all four
things in the wrong sequence passes an outcome test and fails these, which is
the right way round.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from campusid.audit.events import EventType
from campusid.lifecycle.orchestrator import (
    DEPROVISION_ORDER,
    DISABLE_ACCOUNTS,
    REVOKE_ENTITLEMENTS,
    REVOKE_TOKENS,
    TERMINATE_SESSIONS,
    LifecycleOrchestrator,
)
from campusid.lifecycle.rules import LifecycleRules, load_rules
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
LMS = "urn:mace:campus.edu:entitlement:lms:access"
TODAY = date(2026, 6, 30)


@pytest.fixture(scope="module")
def rules() -> LifecycleRules:
    from pathlib import Path

    return load_rules(Path(__file__).resolve().parents[2] / "config" / "lifecycle_rules.yaml")


class _Rules:
    def __init__(self, rules: LifecycleRules) -> None:
        self.current = rules


class _Trace:
    """Every collaborator writes here, so the order between them is visible.

    One list rather than a call count per stub: what is being tested is the
    sequence, and three separate counters cannot express it.
    """

    def __init__(self) -> None:
        self.steps: list[str] = []


class _Sessions:
    def __init__(self, trace: _Trace, sids: list[str]) -> None:
        self._trace = trace
        self._sids = sids

    async def terminate_subject(self, subject_key: str) -> list[str]:
        self._trace.steps.append(f"sessions:{subject_key}")
        return self._sids


class _Grants:
    def __init__(self, trace: _Trace) -> None:
        self._trace = trace

    async def revoke_session_families(self, sid: str) -> list[str]:
        self._trace.steps.append(f"tokens:{sid}")
        return ["family-1"]


class _Lifecycle:
    def __init__(self, trace: _Trace) -> None:
        self._trace = trace
        self.applied: list[Any] = []

    async def apply(self, person_uuid: Any, delta: Any, **kwargs: Any) -> None:
        self._trace.steps.append("entitlements")
        self.applied.append((delta, kwargs))


class _Target:
    def __init__(self, trace: _Trace, name: str) -> None:
        self._trace = trace
        self.name = name

    async def disable(self, person_uuid: str) -> None:
        self._trace.steps.append(f"disable:{self.name}")


@pytest.fixture
def trace() -> _Trace:
    return _Trace()


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


def _orchestrator(
    trace: _Trace,
    rules: LifecycleRules,
    audit: RecordingAuditLog,
    *,
    sids: list[str] | None = None,
    targets: tuple[Any, ...] = (),
) -> LifecycleOrchestrator:
    return LifecycleOrchestrator(
        rules=_Rules(rules),
        lifecycle=_Lifecycle(trace),  # type: ignore[arg-type]
        sessions=_Sessions(trace, sids if sids is not None else []),
        grants=_Grants(trace),
        audit=audit,
        targets=targets,
    )


# --- the order --------------------------------------------------------------


async def test_the_steps_happen_in_the_order_the_requirement_gives(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    orchestrator = _orchestrator(
        trace, rules, audit, sids=["sid-1"], targets=(_Target(trace, "ldap"),)
    )

    await orchestrator.deprovision(PERSON, {"student"}, on=TODAY)

    assert trace.steps == [
        "disable:ldap",
        f"sessions:{PERSON}",
        "tokens:sid-1",
        "entitlements",
    ]


async def test_entitlements_are_revoked_last(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """Revoking them first while a live session still holds an access token
    would let the person go on working while the trail said otherwise."""
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1"])

    await orchestrator.deprovision(PERSON, {"staff"}, on=TODAY)

    assert trace.steps[-1] == "entitlements"


async def test_every_session_of_the_person_is_ended(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """By person, not by identifier. Somebody who logged in through two IdPs has
    two sessions and one subject, and ending half of them is the failure this
    sequence exists to prevent."""
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1", "sid-2", "sid-3"])

    await orchestrator.deprovision(PERSON, {"student"}, on=TODAY)

    assert trace.steps.count("tokens:sid-1") == 1
    assert [step for step in trace.steps if step.startswith("tokens:")] == [
        "tokens:sid-1",
        "tokens:sid-2",
        "tokens:sid-3",
    ]


async def test_each_step_is_audited_as_it_completes(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """So a run that fails halfway shows which step it reached, rather than
    simply being absent from the trail."""
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1"])

    await orchestrator.deprovision(PERSON, {"student"}, on=TODAY)

    steps = [
        event.detail["step"]
        for event in audit.events
        if event.event_type is EventType.DEPROVISION_STEP
    ]
    assert steps == list(DEPROVISION_ORDER)


async def test_the_disable_step_is_recorded_even_with_no_targets(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """An empty step and a missing step read very differently a year later, and
    the difference is the question "did we ever disable the directory account?"."""
    orchestrator = _orchestrator(trace, rules, audit)

    await orchestrator.deprovision(PERSON, {"student"}, on=TODAY)

    disable = next(
        event
        for event in audit.events
        if event.event_type is EventType.DEPROVISION_STEP
        and event.detail["step"] == DISABLE_ACCOUNTS
    )
    assert disable.detail["targets"] == []


async def test_a_leaver_event_summarises_the_run(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1", "sid-2"])

    await orchestrator.deprovision(PERSON, {"student"}, on=TODAY)

    leaver = next(event for event in audit.events if event.event_type is EventType.LIFECYCLE_LEAVER)
    assert leaver.subject == PERSON
    assert leaver.detail["sessions_terminated"] == 2
    # Named `families_revoked` rather than anything containing "token": the
    # audit redactor keys on shapes of secret, and a count is not worth
    # weakening it for.
    assert leaver.detail["families_revoked"] == 2


# --- routing ----------------------------------------------------------------


async def test_losing_the_last_affiliation_is_a_leaver(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """ "The SIS removed their last affiliation" and "the SIS set active to
    false" are the same event downstream, so which field changed must not decide
    whether sessions get terminated."""
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1"])

    await orchestrator.transitioned(PERSON, {"student"}, set(), on=TODAY)

    assert trace.steps[0] == f"sessions:{PERSON}"
    assert any(event.event_type is EventType.LIFECYCLE_LEAVER for event in audit.events)


async def test_a_joiner_terminates_nothing(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1"])

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert trace.steps == ["entitlements"]
    assert any(event.event_type is EventType.LIFECYCLE_JOINER for event in audit.events)


async def test_a_mover_keeps_their_sessions(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """A role change is not a termination. Ending somebody's sessions because
    they took a second job is a support ticket, not security."""
    orchestrator = _orchestrator(trace, rules, audit, sids=["sid-1"])

    await orchestrator.transitioned(PERSON, {"student"}, {"student", "staff"}, on=TODAY)

    assert not [step for step in trace.steps if step.startswith("sessions:")]
    assert any(event.event_type is EventType.LIFECYCLE_MOVER for event in audit.events)


# --- what the trail says about entitlements ---------------------------------


async def test_each_entitlement_is_audited_by_name(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """ "When did they get it" is asked about one grant, and a single event
    carrying a list makes that a search through JSON rather than a filter."""
    orchestrator = _orchestrator(trace, rules, audit)

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    granted = {
        event.target for event in audit.events if event.event_type is EventType.ENTITLEMENT_GRANTED
    }
    assert LMS in granted


async def test_a_revocation_records_when_it_takes_effect(
    trace: _Trace, rules: LifecycleRules, audit: RecordingAuditLog
) -> None:
    """The grace period is on the record, so "why does this person still have
    LMS access" has an answer that is not "nobody knows"."""
    orchestrator = _orchestrator(trace, rules, audit)

    await orchestrator.transitioned(PERSON, {"student"}, {"alum"}, on=TODAY)

    revoked = next(
        event
        for event in audit.events
        if event.event_type is EventType.ENTITLEMENT_REVOKED and event.target == LMS
    )
    assert revoked.detail["grace_days"] == 30
    assert revoked.detail["effective"] == "2026-07-30"


def test_the_documented_order_matches_the_requirement() -> None:
    """Pinned as data so a reordering is a visible edit rather than a moved
    statement somebody has to notice in a diff."""
    assert DEPROVISION_ORDER == (
        DISABLE_ACCOUNTS,
        TERMINATE_SESSIONS,
        REVOKE_TOKENS,
        REVOKE_ENTITLEMENTS,
    )
