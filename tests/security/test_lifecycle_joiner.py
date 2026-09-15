"""A joiner reaches the downstream directory (FR-LC-01, NFR-PROV-01).

The half of the provisioning chain that was missing. `DirectoryWriter.ensure_person`
existed, was tested, and was called by nothing in the application — so a person
arriving over SCIM was written to our own tables, granted entitlements, and never
reached the directory at all. NFR-PROV-01 measures "SCIM create → LDAP account
exists", and that chain had a missing link rather than a slow one.

Two rules are asserted here, and both are the leaver path read in a mirror:

**The account is created after our own tables.** Our state is authoritative and
the downstream account is a consequence of it. The leaver's downstream step goes
first because it is the one that reduces what a person can reach; the joiner's
goes last because it depends on state we own.

**A tombstoned identifier never creates an account.** The leaver path falls back
to a released ePPN, deliberately, because a downstream account has to be
disabled by whatever name it was created under. The joiner path must not: an
account created from a released identifier would undo the deprovisioning that
released it.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from campusid.directory.writes import PersonSpec
from campusid.lifecycle.orchestrator import (
    PROVISION_ACCOUNTS,
    LifecycleOrchestrator,
)
from campusid.lifecycle.retry import MAX_ATTEMPTS
from campusid.lifecycle.rules import LifecycleRules, load_rules
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
LOGIN = "sam.obrien@campus.test"
TODAY = date(2026, 9, 15)


@pytest.fixture(scope="module")
def rules() -> LifecycleRules:
    return load_rules(Path(__file__).resolve().parents[2] / "config" / "lifecycle_rules.yaml")


class _Rules:
    def __init__(self, rules: LifecycleRules) -> None:
        self.current = rules


class _Trace:
    def __init__(self) -> None:
        self.steps: list[str] = []


class _Lifecycle:
    def __init__(self, trace: _Trace) -> None:
        self._trace = trace

    async def apply(self, person_uuid: Any, delta: Any, **kwargs: Any) -> None:
        self._trace.steps.append("entitlements")


class _Target:
    name = "ldap"

    def __init__(self, trace: _Trace) -> None:
        self._trace = trace
        self.specs: list[PersonSpec] = []

    async def provision(self, spec: PersonSpec) -> None:
        self._trace.steps.append(f"provision:{self.name}")
        self.specs.append(spec)

    async def disable(self, login: str) -> None:  # pragma: no cover - leaver path
        self._trace.steps.append(f"disable:{self.name}")


class _Broken(_Target):
    async def provision(self, spec: PersonSpec) -> None:
        raise ConnectionError("directory unreachable")


class _Identifier:
    def __init__(self, value: str, *, id_type: str = "eppn", released: bool = False) -> None:
        self.id_type = id_type
        self.value = value
        self.is_primary = True
        self.released_at = object() if released else None


class _Person:
    given_name = "Samira"
    surname = "O'Brien"
    display_name = "Samira O'Brien"


class _Identity:
    def __init__(self, identifiers: list[_Identifier] | None = None) -> None:
        self._identifiers = identifiers if identifiers is not None else [_Identifier(LOGIN)]

    async def identifiers(
        self, person_uuid: str, *, include_released: bool = False
    ) -> list[_Identifier]:
        if include_released:
            return self._identifiers
        return [row for row in self._identifiers if row.released_at is None]

    async def get(self, person_uuid: str) -> _Person:
        return _Person()


class _Queue:
    def __init__(self) -> None:
        self.filed: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> str:
        self.filed.append(kwargs)
        return "item-1"


async def _nowait(seconds: float) -> None:
    """Backoff, skipped. Thirty seconds of real sleeping proves arithmetic."""


@pytest.fixture
def trace() -> _Trace:
    return _Trace()


def _orchestrator(
    trace: _Trace,
    rules: LifecycleRules,
    *,
    targets: tuple[Any, ...] = (),
    identity: Any = None,
    dead_letters: Any = None,
) -> LifecycleOrchestrator:
    return LifecycleOrchestrator(
        rules=_Rules(rules),
        lifecycle=_Lifecycle(trace),  # type: ignore[arg-type]
        sessions=object(),
        grants=object(),
        audit=RecordingAuditLog(),
        targets=targets,
        identity=identity if identity is not None else _Identity(),
        dead_letters=dead_letters,
        retry_sleep=_nowait,
    )


# --- the account is created --------------------------------------------------


async def test_a_joiner_reaches_the_directory(trace: _Trace, rules: LifecycleRules) -> None:
    target = _Target(trace)
    orchestrator = _orchestrator(trace, rules, targets=(target,))

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert [spec.principal_name for spec in target.specs] == [LOGIN]


async def test_the_account_is_created_after_our_own_tables(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """Our state is authoritative; the downstream account is a consequence.

    The opposite order would let an unreachable directory stop the broker
    recording who somebody is — and the retry would then have nothing to retry
    from, because the transition it is retrying was never written.

    This is the mirror of the leaver ordering rather than a copy of it. There the
    downstream step goes first, because it is the one that reduces what a person
    can reach.
    """
    orchestrator = _orchestrator(trace, rules, targets=(_Target(trace),))

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert trace.steps.index("provision:ldap") > trace.steps.index("entitlements")


async def test_the_spec_carries_what_a_directory_entry_needs(
    trace: _Trace, rules: LifecycleRules
) -> None:
    target = _Target(trace)
    orchestrator = _orchestrator(
        trace,
        rules,
        targets=(target,),
        identity=_Identity([_Identifier(LOGIN), _Identifier("sam@campus.test", id_type="mail")]),
    )

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    (spec,) = target.specs
    assert spec.uid == "sam.obrien", "the uid is the local part, not the scoped name"
    assert spec.surname == "O'Brien"
    assert spec.mail == "sam@campus.test"


async def test_a_person_with_no_surname_still_gets_an_entry(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """A directory requires `sn`. The fallback is the uid rather than a
    placeholder like "Unknown", which is a value somebody later searches for and
    finds forty of."""

    class _Nameless(_Identity):
        async def get(self, person_uuid: str) -> Any:
            return None

    target = _Target(trace)
    orchestrator = _orchestrator(trace, rules, targets=(target,), identity=_Nameless())

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert target.specs[0].surname == "sam.obrien"


# --- what must not happen ----------------------------------------------------


async def test_a_released_identifier_never_creates_an_account(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """The asymmetry with the leaver path, and the reason it is asymmetric.

    A leaver is disabled by whatever name their account was created under, so
    that path falls back to a tombstoned ePPN. Creating from one would undo the
    deprovisioning that released it.
    """
    target = _Target(trace)
    orchestrator = _orchestrator(
        trace,
        rules,
        targets=(target,),
        identity=_Identity([_Identifier(LOGIN, released=True)]),
    )

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert target.specs == []
    assert "provision:ldap" not in trace.steps


async def test_a_deployment_with_no_targets_still_records_the_step(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """An empty step and a missing step read very differently a year later."""
    audit = RecordingAuditLog()
    orchestrator = LifecycleOrchestrator(
        rules=_Rules(rules),
        lifecycle=_Lifecycle(trace),  # type: ignore[arg-type]
        sessions=object(),
        grants=object(),
        audit=audit,
        identity=_Identity(),
    )

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    steps = [event.detail.get("step") for event in audit.events]
    assert PROVISION_ACCOUNTS in steps


# --- when the directory is not there -----------------------------------------


async def test_an_unreachable_directory_is_retried_then_dead_lettered(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """The same machinery the leaver path uses (FR-LC-09).

    A step that absorbed the error would leave a person with entitlements and
    nowhere to use them, with a trail saying they were provisioned.
    """
    queue = _Queue()
    orchestrator = _orchestrator(trace, rules, targets=(_Broken(trace),), dead_letters=queue)

    await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)

    assert len(queue.filed) == 1
    assert queue.filed[0]["operation"] == "provision"
    assert len(queue.filed[0]["attempts"]) == MAX_ATTEMPTS


async def test_a_failure_with_nowhere_to_file_it_propagates(
    trace: _Trace, rules: LifecycleRules
) -> None:
    """Dropping it would leave a person provisioned in our tables and absent
    downstream, with nothing recording the difference."""
    orchestrator = _orchestrator(trace, rules, targets=(_Broken(trace),))

    with pytest.raises(Exception, match="attempts"):
        await orchestrator.transitioned(PERSON, set(), {"student"}, on=TODAY)
