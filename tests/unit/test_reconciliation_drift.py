"""Deciding what two records disagree about (FR-LC-07).

The judgement inside a reconciliation, separated from the walk that feeds it.
Four states, and the pair that looks alike is the pair that matters: a
deactivated person with no directory account is two systems agreeing that
somebody has gone, while an *active* person with no account is a provisioning
gap. A classifier that treated "no entry" as one case would report every
successful deprovisioning as drift, and a nightly report full of false findings
is a report nobody reads.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from campusid.lifecycle.reconciliation import (
    Drift,
    DriftKind,
    Reconciler,
    Report,
    classify,
)

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
LOGIN = "sam.obrien@campus.test"


@dataclass
class _Entry:
    disabled: bool = False


def _classify(status: str, entry: _Entry | None) -> Drift | None:
    return classify(person_uuid=PERSON, login=LOGIN, status=status, entry=entry)


# --- the four states --------------------------------------------------------


def test_active_here_and_enabled_there_is_agreement() -> None:
    assert _classify("active", _Entry(disabled=False)) is None


def test_deactivated_here_and_disabled_there_is_agreement() -> None:
    """The state a successful deprovisioning leaves behind, and the one a
    classifier must not report every night."""
    assert _classify("deactivated", _Entry(disabled=True)) is None


def test_deactivated_here_and_enabled_there_is_the_security_finding() -> None:
    """Somebody re-enabled the account by hand, or a restore undid the write.
    The broker says this person has left; the directory still lets them in."""
    drift = _classify("deactivated", _Entry(disabled=False))

    assert drift is not None
    assert drift.kind is DriftKind.SHOULD_BE_DISABLED
    assert drift.remediable


def test_active_here_and_absent_there_is_a_provisioning_gap() -> None:
    """Usually somebody created just-in-time by a federated login. Creating an
    account is a decision with a password policy attached."""
    drift = _classify("active", None)

    assert drift is not None
    assert drift.kind is DriftKind.MISSING_DOWNSTREAM
    assert not drift.remediable


def test_deactivated_here_and_absent_there_is_agreement() -> None:
    """The pair that looks like the one above and is not. Reporting it would
    make every person who ever left a permanent finding."""
    assert _classify("deactivated", None) is None


@pytest.mark.parametrize("status", ["suspended", "deactivated", "archived"])
def test_every_non_active_status_expects_a_disabled_account(status: str) -> None:
    """The registry has four statuses and only one of them means somebody may
    still log in. A classifier that checked for `deactivated` alone would miss
    the suspended, who are the ones under investigation."""
    drift = _classify(status, _Entry(disabled=False))

    assert drift is not None
    assert drift.kind is DriftKind.SHOULD_BE_DISABLED
    assert status in drift.detail


def test_the_drift_names_the_login_a_remediation_would_use() -> None:
    drift = _classify("deactivated", _Entry(disabled=False))

    assert drift is not None
    assert drift.login == LOGIN
    assert drift.person_uuid == PERSON


# --- what is remediable -----------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (DriftKind.SHOULD_BE_DISABLED, True),
        (DriftKind.MISSING_DOWNSTREAM, False),
        (DriftKind.ORPHANED, False),
        (DriftKind.UNREACHABLE, False),
    ],
)
def test_only_disabling_is_done_automatically(kind: DriftKind, expected: bool) -> None:
    """An orphan might be a service account, a contractor somebody else
    provisioned, or the only administrator account on the box. Disabling it
    automatically is how a reconciliation job takes down a campus."""
    assert Drift(kind=kind, person_uuid=PERSON, login=LOGIN).remediable is expected


# --- the report -------------------------------------------------------------


def test_a_report_groups_by_kind() -> None:
    """What an operator does about each is different, and a report they have to
    read prose to triage is a report they stop running."""
    report = Report(
        drifts=(
            Drift(kind=DriftKind.SHOULD_BE_DISABLED, person_uuid=PERSON, login=LOGIN),
            Drift(kind=DriftKind.MISSING_DOWNSTREAM, person_uuid="other", login="o@campus.test"),
        ),
        scanned=2,
    )

    assert len(report.of_kind(DriftKind.SHOULD_BE_DISABLED)) == 1
    assert len(report.of_kind(DriftKind.ORPHANED)) == 0


def test_a_dry_run_says_so_on_the_report() -> None:
    """So a reader cannot mistake a list of findings for a list of fixes."""
    assert not Report(drifts=(), scanned=3).applied


def test_an_unreachable_entry_is_not_a_clean_result() -> None:
    """A run that could not ask is not a run that found nothing, and a job whose
    outage looks like a bill of health is worse than no job."""
    report = Report(
        drifts=(Drift(kind=DriftKind.UNREACHABLE, person_uuid=PERSON, login=LOGIN),),
        scanned=1,
    )

    assert not report.clean


def test_agreement_is_a_clean_result() -> None:
    assert Report(drifts=(), scanned=10).clean


# --- remediating a report ---------------------------------------------------


class _Target:
    def __init__(self, *, failing: bool = False) -> None:
        self.disabled: list[str] = []
        self._failing = failing

    async def disable(self, login: str) -> None:
        if self._failing:
            raise ConnectionError("directory unreachable")
        self.disabled.append(login)


def _reconciler(target: _Target) -> Reconciler:
    # No session factory is needed: remediating acts on a report rather than
    # re-reading the registry, which is the point of the split.
    return Reconciler(None, client=None, target=target)  # type: ignore[arg-type]


def _report(*kinds: DriftKind) -> Report:
    return Report(
        drifts=tuple(
            Drift(kind=kind, person_uuid=PERSON, login=f"{index}@campus.test")
            for index, kind in enumerate(kinds)
        ),
        scanned=len(kinds),
    )


async def test_remediating_closes_only_what_it_should() -> None:
    target = _Target()

    result = await _reconciler(target).remediate(
        _report(DriftKind.SHOULD_BE_DISABLED, DriftKind.MISSING_DOWNSTREAM, DriftKind.ORPHANED)
    )

    assert target.disabled == ["0@campus.test"]
    assert len(result.remediated) == 1
    assert result.applied


async def test_a_remediation_that_fails_is_reported_not_hidden() -> None:
    """A job that reported success for a disable that did not happen is worse
    than one that reported nothing."""
    target = _Target(failing=True)

    result = await _reconciler(target).remediate(_report(DriftKind.SHOULD_BE_DISABLED))

    assert result.remediated == ()
    assert len(result.failed) == 1


async def test_the_findings_survive_remediation() -> None:
    """The report still says what was wrong, not only what was fixed —
    otherwise "we found nothing" and "we fixed everything" look identical
    afterwards."""
    result = await _reconciler(_Target()).remediate(_report(DriftKind.SHOULD_BE_DISABLED))

    assert len(result.drifts) == 1
    assert result.scanned == 1


async def test_remediating_acts_on_the_report_it_was_given() -> None:
    """Rather than re-comparing. Re-comparing would mean the thing acted on is
    not the thing somebody approved."""
    target = _Target()

    await _reconciler(target).remediate(_report())

    assert target.disabled == []
