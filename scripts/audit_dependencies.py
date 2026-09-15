"""Fail the build on a vulnerable dependency (NFR-SEC-08).

    python scripts/audit_dependencies.py requirements.lock requirements-dev.lock

Runs `pip-audit` against the hash-pinned locks and exits non-zero on any
advisory that is not covered by a live entry in `security/dependency-exceptions.yaml`.

**The dating is the mechanism, not the paperwork.** Every exception carries a
`review_by`, and this refuses to run once one has passed — so an exception taken
in a hurry expires into a build failure rather than into permanent silence. The
failure mode this is built against is the suppression that outlives the reason
for it, which is how a dependency audit becomes a list of things nobody reads.

**It fails on every advisory, not only CVSS >= 7.0.** The requirement sets that
threshold and this is stricter, because the score is about a vulnerability in the
abstract and says nothing about how this project uses the library. A medium in a
parser we hand attacker-controlled XML to is worse than a critical in a code path
we never call, and the exception file is where that judgement is written down and
signed. Filtering by score first would throw away the medium before anybody
looked at it.

**The locks, not the environment.** Auditing installed packages audits whatever
the runner happens to have, which on a cached CI image is not what the next build
will install.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "security" / "dependency-exceptions.yaml"

REQUIRED = ("id", "package", "opened", "review_by", "reason")


@dataclass(frozen=True, slots=True)
class Exception_:
    """One suppressed advisory.

    Named with a trailing underscore rather than shadowing the builtin, which is
    ugly and less ugly than the alternative — a reader of the exception file
    calls these exceptions and the code should use the word they use.
    """

    id: str
    package: str
    opened: date
    review_by: date
    reason: str

    def expired(self, today: date) -> bool:
        return today > self.review_by


def parse(document: dict[str, Any]) -> list[Exception_]:
    """Read the exception file, refusing anything incomplete.

    A missing field is an error rather than a default. Every field here exists so
    that a person reading the file a year from now can decide whether the
    exception still holds, and one that silently defaulted would be the field
    they needed.
    """
    entries = document.get("exceptions") or []
    if not isinstance(entries, list):
        raise ValueError("`exceptions` must be a list")

    parsed = []
    for entry in entries:
        missing = [field for field in REQUIRED if not entry.get(field)]
        if missing:
            raise ValueError(f"exception {entry.get('id', '<unnamed>')} is missing: {missing}")
        parsed.append(
            Exception_(
                id=str(entry["id"]),
                package=str(entry["package"]),
                # Dates rather than strings: PyYAML parses an unquoted
                # YYYY-MM-DD into a `date`, and a quoted one into a string that
                # would compare as text and be wrong exactly once a year.
                opened=_as_date(entry["opened"], entry["id"], "opened"),
                review_by=_as_date(entry["review_by"], entry["id"], "review_by"),
                reason=str(entry["reason"]).strip(),
            )
        )
    return parsed


def _as_date(value: Any, identifier: str, field: str) -> date:
    if isinstance(value, date):
        return value
    raise ValueError(f"exception {identifier}: {field} must be a YYYY-MM-DD date, got {value!r}")


def expired(exceptions: list[Exception_], today: date) -> list[Exception_]:
    return [exception for exception in exceptions if exception.expired(today)]


def audit(locks: list[str], suppressed: list[Exception_]) -> int:
    """Run pip-audit and return its exit status."""
    command = ["pip-audit", "--strict", "--progress-spinner=off"]
    for lock in locks:
        command += ["--requirement", lock]
    for exception in suppressed:
        command += ["--ignore-vuln", exception.id]

    print(f"audit: {' '.join(command)}")
    # The argument list is built here from a fixed program name, paths given on
    # our own command line, and identifiers from a reviewed file in this
    # repository. No shell, so nothing in those strings can be a command.
    return subprocess.call(command)  # noqa: S603


def main(argv: list[str]) -> int:
    locks = argv[1:] or ["requirements.lock", "requirements-dev.lock"]
    today = date.today()

    document = yaml.safe_load(EXCEPTIONS.read_text(encoding="utf-8")) or {}
    exceptions = parse(document)

    stale = expired(exceptions, today)
    if stale:
        for exception in stale:
            print(
                f"audit: exception {exception.id} ({exception.package}) expired on "
                f"{exception.review_by}. Re-examine it and either fix the dependency "
                f"or take the exception again with a new date.",
                file=sys.stderr,
            )
        return 1

    for exception in exceptions:
        print(f"audit: ignoring {exception.id} ({exception.package}) until {exception.review_by}")

    return audit(locks, exceptions)


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main(sys.argv))
