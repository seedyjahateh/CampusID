"""The runbooks exist, are dated, and do not point at missing files (NFR-OPS-05).

Documentation rots differently from code: nothing fails when it does. A runbook
that references a script somebody renamed still reads perfectly and only breaks
when an operator follows it, which is the worst possible moment to discover it.

So this checks the two things a test can check without a human reading the prose:
that every required runbook is present, and that every relative link in the
documentation resolves to a file that exists.

**The `verified on` date is required and deliberately not checked for
freshness.** A test asserting the date is recent would be satisfied by somebody
editing the date, which is exactly the wrong incentive — it would convert "run
the procedure and confirm it works" into "change a line". The date is there for a
human to judge; requiring its presence is what makes the judgement possible.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs"
RUNBOOKS = DOCS / "runbooks"

REQUIRED = {
    "key-rotation.md": "NFR-SEC-06",
    "idp-onboarding.md": "NFR-OPS-05",
    "sp-onboarding.md": "NFR-OPS-05",
    "compromised-account.md": "NFR-OPS-05",
    "provisioning-backlog.md": "NFR-OPS-05",
    "drift-remediation.md": "NFR-OPS-05",
}
"""The six NFR-OPS-05 names, spelled out rather than globbed.

A glob would pass on an empty directory and on a directory somebody renamed a
file inside, which are the two failures worth catching.
"""

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
VERIFIED = re.compile(r"\*\*Verified on:\*\*\s+(\d{4}-\d{2}-\d{2})")


def _markdown() -> list[Path]:
    return sorted(DOCS.rglob("*.md"))


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_the_required_runbook_exists(name: str) -> None:
    assert (
        RUNBOOKS / name
    ).is_file(), f"{name} is named by {REQUIRED[name]} and is not in docs/runbooks/"


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_every_runbook_says_when_it_was_last_verified(name: str) -> None:
    """The date is when somebody last ran the steps, not when the file was
    edited. A runbook nobody has executed in a year is a document rather than a
    procedure, and the date is what makes that visible."""
    text = (RUNBOOKS / name).read_text(encoding="utf-8")

    assert VERIFIED.search(text), f"{name} carries no '**Verified on:** YYYY-MM-DD' line"


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_every_runbook_says_what_it_covers(name: str) -> None:
    """A runbook with no requirement reference is one nobody can tell is still
    needed when the requirement changes."""
    text = (RUNBOOKS / name).read_text(encoding="utf-8")

    assert "**Covers:**" in text, f"{name} does not say which requirements it covers"


def test_no_link_in_the_documentation_points_at_a_missing_file() -> None:
    """Relative links only.

    External URLs are not fetched: a test that reached the network would fail on
    somebody's train and would be the first thing anybody disabled. A broken
    external link is a nuisance; a broken internal one is a runbook step that
    cannot be followed.
    """
    broken: list[str] = []
    for document in _markdown():
        for target in LINK.findall(document.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = (document.parent / target.split("#", 1)[0]).resolve()
            if not path.exists():
                broken.append(f"{document.relative_to(DOCS)} -> {target}")

    assert not broken, "documentation links to files that do not exist: " + ", ".join(broken)


def test_the_index_names_every_runbook() -> None:
    """An index that has fallen behind is worse than no index: somebody reads it,
    concludes the runbook does not exist, and improvises."""
    index = (RUNBOOKS / "README.md").read_text(encoding="utf-8")

    missing = sorted(name for name in REQUIRED if name not in index)

    assert not missing, "runbooks missing from docs/runbooks/README.md: " + ", ".join(missing)


def test_no_runbook_is_a_stub() -> None:
    """A placeholder satisfies every check above and helps nobody at three in the
    morning. The threshold is deliberately low — it catches the empty file and
    the heading with a TODO under it, not a short procedure that happens to be
    short."""
    thin = sorted(
        name
        for name in REQUIRED
        if len((RUNBOOKS / name).read_text(encoding="utf-8").split()) < 200
    )

    assert not thin, "runbooks too short to be procedures: " + ", ".join(thin)
