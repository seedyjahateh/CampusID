"""Every requirement is either referenced or accounted for.

The PRD states 148 requirements. This asserts that each one is either cited
somewhere in the repository — code, tests, configuration, CI, documentation — or
named in `docs/STATUS.md` as something deliberately not built.

**What this proves is narrow and worth stating.** A citation is a claim, not
evidence: a comment naming FR-SAML-05 proves somebody wrote the identifier next
to some code, and the tests beside it are what prove the requirement is met. What
this catches is the requirement nobody has looked at, which is a different and
more common failure — and the one that turns a requirements document into
decoration.

It also catches the opposite: a requirement that used to be unbuilt, is now
built, and is still listed as a gap. A status document that overstates what is
missing goes stale as quietly as one that understates it.

The three capabilities found this week that were implemented, tested and
unreachable from the running application would all have passed this check. That
is the ceiling on what a citation scan can do, and it is why this file says so
rather than implying otherwise.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PRD = ROOT / "docs" / "PRD.md"
STATUS = ROOT / "docs" / "STATUS.md"

REQUIREMENT = re.compile(r"(?:FR|NFR)-[A-Z]+-\d+")

SEARCHED = ("campusid", "tests", "scripts", "perf", "docs", "migrations", ".github", "config")
SUFFIXES = frozenset({".py", ".md", ".yml", ".yaml", ".sh"})
TOP_LEVEL = ("README.md", "docker-compose.yml", "Dockerfile", "requirements.txt")


MANIFEST = re.compile(r"## Not met, in one list.*?```text\n(.*?)```", re.DOTALL)
"""The machine-readable half of the status document.

Prose cannot be parsed for a claim: the section explaining why FR-FED-04 is not
built also mentions FR-FED-01 as context, and a check reading identifiers out of
paragraphs would conclude that both were gaps. So the document states its claim
twice — once for a person, once in a block — and this asserts the two agree about
which requirements exist.
"""


def _stated() -> list[str]:
    return sorted(set(REQUIREMENT.findall(PRD.read_text(encoding="utf-8"))))


def _manifest() -> set[str]:
    block = MANIFEST.search(STATUS.read_text(encoding="utf-8"))
    assert block is not None, "docs/STATUS.md has no '## Not met, in one list' block"
    return set(REQUIREMENT.findall(block.group(1)))


def _cited(
    *,
    exclude: tuple[Path, ...],
    folders: tuple[str, ...] = SEARCHED,
    top_level: tuple[str, ...] = TOP_LEVEL,
) -> set[str]:
    """Every requirement named in the given places.

    The PRD is always excluded — it states them all, so including it would make
    this assert nothing. `STATUS.md` is excluded and read separately, because
    "named as a gap" and "referenced by the work" are different claims and
    collapsing them would let the status document satisfy the check by listing
    everything.
    """
    skip = {path.resolve() for path in exclude}
    found: set[str] = set()

    for folder in folders:
        base = ROOT / folder
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_dir() or path.suffix not in SUFFIXES or path.resolve() in skip:
                continue
            found.update(REQUIREMENT.findall(path.read_text(encoding="utf-8")))

    for name in top_level:
        path = ROOT / name
        if path.exists():
            found.update(REQUIREMENT.findall(path.read_text(encoding="utf-8")))

    return found


@pytest.fixture(scope="module")
def stated() -> list[str]:
    return _stated()


@pytest.fixture(scope="module")
def cited() -> set[str]:
    return _cited(exclude=(PRD, STATUS))


@pytest.fixture(scope="module")
def accounted() -> set[str]:
    return _manifest()


@pytest.fixture(scope="module")
def implemented() -> set[str]:
    """Requirements cited from the application or its tests.

    Narrower than `cited`, and the distinction is what makes the staleness check
    below sound. A requirement named only in `docs/` or `perf/README.md` is being
    *described* — quite possibly described as missing. One named from `campusid/`
    or `tests/` is being built or tested.
    """
    # This file too. Its own prose names requirements as examples, and a check
    # that counted those would report every one of them as built — the same
    # self-exclusion the reason-code and event-type completeness tests make, for
    # the same reason.
    return _cited(
        exclude=(PRD, STATUS, Path(__file__)),
        folders=("campusid", "tests"),
        top_level=(),
    )


def test_the_prd_still_states_requirements(stated: list[str]) -> None:
    """Guards everything below. A regex that stopped matching would make every
    other assertion here vacuously true."""
    assert len(stated) > 100


def test_every_requirement_is_cited_or_accounted_for(
    stated: list[str], cited: set[str], accounted: set[str]
) -> None:
    """The check this file exists for.

    A new requirement fails it until somebody either builds it and says where, or
    decides not to and says why. Both are decisions; neither is a default.
    """
    orphaned = sorted(set(stated) - cited - accounted)

    assert not orphaned, (
        "requirements nobody has referenced or accounted for: "
        + ", ".join(orphaned)
        + ". Cite each where it is implemented, or add it to docs/STATUS.md with the reason."
    )


def test_nothing_listed_as_not_met_is_quietly_built(
    implemented: set[str], accounted: set[str]
) -> None:
    """The opposite direction, and the one that rots unnoticed.

    A requirement the manifest calls unmet, named from the application or its
    tests, is a gap that was closed and never struck out. That misleads as badly
    as an unstated gap: a reader deciding whether to trust the project reads this
    document, and an entry claiming something is missing when it is not costs
    exactly the credibility the document was written to earn.

    `FR-FED-05` is why this exists. It sat among the unscheduled requirements
    until the key-rotation work needed precisely what it asks for, and the entry
    had to be rewritten rather than left to age.

    Compared against citations from `campusid/` and `tests/` only. A requirement
    named in `docs/` or `perf/README.md` is being described, and quite possibly
    described as missing — counting that as evidence of implementation would make
    this test fire on the document explaining the gap.
    """
    stale = sorted(accounted & implemented)

    assert not stale, (
        "docs/STATUS.md lists these as not met, but the application or its tests "
        "reference them: " + ", ".join(stale) + ". Strike each out of the manifest, "
        "or say in the entry which part is still missing."
    )


def test_the_status_document_is_dated() -> None:
    """The same rule the runbooks follow. A statement about what is missing is a
    statement about a moment, and undated it is just an opinion."""
    assert re.search(
        r"\*\*Verified on:\*\*\s+\d{4}-\d{2}-\d{2}", STATUS.read_text(encoding="utf-8")
    )


def test_every_accounted_requirement_actually_exists(
    stated: list[str], accounted: set[str]
) -> None:
    """A status entry for a requirement the PRD does not state is a typo, and a
    typo here silences the check above for the requirement it was meant to
    name."""
    invented = sorted(accounted - set(stated))

    assert not invented, "docs/STATUS.md names requirements the PRD does not: " + ", ".join(
        invented
    )
