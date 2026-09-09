"""Resolving group membership, including nested groups (FR-DIR-04).

A person is in `lms-students`; `lms-students` is in `all-students`; `all-students`
is in `campus-members`. The access is granted on the outermost, so a broker that
reads only direct membership grants nothing and everybody's access appears
broken in a way that looks like a directory problem.

Three things make this harder than a graph walk.

**Directories disagree about which direction the edge points.** With the
`memberOf` overlay the answer is an attribute on the person; without it, the
question has to be asked of every group. Both are supported and the expansion
does not care which supplied the first level.

**Groups contain groups, and sometimes contain themselves.** A cycle in a
directory is a configuration mistake, not an attack, and it is common enough
that an expansion which does not expect one will eventually hang on somebody's
production tree. Visited DNs are tracked, so a cycle terminates rather than
recurses.

**Depth is bounded and the bound is visible.** Five levels by default. A tree
deeper than that is either unusual enough to be configured deliberately or a
mistake, and silently expanding forever is how one login takes thirty seconds.
Hitting the limit is logged with the group that was still expanding, because
"membership is incomplete" is not something to discover from an access denial.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from campusid.logging import get_logger

log = get_logger(__name__)

MAX_DEPTH: Final = 5
"""FR-DIR-04's default. Deep enough for the role hierarchies institutions
actually build, shallow enough that a cycle-free but pathological tree cannot
turn one login into a directory crawl."""

MAX_GROUPS: Final = 1000
"""A ceiling on the whole expansion, not on one level.

A person legitimately in a thousand groups is a directory problem worth knowing
about; an expansion that keeps going is one that turns it into a broker problem.
"""

ParentLookup = Callable[[str], Awaitable[list[str]]]
"""Given a group DN, the DNs of the groups it is itself a member of.

A callback so the expansion is testable without a directory, and so the same
expansion works whether the caller got the first level from `memberOf` or from a
reverse search.
"""


@dataclass(frozen=True, slots=True)
class Expansion:
    """The result of expanding a person's group membership."""

    groups: frozenset[str]
    """Every group DN, direct and inherited."""

    direct: frozenset[str] = field(default_factory=frozenset)
    """The ones the directory named on the person.

    Kept separate because a role derived from direct membership and one derived
    through three levels of nesting are the same grant with very different
    review stories, and FR-AZ-01 asks that the origin be recorded.
    """

    truncated: bool = False
    """Whether a limit stopped the walk. A caller that grants access on this
    should know the answer may be incomplete rather than assume it is final."""

    depth_reached: int = 0


async def expand(
    direct: list[str],
    parents_of: ParentLookup,
    *,
    max_depth: int = MAX_DEPTH,
    max_groups: int = MAX_GROUPS,
) -> Expansion:
    """Walk upward from a person's direct groups through their parents.

    Breadth-first rather than depth-first, so the depth limit means what it says
    — with a depth-first walk, "five levels" would be five levels along whichever
    branch happened to be explored first.
    """
    seen: set[str] = set()
    frontier = _unique(direct)
    truncated = False
    depth = 0

    while frontier and depth < max_depth:
        seen.update(frontier)
        if len(seen) >= max_groups:
            truncated = True
            log.warning("directory.groups.too_many", count=len(seen), limit=max_groups)
            break

        next_frontier: list[str] = []
        for group in frontier:
            for parent in await parents_of(group):
                # A cycle is a configuration mistake rather than an attack, and
                # common enough that an expansion which does not expect one will
                # eventually hang on somebody's production tree.
                if parent not in seen and parent not in next_frontier:
                    next_frontier.append(parent)

        frontier = next_frontier
        if frontier:
            depth += 1

    if frontier and depth >= max_depth:
        # The groups we stopped at are still memberships — they were named by
        # something the person is in. Dropping them would turn a bounded walk
        # into a silently smaller answer, which is the wrong kind of limit.
        seen.update(frontier)
        truncated = True
        log.warning(
            "directory.groups.depth_exceeded",
            depth=max_depth,
            still_expanding=sorted(frontier)[:5],
        )

    return Expansion(
        groups=frozenset(seen),
        direct=frozenset(direct),
        truncated=truncated,
        depth_reached=depth,
    )


def _unique(values: list[str]) -> list[str]:
    """Order-preserving deduplication.

    Order matters only for the log line naming what was still expanding, but a
    duplicated starting group would be walked twice and counted twice against
    the ceiling.
    """
    return list(dict.fromkeys(values))
