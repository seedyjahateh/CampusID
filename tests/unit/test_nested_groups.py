"""Nested group expansion (FR-DIR-04).

Access is granted on the outermost group, so a broker that reads only direct
membership grants nothing and every user's access looks broken in a way that
reads as a directory fault.

The test the requirement names is the deliberate cycle. A group that contains
itself, directly or through two others, is a configuration mistake rather than
an attack — and common enough that an expansion which does not expect one will
eventually hang on somebody's production tree.
"""

from __future__ import annotations

import pytest

from campusid.directory.groups import MAX_DEPTH, MAX_GROUPS, expand

STUDENTS = "cn=lms-students,ou=groups,dc=campus,dc=test"
ALL_STUDENTS = "cn=all-students,ou=groups,dc=campus,dc=test"
MEMBERS = "cn=campus-members,ou=groups,dc=campus,dc=test"
STAFF = "cn=staff,ou=groups,dc=campus,dc=test"


def _tree(edges: dict[str, list[str]]) -> object:
    """A parent lookup over a fixed graph, counting what it was asked."""

    class _Lookup:
        def __init__(self) -> None:
            self.asked: list[str] = []

        async def __call__(self, group: str) -> list[str]:
            self.asked.append(group)
            return edges.get(group, [])

    return _Lookup()


async def test_a_person_inherits_through_the_chain() -> None:
    """The case the requirement is about: the access is granted on
    `campus-members` and the person is only in `lms-students`."""
    parents = _tree({STUDENTS: [ALL_STUDENTS], ALL_STUDENTS: [MEMBERS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert result.groups == {STUDENTS, ALL_STUDENTS, MEMBERS}
    assert result.direct == {STUDENTS}


async def test_direct_membership_is_distinguishable_from_inherited() -> None:
    """A grant held directly and one held through three levels of nesting are
    the same access with very different review stories, and FR-AZ-01 asks that
    the origin be recorded."""
    parents = _tree({STUDENTS: [MEMBERS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert result.direct == {STUDENTS}
    assert MEMBERS in result.groups
    assert MEMBERS not in result.direct


async def test_a_cycle_terminates() -> None:
    """The deliberate membership cycle the requirement asks for. Two groups that
    each contain the other is a mistake somebody has already made in every
    directory of a certain age."""
    parents = _tree({STUDENTS: [ALL_STUDENTS], ALL_STUDENTS: [STUDENTS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert result.groups == {STUDENTS, ALL_STUDENTS}


async def test_a_group_that_contains_itself_terminates() -> None:
    parents = _tree({STUDENTS: [STUDENTS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert result.groups == {STUDENTS}


async def test_a_long_cycle_terminates() -> None:
    """Three groups round a loop, which is the shape that survives a naive
    visited-check written against the direct case."""
    parents = _tree({STUDENTS: [ALL_STUDENTS], ALL_STUDENTS: [MEMBERS], MEMBERS: [STUDENTS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert result.groups == {STUDENTS, ALL_STUDENTS, MEMBERS}


async def test_no_group_is_looked_up_twice() -> None:
    """A diamond — two groups sharing a parent — must not cost two lookups for
    the shared one. Each lookup is a directory round trip."""
    parents = _tree({STUDENTS: [MEMBERS], STAFF: [MEMBERS], MEMBERS: []})

    await expand([STUDENTS, STAFF], parents)  # type: ignore[arg-type]

    assert parents.asked.count(MEMBERS) == 1  # type: ignore[attr-defined]


async def test_a_duplicated_starting_group_is_walked_once() -> None:
    parents = _tree({STUDENTS: [MEMBERS]})

    result = await expand([STUDENTS, STUDENTS], parents)  # type: ignore[arg-type]

    assert parents.asked.count(STUDENTS) == 1  # type: ignore[attr-defined]
    assert result.groups == {STUDENTS, MEMBERS}


async def test_depth_is_bounded_and_the_truncation_is_visible() -> None:
    """Silently expanding forever is how one login takes thirty seconds, and
    silently stopping is how membership becomes incomplete without anybody
    knowing. Neither: it stops, and it says so."""
    chain = {f"cn=g{level},dc=test": [f"cn=g{level + 1},dc=test"] for level in range(20)}
    parents = _tree(chain)

    result = await expand(["cn=g0,dc=test"], parents)  # type: ignore[arg-type]

    assert result.truncated
    assert result.depth_reached == MAX_DEPTH
    # Five hops from the starting group, and the groups reached on the last hop
    # are kept: they were named by something the person is in, so dropping them
    # would make a bounded walk quietly return a smaller answer.
    assert len(result.groups) == MAX_DEPTH + 1


async def test_a_shallow_tree_is_not_reported_as_truncated() -> None:
    parents = _tree({STUDENTS: [MEMBERS]})

    result = await expand([STUDENTS], parents)  # type: ignore[arg-type]

    assert not result.truncated


async def test_the_total_is_bounded_as_well_as_the_depth() -> None:
    """A person legitimately in a thousand groups is a directory problem worth
    knowing about; an expansion that keeps going turns it into a broker one."""
    wide = [f"cn=g{index},dc=test" for index in range(MAX_GROUPS + 10)]
    parents = _tree({})

    result = await expand(wide, parents)  # type: ignore[arg-type]

    assert result.truncated
    assert len(result.groups) <= MAX_GROUPS + 10


async def test_no_membership_expands_to_nothing() -> None:
    """A person in no groups is ordinary, not an error, and must not cost a
    directory query."""
    parents = _tree({})

    result = await expand([], parents)  # type: ignore[arg-type]

    assert result.groups == frozenset()
    assert not result.truncated
    assert parents.asked == []  # type: ignore[attr-defined]


async def test_breadth_first_means_the_depth_limit_means_what_it_says() -> None:
    """With a depth-first walk, "five levels" would be five levels along
    whichever branch happened to be explored first, and the other branches would
    be cut off at wherever the budget ran out."""
    parents = _tree(
        {
            STUDENTS: ["cn=a1,dc=test", "cn=b1,dc=test"],
            "cn=a1,dc=test": ["cn=a2,dc=test"],
            "cn=b1,dc=test": ["cn=b2,dc=test"],
        }
    )

    result = await expand([STUDENTS], parents, max_depth=2)  # type: ignore[arg-type]

    assert {"cn=a1,dc=test", "cn=b1,dc=test"} <= result.groups
    assert result.depth_reached == 2


@pytest.mark.parametrize(("limit", "value"), [("depth", MAX_DEPTH), ("groups", MAX_GROUPS)])
def test_the_limits_are_positive(limit: str, value: int) -> None:
    assert value > 0
