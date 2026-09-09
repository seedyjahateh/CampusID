"""Who gets to decide an attribute (FR-AZ-02, PRD §8.1).

An assertion arrives with whatever the upstream chose to say, and for most
attributes that is fine — a display name is theirs to assert. For four of them it
is not, and the merge is deliberately asymmetric.

The one that matters is `eduPersonEntitlement`. Entitlements are derived from a
recorded relationship to the institution; that is the entire point of deriving
them. An upstream that could assert them into a session would be able to grant
itself anything, and the grant would look exactly like a legitimate one all the
way downstream.

`eduPersonPrincipalName` and `eduPersonUniqueId` are the same argument in a
quieter register. They are identifiers *we* issue. A partner IdP asserting
`sam@campus.test` for one of its own users must not cause us to release that
value as ours.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from campusid.identity.release import (
    BROKER_OWNED,
    SCOPE_OWNED,
    merge,
    registry_attributes,
)
from campusid.policy.attributes import (
    DISPLAY_NAME,
    ENTITLEMENT,
    EPPN,
    MAIL,
    SCOPED_AFFILIATION,
    UNIQUE_ID,
)

pytestmark = pytest.mark.security

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
OURS = "sam.obrien@campus.test"
THEIRS = "somebody.else@campus.test"
LMS = "urn:mace:campus.edu:entitlement:lms:access"
ADMIN = "urn:mace:campus.edu:entitlement:admin:everything"


def test_an_asserted_entitlement_never_survives() -> None:
    """The attack this exists to stop: an upstream granting itself access by
    saying so."""
    merged = merge({ENTITLEMENT: [ADMIN]}, {ENTITLEMENT: [LMS]})

    assert merged[ENTITLEMENT] == [LMS]


def test_an_asserted_entitlement_is_dropped_even_when_we_hold_none() -> None:
    """Replacing with nothing is still replacing. A person we hold no
    entitlements for must not end up with the ones their IdP claimed."""
    merged = merge({ENTITLEMENT: [ADMIN]}, {})

    assert ENTITLEMENT not in merged


def test_our_principal_name_replaces_theirs() -> None:
    """A partner asserting a name in our scope must not have us release it as
    though we had issued it."""
    merged = merge({EPPN: [THEIRS]}, {EPPN: [OURS]})

    assert merged[EPPN] == [OURS]


def test_our_unique_id_replaces_theirs() -> None:
    merged = merge({UNIQUE_ID: ["their-opaque-id"]}, {UNIQUE_ID: ["ours"]})

    assert merged[UNIQUE_ID] == ["ours"]


def test_an_affiliation_in_our_scope_is_ours_to_state() -> None:
    """A partner IdP asserting `faculty@campus.test` is making a claim about us,
    and one it is not entitled to make."""
    merged = merge(
        {SCOPED_AFFILIATION: ["faculty@campus.test"]},
        {SCOPED_AFFILIATION: ["alum@campus.test"]},
        scope="campus.test",
    )

    assert merged[SCOPED_AFFILIATION] == ["alum@campus.test"]


def test_an_affiliation_in_their_scope_survives() -> None:
    """The federation case. A visiting academic is faculty at Partner College,
    which is Partner College's statement to make — dropping it would leave them
    with no affiliation at all."""
    merged = merge(
        {SCOPED_AFFILIATION: ["faculty@partner.edu", "member@partner.edu"]},
        {},
        scope="campus.test",
    )

    assert merged[SCOPED_AFFILIATION] == ["faculty@partner.edu", "member@partner.edu"]


def test_theirs_and_ours_are_both_kept_when_the_scopes_differ() -> None:
    """Somebody can be a visiting academic and a registered student here at the
    same time, and both facts are true."""
    merged = merge(
        {SCOPED_AFFILIATION: ["faculty@partner.edu"]},
        {SCOPED_AFFILIATION: ["student@campus.test"]},
        scope="campus.test",
    )

    assert merged[SCOPED_AFFILIATION] == ["faculty@partner.edu", "student@campus.test"]


def test_an_unscoped_affiliation_reads_as_a_claim_about_us() -> None:
    """`student` with no scope only means anything relative to whoever reads it,
    and read here it reads as a claim about this institution."""
    merged = merge({SCOPED_AFFILIATION: ["student"]}, {}, scope="campus.test")

    assert SCOPED_AFFILIATION not in merged


def test_everything_else_is_left_alone() -> None:
    """A display name is theirs to assert, and overriding it would mean holding
    a copy of every attribute in the federation."""
    merged = merge({DISPLAY_NAME: ["Samira O'Brien"], MAIL: ["sam@campus.test"]}, {})

    assert merged[DISPLAY_NAME] == ["Samira O'Brien"]
    assert merged[MAIL] == ["sam@campus.test"]


def test_the_registry_adds_what_the_idp_omitted() -> None:
    merged = merge({DISPLAY_NAME: ["Samira O'Brien"]}, {ENTITLEMENT: [LMS], EPPN: [OURS]})

    assert merged[ENTITLEMENT] == [LMS]
    assert merged[EPPN] == [OURS]
    assert merged[DISPLAY_NAME] == ["Samira O'Brien"]


def test_the_merge_does_not_mutate_either_side() -> None:
    """The asserted set is also what the audit record of the assertion holds,
    and a merge that rewrote it would make the trail disagree with the wire."""
    asserted = {DISPLAY_NAME: ["Samira O'Brien"], ENTITLEMENT: [ADMIN]}
    ours = {ENTITLEMENT: [LMS]}

    merged = merge(asserted, ours)
    merged[DISPLAY_NAME].append("mutated")

    assert asserted[DISPLAY_NAME] == ["Samira O'Brien"]
    assert asserted[ENTITLEMENT] == [ADMIN]
    assert ours[ENTITLEMENT] == [LMS]


# --- what the registry contributes ------------------------------------------


class _Identifier:
    def __init__(self, id_type: str, value: str, *, primary: bool = False, released: bool = False):
        self.id_type = id_type
        self.value = value
        self.is_primary = primary
        self.released_at = object() if released else None


class _Person:
    def __init__(self, unique_id: str = "opaque-unique-id") -> None:
        self.edu_person_unique_id = unique_id


class _Registry:
    def __init__(
        self,
        person: _Person | None,
        identifiers: list[_Identifier],
        affiliations: list[str],
    ) -> None:
        self._person = person
        self._identifiers = identifiers
        self._affiliations = affiliations

    async def get(self, person_uuid: str) -> _Person | None:
        return self._person

    async def identifiers(self, person_uuid: str) -> list[_Identifier]:
        return self._identifiers

    async def affiliations_on(self, person_uuid: str, when: date) -> list[str]:
        return self._affiliations


class _Lifecycle:
    def __init__(self, held: set[str]) -> None:
        self._held = held

    async def held(self, person_uuid: Any, *, on: date | None = None) -> set[str]:
        return self._held


async def _attributes(
    *,
    known: bool = True,
    identifiers: list[_Identifier] | None = None,
    affiliations: list[str] | None = None,
    held: set[str] | None = None,
) -> dict[str, list[str]]:
    return await registry_attributes(
        PERSON,
        registry=_Registry(
            _Person() if known else None,
            identifiers or [],
            affiliations or [],
        ),
        lifecycle=_Lifecycle(held or set()),
        scope="campus.test",
        on=date(2026, 6, 30),
    )


async def test_the_unique_id_is_always_contributed() -> None:
    """It is ours, it is never reused, and it is what an SP that needs a stable
    non-reassigned handle is given."""
    assert (await _attributes())[UNIQUE_ID] == ["opaque-unique-id"]


async def test_affiliations_are_scoped_to_this_deployment() -> None:
    """`student@campus.test`, not `student`. An unscoped affiliation from a
    federation partner is a claim about somebody else's institution."""
    attributes = await _attributes(affiliations=["student", "member"])

    assert attributes[SCOPED_AFFILIATION] == ["member@campus.test", "student@campus.test"]


async def test_entitlements_come_from_the_grants() -> None:
    attributes = await _attributes(held={LMS})

    assert attributes[ENTITLEMENT] == [LMS]


async def test_a_released_identifier_is_not_contributed() -> None:
    """Kept forever so the value is never reissued, but an identifier somebody
    no longer holds is not something to tell a service provider about."""
    attributes = await _attributes(
        identifiers=[_Identifier("eppn", OURS, primary=True, released=True)]
    )

    assert EPPN not in attributes


async def test_the_primary_identifier_comes_first() -> None:
    attributes = await _attributes(
        identifiers=[
            _Identifier("mail", "second@campus.test"),
            _Identifier("mail", "first@campus.test", primary=True),
        ]
    )

    assert attributes[MAIL] == ["first@campus.test", "second@campus.test"]


async def test_a_person_who_is_not_there_contributes_nothing() -> None:
    """Rather than a half-populated set: a session built on attributes for
    somebody the registry cannot find is a session about nobody."""
    assert await _attributes(known=False) == {}


def test_the_owned_sets_are_pinned() -> None:
    """So widening either is a deliberate edit. Every name in the first is one an
    upstream loses the ability to influence at all; the second it may still
    speak to, but only about its own scope."""
    assert set(BROKER_OWNED) == {EPPN, UNIQUE_ID, ENTITLEMENT}
    assert set(SCOPE_OWNED) == {SCOPED_AFFILIATION}
