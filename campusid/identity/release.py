"""What the broker itself knows about a person, ready for release.

An assertion arrives with what the upstream IdP chose to say. The registry knows
more, and some of what it knows is more authoritative than what arrived — so
before a session is established the two are merged, and the merge is not
symmetric.

**Identifiers we issue win.** `eduPersonPrincipalName` and `eduPersonUniqueId`
are ours. A partner IdP asserting `sam@campus.test` for one of its own users must
not cause us to release that value as though we had issued it, which is exactly
what happens if the asserted value is allowed to stand. So ours replaces theirs
rather than merging with it.

**Entitlements come only from here.** An IdP cannot assert
`eduPersonEntitlement` into a session: the whole point of deriving entitlements
from affiliations is that access follows from a recorded relationship, and an
upstream that could assert them directly would be able to grant itself anything.
Anything asserted under that name is discarded before ours is added.

**Affiliations are ours only within our own scope.** `eduPersonScopedAffiliation`
carries its authority in the value: `faculty@partner.edu` is a statement Partner
College is entitled to make and we are not, while `student@campus.test` is a
statement about *us*. So an asserted value in our scope is dropped and replaced
by what the registry holds, and one in anybody else's is kept. Dropping those
too would break federation — a visiting academic would arrive with no
affiliation at all — and keeping ours would let a partner IdP grant campus
affiliation by asserting it.

Nothing here decides what a service provider *sees*. That is the release policy's
job, and these values are the input to it: a scope grants permission to ask, the
policy decides what comes back.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from campusid.policy.attributes import (
    ENTITLEMENT,
    EPPN,
    MAIL,
    SCOPED_AFFILIATION,
    UNIQUE_ID,
)

BROKER_OWNED: tuple[str, ...] = (EPPN, UNIQUE_ID, ENTITLEMENT)
"""Attributes an upstream may not decide at all.

Replaced outright rather than merged, and listed here so the rule is one thing a
reader can check rather than three assignments to notice.
"""

SCOPE_OWNED: tuple[str, ...] = (SCOPED_AFFILIATION,)
"""Attributes an upstream may decide only outside our scope.

Separate from `BROKER_OWNED` because the authority boundary is inside the value
rather than around the attribute: `faculty@partner.edu` is Partner College's
statement to make, `student@campus.test` is ours.
"""


async def registry_attributes(
    person_uuid: str,
    *,
    registry: Any,
    lifecycle: Any,
    scope: str,
    on: date | None = None,
) -> dict[str, list[str]]:
    """Everything the registry can say about this person, by attribute name."""
    person = await registry.get(person_uuid)
    if person is None:
        return {}

    today = on or date.today()
    attributes: dict[str, list[str]] = {UNIQUE_ID: [person.edu_person_unique_id]}

    identifiers = await registry.identifiers(person_uuid)
    eppn = _live(identifiers, "eppn")
    if eppn:
        attributes[EPPN] = eppn
    mail = _live(identifiers, "mail")
    if mail:
        attributes[MAIL] = mail

    affiliations = await registry.affiliations_on(person_uuid, today)
    if affiliations:
        attributes[SCOPED_AFFILIATION] = [f"{value}@{scope}" for value in sorted(affiliations)]

    held = await lifecycle.held(uuid.UUID(person_uuid), on=today)
    if held:
        attributes[ENTITLEMENT] = sorted(held)

    return attributes


def merge(
    asserted: dict[str, list[str]],
    from_registry: dict[str, list[str]],
    *,
    scope: str = "",
) -> dict[str, list[str]]:
    """Combine what the IdP said with what we know.

    Ours replaces theirs for anything in `BROKER_OWNED`, including replacing it
    with nothing: an IdP that asserts entitlements for a person we hold none for
    must not have those entitlements survive into the session.

    For `SCOPE_OWNED` attributes only the values in our own scope are replaced,
    so a visiting academic keeps `faculty@partner.edu` and cannot acquire
    `faculty@campus.test` by being asserted one.
    """
    merged: dict[str, list[str]] = {}
    for name, values in asserted.items():
        if name in BROKER_OWNED:
            continue
        if name in SCOPE_OWNED:
            kept = [value for value in values if not _in_scope(value, scope)]
            if kept:
                merged[name] = kept
            continue
        merged[name] = list(values)

    for name, values in from_registry.items():
        if name in SCOPE_OWNED and name in merged:
            # Theirs from elsewhere, plus ours from here.
            merged[name] = sorted({*merged[name], *values})
            continue
        merged[name] = list(values)
    return merged


def _in_scope(value: str, scope: str) -> bool:
    """Whether a scoped value claims to be about us.

    An unscoped value counts as ours: `student` with no scope is a bare claim
    that only means anything relative to whoever is reading it, and read here it
    reads as a claim about this institution.
    """
    _, separator, asserted_scope = value.rpartition("@")
    if not separator:
        return True
    return asserted_scope.lower() == scope.lower()


def _live(identifiers: list[Any], id_type: str) -> list[str]:
    """Live values of one identifier type, primary first.

    Released ones are omitted. They are kept forever so the value is never
    reissued, but an identifier somebody no longer holds is not something to
    tell a service provider about.
    """
    rows = [
        identifier
        for identifier in identifiers
        if identifier.id_type == id_type and identifier.released_at is None
    ]
    rows.sort(key=lambda identifier: (not identifier.is_primary, identifier.value))
    return [identifier.value for identifier in rows]
