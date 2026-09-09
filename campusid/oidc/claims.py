"""From released attributes to OIDC claims (FR-OP-11).

Two filters stand between a person's attributes and a client, and keeping them
separate is the whole design of this module.

**Scope is what the client asked for.** A client that did not request `email`
does not get an email claim even if policy would allow it — least privilege
expressed by the application.

**The release policy is what the university permits.** A client that requested
`email` still gets nothing if the SP's policy denies it, or the student
suppressed their directory information. That decision is made in
`campusid.policy.release`, the same engine and the same policy the SAML side
uses, which is what makes FR-OP-11's promise — "OIDC and SAML release identical
sets" — true by construction rather than by two implementations agreeing.

So this module is only the mapping: which internal attribute becomes which
standard claim, under which scope, and in which shape. It never widens anything.
Anything it emits was already released.

**Cardinality follows the claim, not the attribute.** That is the one place the
two models genuinely disagree and it cost a test to notice. `mail` is
multivalued in the eduPerson catalogue — a person legitimately has several
addresses — but OIDC defines `email` as a string, and every client library ever
written reads it as one. Deriving the shape from the SAML side would emit a
one-element array into a field the spec says is a string. So each mapping
carries its own cardinality, taken from the OIDC specification, and where a
multivalued attribute feeds a single-valued claim the first value is used —
which is what `email`'s definition ("preferred e-mail address") actually asks
for.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from campusid.policy.attributes import (
    AFFILIATION,
    DISPLAY_NAME,
    ENTITLEMENT,
    EPPN,
    GIVEN_NAME,
    MAIL,
    ORCID,
    ORG_UNIT,
    PRIMARY_AFFILIATION,
    SCOPED_AFFILIATION,
    SURNAME,
)

SCOPE_OPENID: Final = "openid"
SCOPE_PROFILE: Final = "profile"
SCOPE_EMAIL: Final = "email"
SCOPE_AFFILIATION: Final = "campus:affiliation"
SCOPE_ENTITLEMENT: Final = "campus:entitlement"

SUPPORTED_SCOPES: Final[tuple[str, ...]] = (
    SCOPE_OPENID,
    SCOPE_PROFILE,
    SCOPE_EMAIL,
    SCOPE_AFFILIATION,
    SCOPE_ENTITLEMENT,
)
"""What the discovery document advertises. A scope not listed here cannot be
registered against a client, so the two never drift."""


@dataclass(frozen=True, slots=True)
class ClaimMapping:
    """One attribute, the claim it becomes, and the scope that asks for it."""

    attribute: str
    claim: str
    scope: str
    multivalued: bool = False
    """Per the OIDC specification for this claim, not per the attribute. See the
    module docstring — this is where the two models disagree."""


CLAIMS: Final[tuple[ClaimMapping, ...]] = (
    # Standard claims keep their standard names, so an off-the-shelf client
    # library reads them without configuration.
    ClaimMapping(EPPN, "preferred_username", SCOPE_PROFILE),
    ClaimMapping(DISPLAY_NAME, "name", SCOPE_PROFILE),
    ClaimMapping(GIVEN_NAME, "given_name", SCOPE_PROFILE),
    ClaimMapping(SURNAME, "family_name", SCOPE_PROFILE),
    ClaimMapping(ORCID, "orcid", SCOPE_PROFILE),
    ClaimMapping(MAIL, "email", SCOPE_EMAIL),
    # Everything without a standard equivalent is namespaced rather than
    # invented into the registered namespace, where a later OIDC extension
    # could collide with it.
    ClaimMapping(ORG_UNIT, "campus_org_unit", SCOPE_PROFILE, multivalued=True),
    ClaimMapping(
        SCOPED_AFFILIATION, "campus_scoped_affiliation", SCOPE_AFFILIATION, multivalued=True
    ),
    ClaimMapping(AFFILIATION, "campus_affiliation", SCOPE_AFFILIATION, multivalued=True),
    ClaimMapping(PRIMARY_AFFILIATION, "campus_primary_affiliation", SCOPE_AFFILIATION),
    ClaimMapping(ENTITLEMENT, "campus_entitlement", SCOPE_ENTITLEMENT, multivalued=True),
)
"""The whole mapping, in one table.

An attribute absent from it is unreachable over OIDC whatever policy says, which
is deliberate for anything that has no business in a claim. Restricted
attributes are absent, and a test asserts they stay that way — a second barrier
behind the release engine rather than a substitute for it.
"""

BY_ATTRIBUTE: Final[dict[str, ClaimMapping]] = {mapping.attribute: mapping for mapping in CLAIMS}

SUPPORTED_CLAIMS: Final[tuple[str, ...]] = tuple(mapping.claim for mapping in CLAIMS)
"""What discovery advertises under `claims_supported`, alongside the protocol
claims the ID token always carries."""


def attributes_for_scopes(scopes: frozenset[str]) -> frozenset[str]:
    """Which attributes these scopes ask for."""
    return frozenset(mapping.attribute for mapping in CLAIMS if mapping.scope in scopes)


def claims_for(scopes: frozenset[str], released: dict[str, list[str]]) -> dict[str, Any]:
    """Map released attributes to claims, keeping only what the scopes asked for.

    `released` is the output of the release engine, so this is an intersection
    of two decisions already made — never a third source of authority.
    """
    claims: dict[str, Any] = {}
    for name, values in sorted(released.items()):
        mapping = BY_ATTRIBUTE.get(name)
        if mapping is None or mapping.scope not in scopes or not values:
            continue
        claims[mapping.claim] = list(values) if mapping.multivalued else values[0]
    return claims
