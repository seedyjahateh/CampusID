"""Mapping an upstream provider's claims to our attributes (FR-RP-02).

The inverse of `campusid/oidc/claims.py`: that module turns our internal
attributes into claims for a client, this one turns somebody else's claims into
our internal attributes. Running both means a person who arrives over upstream
OIDC and a person who arrives over SAML reach the release engine in the same
shape, which is the only way the same policy can govern both.

The mapping is configuration rather than code because every OP names things
differently — `preferred_username` here, `uid` there, `sub` at the one that
never got around to it — and the person who knows which is an IAM analyst
looking at a partner's documentation, not somebody editing Python.

Two rules make the conversion safe:

**Nothing is invented.** A claim with no mapping is dropped, not passed through
under its own name. An unmapped attribute would reach the release engine as an
unknown one, be denied by default, and look to an operator like a policy problem
rather than a missing mapping line.

**Nothing is trusted about scoping.** An upstream OP asserting
`eduPersonPrincipalName: someone@campus.test` is claiming authority over *our*
scope, and normalisation drops it — the same check applied to a local IdP,
because a partner is exactly as entitled to name our users as our own IdP is to
name theirs. That is enforced downstream in `policy.normalize`, and this module
exists to hand it values in the form it recognises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from campusid.policy.attributes import (
    DISPLAY_NAME,
    ENTITLEMENT,
    EPPN,
    GIVEN_NAME,
    MAIL,
    ORCID,
    SCOPED_AFFILIATION,
    SURNAME,
    definition,
)


@dataclass(frozen=True, slots=True)
class ClaimMapping:
    """One upstream claim and the attribute it becomes."""

    claim: str
    attribute: str
    multivalued: bool = False
    """Whether the upstream claim carries a list. A single-valued claim arriving
    as a list, or the reverse, is the ordinary shape of an OP disagreeing with
    the specification — handled rather than assumed away."""


DEFAULT_MAPPINGS: Final[tuple[ClaimMapping, ...]] = (
    ClaimMapping("preferred_username", EPPN),
    ClaimMapping("email", MAIL, multivalued=True),
    ClaimMapping("name", DISPLAY_NAME),
    ClaimMapping("given_name", GIVEN_NAME),
    ClaimMapping("family_name", SURNAME),
    ClaimMapping("orcid", ORCID),
    # `groups` is not a standard OIDC claim, but it is what most providers emit
    # and what a partner's documentation will call it.
    ClaimMapping("groups", ENTITLEMENT, multivalued=True),
    ClaimMapping("eduperson_scoped_affiliation", SCOPED_AFFILIATION, multivalued=True),
)
"""The table a deployment starts from.

Every entry is a guess about what a partner calls things, which is why the whole
thing is replaceable per provider rather than compiled in.
"""


@dataclass(frozen=True, slots=True)
class ClaimMapper:
    """Turns one provider's claims into our attributes."""

    mappings: tuple[ClaimMapping, ...] = DEFAULT_MAPPINGS
    subject_claim: str = "sub"
    """Which claim identifies the person at this provider.

    `sub` is the right answer and the specification's answer. It is
    configurable because a provider that reuses `sub` across tenants exists, and
    when one is encountered the fix is a line of configuration rather than a
    fork.
    """

    _by_claim: dict[str, ClaimMapping] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        by_claim: dict[str, ClaimMapping] = {}
        for mapping in self.mappings:
            if definition(mapping.attribute) is None:
                # A mapping onto an attribute the catalogue does not know would
                # produce a value the release engine denies as unknown, which
                # reads as a policy problem rather than a configuration typo.
                raise ValueError(f"{mapping.attribute!r} is not a known attribute")
            if mapping.claim in by_claim:
                raise ValueError(f"claim {mapping.claim!r} is mapped twice")
            by_claim[mapping.claim] = mapping
        object.__setattr__(self, "_by_claim", by_claim)

    def subject(self, claims: dict[str, Any]) -> str:
        """The provider's identifier for this person.

        Required. A token without one identifies nobody, and continuing with a
        blank subject would silently merge every user of that provider into one
        account.
        """
        value = claims.get(self.subject_claim)
        if not isinstance(value, str) or not value:
            raise ValueError(f"the ID token carries no usable {self.subject_claim!r}")
        return value

    def attributes(self, claims: dict[str, Any]) -> dict[str, list[str]]:
        """Everything mapped, in the shape the release engine expects.

        Unmapped claims are dropped rather than carried through under their own
        names — see the module docstring.
        """
        mapped: dict[str, list[str]] = {}
        for claim, raw in claims.items():
            mapping = self._by_claim.get(claim)
            if mapping is None:
                continue
            values = _as_values(raw, multivalued=mapping.multivalued)
            if values:
                mapped[mapping.attribute] = values
        return mapped


def _as_values(raw: Any, *, multivalued: bool) -> list[str]:
    """Coerce a claim into a list of strings, or nothing.

    Booleans and numbers are refused rather than stringified. `email_verified:
    true` becoming the string `"True"` is the kind of coercion that ends up in a
    value filter and matches something it should not.
    """
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, list) and multivalued:
        return [item for item in raw if isinstance(item, str) and item]
    if isinstance(raw, list) and raw:
        # A single-valued claim the provider sent as a list. Taking the first is
        # the reading every client library uses, and refusing it would break an
        # integration over a provider's formatting choice.
        first = raw[0]
        return [first] if isinstance(first, str) and first else []
    return []
