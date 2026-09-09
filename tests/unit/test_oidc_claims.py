"""Scope-to-claim mapping (FR-OP-11).

The point of the module under test is that it is *only* a mapping. Two decisions
have already been made by the time it runs — what the client asked for, and what
policy released — and this file mostly proves it never widens either.
"""

from __future__ import annotations

import pytest

from campusid.oidc.claims import (
    BY_ATTRIBUTE,
    CLAIMS,
    MACHINE_SCOPES,
    SCOPE_AFFILIATION,
    SCOPE_EMAIL,
    SCOPE_ENTITLEMENT,
    SCOPE_OPENID,
    SCOPE_PROFILE,
    SUPPORTED_CLAIMS,
    SUPPORTED_SCOPES,
    attributes_for_scopes,
    claims_for,
)
from campusid.policy.attributes import (
    CATALOGUE,
    DISPLAY_NAME,
    EPPN,
    MAIL,
    SCOPED_AFFILIATION,
    STUDENT_ID,
    Classification,
)

RELEASED = {
    EPPN: ["sam.obrien@campus.test"],
    DISPLAY_NAME: ["Sam O'Brien"],
    MAIL: ["sam.obrien@campus.test", "s.obrien@alumni.campus.test"],
    SCOPED_AFFILIATION: ["student@campus.test", "member@campus.test"],
}


def test_a_scope_selects_its_own_attributes() -> None:
    assert attributes_for_scopes(frozenset({SCOPE_EMAIL})) == frozenset({MAIL})


def test_scopes_accumulate() -> None:
    both = attributes_for_scopes(frozenset({SCOPE_EMAIL, SCOPE_PROFILE}))

    assert MAIL in both
    assert EPPN in both


def test_an_unknown_scope_selects_nothing() -> None:
    assert attributes_for_scopes(frozenset({SCOPE_OPENID, "made-up"})) == frozenset()


def test_only_the_requested_scopes_produce_claims() -> None:
    """A client that did not ask for `profile` does not get a name, whatever
    policy would have allowed."""
    claims = claims_for(frozenset({SCOPE_OPENID, SCOPE_EMAIL}), RELEASED)

    assert set(claims) == {"email"}


def test_openid_alone_produces_no_identity_claims() -> None:
    assert claims_for(frozenset({SCOPE_OPENID}), RELEASED) == {}


def test_an_attribute_policy_withheld_cannot_be_asked_back_in() -> None:
    """The scope is a request, not an entitlement. If the release engine did not
    put an attribute in `released` — denied by rule, or FERPA-suppressed — no
    combination of scopes produces it."""
    withheld = {name: values for name, values in RELEASED.items() if name != MAIL}

    claims = claims_for(frozenset(SUPPORTED_SCOPES), withheld)

    assert "email" not in claims


# --- cardinality -----------------------------------------------------------


def test_a_multivalued_attribute_can_feed_a_single_valued_claim() -> None:
    """The one place the two models genuinely disagree.

    `mail` is multivalued in eduPerson — a person legitimately has several
    addresses — but OIDC defines `email` as a string, and every client library
    reads it as one. Emitting a one-element array into a field the spec says is
    a string is a bug in the client's parser that we would have caused.
    """
    claims = claims_for(frozenset({SCOPE_EMAIL}), RELEASED)

    assert claims["email"] == "sam.obrien@campus.test"


def test_a_multivalued_claim_stays_a_list_even_with_one_value() -> None:
    """Shape follows the mapping, not the data. A person who happens to hold one
    affiliation today must not silently change how a client parses the claim
    when they acquire a second tomorrow."""
    claims = claims_for(frozenset({SCOPE_AFFILIATION}), {SCOPED_AFFILIATION: ["student@x"]})

    assert claims["campus_scoped_affiliation"] == ["student@x"]


def test_an_empty_value_list_produces_no_claim() -> None:
    """An attribute released with nothing in it is not a claim; emitting an
    empty list tells a client the value is "none" rather than "not released"."""
    assert claims_for(frozenset({SCOPE_EMAIL}), {MAIL: []}) == {}


# --- what cannot be reached ------------------------------------------------


def test_a_restricted_attribute_has_no_mapping() -> None:
    """A second barrier behind the release engine, not a substitute for it: even
    a bug that let a student number through the policy layer would find no claim
    to travel in."""
    assert STUDENT_ID not in BY_ATTRIBUTE


def test_no_restricted_attribute_is_reachable_over_oidc() -> None:
    restricted = {
        name
        for name, attribute in CATALOGUE.items()
        if attribute.classification is Classification.RESTRICTED
    }

    assert restricted & set(BY_ATTRIBUTE) == set()


def test_every_mapped_attribute_is_in_the_catalogue() -> None:
    """A claim mapped from an attribute the catalogue does not know would be
    released with no classification behind it — the release engine denies
    unknown attributes, so the mapping would simply never fire, silently."""
    assert set(BY_ATTRIBUTE) <= set(CATALOGUE)


def test_every_mapping_names_an_advertised_scope() -> None:
    """A mapping under a scope the discovery document does not list is an
    attribute nobody can ever ask for."""
    assert {mapping.scope for mapping in CLAIMS} <= set(SUPPORTED_SCOPES)


def test_no_two_attributes_share_a_claim() -> None:
    """A collision would make one attribute silently overwrite the other, and
    which one won would depend on dictionary ordering."""
    assert len(set(SUPPORTED_CLAIMS)) == len(SUPPORTED_CLAIMS)


def test_standard_claims_keep_their_standard_names() -> None:
    """So an off-the-shelf client library reads them without configuration."""
    assert BY_ATTRIBUTE[MAIL].claim == "email"
    assert BY_ATTRIBUTE[DISPLAY_NAME].claim == "name"
    assert BY_ATTRIBUTE[EPPN].claim == "preferred_username"


def test_local_claims_are_namespaced() -> None:
    """Anything without a standard equivalent gets a prefix rather than being
    invented into the registered namespace, where a later OIDC extension could
    collide with it."""
    standard = {"preferred_username", "name", "given_name", "family_name", "email", "orcid"}

    for claim in set(SUPPORTED_CLAIMS) - standard:
        assert claim.startswith("campus_"), claim


@pytest.mark.parametrize(
    "scope",
    [s for s in SUPPORTED_SCOPES if s != SCOPE_OPENID and s not in MACHINE_SCOPES],
)
def test_every_advertised_scope_releases_something(scope: str) -> None:
    """`openid` selects no attributes by design; an advertised scope that
    selects none is a promise the broker does not keep."""
    assert attributes_for_scopes(frozenset({scope}))


@pytest.mark.parametrize("scope", sorted(MACHINE_SCOPES))
def test_a_machine_scope_selects_no_attributes(scope: str) -> None:
    """The exception to the rule above, and the reason it is written as an
    exception rather than a gap in the mapping.

    A provisioning scope authorises a machine to manage the directory; there is
    no person in the request for it to release attributes about. If one ever
    started selecting attributes, a `client_credentials` token would be able to
    carry claims about somebody who never authenticated."""
    assert attributes_for_scopes(frozenset({scope})) == frozenset()


def test_entitlement_is_its_own_scope() -> None:
    """Authorisation data is separated from profile data on purpose: a client
    that wants a display name should not receive the list of everything the
    person is entitled to do."""
    assert SCOPE_ENTITLEMENT not in {SCOPE_PROFILE, SCOPE_AFFILIATION}
    assert (
        attributes_for_scopes(frozenset({SCOPE_PROFILE}))
        & attributes_for_scopes(frozenset({SCOPE_ENTITLEMENT}))
        == frozenset()
    )
