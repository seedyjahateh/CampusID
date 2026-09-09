"""Mapping an upstream provider's claims to our attributes (FR-RP-02).

The inverse of the downstream mapping, and the reason the same release policy
can govern a person who arrives over SAML and one who arrives over upstream
OIDC: both reach the engine in the same shape.
"""

from __future__ import annotations

import pytest

from campusid.policy.attributes import (
    DISPLAY_NAME,
    ENTITLEMENT,
    EPPN,
    MAIL,
    STUDENT_ID,
    SURNAME,
)
from campusid.rp.claims import DEFAULT_MAPPINGS, ClaimMapper, ClaimMapping

UPSTREAM = {
    "sub": "248289761001",
    "preferred_username": "sam.obrien@partner.test",
    "email": "sam.obrien@partner.test",
    "name": "Samira O'Brien",
    "family_name": "O'Brien",
    "groups": ["research-computing", "library-staff"],
    "email_verified": True,
    "updated_at": 1758000000,
}


@pytest.fixture
def mapper() -> ClaimMapper:
    return ClaimMapper()


def test_a_mapped_claim_becomes_its_attribute(mapper: ClaimMapper) -> None:
    assert mapper.attributes(UPSTREAM)[EPPN] == ["sam.obrien@partner.test"]


def test_a_multivalued_claim_keeps_its_values(mapper: ClaimMapper) -> None:
    assert mapper.attributes(UPSTREAM)[ENTITLEMENT] == ["research-computing", "library-staff"]


def test_an_unmapped_claim_is_dropped(mapper: ClaimMapper) -> None:
    """Not passed through under its own name. An unmapped attribute would reach
    the release engine as an unknown one, be denied by default, and look to an
    operator like a policy problem rather than a missing mapping line."""
    mapped = mapper.attributes(UPSTREAM)

    assert "email_verified" not in mapped
    assert "updated_at" not in mapped
    assert set(mapped) <= {EPPN, MAIL, DISPLAY_NAME, SURNAME, ENTITLEMENT}


def test_a_boolean_claim_is_not_stringified(mapper: ClaimMapper) -> None:
    """`email_verified: true` becoming the string "True" is the kind of coercion
    that ends up in a value filter and matches something it should not."""
    mapped = ClaimMapper(mappings=(ClaimMapping("email_verified", MAIL),)).attributes(
        {"email_verified": True}
    )

    assert mapped == {}


def test_a_numeric_claim_is_not_stringified() -> None:
    mapped = ClaimMapper(mappings=(ClaimMapping("updated_at", MAIL),)).attributes(
        {"updated_at": 1758000000}
    )

    assert mapped == {}


def test_an_empty_value_produces_no_attribute(mapper: ClaimMapper) -> None:
    """An attribute released with nothing in it is not a fact about anybody."""
    assert mapper.attributes({"preferred_username": ""}) == {}


def test_a_single_valued_claim_sent_as_a_list_is_accepted(mapper: ClaimMapper) -> None:
    """The ordinary shape of a provider disagreeing with the specification.
    Refusing would break an integration over a formatting choice."""
    assert mapper.attributes({"name": ["Samira O'Brien"]})[DISPLAY_NAME] == ["Samira O'Brien"]


def test_a_multivalued_claim_sent_as_a_string_is_accepted(mapper: ClaimMapper) -> None:
    assert mapper.attributes({"groups": "research-computing"})[ENTITLEMENT] == [
        "research-computing"
    ]


def test_non_string_members_of_a_list_are_dropped(mapper: ClaimMapper) -> None:
    assert mapper.attributes({"groups": ["real", 42, None, "also-real"]})[ENTITLEMENT] == [
        "real",
        "also-real",
    ]


# --- the subject ------------------------------------------------------------


def test_the_subject_comes_from_sub(mapper: ClaimMapper) -> None:
    assert mapper.subject(UPSTREAM) == "248289761001"


def test_a_missing_subject_is_refused(mapper: ClaimMapper) -> None:
    """Continuing with a blank subject would silently merge every user of that
    provider into one account — the worst possible failure for a broker."""
    with pytest.raises(ValueError, match="sub"):
        mapper.subject({"email": "sam@partner.test"})


def test_an_empty_subject_is_refused(mapper: ClaimMapper) -> None:
    with pytest.raises(ValueError, match="sub"):
        mapper.subject({"sub": ""})


def test_the_subject_claim_is_configurable() -> None:
    """`sub` is the right answer and the specification's answer. It is
    configurable because a provider that reuses `sub` across tenants exists, and
    the fix should be a line of configuration rather than a fork."""
    mapper = ClaimMapper(subject_claim="oid")

    assert mapper.subject({"oid": "tenant-scoped-id"}) == "tenant-scoped-id"


# --- what a mapping may not do ---------------------------------------------


def test_a_mapping_onto_an_unknown_attribute_is_refused() -> None:
    """It would produce a value the release engine denies as unknown, which
    reads as a policy problem rather than the configuration typo it is."""
    with pytest.raises(ValueError, match="not a known attribute"):
        ClaimMapper(mappings=(ClaimMapping("whatever", "urn:invented:attribute"),))


def test_a_claim_mapped_twice_is_refused() -> None:
    """Which mapping won would depend on tuple order, which is not a thing a
    configuration file should encode by accident."""
    with pytest.raises(ValueError, match="mapped twice"):
        ClaimMapper(mappings=(ClaimMapping("email", MAIL), ClaimMapping("email", DISPLAY_NAME)))


def test_an_education_record_can_be_mapped_but_is_never_released() -> None:
    """The mapping layer does not enforce classification and should not: a
    partner may genuinely assert a student number, and the record of having
    received it is real. The release engine is what refuses to pass it on, and
    a test elsewhere proves that."""
    mapper = ClaimMapper(mappings=(ClaimMapping("student_number", STUDENT_ID),))

    assert mapper.attributes({"student_number": "S001"}) == {STUDENT_ID: ["S001"]}


def test_the_default_table_maps_only_known_attributes() -> None:
    """Constructing the default mapper is itself the assertion — its validation
    runs over every entry."""
    assert ClaimMapper(mappings=DEFAULT_MAPPINGS).attributes({}) == {}


def test_the_default_table_covers_the_claims_every_provider_emits() -> None:
    """`sub` is handled separately; these are the ones a partner's
    documentation will list."""
    claims = {mapping.claim for mapping in DEFAULT_MAPPINGS}

    assert {"preferred_username", "email", "name", "given_name", "family_name"} <= claims
