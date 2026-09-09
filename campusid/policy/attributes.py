"""The attribute catalogue (PRD section 8.3).

Every attribute the broker knows about, with the two facts that decide whether
it may be released: its data classification, and whether FERPA counts it as
directory information.

Classification is not decoration. `restricted` attributes — a student number, an
employee number — are education records under FERPA and are **never** released
over SAML or OIDC, by any policy, to any SP. That is enforced in the engine
rather than left to whoever writes a policy file, because the failure mode of
getting it wrong is a disclosure that cannot be undone.

The `ferpa_directory_item` flag marks what a student may opt out of having
disclosed (34 CFR 99.37). It is the second half of the suppression control:
without it, a suppression flag would have to name attributes individually, and
an attribute added later would default to being disclosed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Classification(StrEnum):
    """How sensitive an attribute is, and therefore who may ever see it."""

    PUBLIC = "public"
    """Releasable to anyone; carries no personal detail. A pairwise identifier
    is public in this sense — it identifies a session, not a person."""

    DIRECTORY = "directory"
    """FERPA directory information: releasable unless the student opted out."""

    INTERNAL = "internal"
    """Releasable to SPs that need it, never merely because it was asked for."""

    RESTRICTED = "restricted"
    """An education record. Never released. Not policy-overridable."""


@dataclass(frozen=True, slots=True)
class AttributeDefinition:
    """One attribute, as the broker understands it."""

    name: str
    """The SAML/OIDC name. `urn:oid:` form for eduPerson, because Shibboleth
    and Keycloak both key their mappers on it; the basic form silently
    releases nothing."""

    friendly_name: str
    classification: Classification
    ferpa_directory_item: bool = False
    multivalued: bool = True


EPPN: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
UNIQUE_ID: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.13"
SUBJECT_ID: Final = "urn:oasis:names:tc:SAML:attribute:subject-id"
PAIRWISE_ID: Final = "urn:oasis:names:tc:SAML:attribute:pairwise-id"
MAIL: Final = "urn:oid:0.9.2342.19200300.100.1.3"
DISPLAY_NAME: Final = "urn:oid:2.16.840.1.113730.3.1.241"
GIVEN_NAME: Final = "urn:oid:2.5.4.42"
SURNAME: Final = "urn:oid:2.5.4.4"
SCOPED_AFFILIATION: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
AFFILIATION: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
PRIMARY_AFFILIATION: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
ENTITLEMENT: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
ASSURANCE: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
ORG_UNIT: Final = "urn:oid:2.5.4.11"
ORCID: Final = "urn:oid:1.3.6.1.4.1.5923.1.1.1.16"
STUDENT_ID: Final = "urn:campusid:attribute:student-id"
EMPLOYEE_ID: Final = "urn:campusid:attribute:employee-id"

CATALOGUE: Final[dict[str, AttributeDefinition]] = {
    definition.name: definition
    for definition in (
        # --- identifiers ---------------------------------------------------
        AttributeDefinition(SUBJECT_ID, "subject-id", Classification.DIRECTORY, multivalued=False),
        AttributeDefinition(PAIRWISE_ID, "pairwise-id", Classification.PUBLIC, multivalued=False),
        AttributeDefinition(
            EPPN, "eduPersonPrincipalName", Classification.DIRECTORY, multivalued=False
        ),
        AttributeDefinition(
            UNIQUE_ID, "eduPersonUniqueId", Classification.INTERNAL, multivalued=False
        ),
        # --- name and contact, all FERPA directory items -------------------
        AttributeDefinition(MAIL, "mail", Classification.DIRECTORY, ferpa_directory_item=True),
        AttributeDefinition(
            DISPLAY_NAME,
            "displayName",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
            multivalued=False,
        ),
        AttributeDefinition(
            GIVEN_NAME,
            "givenName",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
            multivalued=False,
        ),
        AttributeDefinition(
            SURNAME,
            "sn",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
            multivalued=False,
        ),
        # --- affiliation ----------------------------------------------------
        AttributeDefinition(
            SCOPED_AFFILIATION,
            "eduPersonScopedAffiliation",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
        ),
        AttributeDefinition(
            AFFILIATION,
            "eduPersonAffiliation",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
        ),
        AttributeDefinition(
            PRIMARY_AFFILIATION,
            "eduPersonPrimaryAffiliation",
            Classification.DIRECTORY,
            ferpa_directory_item=True,
            multivalued=False,
        ),
        AttributeDefinition(ORG_UNIT, "ou", Classification.DIRECTORY, ferpa_directory_item=True),
        # --- authorisation --------------------------------------------------
        AttributeDefinition(ENTITLEMENT, "eduPersonEntitlement", Classification.INTERNAL),
        AttributeDefinition(ASSURANCE, "eduPersonAssurance", Classification.INTERNAL),
        # --- research -------------------------------------------------------
        AttributeDefinition(ORCID, "eduPersonOrcid", Classification.PUBLIC, multivalued=False),
        # --- never released -------------------------------------------------
        # Education records under FERPA. Present in the catalogue precisely so
        # the engine can refuse them by name, and so a test can assert that no
        # policy anywhere lists one.
        AttributeDefinition(STUDENT_ID, "studentID", Classification.RESTRICTED, multivalued=False),
        AttributeDefinition(
            EMPLOYEE_ID, "employeeNumber", Classification.RESTRICTED, multivalued=False
        ),
    )
}

RESEARCH_AND_SCHOLARSHIP: Final = "http://refeds.org/category/research-and-scholarship"
"""The REFEDS R&S entity category.

An SP tagged with it receives a fixed bundle without any per-attribute
configuration. The point is operational, not technical: a category an SP earns
once is reviewable, where two hundred hand-written per-SP rules are not.
"""

RS_BUNDLE: Final[frozenset[str]] = frozenset(
    {SUBJECT_ID, EPPN, MAIL, DISPLAY_NAME, GIVEN_NAME, SURNAME, SCOPED_AFFILIATION}
)
"""Exactly the R&S set. Adding to this is a federation-wide decision, not a
local convenience, so a test pins it."""


def definition(name: str) -> AttributeDefinition | None:
    """Look up an attribute, or None if the broker does not know it."""
    return CATALOGUE.get(name)
