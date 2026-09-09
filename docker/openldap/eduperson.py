"""The eduPerson attributes the broker reads, as an OpenLDAP schema entry.

A subset rather than the whole specification: the five attributes this project
actually searches on or releases, plus the auxiliary object class that permits
them. Shipping the full schema would be transcription; shipping none of it would
mean the development directory could not answer the queries the OpenLDAP profile
is named for.

That is not a cosmetic difference. An LDAP server rejects a *whole filter* that
names an attribute type it does not know, so a profile listing
`eduPersonPrincipalName` against a directory without the schema fails every
search with `invalid attribute type` — not with an empty result. The development
directory therefore has to have the schema, or it would be proving the client
works against a server unlike the one it is written for.

Object identifiers are the real ones from the eduPerson specification, under
the arc `1.3.6.1.4.1.5923.1.1`. Inventing OIDs would make this directory
subtly incompatible with a real one, which is the opposite of what a fixture
is for.
"""

from __future__ import annotations

from typing import Final

SCHEMA_DN: Final = "cn=eduperson,cn=schema,cn=config"

STRING: Final = "1.3.6.1.4.1.1466.115.121.1.15"
CASE_IGNORE: Final = "2.5.13.2"
CASE_IGNORE_SUBSTRINGS: Final = "2.5.13.4"

ATTRIBUTE_TYPES: Final[tuple[str, ...]] = (
    # `eduPersonAffiliation` — unscoped, multivalued, controlled vocabulary.
    f"( 1.3.6.1.4.1.5923.1.1.1.1 NAME 'eduPersonAffiliation' "
    f"EQUALITY {CASE_IGNORE} SUBSTR {CASE_IGNORE_SUBSTRINGS} SYNTAX {STRING} )",
    # `eduPersonPrincipalName` — single-valued on purpose. A person with two
    # principal names has two identities, and the directory should say so
    # rather than let an application pick one.
    f"( 1.3.6.1.4.1.5923.1.1.1.6 NAME 'eduPersonPrincipalName' "
    f"EQUALITY {CASE_IGNORE} SUBSTR {CASE_IGNORE_SUBSTRINGS} SYNTAX {STRING} SINGLE-VALUE )",
    # `eduPersonEntitlement` — URN-valued and multivalued.
    f"( 1.3.6.1.4.1.5923.1.1.1.7 NAME 'eduPersonEntitlement' "
    f"EQUALITY {CASE_IGNORE} SUBSTR {CASE_IGNORE_SUBSTRINGS} SYNTAX {STRING} )",
    # `eduPersonScopedAffiliation` — `student@campus.test`. The scope is the
    # authority boundary, which is why it is a separate attribute from the
    # unscoped form rather than a formatting of it.
    f"( 1.3.6.1.4.1.5923.1.1.1.9 NAME 'eduPersonScopedAffiliation' "
    f"EQUALITY {CASE_IGNORE} SUBSTR {CASE_IGNORE_SUBSTRINGS} SYNTAX {STRING} )",
    # `eduPersonUniqueId` — opaque, scoped, never reassigned.
    f"( 1.3.6.1.4.1.5923.1.1.1.13 NAME 'eduPersonUniqueId' "
    f"EQUALITY {CASE_IGNORE} SUBSTR {CASE_IGNORE_SUBSTRINGS} SYNTAX {STRING} SINGLE-VALUE )",
)

OBJECT_CLASSES: Final[tuple[str, ...]] = (
    # Auxiliary, so it decorates an `inetOrgPerson` rather than replacing it.
    # Every attribute is optional: a person who has not been assigned an
    # entitlement is not an invalid entry.
    "( 1.3.6.1.4.1.5923.1.1.2 NAME 'eduPerson' AUXILIARY "
    "MAY ( eduPersonAffiliation $ eduPersonPrincipalName $ eduPersonEntitlement $ "
    "eduPersonScopedAffiliation $ eduPersonUniqueId ) )",
)


def schema_entry() -> dict[str, object]:
    """The attributes of the `olcSchemaConfig` entry to add under `cn=config`."""
    return {
        "cn": "eduperson",
        "olcAttributeTypes": list(ATTRIBUTE_TYPES),
        "olcObjectClasses": list(OBJECT_CLASSES),
    }
