"""Turning what an upstream said into something the registry can match on.

Two protocols arrive with the same facts under different names. SAML delivers
`urn:oid:1.3.6.1.4.1.5923.1.1.1.6`, OIDC delivers `eduperson_principal_name`, and
the identity registry should know about neither — its rules are about evidence,
not about wire formats.

**A multivalued attribute is narrowed to one value here, deliberately.** `mail`
is multivalued in eduPerson and a person may assert three addresses; the registry
matches on one. Taking the first is a decision, and the decision is that an IdP
lists the primary address first — which is what the specification's ordering
means and what every IdP in the federation actually does. Matching on *any* of
them would widen the weakest linking rule in the system, which is the last one
that should be widened.

**Nothing here validates.** The attributes reaching this point have already been
through the gate and the normaliser, so a value that is out of scope or outside
a controlled vocabulary is already gone. Re-checking would be a second opinion
that can disagree with the first.
"""

from __future__ import annotations

from typing import Any

from campusid.identity.registry import Assertion
from campusid.policy.attributes import (
    DISPLAY_NAME,
    EPPN,
    GIVEN_NAME,
    MAIL,
    SURNAME,
    UNIQUE_ID,
)

PROTOCOL_SAML = "saml"
PROTOCOL_OIDC = "oidc"


def from_saml(issuer: str, name_id: str, attributes: dict[str, list[str]]) -> Assertion:
    """What a validated SAML assertion says about somebody.

    `name_id` is the subject rather than any attribute, because the registry's
    second rule is "we have seen this exact subject at this exact issuer
    before" — and an attribute the IdP could change is not that.
    """
    return Assertion(
        idp_entity_id=issuer,
        protocol=PROTOCOL_SAML,
        subject=name_id,
        unique_id=_one(attributes, UNIQUE_ID),
        eppn=_one(attributes, EPPN),
        mail=_one(attributes, MAIL),
        display_name=_one(attributes, DISPLAY_NAME),
        given_name=_one(attributes, GIVEN_NAME),
        surname=_one(attributes, SURNAME),
    )


def from_claims(issuer: str, subject: str, claims: dict[str, Any]) -> Assertion:
    """The same, from an upstream OpenID Provider's claims.

    `sub` is the subject for the same reason `NameID` is: it is the one value
    the OP promises is stable for this person at this issuer.
    """
    return Assertion(
        idp_entity_id=issuer,
        protocol=PROTOCOL_OIDC,
        subject=subject,
        unique_id=_claim(claims, "eduperson_unique_id"),
        eppn=_claim(claims, "eduperson_principal_name") or _claim(claims, "preferred_username"),
        mail=_claim(claims, "email"),
        display_name=_claim(claims, "name"),
        given_name=_claim(claims, "given_name"),
        surname=_claim(claims, "family_name"),
    )


def _one(attributes: dict[str, list[str]], name: str) -> str | None:
    """The first value, or none.

    See the module docstring: first rather than any. Widening the weakest
    linking rule to "matches one of the three addresses they claim" is the
    opposite of what §8.4's ordering is for.
    """
    values = attributes.get(name) or []
    return values[0] if values else None


def _claim(claims: dict[str, Any], name: str) -> str | None:
    """One claim as a string.

    A claim that arrives as a list is read the same way a SAML attribute is —
    an OP is entitled to send `email` as an array even though the specification
    says otherwise, and several do.
    """
    value = claims.get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None
