"""SP metadata generation and schema validation (FR-FED-01).

Metadata is how a federation peer learns what we are: which endpoints to use,
which keys to trust, what we will and will not accept. Getting it wrong is the
single most common cause of a failed integration, and the failures are opaque
— an IdP that cannot parse our descriptor reports very little.

So this module builds it with lxml rather than string templates (element order
in SAML metadata is schema-significant, and a template makes that invisible)
and validates the result against the real OASIS schema.

`RequestedAttribute/@isRequired` is set honestly: only `subject-id` and
`eduPersonPrincipalName` are marked required. An SP that marks everything
required is the anti-pattern this project argues against — it converts an IdP's
release policy into an all-or-nothing decision and pushes operators toward
over-release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from lxml import etree

from campusid.saml.namespaces import DS, MD, SAML
from campusid.saml.parser import hardened_parser
from campusid.saml.schema import METADATA_SCHEMA, load_schema
from campusid.saml.stores import utcnow

SAML2_PROTOCOL: Final = "urn:oasis:names:tc:SAML:2.0:protocol"
BINDING_HTTP_POST: Final = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_HTTP_REDIRECT: Final = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

NAMEID_PERSISTENT: Final = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_TRANSIENT: Final = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
NAMEID_EMAIL: Final = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

ATTRIBUTE_NAME_FORMAT_URI: Final = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"


@dataclass(frozen=True, slots=True)
class RequestedAttribute:
    """An attribute we ask IdPs to release."""

    name: str
    friendly_name: str
    is_required: bool = False


@dataclass(frozen=True, slots=True)
class ContactPerson:
    """A published contact.

    A monitored security contact is a Baseline Expectation of federation
    membership and the precondition for SIRTFI: without one, nobody can tell us
    our SP is compromised.
    """

    contact_type: str
    given_name: str
    surname: str
    email_address: str


@dataclass(frozen=True, slots=True)
class ServiceProviderDescription:
    """Everything needed to render our metadata."""

    entity_id: str
    acs_url: str
    signing_certificates: tuple[str, ...]
    slo_url: str | None = None
    encryption_certificates: tuple[str, ...] = ()
    organization_name: str = "CampusID"
    organization_display_name: str = "CampusID Identity Broker"
    organization_url: str = "https://campus.test/"
    contacts: tuple[ContactPerson, ...] = ()
    name_id_formats: tuple[str, ...] = (NAMEID_PERSISTENT, NAMEID_TRANSIENT, NAMEID_EMAIL)
    requested_attributes: tuple[RequestedAttribute, ...] = ()
    valid_for: timedelta = field(default=timedelta(days=7))


DEFAULT_REQUESTED_ATTRIBUTES: Final[tuple[RequestedAttribute, ...]] = (
    RequestedAttribute(
        "urn:oasis:names:tc:SAML:attribute:subject-id", "subject-id", is_required=True
    ),
    RequestedAttribute(
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName", is_required=True
    ),
    RequestedAttribute("urn:oid:0.9.2342.19200300.100.1.3", "mail"),
    RequestedAttribute("urn:oid:2.16.840.1.113730.3.1.241", "displayName"),
    RequestedAttribute("urn:oid:2.5.4.42", "givenName"),
    RequestedAttribute("urn:oid:2.5.4.4", "sn"),
    RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "eduPersonScopedAffiliation"),
    RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "eduPersonEntitlement"),
)
"""Only the two identifiers are required. Everything else is optional so an IdP
can release a subset without the integration failing outright."""


def build_sp_metadata(
    description: ServiceProviderDescription, now: datetime | None = None
) -> bytes:
    """Render the SP `EntityDescriptor`.

    Child order follows the metadata schema exactly. `SPSSODescriptor` extends
    `SSODescriptorType` extends `RoleDescriptorType`, so the sequence is
    KeyDescriptor, Organization, ContactPerson, ArtifactResolutionService,
    SingleLogoutService, ManageNameIDService, NameIDFormat,
    AssertionConsumerService, AttributeConsumingService. Emitting them in a
    more natural-looking order produces metadata that peers reject.
    """
    now = now or utcnow()

    entity = _element(
        MD,
        "EntityDescriptor",
        entityID=description.entity_id,
        validUntil=_xs_datetime(now + description.valid_for),
        cacheDuration=f"PT{int(description.valid_for.total_seconds()) // 2}S",
    )

    sp = _subelement(
        entity,
        MD,
        "SPSSODescriptor",
        protocolSupportEnumeration=SAML2_PROTOCOL,
        AuthnRequestsSigned="true",
        WantAssertionsSigned="true",
    )

    for certificate in description.signing_certificates:
        _key_descriptor(sp, "signing", certificate)
    for certificate in description.encryption_certificates:
        _key_descriptor(sp, "encryption", certificate)

    if description.slo_url:
        _subelement(
            sp,
            MD,
            "SingleLogoutService",
            Binding=BINDING_HTTP_REDIRECT,
            Location=description.slo_url,
        )

    for name_id_format in description.name_id_formats:
        _subelement(sp, MD, "NameIDFormat").text = name_id_format

    _subelement(
        sp,
        MD,
        "AssertionConsumerService",
        Binding=BINDING_HTTP_POST,
        Location=description.acs_url,
        index="0",
        isDefault="true",
    )

    if description.requested_attributes:
        service = _subelement(sp, MD, "AttributeConsumingService", index="0", isDefault="true")
        _subelement(
            service, MD, "ServiceName", **{_xml("lang"): "en"}
        ).text = description.organization_display_name
        for attribute in description.requested_attributes:
            _subelement(
                service,
                MD,
                "RequestedAttribute",
                Name=attribute.name,
                NameFormat=ATTRIBUTE_NAME_FORMAT_URI,
                FriendlyName=attribute.friendly_name,
                isRequired="true" if attribute.is_required else "false",
            )

    organization = _subelement(entity, MD, "Organization")
    _subelement(
        organization, MD, "OrganizationName", **{_xml("lang"): "en"}
    ).text = description.organization_name
    _subelement(
        organization, MD, "OrganizationDisplayName", **{_xml("lang"): "en"}
    ).text = description.organization_display_name
    _subelement(
        organization, MD, "OrganizationURL", **{_xml("lang"): "en"}
    ).text = description.organization_url

    for contact in description.contacts:
        person = _subelement(entity, MD, "ContactPerson", contactType=contact.contact_type)
        _subelement(person, MD, "GivenName").text = contact.given_name
        _subelement(person, MD, "SurName").text = contact.surname
        _subelement(person, MD, "EmailAddress").text = f"mailto:{contact.email_address}"

    return etree.tostring(entity, xml_declaration=True, encoding="UTF-8", pretty_print=True)


def validate_metadata(document: bytes) -> None:
    """Validate against the OASIS metadata schema, raising on failure.

    `etree.DocumentInvalid` carries the schema's own error log, which names the
    offending element — far more useful than a generic message when the cause
    is usually a child in the wrong position.
    """
    # Hardened: metadata arriving from a peer is untrusted input, fetched over
    # the network, and schema validation happens *after* parsing. An XXE in a
    # metadata document would fire before the schema ever saw it.
    metadata_schema().assertValid(etree.fromstring(document, parser=hardened_parser()))


def metadata_schema() -> etree.XMLSchema:
    """The compiled SAML metadata schema."""
    return load_schema(METADATA_SCHEMA)


def certificate_body(pem: str) -> str:
    """Strip a PEM certificate to the base64 body `ds:X509Certificate` wants."""
    return "".join(
        line.strip()
        for line in pem.strip().splitlines()
        if line.strip() and not line.startswith("-----")
    )


def _key_descriptor(parent: etree._Element, use: str, certificate: str) -> None:
    descriptor = _subelement(parent, MD, "KeyDescriptor", use=use)
    key_info = _subelement(descriptor, DS, "KeyInfo")
    x509_data = _subelement(key_info, DS, "X509Data")
    _subelement(x509_data, DS, "X509Certificate").text = certificate_body(certificate)


_NSMAP: Final[dict[str, str]] = {"md": MD, "ds": DS, "saml": SAML}


def _element(namespace: str, tag: str, **attributes: str) -> etree._Element:
    element = etree.Element(f"{{{namespace}}}{tag}", nsmap=_NSMAP)
    for name, value in attributes.items():
        element.set(name, value)
    return element


def _subelement(
    parent: etree._Element, namespace: str, tag: str, **attributes: str
) -> etree._Element:
    element = etree.SubElement(parent, f"{{{namespace}}}{tag}")
    for name, value in attributes.items():
        element.set(name, value)
    return element


def _xml(local_name: str) -> str:
    return f"{{http://www.w3.org/XML/1998/namespace}}{local_name}"


def _xs_datetime(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
