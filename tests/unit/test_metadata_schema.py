"""SP metadata generation and schema validation (PRD acceptance criterion 6).

The schema check is the point. Element order in SAML metadata is significant,
and a descriptor with children in a plausible-but-wrong order is accepted by
every tool that reads it loosely and rejected by the strict ones — which is how
an integration passes in test and fails against a real IdP.
"""

from __future__ import annotations

import pytest
from lxml import etree

from campusid.saml.metadata_sp import (
    BINDING_HTTP_POST,
    DEFAULT_REQUESTED_ATTRIBUTES,
    ContactPerson,
    RequestedAttribute,
    ServiceProviderDescription,
    build_sp_metadata,
    certificate_body,
    metadata_schema,
    validate_metadata,
)
from campusid.saml.namespaces import DS, MD, qn
from tests.support.saml_forge import SigningKey, generate_signing_key


@pytest.fixture(scope="module")
def key() -> SigningKey:
    return generate_signing_key("broker.test")


@pytest.fixture
def description(key: SigningKey) -> ServiceProviderDescription:
    return ServiceProviderDescription(
        entity_id="https://broker.test/saml/metadata",
        acs_url="https://broker.test/saml/acs",
        slo_url="https://broker.test/saml/sls",
        signing_certificates=(key.certificate_pem,),
        contacts=(
            ContactPerson("technical", "Dana", "Wu", "iam@campus.test"),
            ContactPerson("other", "Security", "Office", "security@campus.test"),
        ),
        requested_attributes=DEFAULT_REQUESTED_ATTRIBUTES,
    )


def test_metadata_validates_against_the_oasis_schema(
    description: ServiceProviderDescription,
) -> None:
    validate_metadata(build_sp_metadata(description))


def test_metadata_with_an_encryption_key_validates(key: SigningKey) -> None:
    validate_metadata(
        build_sp_metadata(
            ServiceProviderDescription(
                entity_id="https://broker.test/saml/metadata",
                acs_url="https://broker.test/saml/acs",
                signing_certificates=(key.certificate_pem,),
                encryption_certificates=(key.certificate_pem,),
            )
        )
    )


def test_minimal_metadata_validates(key: SigningKey) -> None:
    """No SLO, no contacts, no requested attributes: still valid."""
    validate_metadata(
        build_sp_metadata(
            ServiceProviderDescription(
                entity_id="https://broker.test/saml/metadata",
                acs_url="https://broker.test/saml/acs",
                signing_certificates=(key.certificate_pem,),
            )
        )
    )


def test_two_signing_certificates_validate(key: SigningKey) -> None:
    """A key rollover publishes both certificates at once (FR-FED-05)."""
    incoming = generate_signing_key("broker-next.test")

    validate_metadata(
        build_sp_metadata(
            ServiceProviderDescription(
                entity_id="https://broker.test/saml/metadata",
                acs_url="https://broker.test/saml/acs",
                signing_certificates=(key.certificate_pem, incoming.certificate_pem),
            )
        )
    )


def test_the_schema_check_actually_rejects_bad_metadata() -> None:
    """The control.

    A validator that accepted anything would make every test above pass. This
    reorders `Organization` before `SPSSODescriptor` — plausible-looking, and
    invalid.
    """
    broken = (
        f'<md:EntityDescriptor xmlns:md="{MD}" entityID="https://broker.test">'
        f"<md:Organization>"
        f'<md:OrganizationName xml:lang="en">CampusID</md:OrganizationName>'
        f'<md:OrganizationDisplayName xml:lang="en">CampusID</md:OrganizationDisplayName>'
        f'<md:OrganizationURL xml:lang="en">https://campus.test/</md:OrganizationURL>'
        f"</md:Organization>"
        f'<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<md:AssertionConsumerService Binding="{BINDING_HTTP_POST}"'
        f' Location="https://broker.test/saml/acs" index="0"/>'
        f"</md:SPSSODescriptor>"
        f"</md:EntityDescriptor>"
    ).encode()

    with pytest.raises(etree.DocumentInvalid):
        validate_metadata(broken)


def test_advertises_the_security_posture_we_enforce(
    description: ServiceProviderDescription,
) -> None:
    """Metadata is a promise to peers; it must match what the gate does.

    Advertising `WantAssertionsSigned="false"` while the gate requires one
    would have IdPs configure themselves into failing logins.
    """
    root = etree.fromstring(build_sp_metadata(description))
    sp = root.find(qn(MD, "SPSSODescriptor"))
    assert sp is not None

    assert sp.get("WantAssertionsSigned") == "true"
    assert sp.get("AuthnRequestsSigned") == "true"


def test_publishes_the_signing_certificate(
    description: ServiceProviderDescription, key: SigningKey
) -> None:
    root = etree.fromstring(build_sp_metadata(description))
    certificate = root.find(f".//{qn(DS, 'X509Certificate')}")

    assert certificate is not None
    assert certificate.text == certificate_body(key.certificate_pem)
    assert "BEGIN CERTIFICATE" not in (certificate.text or "")


def test_only_the_two_identifiers_are_required(
    description: ServiceProviderDescription,
) -> None:
    """An SP that marks every attribute required turns the IdP's release policy
    into all-or-nothing, which is how over-release gets normalised."""
    root = etree.fromstring(build_sp_metadata(description))

    required = {
        element.get("FriendlyName")
        for element in root.iter(qn(MD, "RequestedAttribute"))
        if element.get("isRequired") == "true"
    }

    assert required == {"subject-id", "eduPersonPrincipalName"}


def test_requested_attributes_use_uri_name_format(
    description: ServiceProviderDescription,
) -> None:
    """Shibboleth and Keycloak key their attribute mappers on the URI form;
    the basic form silently releases nothing."""
    root = etree.fromstring(build_sp_metadata(description))

    formats = {element.get("NameFormat") for element in root.iter(qn(MD, "RequestedAttribute"))}

    assert formats == {"urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}


def test_metadata_declares_an_expiry(description: ServiceProviderDescription) -> None:
    """Metadata without `validUntil` never goes stale, so a compromised key
    stays trusted until someone notices by hand."""
    root = etree.fromstring(build_sp_metadata(description))

    assert root.get("validUntil", "").endswith("Z")
    assert root.get("cacheDuration", "").startswith("PT")


def test_a_custom_requested_attribute_validates(key: SigningKey) -> None:
    validate_metadata(
        build_sp_metadata(
            ServiceProviderDescription(
                entity_id="https://broker.test/saml/metadata",
                acs_url="https://broker.test/saml/acs",
                signing_certificates=(key.certificate_pem,),
                requested_attributes=(
                    RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.13", "eduPersonUniqueId"),
                ),
            )
        )
    )


def test_schema_compilation_is_cached() -> None:
    """Compilation costs ~50ms; the metadata endpoint must not pay it per request."""
    assert metadata_schema() is metadata_schema()


def test_schema_loading_never_reaches_the_network() -> None:
    """The metadata schema imports xmldsig, xmlenc and xml.xsd by absolute URL.

    Resolving those over the network would make validation slow, flaky, broken
    in CI, and dependent on whoever can answer for w3.org. This asserts every
    import is satisfied from the vendored directory.
    """
    from campusid.saml.metadata_sp import SCHEMA_DIR, _LocalSchemaResolver

    resolver = _LocalSchemaResolver()

    with pytest.raises(FileNotFoundError, match="not vendored"):
        resolver.resolve("http://example.test/not-vendored.xsd", None, None)

    assert (SCHEMA_DIR / "xmldsig-core-schema.xsd").is_file()
    assert (SCHEMA_DIR / "xenc-schema.xsd").is_file()
    assert (SCHEMA_DIR / "xml.xsd").is_file()
