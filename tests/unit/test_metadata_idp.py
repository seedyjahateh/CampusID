"""Parsing IdP metadata (FR-FED-02/03).

Metadata is the root of trust: the certificate that verifies every assertion
and the endpoint the browser is sent to both come from here. A parser that
accepts too much silently weakens every check downstream, so the rejections
matter as much as the successes.
"""

from __future__ import annotations

import datetime as dt

import pytest

from campusid.errors import MetadataRejected, ReasonCode
from campusid.saml.metadata_idp import parse_idp_metadata
from campusid.saml.metadata_sp import BINDING_HTTP_POST
from campusid.saml.namespaces import MD
from tests.support.saml_forge import ForgedIdP


def test_parses_a_well_formed_descriptor(idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(idp.metadata())

    assert descriptor.entity_id == idp.entity_id
    assert descriptor.redirect_sso_url == f"{idp.entity_id}/sso"
    assert descriptor.sso_bindings[BINDING_HTTP_POST] == f"{idp.entity_id}/sso"
    assert descriptor.slo_url == f"{idp.entity_id}/slo"
    assert descriptor.want_authn_requests_signed is True
    assert descriptor.cache_duration == dt.timedelta(hours=1)


def test_the_signing_certificate_is_usable_for_verification(idp: ForgedIdP) -> None:
    """The parsed certificate must verify a real assertion from this IdP.

    Round-tripping through metadata is where PEM/DER mistakes surface, and
    their failure mode is an opaque `signature_invalid` on every login.
    """
    from campusid.saml.namespaces import Q_ASSERTION
    from campusid.saml.parser import parse_saml
    from campusid.saml.signature import ASSERTION_SIGNATURE_LOCATION, verify_signature

    descriptor = parse_idp_metadata(idp.metadata())
    root = parse_saml(idp.response())
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None

    result = verify_signature(
        root,
        assertion,
        location=ASSERTION_SIGNATURE_LOCATION,
        certificates=descriptor.signing_certificates,
    )

    assert result.element.get("ID") == "_assertion1"


def test_a_key_with_no_use_attribute_counts_as_signing(idp: ForgedIdP) -> None:
    """`use` is optional and its absence means both purposes.

    Plenty of IdPs publish one dual-purpose key; skipping those would break
    every login against them.
    """
    descriptor = parse_idp_metadata(idp.metadata(key_use=None))

    assert len(descriptor.signing_certificates) == 1


def test_an_encryption_only_key_is_not_used_for_signing(idp: ForgedIdP) -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(key_use="encryption"))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_metadata_without_a_signing_key_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(include_key=False))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_metadata_without_an_sso_endpoint_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(include_sso=False))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_expired_metadata_is_refused(idp: ForgedIdP) -> None:
    """Metadata that never expires means a retired key stays trusted until a
    human notices — the failure `validUntil` exists to prevent."""
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(valid_until=dt.datetime.now(dt.UTC) - dt.timedelta(days=1)))

    assert exc.value.reason is ReasonCode.METADATA_EXPIRED


def test_metadata_valid_until_the_future_is_accepted(idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(
        idp.metadata(valid_until=dt.datetime.now(dt.UTC) + dt.timedelta(days=7))
    )

    assert descriptor.valid_until is not None


def test_a_corrupt_certificate_is_refused_at_parse_time(idp: ForgedIdP) -> None:
    """Rejected here, where the error names the metadata, rather than at the
    first login where it would look like a signature problem."""
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(certificate_override="bm90LWEtY2VydGlmaWNhdGU="))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_an_sp_descriptor_is_not_mistaken_for_an_idp(idp: ForgedIdP) -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(role="SPSSODescriptor"))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_metadata_that_fails_the_schema_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(b"<md:EntityDescriptor/>")

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_a_wrong_root_element_is_refused() -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(b"<Nonsense/>", validate_schema=False)

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_requesting_a_different_entity_is_refused(idp: ForgedIdP) -> None:
    """Naming the expected entityID guards against a redirect or a swapped
    file handing us metadata for a different IdP entirely."""
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(), entity_id="https://not-this-one.test/saml")

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_the_expected_entity_is_accepted(idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(idp.metadata(), entity_id=idp.entity_id)

    assert descriptor.entity_id == idp.entity_id


def test_missing_redirect_binding_is_reported_clearly(idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(idp.metadata(sso_bindings=(BINDING_HTTP_POST,)))

    with pytest.raises(MetadataRejected) as exc:
        _ = descriptor.redirect_sso_url

    assert exc.value.reason is ReasonCode.METADATA_INVALID


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        ("PT3600S", dt.timedelta(hours=1)),
        ("P1D", dt.timedelta(days=1)),
        ("PT15M", dt.timedelta(minutes=15)),
        ("P1DT2H30M", dt.timedelta(days=1, hours=2, minutes=30)),
    ],
)
def test_cache_duration_parsing(idp: ForgedIdP, duration: str, expected: dt.timedelta) -> None:
    assert parse_idp_metadata(idp.metadata(cache_duration=duration)).cache_duration == expected


def test_an_unsupported_duration_is_refused(idp: ForgedIdP) -> None:
    """Years and months have no fixed length, so honouring them would mean
    guessing. No federation publishes a cache duration in months."""
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(idp.metadata(cache_duration="P1Y"))

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_malformed_xml_is_refused_even_without_schema_validation() -> None:
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(b"<md:EntityDescriptor><unclosed>", validate_schema=False)

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_an_entity_without_an_entity_id_is_refused() -> None:
    document = (
        f'<md:EntityDescriptor xmlns:md="{MD}">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="p"/>'
        f"</md:EntityDescriptor>"
    ).encode()

    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(document, validate_schema=False)

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def _aggregate(first: bytes, second: bytes) -> bytes:
    return (
        f'<md:EntitiesDescriptor xmlns:md="{MD}">'
        + first.decode()
        + second.decode()
        + "</md:EntitiesDescriptor>"
    ).encode()


def test_an_aggregate_requires_naming_the_entity(idp: ForgedIdP, other_idp: ForgedIdP) -> None:
    """A federation aggregate carries hundreds of entities. Picking one
    arbitrarily would silently trust whichever happened to come first."""
    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(_aggregate(idp.metadata(), other_idp.metadata()), validate_schema=False)

    assert exc.value.reason is ReasonCode.METADATA_INVALID


def test_an_aggregate_resolves_the_named_entity(idp: ForgedIdP, other_idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(
        _aggregate(idp.metadata(), other_idp.metadata()),
        entity_id=other_idp.entity_id,
        validate_schema=False,
    )

    assert descriptor.entity_id == other_idp.entity_id


@pytest.mark.parametrize(
    ("label", "valid_until"),
    [
        ("not_a_datetime", "soon"),
        # Refused rather than assumed UTC: guessing shifts the expiry by hours
        # in whichever direction the guess happens to fall.
        ("naive_datetime", "2030-01-01T00:00:00"),
    ],
)
def test_a_malformed_valid_until_is_refused(idp: ForgedIdP, label: str, valid_until: str) -> None:
    document = idp.metadata().replace(
        b"entityID=", f'validUntil="{valid_until}" entityID='.encode(), 1
    )

    with pytest.raises(MetadataRejected) as exc:
        parse_idp_metadata(document, validate_schema=False)

    assert exc.value.reason is ReasonCode.METADATA_INVALID, label


def test_absent_optional_fields_are_none(idp: ForgedIdP) -> None:
    descriptor = parse_idp_metadata(idp.metadata(cache_duration=None, include_slo=False))

    assert descriptor.cache_duration is None
    assert descriptor.valid_until is None
    assert descriptor.slo_url is None
