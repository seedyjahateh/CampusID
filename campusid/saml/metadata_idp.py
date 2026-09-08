"""Parsing an IdP's metadata into something the gate can trust (FR-FED-02/03).

Metadata is the root of trust. Everything the gate later enforces — which
certificate verifies an assertion, which endpoint the browser is sent to —
comes from here, so a permissive parser undermines every check downstream.

Three decisions worth stating.

**A `KeyDescriptor` with no `use` is valid for signing.** The attribute is
optional and its absence means "both uses", so skipping those keys would break
against IdPs that publish one dual-purpose key — a surprisingly common
configuration, and one whose failure mode is an opaque `signature_invalid` on
every login.

**Certificates are parsed, not just decoded.** A descriptor carrying a
truncated or corrupt certificate is rejected here, where the error names the
metadata, rather than at the first login, where it looks like a signature
problem.

**`validUntil` is enforced.** Metadata that never expires means a compromised
or retired key stays trusted until a human notices, which is the failure mode
`validUntil` exists to prevent.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from cryptography import x509
from lxml import etree

from campusid.errors import MetadataRejected, ReasonCode
from campusid.saml.metadata_sp import (
    BINDING_HTTP_REDIRECT,
    validate_metadata,
)
from campusid.saml.namespaces import DS, MD, qn
from campusid.saml.parser import hardened_parser, text_of
from campusid.saml.stores import utcnow

Q_ENTITY_DESCRIPTOR: Final = qn(MD, "EntityDescriptor")
Q_ENTITIES_DESCRIPTOR: Final = qn(MD, "EntitiesDescriptor")
Q_IDP_SSO_DESCRIPTOR: Final = qn(MD, "IDPSSODescriptor")
Q_KEY_DESCRIPTOR: Final = qn(MD, "KeyDescriptor")
Q_SSO_SERVICE: Final = qn(MD, "SingleSignOnService")
Q_SLO_SERVICE: Final = qn(MD, "SingleLogoutService")
Q_X509_CERTIFICATE: Final = qn(DS, "X509Certificate")

_DURATION = re.compile(
    r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$"
)


@dataclass(frozen=True, slots=True)
class IdentityProviderDescriptor:
    """What we learned about an IdP from its metadata."""

    entity_id: str
    sso_bindings: dict[str, str]
    signing_certificates: tuple[str, ...]
    slo_url: str | None = None
    want_authn_requests_signed: bool = False
    valid_until: datetime | None = None
    cache_duration: timedelta | None = None

    @property
    def redirect_sso_url(self) -> str:
        """The SSO endpoint for the HTTP-Redirect binding.

        Preferred over HTTP-POST for `AuthnRequest`: it keeps the request in a
        GET the browser follows without an interstitial auto-submitting form.
        """
        url = self.sso_bindings.get(BINDING_HTTP_REDIRECT)
        if url is None:
            raise MetadataRejected(
                ReasonCode.METADATA_INVALID,
                f"{self.entity_id!r} publishes no HTTP-Redirect SSO endpoint",
            )
        return url


def parse_idp_metadata(
    document: bytes,
    *,
    entity_id: str | None = None,
    now: datetime | None = None,
    validate_schema: bool = True,
) -> IdentityProviderDescriptor:
    """Parse an IdP descriptor, or raise `MetadataRejected`.

    ``entity_id`` selects one entity from an aggregate; with a single-entity
    document it is an assertion that we got the entity we asked for, which
    guards against a redirect or a swapped file handing us a different IdP.
    """
    now = now or utcnow()

    if validate_schema:
        try:
            validate_metadata(document)
        except etree.DocumentInvalid as exc:
            raise MetadataRejected(
                ReasonCode.METADATA_INVALID, f"does not satisfy the metadata schema: {exc}"
            ) from exc
        except etree.XMLSyntaxError as exc:
            raise MetadataRejected(
                ReasonCode.METADATA_INVALID, f"is not well-formed XML: {exc}"
            ) from exc

    try:
        root = etree.fromstring(document, parser=hardened_parser())
    except etree.XMLSyntaxError as exc:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID, f"is not well-formed XML: {exc}"
        ) from exc

    entity = _select_entity(root, entity_id)
    _assert_not_expired(entity, now)

    descriptor = entity.find(Q_IDP_SSO_DESCRIPTOR)
    if descriptor is None:
        raise MetadataRejected(ReasonCode.METADATA_INVALID, "contains no IDPSSODescriptor role")

    resolved_entity_id = entity.get("entityID")
    if not resolved_entity_id:
        raise MetadataRejected(ReasonCode.METADATA_INVALID, "EntityDescriptor has no entityID")

    certificates = _signing_certificates(descriptor)
    if not certificates:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"{resolved_entity_id!r} publishes no usable signing certificate",
        )

    bindings = {
        binding: location
        for service in descriptor.findall(Q_SSO_SERVICE)
        if (binding := service.get("Binding")) and (location := service.get("Location"))
    }
    if not bindings:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"{resolved_entity_id!r} publishes no SingleSignOnService endpoint",
        )

    logout = descriptor.find(Q_SLO_SERVICE)

    return IdentityProviderDescriptor(
        entity_id=resolved_entity_id,
        sso_bindings=bindings,
        signing_certificates=certificates,
        slo_url=logout.get("Location") if logout is not None else None,
        want_authn_requests_signed=descriptor.get("WantAuthnRequestsSigned") == "true",
        valid_until=_valid_until(entity),
        cache_duration=_cache_duration(entity),
    )


def _select_entity(root: etree._Element, entity_id: str | None) -> etree._Element:
    """Find the entity to use, in a single descriptor or an aggregate."""
    if root.tag == Q_ENTITY_DESCRIPTOR:
        candidates = [root]
    elif root.tag == Q_ENTITIES_DESCRIPTOR:
        candidates = list(root.iter(Q_ENTITY_DESCRIPTOR))
    else:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"root element is {etree.QName(root).localname!r}, "
            "expected EntityDescriptor or EntitiesDescriptor",
        )

    if entity_id is not None:
        for candidate in candidates:
            if candidate.get("entityID") == entity_id:
                return candidate
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"does not describe the requested entity {entity_id!r}",
        )

    if len(candidates) != 1:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"describes {len(candidates)} entities; name the one to use",
        )
    return candidates[0]


def _signing_certificates(descriptor: etree._Element) -> tuple[str, ...]:
    """Collect signing certificates, as PEM.

    A `KeyDescriptor` with no `use` attribute serves both purposes per the
    metadata schema, so it counts as a signing key. Ignoring those breaks
    against every IdP that publishes a single dual-use key.
    """
    certificates: list[str] = []
    for key_descriptor in descriptor.findall(Q_KEY_DESCRIPTOR):
        if key_descriptor.get("use") not in (None, "signing"):
            continue
        for element in key_descriptor.iter(Q_X509_CERTIFICATE):
            body = "".join(text_of(element).split())
            if body:
                certificates.append(_to_pem(body))
    return tuple(certificates)


def _to_pem(base64_der: str) -> str:
    """Wrap base64 DER as PEM, rejecting anything that is not a certificate."""
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(textwrap.wrap(base64_der, 64))
        + "\n-----END CERTIFICATE-----\n"
    )
    try:
        x509.load_pem_x509_certificate(pem.encode())
    except ValueError as exc:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID, f"X509Certificate is not a valid certificate: {exc}"
        ) from exc
    return pem


def _assert_not_expired(entity: etree._Element, now: datetime) -> None:
    valid_until = _valid_until(entity)
    if valid_until is not None and now >= valid_until:
        raise MetadataRejected(
            ReasonCode.METADATA_EXPIRED,
            f"validUntil {valid_until.isoformat()} has passed",
        )


def _valid_until(entity: etree._Element) -> datetime | None:
    raw = entity.get("validUntil")
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID, f"validUntil={raw!r} is not a valid xs:dateTime"
        ) from exc
    if parsed.tzinfo is None:
        raise MetadataRejected(ReasonCode.METADATA_INVALID, f"validUntil={raw!r} has no timezone")
    return parsed


def _cache_duration(entity: etree._Element) -> timedelta | None:
    """Parse the `xs:duration` subset that appears in real metadata.

    Years and months are deliberately unsupported: they have no fixed length,
    so honouring them would mean guessing, and no federation publishes a cache
    duration in months.
    """
    raw = entity.get("cacheDuration")
    if raw is None:
        return None
    match = _DURATION.match(raw)
    if match is None:
        raise MetadataRejected(
            ReasonCode.METADATA_INVALID,
            f"cacheDuration={raw!r} is not a supported xs:duration",
        )
    parts = {name: float(value) for name, value in match.groupdict(default="0").items()}
    return timedelta(
        days=parts["days"],
        hours=parts["hours"],
        minutes=parts["minutes"],
        seconds=parts["seconds"],
    )
