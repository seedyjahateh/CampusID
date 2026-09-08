"""Building and signing an `AuthnRequest` for the HTTP-Redirect binding.

**This signature is not XML-DSig.** SAML Bindings 3.4.4.1 signs the *query
string*: the octet sequence formed by concatenating the URL-encoded parameters
in the order `SAMLRequest`, `RelayState` (if present), `SigAlg`. signxml has
nothing to do with it. Every other signature in this codebase is XML; this one
is raw bytes, and treating it like the others produces a request every IdP
rejects with an unhelpful error.

Two encoding traps come with that.

**The payload is raw DEFLATE, not zlib.** `zlib.compress` prepends a two-byte
header and appends a checksum, both of which make the request undecodable to a
peer. The binding wants the bare deflate stream, which is
`zlib.compressobj(wbits=-15)`.

**The signature covers the string as it appears in the URL.** Percent-encoding
must happen once, before signing, and the exact bytes signed must be the exact
bytes sent. Re-encoding between the two — even a change from `%20` to `+` —
invalidates the signature while leaving a URL that looks perfectly correct.
`verify_redirect_signature` therefore reconstructs its input from the raw query
string exactly as a peer would, rather than from any structure we kept, so the
round-trip test proves interoperability rather than self-consistency.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from urllib.parse import quote, unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.metadata_sp import BINDING_HTTP_POST, NAMEID_PERSISTENT
from campusid.saml.namespaces import SAML, SAMLP
from campusid.saml.schema import PROTOCOL_SCHEMA, load_schema
from campusid.saml.stores import utcnow

RSA_SHA256_SIG_ALG: Final = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
PASSWORD_PROTECTED_TRANSPORT: Final = (
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)
REFEDS_MFA: Final = "https://refeds.org/profile/mfa"

SIGNED_PARAMETER_ORDER: Final = ("SAMLRequest", "SAMLResponse", "RelayState", "SigAlg")
"""The order the binding requires. Not alphabetical, not insertion order."""


@dataclass(frozen=True, slots=True)
class AuthnRequestPolicy:
    """What our `AuthnRequest` asks for."""

    entity_id: str
    acs_url: str
    name_id_format: str = NAMEID_PERSISTENT
    force_authn: bool = False
    is_passive: bool = False
    authn_context_class_ref: str | None = PASSWORD_PROTECTED_TRANSPORT
    comparison: str = "exact"
    """`exact` per PRD FR-SAML-11.

    M1 sends `PasswordProtectedTransport`, not the REFEDS MFA profile: Keycloak
    does not satisfy REFEDS MFA and answers with `unspecified`, so requesting
    it with `Comparison="exact"` would fail every login. Step-up (M4) is where
    a stronger context has somewhere to escalate to.
    """


@dataclass(frozen=True, slots=True)
class PreparedAuthnRequest:
    """A request ready to send, and the state needed to correlate its answer."""

    request_id: str
    relay_state: str
    redirect_url: str
    xml: bytes


def build_authn_request(
    policy: AuthnRequestPolicy,
    destination: str,
    *,
    request_id: str,
    now: datetime,
) -> bytes:
    """Render the `AuthnRequest` element.

    Child order follows the protocol schema: `Issuer`, then `NameIDPolicy`,
    then `RequestedAuthnContext`.
    """
    request = etree.Element(
        f"{{{SAMLP}}}AuthnRequest",
        nsmap={"samlp": SAMLP, "saml": SAML},
    )
    request.set("ID", request_id)
    request.set("Version", "2.0")
    request.set("IssueInstant", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    request.set("Destination", destination)
    request.set("ProtocolBinding", BINDING_HTTP_POST)
    request.set("AssertionConsumerServiceURL", policy.acs_url)
    request.set("ForceAuthn", "true" if policy.force_authn else "false")
    request.set("IsPassive", "true" if policy.is_passive else "false")

    issuer = etree.SubElement(request, f"{{{SAML}}}Issuer")
    issuer.text = policy.entity_id

    name_id_policy = etree.SubElement(request, f"{{{SAMLP}}}NameIDPolicy")
    name_id_policy.set("Format", policy.name_id_format)
    name_id_policy.set("AllowCreate", "true")

    if policy.authn_context_class_ref is not None:
        context = etree.SubElement(request, f"{{{SAMLP}}}RequestedAuthnContext")
        context.set("Comparison", policy.comparison)
        class_ref = etree.SubElement(context, f"{{{SAML}}}AuthnContextClassRef")
        class_ref.text = policy.authn_context_class_ref

    result: bytes = etree.tostring(request, encoding="UTF-8", xml_declaration=False)
    return result


def prepare_redirect(
    policy: AuthnRequestPolicy,
    destination: str,
    signing_key_pem: bytes,
    *,
    request_id: str | None = None,
    relay_state: str | None = None,
    now: datetime | None = None,
    sig_alg: str = RSA_SHA256_SIG_ALG,
) -> PreparedAuthnRequest:
    """Build, deflate, encode and sign a redirect-binding `AuthnRequest`.

    ``relay_state`` doubles as the correlation key for the outstanding-request
    store. It is opaque and unguessable so that a response can be tied back to
    the browser that started the flow without a cookie — a `SameSite=Lax`
    cookie is not sent on the cross-site POST an external IdP makes to our ACS.
    """
    now = now or utcnow()
    request_id = request_id or new_id()
    relay_state = relay_state or secrets.token_urlsafe(32)

    xml = build_authn_request(policy, destination, request_id=request_id, now=now)
    encoded = base64.b64encode(deflate(xml)).decode("ascii")

    signing_input = "&".join(
        (
            f"SAMLRequest={quote(encoded, safe='')}",
            f"RelayState={quote(relay_state, safe='')}",
            f"SigAlg={quote(sig_alg, safe='')}",
        )
    )
    signature = _sign(signing_input.encode("ascii"), signing_key_pem)
    separator = "&" if "?" in destination else "?"

    return PreparedAuthnRequest(
        request_id=request_id,
        relay_state=relay_state,
        redirect_url=(
            f"{destination}{separator}{signing_input}"
            f"&Signature={quote(base64.b64encode(signature).decode('ascii'), safe='')}"
        ),
        xml=xml,
    )


def verify_redirect_signature(query_string: str, certificates: tuple[str, ...]) -> None:
    """Verify a redirect-binding signature the way a peer would.

    Reconstructs the signed octets from the **raw** query string rather than
    from any parsed structure. That is what makes the round-trip test
    meaningful: sharing a helper with the signer would only prove we agree with
    ourselves, while this catches a mismatch between what we signed and what we
    actually put on the wire.
    """
    raw: dict[str, str] = {}
    for pair in query_string.split("&"):
        name, _, value = pair.partition("=")
        raw.setdefault(name, value)

    if "Signature" not in raw:
        raise SamlRejected(ReasonCode.SIGNATURE_MISSING, "query string carries no Signature")

    signing_input = "&".join(
        f"{name}={raw[name]}" for name in SIGNED_PARAMETER_ORDER if name in raw
    ).encode("ascii")
    signature = base64.b64decode(unquote(raw["Signature"]))

    for certificate in certificates:
        public_key = load_pem_x509_certificate(certificate.encode()).public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            continue
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            continue
        return

    raise SamlRejected(
        ReasonCode.SIGNATURE_INVALID,
        f"no registered certificate ({len(certificates)} tried) verifies the query signature",
    )


def decode_saml_request(encoded: str) -> bytes:
    """Reverse the transport encoding: base64, then raw inflate."""
    try:
        return inflate(base64.b64decode(unquote(encoded)))
    except (ValueError, zlib.error) as exc:
        raise SamlRejected(
            ReasonCode.MALFORMED_RESPONSE, f"SAMLRequest is not valid base64/deflate: {exc}"
        ) from exc


def deflate(data: bytes) -> bytes:
    """Raw DEFLATE, with no zlib header or trailing checksum."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def inflate(data: bytes) -> bytes:
    """Inverse of `deflate`."""
    return zlib.decompress(data, -zlib.MAX_WBITS)


def new_id() -> str:
    """A SAML identifier.

    `ID` is `xs:ID`, an NCName, so it may not start with a digit — hence the
    leading underscore that every SAML implementation emits.
    """
    return f"_{secrets.token_hex(16)}"


def validate_protocol_document(document: bytes) -> None:
    """Validate against the SAML protocol schema, raising on failure."""
    load_schema(PROTOCOL_SCHEMA).assertValid(
        etree.fromstring(document, parser=etree.XMLParser(no_network=True))
    )


def _sign(payload: bytes, signing_key_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(signing_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError(f"redirect-binding signing needs an RSA key, got {type(key).__name__}")
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
