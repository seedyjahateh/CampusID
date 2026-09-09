"""A hostile IdP, for tests.

Mints SAML responses with real signatures and arbitrary defects, so a negative
test reads as one line of intent rather than a pasted blob of XML:

    idp.response(audience="https://elsewhere.test")
    idp.response(sign_with=other_idp.key)
    idp.response(xsw=3)

Keys are generated in memory per test session and never written to disk.
`.gitignore` blocks `*.pem`/`*.key` and gitleaks runs over the full history in
CI, so a committed test key would fail the build — as it should, in a project
whose subject is credential handling.

Distinct from `xmlbuild.py`, which builds structurally-shaped XML with
cryptographically meaningless signatures. That is the right tool for the
predicates that run *before* verification, and it costs no key generation. This
module is for anything that has to actually verify.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
from dataclasses import dataclass, field
from typing import Literal

import signxml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import DigestAlgorithm, SignatureMethod, XMLSigner

from campusid.saml.metadata_sp import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    SAML2_PROTOCOL,
    certificate_body,
)
from campusid.saml.namespaces import (
    BEARER_CONFIRMATION_METHOD,
    MD,
    NS,
    Q_ASSERTION,
    Q_ISSUER,
    Q_RESPONSE,
    Q_SIGNATURE,
    SAML,
    SAMLP,
    XENC,
    XENC11,
)

XMLDSIG_TIME = "%Y-%m-%dT%H:%M:%SZ"

SignTarget = Literal["assertion", "response", "both"] | None

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)

# --- XML Encryption algorithm URIs ------------------------------------------
# Declared before ForgedIdP because they are default argument values, which
# Python evaluates when the class body runs.
AES128_GCM = f"{XENC11}aes128-gcm"
AES256_GCM = f"{XENC11}aes256-gcm"
AES256_CBC = f"{XENC}aes256-cbc"
RSA_OAEP = f"{XENC11}rsa-oaep"
RSA_OAEP_MGF1P = f"{XENC}rsa-oaep-mgf1p"
RSA_1_5 = f"{XENC}rsa-1_5"

_GCM_KEY_BYTES = {AES128_GCM: 16, f"{XENC11}aes192-gcm": 24, AES256_GCM: 32}


@dataclass(frozen=True, slots=True)
class SigningKey:
    """An RSA key and its self-signed certificate, PEM-encoded.

    The asymmetry is signxml's: it takes the key as bytes and the certificate
    as text. Certificates are text throughout the broker anyway, since SAML
    metadata carries them as base64 in an XML element.
    """

    private_pem: bytes
    certificate_pem: str


def generate_signing_key(common_name: str = "idp.test") -> SigningKey:
    """Generate a 2048-bit RSA key and a self-signed certificate.

    ~100 ms, so bind it to a session-scoped fixture rather than a function one.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return SigningKey(
        private_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
    )


def _timestamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.UTC).strftime(XMLDSIG_TIME)


@dataclass
class ForgedIdP:
    """A SAML IdP that will sign anything you ask it to."""

    entity_id: str = "https://idp.test/saml"
    key: SigningKey = field(default_factory=generate_signing_key)

    # --- what a well-behaved response looks like -------------------------
    default_audience: str = "https://broker.test/saml/metadata"
    default_destination: str = "https://broker.test/saml/acs"

    def metadata(
        self,
        *,
        valid_until: dt.datetime | None = None,
        cache_duration: str | None = "PT3600S",
        key_use: str | None = "signing",
        include_key: bool = True,
        include_sso: bool = True,
        include_slo: bool = True,
        certificate_override: str | None = None,
        sso_bindings: tuple[str, ...] = (BINDING_HTTP_REDIRECT, BINDING_HTTP_POST),
        role: str = "IDPSSODescriptor",
    ) -> bytes:
        """Render this IdP's `EntityDescriptor`.

        Child order follows the metadata schema: KeyDescriptor,
        SingleLogoutService, NameIDFormat, SingleSignOnService. The parser
        validates against the real XSD, so fixtures have to be genuinely
        valid — which is the point.
        """
        attributes = f' entityID="{self.entity_id}"'
        if valid_until is not None:
            attributes += f' validUntil="{_timestamp(valid_until)}"'
        if cache_duration is not None:
            attributes += f' cacheDuration="{cache_duration}"'

        key = ""
        if include_key:
            body = (
                certificate_override
                if certificate_override is not None
                else certificate_body(self.key.certificate_pem)
            )
            use = f' use="{key_use}"' if key_use else ""
            key = (
                f"<md:KeyDescriptor{use}>"
                f'<ds:KeyInfo xmlns:ds="{NS["ds"]}"><ds:X509Data>'
                f"<ds:X509Certificate>{body}</ds:X509Certificate>"
                f"</ds:X509Data></ds:KeyInfo>"
                f"</md:KeyDescriptor>"
            )

        slo = (
            f'<md:SingleLogoutService Binding="{BINDING_HTTP_REDIRECT}"'
            f' Location="{self.entity_id}/slo"/>'
            if include_slo
            else ""
        )
        sso = (
            "".join(
                f'<md:SingleSignOnService Binding="{binding}"' f' Location="{self.entity_id}/sso"/>'
                for binding in sso_bindings
            )
            if include_sso
            else ""
        )

        return (
            f'<md:EntityDescriptor xmlns:md="{MD}"{attributes}>'
            f'<md:{role} WantAuthnRequestsSigned="true"'
            f' protocolSupportEnumeration="{SAML2_PROTOCOL}">'
            f"{key}{slo}{sso}"
            f"</md:{role}>"
            f"</md:EntityDescriptor>"
        ).encode()

    def response(
        self,
        *,
        # identifiers
        response_id: str = "_response1",
        assertion_id: str = "_assertion1",
        issuer: str | None = None,
        assertion_issuer: str | None = None,
        # binding
        audience: str | None = None,
        destination: str | None = None,
        recipient: str | None = None,
        in_response_to: str | None = "_request1",
        status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
        # subject
        name_id: str = "sam.obrien@campus.edu",
        name_id_format: str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        confirmation_method: str = BEARER_CONFIRMATION_METHOD,
        include_subject: bool = True,
        include_conditions: bool = True,
        # validity window
        now: dt.datetime | None = None,
        not_before: dt.datetime | None = None,
        not_on_or_after: dt.datetime | None = None,
        subject_not_on_or_after: dt.datetime | None = None,
        # authentication statement
        authn_instant: dt.datetime | None = None,
        authn_context: str
        | None = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        session_index: str = "_session1",
        attributes: dict[str, list[str]] | None = None,
        extra_conditions: str = "",
        # signing
        sign: SignTarget = "assertion",
        sign_with: SigningKey | None = None,
        # encryption
        encrypt_for: str | None = None,
        encryption_algorithm: str = AES256_GCM,
        key_transport_algorithm: str = RSA_OAEP,
        nested_encrypted_key: bool = True,
        # post-signing tampering
        signature_method_uri: str | None = None,
        digest_method_uri: str | None = None,
        c14n_method_uri: str | None = None,
        xsw: int | None = None,
    ) -> bytes:
        """Build a SAML Response. Every argument is a way to make it wrong."""
        now = now or dt.datetime.now(dt.UTC)
        issuer = issuer if issuer is not None else self.entity_id
        assertion_issuer = assertion_issuer if assertion_issuer is not None else issuer
        audience = audience if audience is not None else self.default_audience
        destination = destination if destination is not None else self.default_destination
        recipient = recipient if recipient is not None else destination

        not_before = not_before or now - dt.timedelta(seconds=30)
        not_on_or_after = not_on_or_after or now + dt.timedelta(minutes=5)
        subject_not_on_or_after = subject_not_on_or_after or not_on_or_after
        authn_instant = authn_instant or now

        root = etree.fromstring(
            self._markup(
                response_id=response_id,
                assertion_id=assertion_id,
                issuer=issuer,
                assertion_issuer=assertion_issuer,
                audience=audience,
                destination=destination,
                recipient=recipient,
                in_response_to=in_response_to,
                status_code=status_code,
                name_id=name_id,
                name_id_format=name_id_format,
                confirmation_method=confirmation_method,
                include_subject=include_subject,
                include_conditions=include_conditions,
                issue_instant=_timestamp(now),
                not_before=_timestamp(not_before),
                not_on_or_after=_timestamp(not_on_or_after),
                subject_not_on_or_after=_timestamp(subject_not_on_or_after),
                authn_instant=_timestamp(authn_instant),
                authn_context=authn_context,
                session_index=session_index,
                attributes=attributes or {},
                extra_conditions=extra_conditions,
            ).encode(),
            parser=_PARSER,
        )

        signing_key = sign_with or self.key
        if sign in ("assertion", "both"):
            self._sign_assertion(root, assertion_id, signing_key)
        if sign in ("response", "both"):
            root = self._sign_response(root, response_id, signing_key)

        if signature_method_uri or digest_method_uri or c14n_method_uri:
            _rewrite_algorithms(root, signature_method_uri, digest_method_uri, c14n_method_uri)
        if encrypt_for is not None:
            _encrypt_assertion(
                root,
                encrypt_for,
                content_algorithm=encryption_algorithm,
                key_algorithm=key_transport_algorithm,
                nested_key=nested_encrypted_key,
            )
        if xsw is not None:
            root = apply_xsw(root, xsw)

        return etree.tostring(root, encoding="utf-8")

    # --- signing -----------------------------------------------------------

    @staticmethod
    def _signer() -> XMLSigner:
        return XMLSigner(
            method=signxml.methods.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )

    def _sign_assertion(self, root: etree._Element, assertion_id: str, key: SigningKey) -> None:
        assertion = root.find(Q_ASSERTION)
        assert assertion is not None
        signed = self._signer().sign(
            assertion,
            key=key.private_pem,
            cert=key.certificate_pem,
            reference_uri=assertion_id,
        )
        _move_signature_after_issuer(signed)
        root.replace(assertion, signed)

    def _sign_response(
        self, root: etree._Element, response_id: str, key: SigningKey
    ) -> etree._Element:
        signed: etree._Element = self._signer().sign(
            root,
            key=key.private_pem,
            cert=key.certificate_pem,
            reference_uri=response_id,
        )
        _move_signature_after_issuer(signed)
        return signed

    # --- markup ------------------------------------------------------------

    @staticmethod
    def _markup(
        *,
        response_id: str,
        assertion_id: str,
        issuer: str,
        assertion_issuer: str,
        audience: str,
        destination: str,
        recipient: str,
        in_response_to: str | None,
        status_code: str,
        name_id: str,
        name_id_format: str,
        confirmation_method: str,
        include_subject: bool,
        include_conditions: bool,
        issue_instant: str,
        not_before: str,
        not_on_or_after: str,
        subject_not_on_or_after: str,
        authn_instant: str,
        authn_context: str | None,
        session_index: str,
        attributes: dict[str, list[str]],
        extra_conditions: str = "",
    ) -> str:
        in_response_to_attr = (
            f' InResponseTo="{in_response_to}"' if in_response_to is not None else ""
        )
        confirmation_in_response_to = (
            f' InResponseTo="{in_response_to}"' if in_response_to is not None else ""
        )
        authn_statement = (
            f'<saml:AuthnStatement AuthnInstant="{authn_instant}"'
            f' SessionIndex="{session_index}">'
            f"<saml:AuthnContext>"
            f"<saml:AuthnContextClassRef>{authn_context}</saml:AuthnContextClassRef>"
            f"</saml:AuthnContext>"
            f"</saml:AuthnStatement>"
            if authn_context is not None
            else ""
        )
        attribute_statement = ""
        if attributes:
            rendered = "".join(
                '<saml:Attribute Name="{name}"'
                ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
                "{values}</saml:Attribute>".format(
                    name=name,
                    values="".join(
                        f"<saml:AttributeValue>{value}</saml:AttributeValue>" for value in values
                    ),
                )
                for name, values in attributes.items()
            )
            attribute_statement = f"<saml:AttributeStatement>{rendered}</saml:AttributeStatement>"

        subject = (
            f"<saml:Subject>"
            f'<saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="{confirmation_method}">'
            f"<saml:SubjectConfirmationData{confirmation_in_response_to}"
            f' NotOnOrAfter="{subject_not_on_or_after}" Recipient="{recipient}"/>'
            f"</saml:SubjectConfirmation>"
            f"</saml:Subject>"
            if include_subject
            else ""
        )
        conditions = (
            f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">'
            f"<saml:AudienceRestriction>"
            f"<saml:Audience>{audience}</saml:Audience>"
            f"</saml:AudienceRestriction>"
            f"{extra_conditions}"
            f"</saml:Conditions>"
            if include_conditions
            else ""
        )

        return (
            f'<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}"'
            f' ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}"'
            f' Destination="{destination}"{in_response_to_attr}>'
            f"<saml:Issuer>{issuer}</saml:Issuer>"
            f'<samlp:Status><samlp:StatusCode Value="{status_code}"/></samlp:Status>'
            f'<saml:Assertion ID="{assertion_id}" Version="2.0"'
            f' IssueInstant="{issue_instant}">'
            f"<saml:Issuer>{assertion_issuer}</saml:Issuer>"
            f"{subject}"
            f"{conditions}"
            f"{authn_statement}"
            f"{attribute_statement}"
            f"</saml:Assertion>"
            f"</samlp:Response>"
        )


def _move_signature_after_issuer(element: etree._Element) -> None:
    """Relocate `ds:Signature` to the position the SAML schema requires.

    signxml appends it last; SAML puts it immediately after `saml:Issuer`. Real
    IdPs emit the schema order, so fixtures should too. Safe because the
    enveloped-signature transform removes the element before digesting, so its
    position within the same parent does not change what was signed. Pinned by
    `test_saml_forge.py::test_signature_sits_after_issuer_and_still_verifies`.
    """
    signature = element.find(Q_SIGNATURE)
    if signature is None:
        return
    element.remove(signature)
    issuer = element.find(Q_ISSUER)
    element.insert(list(element).index(issuer) + 1 if issuer is not None else 0, signature)


def _rewrite_algorithms(
    root: etree._Element,
    signature_method_uri: str | None,
    digest_method_uri: str | None,
    c14n_method_uri: str | None,
) -> None:
    """Rewrite algorithm URIs after signing.

    signxml will not *produce* a SHA-1 signature, so the only way to exercise
    the weak-algorithm path is to relabel a valid signature. The result is
    cryptographically broken, which is fine and in fact the point: the
    allowlist runs before verification, so a correct implementation rejects it
    as `weak_algorithm` and never reaches the failing digest check.
    """
    for signature in root.iter(Q_SIGNATURE):
        if signature_method_uri:
            for node in signature.iter(f"{{{NS['ds']}}}SignatureMethod"):
                node.set("Algorithm", signature_method_uri)
        if digest_method_uri:
            for node in signature.iter(f"{{{NS['ds']}}}DigestMethod"):
                node.set("Algorithm", digest_method_uri)
        if c14n_method_uri:
            for node in signature.iter(f"{{{NS['ds']}}}CanonicalizationMethod"):
                node.set("Algorithm", c14n_method_uri)


# --- XML Encryption ---------------------------------------------------------


def _encrypt_assertion(
    root: etree._Element,
    recipient_certificate_pem: str,
    *,
    content_algorithm: str,
    key_algorithm: str,
    nested_key: bool,
) -> None:
    """Replace the Response's Assertion with an EncryptedAssertion.

    Encrypts for real, so the decryptor is exercised against genuine
    ciphertext. ``nested_key`` toggles between the two layouts real IdPs use:
    the `EncryptedKey` inside `EncryptedData/KeyInfo`, or as its sibling.
    """
    assertion = root.find(Q_ASSERTION)
    assert assertion is not None
    plaintext = etree.tostring(assertion, encoding="utf-8")

    key_length = _GCM_KEY_BYTES.get(content_algorithm, 32)
    session_key = os.urandom(key_length)

    if content_algorithm.endswith("-gcm"):
        iv = os.urandom(12)
        body = iv + AESGCM(session_key).encrypt(iv, plaintext, None)
    else:
        # CBC, only so the refusal path can be tested. Padding is ISO 10126 as
        # XML-Enc specifies, not PKCS#7.
        iv = os.urandom(16)
        pad = 16 - (len(plaintext) % 16)
        padded = plaintext + os.urandom(pad - 1) + bytes([pad])
        encryptor = Cipher(algorithms.AES(session_key), modes.CBC(iv)).encryptor()
        body = iv + encryptor.update(padded) + encryptor.finalize()

    public_key = load_pem_x509_certificate(recipient_certificate_pem.encode()).public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    if key_algorithm == RSA_OAEP_MGF1P:
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),  # noqa: S303 - fixed by the 2002 spec
            algorithm=hashes.SHA1(),  # noqa: S303
            label=None,
        )
        key_method = f'<xenc:EncryptionMethod Algorithm="{key_algorithm}"/>'
    else:
        oaep = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        )
        key_method = (
            f'<xenc:EncryptionMethod Algorithm="{key_algorithm}">'
            f'<ds:DigestMethod xmlns:ds="{NS["ds"]}" Algorithm="{XENC}sha256"/>'
            f'<xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{XENC11}mgf1sha256"/>'
            f"</xenc:EncryptionMethod>"
        )
    wrapped = public_key.encrypt(session_key, oaep)

    encrypted_key = (
        f'<xenc:EncryptedKey xmlns:xenc="{XENC}">'
        f"{key_method}"
        f"<xenc:CipherData>"
        f"<xenc:CipherValue>{base64.b64encode(wrapped).decode()}</xenc:CipherValue>"
        f"</xenc:CipherData>"
        f"</xenc:EncryptedKey>"
    )
    key_info = (
        f'<ds:KeyInfo xmlns:ds="{NS["ds"]}">{encrypted_key}</ds:KeyInfo>' if nested_key else ""
    )
    sibling_key = "" if nested_key else encrypted_key

    markup = (
        f'<saml:EncryptedAssertion xmlns:saml="{SAML}" xmlns:xenc="{XENC}">'
        f'<xenc:EncryptedData Type="{XENC}Element">'
        f'<xenc:EncryptionMethod Algorithm="{content_algorithm}"/>'
        f"{key_info}"
        f"<xenc:CipherData>"
        f"<xenc:CipherValue>{base64.b64encode(body).decode()}</xenc:CipherValue>"
        f"</xenc:CipherData>"
        f"</xenc:EncryptedData>"
        f"{sibling_key}"
        f"</saml:EncryptedAssertion>"
    )
    root.replace(assertion, etree.fromstring(markup.encode(), parser=_PARSER))


# --- XML Signature Wrapping variants ---------------------------------------


def _evil_assertion(
    assertion_id: str = "_evil", name_id: str = "attacker@evil.test"
) -> etree._Element:
    """An assertion asserting a different principal, with no valid signature."""
    return etree.fromstring(
        f'<saml:Assertion xmlns:saml="{SAML}" ID="{assertion_id}" Version="2.0">'
        f"<saml:Issuer>https://idp.test/saml</saml:Issuer>"
        f"<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject>"
        f"</saml:Assertion>".encode(),
        parser=_PARSER,
    )


def _empty(tag: str, **attributes: str) -> etree._Element:
    element = etree.Element(tag, nsmap={"saml": SAML, "samlp": SAMLP, "ds": NS["ds"]})
    for name, value in attributes.items():
        element.set(name, value)
    return element


def apply_xsw(root: etree._Element, variant: int) -> etree._Element:
    """Apply one XML Signature Wrapping variant to a signed document.

    Numbering follows the SAML Raider / Somorovsky taxonomy: variants 1-2
    attack a Response signature, 3-8 an Assertion signature. In every case the
    original signature stays cryptographically valid over the original element;
    only the structure around it changes, so that a naive consumer reads the
    attacker's assertion instead.
    """
    try:
        return _XSW_VARIANTS[variant](root)
    except KeyError:
        raise ValueError(f"unknown XSW variant {variant!r}; expected 1-8") from None


def _xsw1(root: etree._Element) -> etree._Element:
    """Evil Response as root; the signed Response hidden in its `ds:Object`."""
    evil = _empty(Q_RESPONSE, ID="_evilresponse", Version="2.0")
    signature = _empty(Q_SIGNATURE)
    obj = _empty(f"{{{NS['ds']}}}Object")
    obj.append(root)
    signature.append(obj)
    evil.append(signature)
    evil.append(_evil_assertion())
    return evil


def _xsw2(root: etree._Element) -> etree._Element:
    """Evil Response as root; the signed Response a sibling of its signature."""
    evil = _empty(Q_RESPONSE, ID="_evilresponse", Version="2.0")
    evil.append(_empty(Q_SIGNATURE))
    evil.append(root)
    evil.append(_evil_assertion())
    return evil


def _xsw3(root: etree._Element) -> etree._Element:
    """Evil assertion inserted before the signed one."""
    root.insert(0, _evil_assertion())
    return root


def _xsw4(root: etree._Element) -> etree._Element:
    """Signed assertion relocated inside the evil assertion."""
    original = root.find(Q_ASSERTION)
    assert original is not None
    evil = _evil_assertion()
    root.remove(original)
    evil.append(original)
    root.append(evil)
    return root


def _xsw5(root: etree._Element) -> etree._Element:
    """Evil assertion carries the signature; the original moves to Extensions."""
    original = root.find(Q_ASSERTION)
    assert original is not None
    signature = original.find(Q_SIGNATURE)
    assert signature is not None

    evil = _evil_assertion()
    original.remove(signature)
    evil.append(signature)

    extensions = _empty(f"{{{SAMLP}}}Extensions")
    root.remove(original)
    extensions.append(original)
    root.insert(0, extensions)
    root.append(evil)
    return root


def _xsw6(root: etree._Element) -> etree._Element:
    """Original assertion hidden inside the evil assertion's `ds:Object`."""
    original = root.find(Q_ASSERTION)
    assert original is not None
    signature = original.find(Q_SIGNATURE)
    assert signature is not None

    evil = _evil_assertion()
    original.remove(signature)
    obj = _empty(f"{{{NS['ds']}}}Object")
    root.remove(original)
    obj.append(original)
    signature.append(obj)
    evil.append(signature)
    root.append(evil)
    return root


def _xsw7(root: etree._Element) -> etree._Element:
    """Signed assertion hidden in `samlp:Extensions`; evil one is a sibling."""
    original = root.find(Q_ASSERTION)
    assert original is not None
    extensions = _empty(f"{{{SAMLP}}}Extensions")
    root.remove(original)
    extensions.append(original)
    root.insert(0, extensions)
    root.append(_evil_assertion())
    return root


def _xsw8(root: etree._Element) -> etree._Element:
    """Original assertion in a `ds:Object` under its own detached signature."""
    original = root.find(Q_ASSERTION)
    assert original is not None
    signature = original.find(Q_SIGNATURE)
    assert signature is not None

    original.remove(signature)
    obj = _empty(f"{{{NS['ds']}}}Object")
    root.remove(original)
    obj.append(original)
    signature.append(obj)

    evil = _evil_assertion()
    evil.append(signature)
    root.append(evil)
    return root


_XSW_VARIANTS = {
    1: _xsw1,
    2: _xsw2,
    3: _xsw3,
    4: _xsw4,
    5: _xsw5,
    6: _xsw6,
    7: _xsw7,
    8: _xsw8,
}
