"""Minimal XML builders for structural tests.

These produce *structurally* valid SAML with cryptographically meaningless
signatures — enough to exercise the parser, the algorithm allowlist and the XSW
predicates, all of which run before any verification. Real signing lives in the
forge (`saml_forge.py`).
"""

from __future__ import annotations

from lxml import etree

RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
EXC_C14N_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def signature_xml(
    *,
    reference_uri: str = "#_a1",
    signature_method: str = RSA_SHA256,
    digest_method: str = SHA256,
    c14n_method: str = EXC_C14N,
    transforms: tuple[str, ...] = (ENVELOPED, EXC_C14N),
    reference_count: int = 1,
) -> str:
    """Render a `ds:Signature` element as a string."""
    transform_xml = "".join(f'<ds:Transform Algorithm="{t}"/>' for t in transforms)
    reference = (
        f'<ds:Reference URI="{reference_uri}">'
        f"<ds:Transforms>{transform_xml}</ds:Transforms>"
        f'<ds:DigestMethod Algorithm="{digest_method}"/>'
        f"<ds:DigestValue>ZGVhZGJlZWY=</ds:DigestValue>"
        f"</ds:Reference>"
    )
    return (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        "<ds:SignedInfo>"
        f'<ds:CanonicalizationMethod Algorithm="{c14n_method}"/>'
        f'<ds:SignatureMethod Algorithm="{signature_method}"/>'
        f"{reference * reference_count}"
        "</ds:SignedInfo>"
        "<ds:SignatureValue>ZGVhZGJlZWY=</ds:SignatureValue>"
        "</ds:Signature>"
    )


def response_xml(
    *,
    response_id: str = "_r1",
    assertion_id: str = "_a1",
    response_signature: str = "",
    assertion_signature: str = "",
    extra_assertions: str = "",
    extensions: str = "",
) -> str:
    """Render a `samlp:Response` wrapping one `saml:Assertion`."""
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{response_id}" Version="2.0">'
        "<saml:Issuer>https://idp.test/saml</saml:Issuer>"
        f"{response_signature}"
        f"{extensions}"
        f'<saml:Assertion ID="{assertion_id}" Version="2.0">'
        "<saml:Issuer>https://idp.test/saml</saml:Issuer>"
        f"{assertion_signature}"
        "<saml:Subject><saml:NameID>sam.obrien@campus.edu</saml:NameID></saml:Subject>"
        "</saml:Assertion>"
        f"{extra_assertions}"
        "</samlp:Response>"
    )


def parse(markup: str) -> etree._Element:
    """Parse builder output directly, bypassing the hardened parser.

    Used where a test needs to hand a specific structure to one predicate in
    isolation, without the parser's own checks firing first.
    """
    return etree.fromstring(markup.encode(), parser=_PARSER)
