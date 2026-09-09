"""XML namespace constants and qualified-name helpers."""

from __future__ import annotations

from typing import Final

SAML: Final = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP: Final = "urn:oasis:names:tc:SAML:2.0:protocol"
MD: Final = "urn:oasis:names:tc:SAML:2.0:metadata"
MDUI: Final = "urn:oasis:names:tc:SAML:metadata:ui"
DS: Final = "http://www.w3.org/2000/09/xmldsig#"
XENC: Final = "http://www.w3.org/2001/04/xmlenc#"
XENC11: Final = "http://www.w3.org/2009/xmlenc11#"
XS: Final = "http://www.w3.org/2001/XMLSchema"
XSI: Final = "http://www.w3.org/2001/XMLSchema-instance"

NS: Final[dict[str, str]] = {
    "saml": SAML,
    "samlp": SAMLP,
    "md": MD,
    "mdui": MDUI,
    "ds": DS,
    "xenc": XENC,
    "xenc11": XENC11,
}
"""Prefix map for XPath queries. Never rely on prefixes in the source document —
an attacker chooses those."""


def qn(namespace: str, local_name: str) -> str:
    """Build a Clark-notation qualified name, e.g. ``{urn:...}Assertion``."""
    return f"{{{namespace}}}{local_name}"


# Elements referenced often enough to be worth naming once.
Q_RESPONSE: Final = qn(SAMLP, "Response")
Q_STATUS: Final = qn(SAMLP, "Status")
Q_STATUS_CODE: Final = qn(SAMLP, "StatusCode")
Q_EXTENSIONS: Final = qn(SAMLP, "Extensions")
Q_ASSERTION: Final = qn(SAML, "Assertion")
Q_ENCRYPTED_ASSERTION: Final = qn(SAML, "EncryptedAssertion")
Q_ISSUER: Final = qn(SAML, "Issuer")
Q_SUBJECT: Final = qn(SAML, "Subject")
Q_NAME_ID: Final = qn(SAML, "NameID")
Q_SUBJECT_CONFIRMATION: Final = qn(SAML, "SubjectConfirmation")
Q_SUBJECT_CONFIRMATION_DATA: Final = qn(SAML, "SubjectConfirmationData")
Q_CONDITIONS: Final = qn(SAML, "Conditions")
Q_AUDIENCE_RESTRICTION: Final = qn(SAML, "AudienceRestriction")
Q_AUDIENCE: Final = qn(SAML, "Audience")
Q_ONE_TIME_USE: Final = qn(SAML, "OneTimeUse")
Q_PROXY_RESTRICTION: Final = qn(SAML, "ProxyRestriction")
Q_AUTHN_STATEMENT: Final = qn(SAML, "AuthnStatement")
Q_AUTHN_CONTEXT: Final = qn(SAML, "AuthnContext")
Q_AUTHN_CONTEXT_CLASS_REF: Final = qn(SAML, "AuthnContextClassRef")
Q_ATTRIBUTE_STATEMENT: Final = qn(SAML, "AttributeStatement")
Q_ATTRIBUTE: Final = qn(SAML, "Attribute")
Q_ATTRIBUTE_VALUE: Final = qn(SAML, "AttributeValue")
Q_SIGNATURE: Final = qn(DS, "Signature")
Q_SIGNED_INFO: Final = qn(DS, "SignedInfo")
Q_SIGNATURE_METHOD: Final = qn(DS, "SignatureMethod")
Q_DIGEST_METHOD: Final = qn(DS, "DigestMethod")
Q_CANONICALIZATION_METHOD: Final = qn(DS, "CanonicalizationMethod")
Q_REFERENCE: Final = qn(DS, "Reference")
Q_TRANSFORMS: Final = qn(DS, "Transforms")
Q_TRANSFORM: Final = qn(DS, "Transform")
Q_OBJECT: Final = qn(DS, "Object")

Q_ENCRYPTED_DATA: Final = qn(XENC, "EncryptedData")
Q_ENCRYPTED_KEY: Final = qn(XENC, "EncryptedKey")
Q_ENCRYPTION_METHOD: Final = qn(XENC, "EncryptionMethod")
Q_CIPHER_DATA: Final = qn(XENC, "CipherData")
Q_CIPHER_VALUE: Final = qn(XENC, "CipherValue")
Q_KEY_INFO: Final = qn(DS, "KeyInfo")
Q_RETRIEVAL_METHOD: Final = qn(DS, "RetrievalMethod")
Q_MGF: Final = qn(XENC11, "MGF")

BEARER_CONFIRMATION_METHOD: Final = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
STATUS_SUCCESS: Final = "urn:oasis:names:tc:SAML:2.0:status:Success"
