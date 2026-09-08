"""The 2018 ruby-saml / python3-saml comment-splicing bypass.

`<NameID>user@evil.com<!--x-->@campus.edu</NameID>` still verifies, because
exclusive canonicalisation strips comments before digesting. An XML API that
returns only the first text node then reads `user@evil.com` — a different,
attacker-chosen principal — out of a genuinely signed assertion.

Three independent defenses, tested here and in `test_algorithm_allowlist.py`:
comments stripped at parse time, all text concatenated on read, and
comment-preserving canonicalisation refused outright.
"""

from __future__ import annotations

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.algorithms import assert_algorithms_permitted
from campusid.saml.namespaces import Q_NAME_ID
from campusid.saml.parser import parse_saml, text_of

pytestmark = pytest.mark.security


SPLICED_NAME_ID = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">
  <saml:Assertion ID="_a1">
    <saml:Subject>
      <saml:NameID>attacker@evil.test<!--ignored-->@campus.edu</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""


def test_spliced_name_id_reads_as_the_full_value() -> None:
    """The spliced value must never read back as the attacker's prefix alone."""
    root = parse_saml(SPLICED_NAME_ID)
    name_id = root.find(f".//{Q_NAME_ID}")
    assert name_id is not None

    assert text_of(name_id) == "attacker@evil.test@campus.edu"
    assert text_of(name_id) != "attacker@evil.test"


def test_text_of_survives_a_splice_that_element_text_would_truncate() -> None:
    """Guards `text_of` itself against being "simplified" back to `.text`.

    Parsed *without* comment removal, so this fails loudly if someone replaces
    the `itertext()` join with `element.text` — the second defense has to hold
    on its own, not only behind the first.
    """
    permissive = etree.XMLParser(resolve_entities=False, no_network=True)
    name_id = etree.fromstring(
        b"<NameID>attacker@evil.test<!--x-->@campus.edu</NameID>", parser=permissive
    )

    assert name_id.text == "attacker@evil.test"  # what the CVE relied on
    assert text_of(name_id) == "attacker@evil.test@campus.edu"


def test_comment_preserving_canonicalisation_is_refused() -> None:
    """The third defense.

    Our parser strips comments, so a signature that genuinely covers them would
    fail with an opaque digest mismatch. Refusing `#WithComments` by name turns
    that into a legible hardening violation — and refuses the algorithm the
    attack depends on.
    """
    signature = etree.fromstring(
        b"""<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod
                  Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>
                <ds:SignatureMethod
                  Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              </ds:SignedInfo>
            </ds:Signature>""",
        parser=etree.XMLParser(resolve_entities=False, no_network=True),
    )

    with pytest.raises(SamlRejected) as exc:
        assert_algorithms_permitted(signature)

    assert exc.value.reason is ReasonCode.XML_HARDENING_VIOLATION
