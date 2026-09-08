"""Positive-path behaviour of the hardened parser.

The rejection paths live in `tests/security/test_xml_hardening.py`; this file
covers what the parser must still accept and return correctly, so hardening does
not quietly break valid traffic.
"""

from __future__ import annotations

from lxml import etree

from campusid.saml.namespaces import Q_ASSERTION, Q_NAME_ID
from campusid.saml.parser import hardened_parser, parse_saml, serialise, text_of
from tests.support.xmlbuild import response_xml


def test_a_well_formed_response_parses() -> None:
    root = parse_saml(response_xml().encode())

    assert root.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}Response"
    assert root.get("ID") == "_r1"
    assert root.find(f".//{Q_ASSERTION}") is not None


def test_comments_are_stripped_at_parse_time() -> None:
    root = parse_saml(b"<a><!-- secret --><b>x</b></a>")

    assert b"secret" not in serialise(root)


def test_processing_instructions_are_stripped() -> None:
    root = parse_saml(b"<a><?php echo 1; ?><b>x</b></a>")

    assert b"php" not in serialise(root)


def test_text_of_returns_empty_for_a_missing_element() -> None:
    """Callers look up optional elements; a missing one is not an error here,
    it is an empty value that the gate's own checks then reject."""
    assert text_of(None) == ""


def test_text_of_reads_a_normal_value() -> None:
    root = parse_saml(response_xml().encode())

    assert text_of(root.find(f".//{Q_NAME_ID}")) == "sam.obrien@campus.edu"


def test_serialise_round_trips() -> None:
    root = parse_saml(response_xml().encode())

    assert serialise(root).startswith(b"<samlp:Response")
    assert parse_saml(serialise(root)).get("ID") == "_r1"


def test_entities_are_not_resolved() -> None:
    """Pins `resolve_entities=False` behaviourally.

    lxml exposes no readable parser options, so the setting can only be
    verified by its effect. Deliberately goes through the raw parser rather
    than `parse_saml`, which refuses the DOCTYPE first: this proves the second
    layer holds on its own, so a future relaxation of the DOCTYPE rule cannot
    silently re-open XXE.
    """
    declared_entity = b'<!DOCTYPE r [<!ENTITY e "EXPANDED_SECRET">]><r>&e;</r>'

    root = etree.fromstring(declared_entity, parser=hardened_parser())

    assert b"EXPANDED_SECRET" not in etree.tostring(root)
    assert text_of(root) == "&e;"  # left as an inert reference, never expanded
