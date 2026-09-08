"""Hardened XML parsing — the only module permitted to touch untrusted XML.

Everything here exists because SAML hands an unauthenticated attacker a parser.
The document arrives before any signature has been checked, so parsing itself is
part of the attack surface.

Three classes of attack are handled at this layer:

**Entity attacks** (XXE, billion laughs). Defeated by refusing to load or resolve
DTDs and entities at all, rather than by trying to bound expansion.

**Identifier ambiguity.** XML Signature resolves ``Reference URI="#foo"`` by
searching for an element with that ID. lxml has no DTD-derived ``xml:id``
typing, so this is an XPath search, and if two elements share an ID the
verifier and the consumer can disagree about which one they mean. We reject
duplicate IDs outright.

**Comment truncation** — the 2018 ruby-saml / python3-saml authentication
bypass. ``<NameID>user@evil.com<!--x-->@campus.edu</NameID>`` still verifies,
because exclusive canonicalisation strips comments before digesting, but an
XML API that returns only the first text node reads ``user@evil.com``. Two
defenses here (strip comments at parse time, and `text_of` below); the third
lives in `algorithms.py`, which refuses ``#WithComments`` canonicalisation.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final, cast

from lxml import etree

from campusid.errors import ReasonCode, SamlRejected

MAX_DOCUMENT_BYTES: Final = 512 * 1024
"""Hard ceiling on a SAML message. Real assertions are a few kilobytes; a
megabyte-scale one is an attack or a bug, and either way should not be parsed."""


def hardened_parser() -> etree.XMLParser:
    """Build the parser used for every untrusted document.

    ``resolve_entities=False`` is the load-bearing one: without entity
    resolution, neither XXE nor billion-laughs has anything to expand.
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        attribute_defaults=False,
        huge_tree=False,
        remove_comments=True,
        remove_pis=True,
        recover=False,
    )


def parse_saml(data: bytes) -> etree._Element:
    """Parse an untrusted SAML document, or raise `SamlRejected`.

    The returned tree has no comments, no processing instructions, no DTD, and
    unique ``ID`` values. Nothing downstream needs to re-check those.
    """
    if len(data) > MAX_DOCUMENT_BYTES:
        raise SamlRejected(
            ReasonCode.PAYLOAD_TOO_LARGE,
            f"{len(data)} bytes exceeds the {MAX_DOCUMENT_BYTES} byte ceiling",
        )

    try:
        root = etree.fromstring(data, parser=hardened_parser())
    except etree.XMLSyntaxError as exc:
        raise SamlRejected(ReasonCode.MALFORMED_RESPONSE, str(exc)) from exc

    _reject_doctype(root)
    _reject_duplicate_ids(root)
    return root


def _reject_doctype(root: etree._Element) -> None:
    """Refuse any document carrying a DTD.

    Nothing in SAML needs one, and its only uses here are entity attacks and
    attribute-default injection. Safe to check after parsing precisely because
    the parser neither loaded nor resolved it.

    This subsumes any separate check for entity references: an entity cannot be
    referenced without first being declared, and every declaration lives in a
    DTD. Refusing the DOCTYPE removes the whole class rather than trying to
    catch its instances.
    """
    # lxml-stubs omits DocInfo.doctype; it exists and returns "" when absent.
    doctype: str = root.getroottree().docinfo.doctype  # type: ignore[attr-defined]
    if doctype:
        raise SamlRejected(ReasonCode.XML_HARDENING_VIOLATION, "document declares a DOCTYPE")


def _reject_duplicate_ids(root: etree._Element) -> None:
    """Refuse documents where two elements share an ``ID``.

    signxml resolves a signature reference by taking the first XPath match;
    our own lookups may reach a different element. Rather than reconcile the
    two, refuse the ambiguity.
    """
    # iter() yields only elements here: the hardened parser has already removed
    # comments and processing instructions, and a DOCTYPE-free document cannot
    # contain entity nodes.
    seen: set[str] = set()
    for element in root.iter():
        identifier = element.get("ID")
        if identifier is None:
            continue
        if identifier in seen:
            raise SamlRejected(
                ReasonCode.DUPLICATE_ELEMENT_ID,
                f"ID {identifier!r} appears more than once",
            )
        seen.add(identifier)


def text_of(element: etree._Element | None) -> str:
    """Return **all** text within ``element``, concatenated.

    Never use ``element.text``. It returns only the first text node, which is
    exactly the truncation the 2018 comment-splicing bypass relies on. Comments
    are already stripped at parse time; this is the second, independent guard,
    and it also covers text split by any other node type.
    """
    if element is None:
        return ""
    # lxml-stubs widens itertext() to str | bytes; text nodes are always str.
    return "".join(cast("Iterator[str]", element.itertext()))


def serialise(element: etree._Element) -> bytes:
    """Serialise an element back to bytes, for logging and diagnostics."""
    result: bytes = etree.tostring(element, encoding="utf-8")
    return result
