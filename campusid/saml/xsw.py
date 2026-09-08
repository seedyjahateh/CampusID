"""Structural defenses against XML Signature Wrapping.

XSW works by leaving a validly-signed element in the document while arranging
for the consumer to read a *different*, attacker-authored one. The signature
still verifies; the SP just reads the wrong thing.

The obvious defense — "only read the element the verifier returned" — makes the
attack ineffective but lets the request **succeed**, because the genuine
assertion is what gets processed. That is not good enough here: PRD acceptance
criterion 4 requires these documents be *rejected* with
`signature_wrapping_detected`. A wrapped document is evidence of an attack in
progress and must be refused and audited, not silently tolerated.

So rejection is affirmative and happens *before* verification. The predicates
below are the mechanism; reading only `signed_xml` (in `gate.py`) is the safety
net behind them.

Defense IDs match the README table and PRD §12.2:

* **D0** DOCTYPE / duplicate-ID / `#WithComments` refusal — `parser.py`, `algorithms.py`
* **D1** exactly one `Response` and one `Assertion` — here
* **D2** process only `signed_xml` — `gate.py`
* **D3** pinned signature `location` — `signature.py`
* **D4** reference binds to the signature's own parent — here
* **D5** signatures only in permitted positions — here

D1 and D2 overlap heavily for XSW3-8. That is layering, not three orthogonal
controls, and the README says so; a reviewer is better served by an honest
account of which layer is authoritative than by an inflated count.
"""

from __future__ import annotations

from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import (
    Q_ASSERTION,
    Q_ENCRYPTED_ASSERTION,
    Q_REFERENCE,
    Q_RESPONSE,
    Q_SIGNATURE,
    Q_SIGNED_INFO,
    Q_TRANSFORM,
)

ENVELOPED_SIGNATURE_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def assert_single_response_and_assertion(root: etree._Element) -> None:
    """**D1** — exactly one `Response` and at most one assertion, document-wide.

    Catches XSW3, XSW4 and XSW7, which all work by adding a second `Assertion`
    somewhere the schema tolerates (as a sibling, nested inside the evil
    assertion, or hidden in `samlp:Extensions`).

    Counted across the whole document rather than among direct children,
    precisely because `Extensions` and `ds:Object` are where attackers hide the
    spare copy.
    """
    responses = list(root.iter(Q_RESPONSE))
    if len(responses) > 1:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"document contains {len(responses)} Response elements",
        )

    assertions = list(root.iter(Q_ASSERTION))
    encrypted = list(root.iter(Q_ENCRYPTED_ASSERTION))
    total = len(assertions) + len(encrypted)
    if total > 1:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"document contains {total} assertions "
            f"({len(assertions)} plain, {len(encrypted)} encrypted)",
        )


def assert_signature_placement(root: etree._Element) -> None:
    """**D5** — a `ds:Signature` may only be a direct child of the `Response`
    or of the `Assertion`, and at most one in each position.

    A coarse net that catches all eight variants: every one of them has to put a
    signature, or hide a signed element carrying one, somewhere other than these
    two positions. Kept alongside the finer-grained D4 so each variant maps to a
    named defense rather than to a single catch-all.
    """
    permitted: list[etree._Element] = []
    if root.tag == Q_RESPONSE:
        permitted.append(root)
        permitted.extend(root.findall(Q_ASSERTION))
    elif root.tag == Q_ASSERTION:
        permitted.append(root)

    occupied: list[etree._Element] = []
    for signature in root.iter(Q_SIGNATURE):
        parent = signature.getparent()
        if parent is None or not any(parent is candidate for candidate in permitted):
            raise SamlRejected(
                ReasonCode.SIGNATURE_WRAPPING_DETECTED,
                "ds:Signature appears outside the Response or Assertion element",
            )
        if any(parent is candidate for candidate in occupied):
            raise SamlRejected(
                ReasonCode.SIGNATURE_WRAPPING_DETECTED,
                "element carries more than one ds:Signature",
            )
        occupied.append(parent)


def assert_reference_binds_to_parent(signature: etree._Element) -> None:
    """**D4** — the signature must reference the element it is a child of.

    This is the check that kills XSW1, 2, 5, 6 and 8 at the right layer. Each of
    those leaves the signature structurally where it belongs but points its
    `Reference URI` at an element *elsewhere* in the document, so the digest
    covers the genuine assertion while the consumer reads the evil one.

    Requires exactly one reference (multiple references let an attacker add a
    second, satisfied one), a same-document `#ID` reference (external references
    would fetch attacker-chosen content), and the enveloped-signature transform
    (without it the signature would purport to cover itself).
    """
    parent = signature.getparent()
    if parent is None:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED, "ds:Signature has no parent element"
        )

    references = signature.findall(f"{Q_SIGNED_INFO}/{Q_REFERENCE}")
    if len(references) != 1:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"expected exactly one ds:Reference, found {len(references)}",
        )

    uri = references[0].get("URI")
    if not uri or not uri.startswith("#"):
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"reference URI {uri!r} is not a same-document ID reference",
        )

    parent_id = parent.get("ID")
    if parent_id is None or uri[1:] != parent_id:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            f"reference URI {uri!r} does not match the signed element's ID {parent_id!r}",
        )

    transforms = {transform.get("Algorithm") for transform in references[0].iter(Q_TRANSFORM)}
    if ENVELOPED_SIGNATURE_TRANSFORM not in transforms:
        raise SamlRejected(
            ReasonCode.SIGNATURE_WRAPPING_DETECTED,
            "reference lacks the enveloped-signature transform",
        )
