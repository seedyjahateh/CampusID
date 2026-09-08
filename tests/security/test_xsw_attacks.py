"""The eight XML Signature Wrapping variants, end to end (PRD acceptance 4).

Each document here carries a *cryptographically valid* signature over the
genuine assertion. That is what makes wrapping dangerous: verification
succeeds, and only the structure betrays the attack. So these must be refused
with `signature_wrapping_detected` — not merely survived.

Numbering follows the SAML Raider / Somorovsky taxonomy: 1-2 attack a Response
signature, 3-8 an Assertion signature.
"""

from __future__ import annotations

import pytest
from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import Q_SIGNATURE
from campusid.saml.parser import parse_saml
from campusid.saml.xsw import (
    assert_no_wrapping,
    assert_reference_binds_to_parent,
    assert_signature_placement,
    assert_single_response_and_assertion,
)
from tests.support.saml_forge import ForgedIdP

pytestmark = pytest.mark.security

RESPONSE_SIGNATURE_VARIANTS = (1, 2)
ALL_VARIANTS = tuple(range(1, 9))

DEFENCE_MATRIX: dict[int, frozenset[str]] = {
    1: frozenset({"D1", "D4", "D5"}),
    2: frozenset({"D1", "D4", "D5"}),
    3: frozenset({"D1"}),
    4: frozenset({"D1", "D5"}),
    5: frozenset({"D1", "D4"}),
    6: frozenset({"D1", "D4"}),
    7: frozenset({"D1", "D5"}),
    8: frozenset({"D1", "D4"}),
}
"""Measured, not assumed — this table is generated from behaviour and pinned.

Two things it says that a hand-written table would have got wrong:

**D1 is the universal net, not D5.** Every variant adds a second `Response` or
`Assertion` somewhere, so the count check is what catches all eight.

**XSW3 is caught by D1 alone.** Its signature sits in a legitimate place and
references its own parent correctly, so D4 and D5 both pass; only the assertion
count betrays it. D2 (processing only the verified element, in `signature.py`)
is the second layer there, but it makes the attack *ineffective* rather than
*detected* — so if D1 were ever weakened, XSW3 would stop being reported.
"""


def _wrapped(idp: ForgedIdP, variant: int) -> bytes:
    return idp.response(
        sign="response" if variant in RESPONSE_SIGNATURE_VARIANTS else "assertion",
        xsw=variant,
    )


def _catching_defences(root: etree._Element) -> frozenset[str]:
    """Which named defences independently reject this document."""
    caught = set()

    for name, check in (
        ("D1", assert_single_response_and_assertion),
        ("D5", assert_signature_placement),
    ):
        try:
            check(root)
        except SamlRejected:
            caught.add(name)

    # D4 is per-signature rather than per-document.
    for signature in root.iter(Q_SIGNATURE):
        try:
            assert_reference_binds_to_parent(signature)
        except SamlRejected:
            caught.add("D4")
            break

    return frozenset(caught)


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_wrapped_document_is_rejected(idp: ForgedIdP, variant: int) -> None:
    """The acceptance criterion: refused, with the wrapping reason code."""
    root = parse_saml(_wrapped(idp, variant))

    with pytest.raises(SamlRejected) as exc:
        assert_no_wrapping(root)

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


@pytest.mark.parametrize("variant", ALL_VARIANTS)
def test_defence_coverage_matches_the_documented_matrix(idp: ForgedIdP, variant: int) -> None:
    """Keeps the README's variant/defence table honest.

    Asserting only that *something* rejected the document would let one defence
    quietly stop working while a coarser one masked it — which is precisely the
    failure mode for XSW3, where a single defence is load-bearing.
    """
    caught = _catching_defences(parse_saml(_wrapped(idp, variant)))

    assert caught == DEFENCE_MATRIX[variant], (
        f"XSW{variant} defence coverage changed: "
        f"expected {sorted(DEFENCE_MATRIX[variant])}, measured {sorted(caught)}"
    )


def test_every_variant_is_caught(idp: ForgedIdP) -> None:
    """No variant may rely on zero named defences."""
    assert all(DEFENCE_MATRIX[variant] for variant in ALL_VARIANTS)


@pytest.mark.parametrize("signing", ["assertion", "response", "both"])
def test_a_legitimate_document_passes_every_defence(idp: ForgedIdP, signing: str) -> None:
    """The control.

    Without it, a predicate that rejected everything would make the whole suite
    pass. `both` matters specifically: Keycloak signs the Response and the
    Assertion by default, and two signatures in their proper places must not
    read as wrapping.
    """
    root = parse_saml(idp.response(sign=signing))  # type: ignore[arg-type]

    assert _catching_defences(root) == frozenset()
    assert_no_wrapping(root)
