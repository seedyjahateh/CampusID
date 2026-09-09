"""The validation matrix (PRD acceptance criterion 3).

Every check in the gate, exercised in both directions: a document that must be
accepted, and one that must be refused with that check's own reason code.

Asserting the *specific* code matters. A suite that only proved "rejected"
would pass just as happily if every document failed for the same accidental
reason, and the audit trail would then be unable to answer the questions in PRD
section 5.11.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import pytest

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.gate import AssertionGate, GatePolicy, IdPResolver
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore

pytestmark = pytest.mark.security

Forge = Callable[[ForgedIdP], bytes]

XXE = b"""<?xml version="1.0"?>
<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"/>"""

UNSUPPORTED_CONDITION = (
    '<saml:Condition xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    ' xsi:type="saml:AudienceRestrictionType"/>'
)

REJECTIONS: list[tuple[str, Forge, ReasonCode]] = [
    (
        "hardened_parse",
        lambda idp: XXE,
        ReasonCode.XML_HARDENING_VIOLATION,
    ),
    (
        "structural_integrity",
        lambda idp: idp.response(xsw=3),
        ReasonCode.SIGNATURE_WRAPPING_DETECTED,
    ),
    (
        "status",
        lambda idp: idp.response(status_code="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
        ReasonCode.IDP_ERROR_STATUS,
    ),
    (
        "issuer_registered",
        lambda idp: idp.response(issuer="https://stranger.test/saml"),
        ReasonCode.UNKNOWN_ISSUER,
    ),
    (
        "issuer_agreement",
        lambda idp: idp.response(assertion_issuer="https://other-idp.test/saml"),
        ReasonCode.ISSUER_MISMATCH,
    ),
    (
        "signature_present",
        lambda idp: idp.response(sign=None),
        ReasonCode.SIGNATURE_MISSING,
    ),
    (
        "signature_valid",
        lambda idp: idp.response(sign_with=ForgedIdP().key),
        ReasonCode.SIGNATURE_INVALID,
    ),
    (
        "algorithm_allowlist",
        lambda idp: idp.response(signature_method_uri="http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        ReasonCode.WEAK_ALGORITHM,
    ),
    (
        "destination",
        lambda idp: idp.response(destination="https://elsewhere.test/saml/acs"),
        ReasonCode.DESTINATION_MISMATCH,
    ),
    (
        "in_response_to",
        lambda idp: idp.response(in_response_to="_never-sent"),
        ReasonCode.UNKNOWN_INRESPONSETO,
    ),
    (
        "unsolicited",
        lambda idp: idp.response(in_response_to=None),
        ReasonCode.UNSOLICITED_RESPONSE,
    ),
    (
        "subject_confirmation_recipient",
        lambda idp: idp.response(recipient="https://elsewhere.test/saml/acs"),
        ReasonCode.SUBJECT_CONFIRMATION_INVALID,
    ),
    (
        # Conditions kept valid so this isolates the confirmation window. The
        # two normally expire together, and `conditions` runs first.
        "subject_confirmation_expiry",
        lambda idp: idp.response(
            subject_not_on_or_after=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
        ),
        ReasonCode.SUBJECT_CONFIRMATION_INVALID,
    ),
    (
        "audience",
        lambda idp: idp.response(audience="https://someone-else.test/metadata"),
        ReasonCode.AUDIENCE_MISMATCH,
    ),
    (
        "conditions_expired",
        lambda idp: idp.response(not_on_or_after=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)),
        ReasonCode.ASSERTION_EXPIRED,
    ),
    (
        "conditions_not_yet_valid",
        lambda idp: idp.response(not_before=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)),
        ReasonCode.ASSERTION_NOT_YET_VALID,
    ),
    (
        "conditions_understood",
        lambda idp: idp.response(extra_conditions=UNSUPPORTED_CONDITION),
        ReasonCode.UNSUPPORTED_CONDITION,
    ),
    (
        "authn_statement",
        lambda idp: idp.response(authn_context=None),
        ReasonCode.MISSING_AUTHN_STATEMENT,
    ),
]


@pytest.mark.parametrize(
    ("check", "forge", "reason"),
    REJECTIONS,
    ids=[case[0] for case in REJECTIONS],
)
async def test_rejects(
    gate: AssertionGate, idp: ForgedIdP, check: str, forge: Forge, reason: ReasonCode
) -> None:
    with pytest.raises(SamlRejected) as exc:
        await gate.validate(forge(idp))

    assert exc.value.reason is reason, f"{check}: rejected for the wrong reason"


async def test_a_replayed_response_cannot_reuse_the_outstanding_request(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """The first line of defence against replay is not the replay cache.

    An `AuthnRequest` is single-use, so a captured response replayed at the ACS
    fails correlation before the cache is ever consulted. Worth pinning: it
    means the two controls are independent, and losing one does not silently
    open the door.
    """
    document = idp.response()
    await gate.validate(document)

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.UNKNOWN_INRESPONSETO


async def test_rejects_a_replayed_assertion(
    gate: AssertionGate, idp: ForgedIdP, request_store: InMemoryRequestStore
) -> None:
    """The replay cache proper, isolated.

    Re-seeding the outstanding request between attempts removes the
    correlation defence above, so this proves the cache stands on its own —
    which is what matters for an IdP configured to allow unsolicited SSO,
    where there is no request to correlate against.
    """
    document = idp.response()
    outstanding = request_store.requests["_request1"]
    await gate.validate(document)

    request_store.requests["_request1"] = outstanding

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.REPLAY_DETECTED


# --- the accepting half of the matrix -------------------------------------


async def test_accepts_a_well_formed_response(gate: AssertionGate, idp: ForgedIdP) -> None:
    facts = await gate.validate(idp.response())

    assert facts.issuer == idp.entity_id
    assert facts.name_id == "sam.obrien@campus.edu"
    assert facts.assertion_id == "_assertion1"
    assert facts.session_index == "_session1"
    assert facts.relay_state == "relay-token"
    assert facts.authn_context.endswith("PasswordProtectedTransport")  # type: ignore[union-attr]


async def test_accepts_and_extracts_released_attributes(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    facts = await gate.validate(
        idp.response(
            attributes={
                "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": ["sam.obrien@campus.edu"],
                "urn:oid:1.3.6.1.4.1.5923.1.1.1.9": [
                    "student@campus.edu",
                    "member@campus.edu",
                ],
            }
        )
    )

    assert facts.attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"] == [
        "student@campus.edu",
        "member@campus.edu",
    ]


@pytest.mark.parametrize("signing", ["assertion", "both"])
async def test_accepts_either_signing_arrangement(
    gate: AssertionGate, idp: ForgedIdP, signing: str
) -> None:
    """Keycloak signs both by default; a signed Response around a signed
    Assertion must not be mistaken for wrapping."""
    facts = await gate.validate(idp.response(sign=signing))  # type: ignore[arg-type]

    assert facts.assertion_id == "_assertion1"


@pytest.mark.parametrize("offset_seconds", [-170, 0, 170])
async def test_accepts_within_the_clock_skew_allowance(
    gate: AssertionGate, idp: ForgedIdP, offset_seconds: int
) -> None:
    """Clock skew between an IdP and an SP is the most common cause of a
    working integration failing in production.

    Offsets stay ten seconds clear of the 180s boundary because the gate reads
    its own clock, a moment after this test read one: at -179 the margin is a
    single second and the test fails whenever the machine is loaded. The exact
    boundary is pinned deterministically below instead.
    """
    now = dt.datetime.now(dt.UTC)
    facts = await gate.validate(
        idp.response(not_on_or_after=now + dt.timedelta(seconds=offset_seconds))
    )

    assert facts.assertion_id == "_assertion1"


@pytest.mark.parametrize(
    ("offset_seconds", "accepted"),
    [(-181, False), (-180, False), (-179, True), (0, True)],
)
async def test_the_skew_boundary_is_exact(
    gate_policy: GatePolicy,
    resolve_idp: IdPResolver,
    request_store: InMemoryRequestStore,
    idp: ForgedIdP,
    offset_seconds: int,
    accepted: bool,
) -> None:
    """The boundary itself, with a frozen clock.

    Wall-clock tests cannot assert a one-second edge without being flaky, and a
    skew allowance that silently drifts by a second either rejects valid logins
    or extends the window an attacker has.
    """
    frozen = dt.datetime(2026, 9, 8, 12, 0, tzinfo=dt.UTC)
    gate = AssertionGate(
        policy=gate_policy,
        resolve_idp=resolve_idp,
        replay_cache=InMemoryReplayCache(),
        request_store=request_store,
        now=lambda: frozen,
    )
    document = idp.response(
        not_on_or_after=frozen + dt.timedelta(seconds=offset_seconds),
        subject_not_on_or_after=frozen + dt.timedelta(hours=1),
        not_before=frozen - dt.timedelta(hours=1),
        authn_instant=frozen,
    )

    if accepted:
        assert (await gate.validate(document)).assertion_id == "_assertion1"
    else:
        with pytest.raises(SamlRejected) as exc:
            await gate.validate(document)
        assert exc.value.reason is ReasonCode.ASSERTION_EXPIRED


async def test_a_recognised_condition_is_accepted(gate: AssertionGate, idp: ForgedIdP) -> None:
    """`OneTimeUse` is understood — the replay cache is precisely its contract
    — so it must not trip the unsupported-condition rule."""
    one_time_use = '<saml:OneTimeUse xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>'

    facts = await gate.validate(idp.response(extra_conditions=one_time_use))

    assert facts.assertion_id == "_assertion1"
