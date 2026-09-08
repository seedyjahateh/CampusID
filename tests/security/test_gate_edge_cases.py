"""Gate branches the main matrix does not reach.

Malformed-but-signed documents, mostly. Each is produced by the forge so the
signature stays valid, which is what makes them interesting: the gate has
already authenticated the issuer and still has to refuse the content.
"""

from __future__ import annotations

import datetime as dt

import pytest

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.gate import (
    AssertionGate,
    GatePolicy,
    TrustedIdP,
    _instant,
    _required_attribute,
)
from campusid.saml.namespaces import SAML
from campusid.saml.stores import OutstandingRequest
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore
from tests.support.xmlbuild import parse

pytestmark = pytest.mark.security


def _gate(
    idp: ForgedIdP,
    *,
    policy: GatePolicy | None = None,
    trusted: TrustedIdP | None = None,
    request_store: InMemoryRequestStore | None = None,
) -> AssertionGate:
    trusted = trusted or TrustedIdP(
        entity_id=idp.entity_id, signing_certificates=(idp.key.certificate_pem,)
    )
    return AssertionGate(
        policy=policy
        or GatePolicy(audience=idp.default_audience, destination=idp.default_destination),
        resolve_idp={idp.entity_id: trusted}.get,
        replay_cache=InMemoryReplayCache(),
        request_store=request_store or InMemoryRequestStore(),
    )


async def test_an_assertion_without_a_subject_is_refused(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    with pytest.raises(SamlRejected) as exc:
        await gate.validate(idp.response(include_subject=False))

    assert exc.value.reason is ReasonCode.SUBJECT_CONFIRMATION_INVALID


async def test_a_non_bearer_confirmation_method_is_refused(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """Holder-of-key confirmation would require proving possession of a key we
    never see. Accepting it as though it were bearer would treat an
    unsatisfied condition as satisfied."""
    with pytest.raises(SamlRejected) as exc:
        await gate.validate(
            idp.response(confirmation_method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
        )

    assert exc.value.reason is ReasonCode.SUBJECT_CONFIRMATION_INVALID


async def test_an_assertion_without_conditions_is_refused(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """No Conditions means no AudienceRestriction, so the assertion is not
    addressed to anyone in particular and could be replayed at any SP."""
    with pytest.raises(SamlRejected) as exc:
        await gate.validate(idp.response(include_conditions=False))

    assert exc.value.reason is ReasonCode.AUDIENCE_MISMATCH


async def test_a_response_with_no_issuer_is_refused(idp: ForgedIdP) -> None:
    with pytest.raises(SamlRejected) as exc:
        await _gate(idp).validate(idp.response(issuer="", assertion_issuer=""))

    assert exc.value.reason is ReasonCode.UNKNOWN_ISSUER


async def test_a_response_answering_another_idps_request_is_refused(
    idp: ForgedIdP,
) -> None:
    """The outstanding request records which IdP it was sent to. A response
    from a different one — even a trusted one — is not an answer to it."""
    store = InMemoryRequestStore()
    store.requests["_request1"] = OutstandingRequest(
        request_id="_request1",
        idp_entity_id="https://somewhere-else.test/saml",
        relay_state="relay-token",
        created_at=dt.datetime.now(dt.UTC),
    )

    with pytest.raises(SamlRejected) as exc:
        await _gate(idp, request_store=store).validate(idp.response())

    assert exc.value.reason is ReasonCode.UNKNOWN_INRESPONSETO


async def test_unsolicited_responses_are_accepted_when_enabled(idp: ForgedIdP) -> None:
    """IdP-initiated SSO is off by default and opt-in per IdP, because an
    unsolicited response cannot be correlated to anything the user started."""
    gate = _gate(
        idp,
        trusted=TrustedIdP(
            entity_id=idp.entity_id,
            signing_certificates=(idp.key.certificate_pem,),
            allow_unsolicited=True,
        ),
    )

    facts = await gate.validate(idp.response(in_response_to=None))

    assert facts.relay_state is None


async def test_a_response_without_a_destination_is_accepted(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """`Destination` is optional in SAML, and unprotected when only the
    assertion is signed. Its absence is not a failure — `Recipient`, inside the
    signature, is what actually binds delivery."""
    facts = await gate.validate(idp.response(destination=None))

    assert facts.assertion_id == "_assertion1"


async def test_an_authn_instant_older_than_max_age_is_refused(idp: ForgedIdP) -> None:
    store = InMemoryRequestStore()
    store.requests["_request1"] = OutstandingRequest(
        request_id="_request1",
        idp_entity_id=idp.entity_id,
        relay_state="relay-token",
        created_at=dt.datetime.now(dt.UTC),
    )
    gate = _gate(
        idp,
        policy=GatePolicy(
            audience=idp.default_audience,
            destination=idp.default_destination,
            max_authn_age=dt.timedelta(minutes=5),
        ),
        request_store=store,
    )

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(
            idp.response(authn_instant=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2))
        )

    assert exc.value.reason is ReasonCode.ASSERTION_EXPIRED


async def test_an_assertion_signed_only_at_response_level_is_accepted(
    idp: ForgedIdP,
) -> None:
    """Keycloak's default is to sign the Response, not the Assertion. An IdP
    configured that way is accepted only when explicitly registered as such."""
    gate = _gate(
        idp,
        trusted=TrustedIdP(
            entity_id=idp.entity_id,
            signing_certificates=(idp.key.certificate_pem,),
            want_assertions_signed=False,
        ),
        request_store=_seeded_store(idp),
    )

    facts = await gate.validate(idp.response(sign="response"))

    assert facts.assertion_id == "_assertion1"


async def test_a_wholly_unsigned_response_is_refused_even_when_lenient(
    idp: ForgedIdP,
) -> None:
    """`want_assertions_signed=False` relaxes *where* the signature must be,
    never whether there is one."""
    gate = _gate(
        idp,
        trusted=TrustedIdP(
            entity_id=idp.entity_id,
            signing_certificates=(idp.key.certificate_pem,),
            want_assertions_signed=False,
        ),
        request_store=_seeded_store(idp),
    )

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(idp.response(sign=None))

    assert exc.value.reason is ReasonCode.SIGNATURE_MISSING


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("not_a_datetime", "yesterday"),
        ("empty", ""),
        # Refused rather than assumed to be UTC: guessing a timezone shifts the
        # validity window by hours, which either rejects good logins or accepts
        # expired ones depending on which way the guess falls.
        ("naive_datetime", "2026-09-08T12:00:00"),
    ],
)
def test_malformed_timestamps_are_refused(label: str, value: str) -> None:
    """Tested against the helper directly.

    Splicing a bad timestamp into a signed document would break the signature,
    so the gate would refuse it as `signature_invalid` and the test would pass
    without ever reaching the timestamp parser.
    """
    element = parse(f'<saml:Conditions xmlns:saml="{SAML}" NotOnOrAfter="{value}"/>')

    with pytest.raises(SamlRejected) as exc:
        _instant(element, "NotOnOrAfter", required=True)

    assert exc.value.reason is ReasonCode.MALFORMED_RESPONSE, label


def test_a_missing_required_timestamp_is_refused() -> None:
    element = parse(f'<saml:Conditions xmlns:saml="{SAML}"/>')

    with pytest.raises(SamlRejected) as exc:
        _instant(element, "NotOnOrAfter", required=True)

    assert exc.value.reason is ReasonCode.MALFORMED_RESPONSE


def test_an_optional_timestamp_may_be_absent() -> None:
    element = parse(f'<saml:Conditions xmlns:saml="{SAML}"/>')

    assert _instant(element, "NotBefore", required=False) is None


def test_a_missing_required_attribute_is_refused() -> None:
    element = parse(f'<saml:Assertion xmlns:saml="{SAML}"/>')

    with pytest.raises(SamlRejected) as exc:
        _required_attribute(element, "ID")

    assert exc.value.reason is ReasonCode.MALFORMED_RESPONSE


def _seeded_store(idp: ForgedIdP) -> InMemoryRequestStore:
    store = InMemoryRequestStore()
    store.requests["_request1"] = OutstandingRequest(
        request_id="_request1",
        idp_entity_id=idp.entity_id,
        relay_state="relay-token",
        created_at=dt.datetime.now(dt.UTC),
    )
    return store
