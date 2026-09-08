"""Check ordering, asserted through behaviour.

Ordering in the gate is a security property, not a stylistic one, so it is
tested by consequence rather than by inspecting a list of check names. Each
test below builds a document that fails *two* checks at once and asserts which
one reports — which is the only way to prove the sequence from the outside.

The two poisoning tests are the important ones. Both describe the same shape of
bug: a check that consumes state before the signature has been verified lets an
unauthenticated attacker destroy a legitimate user's login.
"""

from __future__ import annotations

import datetime as dt

import pytest

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.gate import AssertionGate
from tests.support.saml_forge import ForgedIdP
from tests.support.stores import InMemoryReplayCache, InMemoryRequestStore

pytestmark = pytest.mark.security


async def test_a_forged_response_cannot_poison_the_replay_cache(
    gate: AssertionGate,
    idp: ForgedIdP,
    replay_cache: InMemoryReplayCache,
) -> None:
    """Replay must be recorded only *after* the signature verifies.

    Otherwise an attacker who can observe assertion IDs — or simply guess one —
    POSTs a forged response carrying that ID, the gate records it, and the
    genuine assertion is then rejected as a replay. That is a denial of service
    on login, mounted without any credential.
    """
    stolen_id = "_assertion1"
    forged = idp.response(assertion_id=stolen_id, sign_with=ForgedIdP().key)

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(forged)
    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID

    assert replay_cache.remembered == {}, "a forged response reached the replay cache"

    # The genuine assertion, with the same ID, must still be accepted.
    facts = await gate.validate(idp.response(assertion_id=stolen_id))
    assert facts.assertion_id == stolen_id


async def test_a_forged_response_cannot_burn_the_outstanding_request(
    gate: AssertionGate,
    idp: ForgedIdP,
    request_store: InMemoryRequestStore,
) -> None:
    """Same shape as replay poisoning, one step earlier.

    The outstanding request is single-use, so consuming it before verifying the
    signature would let a forged response cancel a real login in flight.
    """
    forged = idp.response(sign_with=ForgedIdP().key)

    with pytest.raises(SamlRejected):
        await gate.validate(forged)

    assert "_request1" in request_store.requests, "a forged response consumed the request"

    facts = await gate.validate(idp.response())
    assert facts.relay_state == "relay-token"


async def test_structure_is_checked_before_the_signature(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """A wrapped document must report wrapping, whatever else is wrong with it.

    If verification ran first this would surface as `signature_invalid`, and
    the audit trail would show a routine bad signature instead of an attack.
    """
    document = idp.response(xsw=3, sign_with=ForgedIdP().key)

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.SIGNATURE_WRAPPING_DETECTED


async def test_the_signature_is_checked_before_the_conditions(
    gate: AssertionGate, idp: ForgedIdP
) -> None:
    """Nothing inside an unverified assertion is worth reporting on.

    Announcing `assertion_expired` for a document we never authenticated would
    describe attacker-supplied content as though it were fact.
    """
    document = idp.response(
        sign_with=ForgedIdP().key,
        not_on_or_after=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1),
    )

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID


async def test_status_is_checked_before_the_signature(gate: AssertionGate, idp: ForgedIdP) -> None:
    """An IdP reporting failure sends no assertion at all.

    Without this ordering the gate would report `signature_missing`, and the
    operator would spend the afternoon debugging signing configuration instead
    of reading the IdP's actual error.
    """
    document = idp.response(status_code="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", sign=None)

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.IDP_ERROR_STATUS


async def test_the_issuer_must_be_resolved_before_a_certificate_is_chosen(
    gate: AssertionGate, idp: ForgedIdP, other_idp: ForgedIdP
) -> None:
    """The defining multi-IdP broker bug.

    `other_idp` is a *registered, trusted* peer. Its signature is perfectly
    valid — just not for this issuer. Verifying against any registered
    certificate rather than the issuer's own would let every peer impersonate
    every other peer.
    """
    document = idp.response(sign_with=other_idp.key)

    with pytest.raises(SamlRejected) as exc:
        await gate.validate(document)

    assert exc.value.reason is ReasonCode.SIGNATURE_INVALID
