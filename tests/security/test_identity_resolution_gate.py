"""Refusing a login the registry will not vouch for (PRD §8.4).

The assertion has already survived all fifteen checks by this point: the
signature is good, the audience is us, the IdP is one we trust. What is left is a
different question — *who* it is about — and there are two answers that must not
become a session.

**A match on an email address and nothing stronger.** §8.4's fourth rule
declines to link on that, because an IdP that can assert any address could assert
somebody else's. Letting the login through anyway with a fresh person attached
would be worse than refusing: two records for one human, and the weaker one
holding a session.

**A person we have deprovisioned.** The upstream IdP will go on authenticating
them happily — their account there is not ours to disable — so this refusal is
the entire reason identity is held here rather than at the IdP.

Both are recorded with distinct reason codes and both show the browser the same
page as every other rejection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from campusid.errors import BrokerError, ReasonCode
from campusid.identity.registry import LinkBasis, Resolution
from campusid.routes.saml import _resolve_person
from campusid.saml.gate import AssertionFacts
from campusid.session.store import Session

pytestmark = pytest.mark.security

ISSUER = "https://idp.campus.test/saml"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)

FACTS = AssertionFacts(
    issuer=ISSUER,
    assertion_id="_assertion1",
    name_id="opaque-name-id",
    name_id_format=None,
    not_on_or_after=NOW,
    authn_instant=NOW,
    authn_context=None,
    session_index=None,
)


class _Person:
    def __init__(self, status: str) -> None:
        self.status = status


class _Identity:
    """The registry, reduced to what the ACS asks of it."""

    def __init__(self, resolution: Resolution, person: _Person | None) -> None:
        self.resolution = resolution
        self.person = person
        self.asked: list[Any] = []

    async def resolve(self, assertion: Any) -> Resolution:
        self.asked.append(assertion)
        return self.resolution

    async def get(self, person_uuid: str) -> _Person | None:
        return self.person


def _state(resolution: Resolution, person: _Person | None) -> Any:
    return type("State", (), {"identity": _Identity(resolution, person)})()


async def test_a_resolved_active_person_is_admitted() -> None:
    state = _state(Resolution(PERSON, LinkBasis.EXISTING_ACCOUNT), _Person("active"))

    assert await _resolve_person(state, FACTS) == PERSON


async def test_a_mail_only_match_is_refused() -> None:
    """§8.4 rule 4. There is a person it might be, and acting on "might" is the
    account takeover the rule declines to perform."""
    state = _state(Resolution(None, LinkBasis.MANUAL_REVIEW), None)

    with pytest.raises(BrokerError) as exc:
        await _resolve_person(state, FACTS)

    assert exc.value.reason is ReasonCode.IDENTITY_REVIEW_REQUIRED


@pytest.mark.parametrize("status", ["suspended", "deactivated", "archived"])
async def test_a_deprovisioned_person_is_refused(status: str) -> None:
    """The IdP will still authenticate them. This is what stops them, and it is
    why identity is held here."""
    state = _state(Resolution(PERSON, LinkBasis.EXISTING_ACCOUNT), _Person(status))

    with pytest.raises(BrokerError) as exc:
        await _resolve_person(state, FACTS)

    assert exc.value.reason is ReasonCode.IDENTITY_SUSPENDED


async def test_the_assertion_reaches_the_registry_with_its_subject() -> None:
    """The `NameID` is the subject, not an attribute: the registry's second rule
    is "we have seen this exact subject at this exact issuer", and an attribute
    the IdP can change is not that."""
    state = _state(Resolution(PERSON, LinkBasis.EXISTING_ACCOUNT), _Person("active"))

    await _resolve_person(state, FACTS)

    asserted = state.identity.asked[0]
    assert asserted.subject == "opaque-name-id"
    assert asserted.idp_entity_id == ISSUER


# --- what the session is keyed on -------------------------------------------


def _session(**overrides: Any) -> Session:
    now = NOW
    fields: dict[str, Any] = {
        "sid": "sid-1",
        "idp_entity_id": ISSUER,
        "name_id": "opaque-name-id",
        "name_id_format": None,
        "auth_time": now,
        "created_at": now,
        "last_seen_at": now,
        "absolute_expiry": now,
    }
    fields.update(overrides)
    return Session(**fields)


def test_a_session_is_keyed_on_the_person() -> None:
    """So "end every session this person has" means every session, rather than
    every session from one IdP. Somebody who logged in through the campus IdP and
    again through a partner is one subject, and a deprovisioning that ended half
    of them would be the failure FR-LC-03 exists to prevent."""
    assert _session(person_uuid=PERSON).subject_key == PERSON


def test_two_logins_by_one_person_share_a_subject_key() -> None:
    campus = _session(person_uuid=PERSON)
    partner = _session(
        sid="sid-2",
        idp_entity_id="https://partner.test/saml",
        name_id="different",
        person_uuid=PERSON,
    )

    assert campus.subject_key == partner.subject_key


def test_a_session_without_a_person_keeps_the_older_key() -> None:
    """A stored session written before the registry was wired in still loads,
    and the pair is never split: a `NameID` is meaningful only within the IdP
    that minted it."""
    assert _session().subject_key == f"{ISSUER}|opaque-name-id"
