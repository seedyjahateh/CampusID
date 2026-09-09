"""What may and may not appear in the audit trail (FR-AUD-06).

The trail is never deleted from, so a credential written into it is a credential
written down permanently. Redaction is therefore structural — enforced by the
emitter rather than trusted to each of the forty call sites — and this file is
mostly about the values that must not survive the trip.
"""

from __future__ import annotations

import pytest

from campusid.audit.events import (
    REDACTED,
    SECRET_MARKERS,
    EventType,
    Outcome,
    redact,
)
from campusid.policy.attributes import (
    CATALOGUE,
    EMPLOYEE_ID,
    EPPN,
    MAIL,
    PAIRWISE_ID,
    STUDENT_ID,
    Classification,
)
from tests.support.audit import RecordingAuditLog

pytestmark = pytest.mark.security

SECRETS = {
    "access_token": "eyJhbGciOiJSUzI1NiJ9.stolen",
    "refresh_token": "R-8dGf-secret",
    "client_secret": "s" * 43,
    "password": "hunter2",
    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "session_cookie": "__Host-campusid_session=abc",
    "saml_assertion": "<saml:Assertion>...</saml:Assertion>",
    "pairwise_salt": "restore-critical",
    "authorization_code": "c-12345",
    "signing_key": "-----BEGIN PRIVATE KEY-----",
    "api_credential": "abc",
}


@pytest.mark.parametrize("field", sorted(SECRETS))
def test_a_credential_never_reaches_the_trail(field: str) -> None:
    assert redact({field: SECRETS[field]})[field] == REDACTED


def test_the_secret_marker_list_is_about_shapes_not_names() -> None:
    """Matched as substrings on purpose. A field called `refresh_token_hint` or
    `saml_response_assertion` is exactly as disclosing as one called `token`,
    and an exact list only ever catches the names somebody thought of."""
    assert redact({"refresh_token_hint": "x"})["refresh_token_hint"] == REDACTED
    assert redact({"upstream_id_token": "x"})["upstream_id_token"] == REDACTED


def test_an_innocuous_field_survives() -> None:
    """False positives cost a redacted debugging aid; false negatives cost a
    credential in a table that is never deleted from. But the rule still has to
    leave the trail usable."""
    detail = redact({"client_id": "campus-portal", "scopes": ["openid"], "generation": 3})

    assert detail == {"client_id": "campus-portal", "scopes": ["openid"], "generation": 3}


def test_every_marker_is_lowercase() -> None:
    """The check lowercases the key before matching, so an uppercase marker
    would never fire — a silent hole in the one list that must not have one."""
    assert all(marker == marker.lower() for marker in SECRET_MARKERS)


# --- attribute values ------------------------------------------------------


def test_attribute_names_are_always_kept() -> None:
    """Knowing that `mail` was released is the point of the record. Knowing what
    the address was is not."""
    detail = redact({"attributes": {MAIL: ["sam@campus.test"], EPPN: ["sam@campus.test"]}})

    assert set(detail["attributes"]) == {MAIL, EPPN}


def test_a_directory_attributes_value_is_redacted() -> None:
    detail = redact({"attributes": {MAIL: ["sam.obrien@campus.test"]}})

    assert detail["attributes"][MAIL] == REDACTED


def test_a_public_attributes_value_survives() -> None:
    """A pairwise identifier is `public` in the catalogue's sense: it identifies
    a session at one SP, not a person. Recording it is what lets an
    investigation follow one user's activity at one application."""
    detail = redact({"attributes": {PAIRWISE_ID: ["Ky7Qw2mVc1Zr@campus.test"]}})

    assert detail["attributes"][PAIRWISE_ID] == ["Ky7Qw2mVc1Zr@campus.test"]


@pytest.mark.parametrize("name", [STUDENT_ID, EMPLOYEE_ID])
def test_an_education_records_value_never_appears(name: str) -> None:
    """The failure that would matter most: a studentID sitting in the disclosure
    record that exists to prove studentIDs are never disclosed."""
    detail = redact({"attributes": {name: ["S00184213"]}})

    assert detail["attributes"][name] == REDACTED


def test_an_unknown_attributes_value_is_redacted() -> None:
    """An unrecognised name is exactly the case where we cannot say the value is
    safe, so it is not released and not recorded."""
    detail = redact({"attributes": {"urn:made:up": ["something"]}})

    assert detail["attributes"]["urn:made:up"] == REDACTED


def test_only_public_attributes_keep_their_values() -> None:
    """Asserted against the whole catalogue rather than a sample, so an
    attribute added later is covered without anyone remembering to."""
    everything = {name: ["value"] for name in CATALOGUE}

    detail = redact({"attributes": everything})

    for name, attribute in CATALOGUE.items():
        expected = ["value"] if attribute.classification is Classification.PUBLIC else REDACTED
        assert detail["attributes"][name] == expected, name


def test_redaction_is_visible_rather_than_silent() -> None:
    """A dropped key would read as an attribute that was never released, which
    is a different and wrong statement about what happened."""
    detail = redact({"attributes": {MAIL: ["x"]}, "access_token": "y"})

    assert "attributes" in detail
    assert "access_token" in detail


# --- through the emitter ---------------------------------------------------


async def test_the_emitter_redacts_rather_than_the_call_site() -> None:
    """A rule enforced in one place is a rule; enforced at forty call sites it
    is a convention, and conventions are what the fortieth call site breaks."""
    audit = RecordingAuditLog()

    event = await audit.record(
        EventType.TOKEN_ISSUED,
        Outcome.SUCCESS,
        detail={"refresh_token": "R-secret", "attributes": {STUDENT_ID: ["S001"]}},
    )

    assert event.detail["refresh_token"] == REDACTED
    assert event.detail["attributes"][STUDENT_ID] == REDACTED


async def test_no_recorded_event_carries_a_known_secret_fixture() -> None:
    """The sweep FR-AUD-06 describes: emit everything the flows emit, then scan
    what came out for values we know are secret."""
    audit = RecordingAuditLog()
    for field, value in SECRETS.items():
        await audit.record(EventType.AUTH_SUCCESS, Outcome.SUCCESS, detail={field: value})

    recorded = repr([event.detail for event in audit.events])

    for value in SECRETS.values():
        assert value not in recorded
