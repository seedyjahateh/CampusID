"""Between the registry and a SCIM User (PRD §8.5).

Two directions that are not symmetric: outward is a projection with a
disclosure decision in it, inward is a translation with judgement in it. Both
halves are here because a round trip that loses something is the failure mode,
and neither half shows it alone.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

import pytest

from campusid.identity.models import Affiliation, Identifier, Person
from campusid.scim.errors import ScimError
from campusid.scim.resources import (
    STATUS_SUSPENDED,
    UserRecord,
    etag,
    from_scim,
    to_scim,
)
from campusid.scim.schemas import CAMPUS_USER, CORE_USER, ENTERPRISE_USER

ISSUER = "https://broker.test"
PERSON_UUID = uuid.UUID("2819c223-7f76-453a-919d-413861904646")
NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


def _identifier(
    id_type: str, value: str, *, primary: bool = True, released: bool = False
) -> Identifier:
    return Identifier(
        id=uuid.uuid4(),
        person_uuid=PERSON_UUID,
        id_type=id_type,
        value=value,
        scope="campus.test",
        is_primary=primary,
        issued_at=NOW,
        released_at=NOW if released else None,
    )


def _record(**overrides: Any) -> UserRecord:
    person = Person(
        person_uuid=PERSON_UUID,
        edu_person_unique_id="opaque@campus.test",
        display_name="Samira O'Brien",
        given_name="Samira",
        surname="O'Brien",
        status=overrides.pop("status", "active"),
        ferpa_directory_suppressed=overrides.pop("suppressed", False),
        created_at=NOW,
        updated_at=NOW,
    )
    return UserRecord(
        person=person,
        identifiers=overrides.pop(
            "identifiers",
            [
                _identifier("eppn", "sam.obrien@campus.test"),
                _identifier("mail", "sam.obrien@campus.test"),
            ],
        ),
        affiliations=overrides.pop("affiliations", []),
        external_id=overrides.pop("external_id", None),
    )


# --- outward ----------------------------------------------------------------


def test_a_person_projects_as_a_scim_user() -> None:
    resource = to_scim(_record(), issuer=ISSUER)

    assert resource["schemas"] == [CORE_USER]
    assert resource["id"] == str(PERSON_UUID)
    assert resource["userName"] == "sam.obrien@campus.test"
    assert resource["active"] is True
    assert resource["name"]["familyName"] == "O'Brien"


def test_a_person_with_no_eppn_at_all_still_has_a_username() -> None:
    """RFC 7643 §4.1 makes `userName` REQUIRED, so it is never null.

    The state should not arise and it did, in a development database left by an
    interrupted run: the person had no identifier rows, and the resource went out
    with `"userName": null`. A conformance client reading a listing gets a type
    error on a field the specification promises is a string, several layers away
    from anything that names the cause.

    `edu_person_unique_id` is the floor because it is the broker's own permanent,
    scoped name for the person and the column cannot be null.
    """
    resource = to_scim(_record(identifiers=[]), issuer=ISSUER)

    assert resource["userName"] == "opaque@campus.test"


def test_a_released_eppn_is_still_the_username() -> None:
    """Asserted alongside the floor above so the two cannot be confused.

    A soft-deleted person has every identifier tombstoned, and what they were
    called is a historical fact. Falling through to the opaque id here would
    change a deprovisioned person's `userName` the moment they were
    deprovisioned, which is exactly when an auditor goes looking for it.
    """
    record = _record(identifiers=[_identifier("eppn", "gone@campus.test", released=True)])

    assert to_scim(record, issuer=ISSUER)["userName"] == "gone@campus.test"


def test_a_person_with_only_an_email_falls_through_to_the_opaque_id() -> None:
    """The floor is about the absence of an ePPN, not the absence of
    identifiers: an address is not a `userName` and never substitutes for one."""
    record = _record(identifiers=[_identifier("mail", "sam@campus.test")])

    assert to_scim(record, issuer=ISSUER)["userName"] == "opaque@campus.test"


def test_a_suspended_person_is_inactive() -> None:
    resource = to_scim(_record(status=STATUS_SUSPENDED), issuer=ISSUER)

    assert resource["active"] is False


def test_a_released_email_is_not_projected() -> None:
    """Kept in the registry forever so the address is never reissued, but an
    address somebody no longer has is not a way to reach them."""
    record = _record(
        identifiers=[
            _identifier("eppn", "sam.obrien@campus.test"),
            _identifier("mail", "old@campus.test", primary=False, released=True),
            _identifier("mail", "sam.obrien@campus.test"),
        ]
    )

    resource = to_scim(record, issuer=ISSUER)

    assert [email["value"] for email in resource["emails"]] == ["sam.obrien@campus.test"]


def test_the_primary_email_comes_first() -> None:
    record = _record(
        identifiers=[
            _identifier("eppn", "sam@campus.test"),
            _identifier("mail", "secondary@campus.test", primary=False),
            _identifier("mail", "primary@campus.test", primary=True),
        ]
    )

    resource = to_scim(record, issuer=ISSUER)

    assert resource["emails"][0]["value"] == "primary@campus.test"
    assert resource["emails"][0]["primary"] is True


def test_a_username_falls_back_to_a_non_primary_identifier() -> None:
    """An identifier issued before the concept of primary existed, or one whose
    primary was released, would otherwise make the record look like it has no
    ePPN at all."""
    record = _record(identifiers=[_identifier("eppn", "sam@campus.test", primary=False)])

    assert to_scim(record, issuer=ISSUER)["userName"] == "sam@campus.test"


def test_an_employee_number_is_projected_to_the_owning_client() -> None:
    """`restricted` in the catalogue and never released to a service provider —
    but SCIM is not attribute release. This is the provisioning client that
    supplied the value reading back the record it owns."""
    record = _record(
        identifiers=[
            _identifier("eppn", "sam@campus.test"),
            _identifier("employee_id", "E00184213"),
        ]
    )

    resource = to_scim(record, issuer=ISSUER)

    assert resource[ENTERPRISE_USER]["employeeNumber"] == "E00184213"
    assert ENTERPRISE_USER in resource["schemas"]


def test_affiliations_carry_their_dates() -> None:
    """The reason the extension exists: SCIM core cannot say when somebody was
    a student."""
    record = _record(
        affiliations=[
            Affiliation(
                id=uuid.uuid4(),
                person_uuid=PERSON_UUID,
                affiliation="student",
                is_primary=True,
                org_unit="Computer Science",
                valid_from=date(2022, 9, 1),
                valid_until=date(2026, 6, 30),
                source="sis",
            ),
            Affiliation(
                id=uuid.uuid4(),
                person_uuid=PERSON_UUID,
                affiliation="alum",
                is_primary=False,
                org_unit=None,
                valid_from=date(2026, 7, 1),
                valid_until=None,
                source="sis",
            ),
        ]
    )

    affiliations = to_scim(record, issuer=ISSUER)[CAMPUS_USER]["affiliations"]

    assert affiliations[0]["value"] == "student"
    assert affiliations[0]["validUntil"] == "2026-06-30"
    assert "validUntil" not in affiliations[1]


def test_the_ferpa_flag_is_projected_when_set() -> None:
    resource = to_scim(_record(suppressed=True), issuer=ISSUER)

    assert resource[CAMPUS_USER]["ferpaDirectorySuppressed"] is True


def test_an_extension_with_nothing_in_it_is_omitted() -> None:
    """An empty extension object tells a client the schema applies and carries
    nothing, which is a different and misleading statement."""
    resource = to_scim(_record(), issuer=ISSUER)

    assert CAMPUS_USER not in resource
    assert ENTERPRISE_USER not in resource["schemas"]


def test_the_location_is_absolute() -> None:
    resource = to_scim(_record(), issuer=ISSUER)

    assert resource["meta"]["location"] == f"{ISSUER}/scim/v2/Users/{PERSON_UUID}"


def test_the_timestamps_are_rfc_3339_with_a_z() -> None:
    """What every SCIM client expects to parse."""
    meta = to_scim(_record(), issuer=ISSUER)["meta"]

    assert meta["created"].endswith("Z")
    assert "+00:00" not in meta["created"]


# --- the ETag ---------------------------------------------------------------


def test_the_version_is_a_weak_etag() -> None:
    """Weak because two representations differing only in attribute order are
    the same resource, and strong comparison would make a client's `If-Match`
    fail for a reason it could never diagnose."""
    version = to_scim(_record(), issuer=ISSUER)["meta"]["version"]

    assert version.startswith('W/"')


def test_the_same_record_projects_the_same_version() -> None:
    """Otherwise every read would invalidate the client's cached ETag."""
    first = to_scim(_record(), issuer=ISSUER)["meta"]["version"]
    second = to_scim(_record(), issuer=ISSUER)["meta"]["version"]

    assert first == second


def test_a_changed_record_projects_a_different_version() -> None:
    changed = to_scim(_record(status=STATUS_SUSPENDED), issuer=ISSUER)["meta"]["version"]

    assert changed != to_scim(_record(), issuer=ISSUER)["meta"]["version"]


def test_the_version_does_not_depend_on_itself() -> None:
    """Computed over the document with `meta` excluded. Including it would make
    the hash depend on its own output."""
    resource = to_scim(_record(), issuer=ISSUER)

    assert etag(resource) == resource["meta"]["version"]


# --- inward -----------------------------------------------------------------


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schemas": [CORE_USER],
        "userName": "sam.obrien@campus.test",
        "name": {"givenName": "Samira", "familyName": "O'Brien"},
        "emails": [{"value": "sam.obrien@campus.test", "type": "work", "primary": True}],
        "active": True,
    }
    document.update(overrides)
    return document


def test_a_scim_user_parses() -> None:
    parsed = from_scim(_document())

    assert parsed.user_name == "sam.obrien@campus.test"
    assert parsed.given_name == "Samira"
    assert parsed.emails == [("sam.obrien@campus.test", True)]
    assert parsed.active is True


def test_the_username_is_lowercased() -> None:
    """The registry stores identifiers lowercased, and a client sending mixed
    case must not create a second one."""
    assert from_scim(_document(userName="Sam.OBrien@Campus.Test")).user_name == (
        "sam.obrien@campus.test"
    )


def test_inactive_maps_to_suspended_not_deleted() -> None:
    """The registry has four statuses and SCIM has a boolean, so the mapping has
    to choose. `suspended` is the reversible one, which is right for a flag a
    client can flip back — the end-states are an administrator's decision."""
    assert from_scim(_document(active=False)).status == STATUS_SUSPENDED


def test_a_missing_username_is_refused() -> None:
    with pytest.raises(ScimError, match="userName"):
        from_scim({"schemas": [CORE_USER]})


def test_a_non_boolean_active_is_refused() -> None:
    """`"false"` is a string and would be truthy. A client sending it means the
    opposite of what happens."""
    with pytest.raises(ScimError, match="active"):
        from_scim(_document(active="false"))


def test_an_address_without_an_at_sign_is_refused() -> None:
    with pytest.raises(ScimError, match="email"):
        from_scim(_document(emails=[{"value": "not-an-address"}]))


def test_two_primary_emails_are_refused() -> None:
    """RFC 7643 §2.4. Two would make "the primary address" a question with two
    answers, and which one won would depend on iteration order."""
    with pytest.raises(ScimError, match="one email may be primary"):
        from_scim(
            _document(
                emails=[
                    {"value": "a@campus.test", "primary": True},
                    {"value": "b@campus.test", "primary": True},
                ]
            )
        )


def test_affiliations_parse_with_their_dates() -> None:
    parsed = from_scim(
        _document(
            **{
                CAMPUS_USER: {
                    "affiliations": [
                        {
                            "value": "student",
                            "primary": True,
                            "orgUnit": "Computer Science",
                            "validFrom": "2022-09-01",
                            "validUntil": "2026-06-30",
                        }
                    ]
                }
            }
        )
    )

    affiliation = parsed.affiliations[0]
    assert affiliation.value == "student"
    assert affiliation.valid_from == date(2022, 9, 1)
    assert affiliation.valid_until == date(2026, 6, 30)


def test_a_full_timestamp_is_accepted_where_a_date_is_expected() -> None:
    """The schema declares `dateTime` because SCIM has no bare date type, but an
    SIS sends `2026-06-30` as often as it sends an instant. Refusing the shorter
    form would be conformance theatre at an integrator's expense."""
    parsed = from_scim(
        _document(
            **{
                CAMPUS_USER: {
                    "affiliations": [{"value": "student", "validFrom": "2022-09-01T00:00:00Z"}]
                }
            }
        )
    )

    assert parsed.affiliations[0].valid_from == date(2022, 9, 1)


def test_an_affiliation_ending_before_it_starts_is_refused() -> None:
    with pytest.raises(ScimError, match="before it starts"):
        from_scim(
            _document(
                **{
                    CAMPUS_USER: {
                        "affiliations": [
                            {
                                "value": "student",
                                "validFrom": "2026-01-01",
                                "validUntil": "2022-01-01",
                            }
                        ]
                    }
                }
            )
        )


def test_an_unparseable_date_is_refused_by_name() -> None:
    """A 400 naming the attribute is what lets an SIS integrator fix their
    mapping; an integrity error surfaces as a 500 and tells them nothing."""
    with pytest.raises(ScimError, match="validFrom"):
        from_scim(
            _document(
                **{CAMPUS_USER: {"affiliations": [{"value": "student", "validFrom": "soon"}]}}
            )
        )


def test_the_ferpa_flag_parses() -> None:
    parsed = from_scim(_document(**{CAMPUS_USER: {"ferpaDirectorySuppressed": True}}))

    assert parsed.ferpa_directory_suppressed is True


def test_an_employee_number_parses_from_the_enterprise_extension() -> None:
    parsed = from_scim(_document(**{ENTERPRISE_USER: {"employeeNumber": "E00184213"}}))

    assert parsed.employee_number == "E00184213"


def test_an_unknown_extension_is_ignored_rather_than_refused() -> None:
    """A client sending an extension we do not implement is not making an
    error — SCIM is explicitly extensible, and refusing would break a client
    that also talks to another server."""
    parsed = from_scim(_document(**{"urn:example:2.0:User": {"whatever": True}}))

    assert parsed.user_name == "sam.obrien@campus.test"


def test_something_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ScimError, match="must be an object"):
        from_scim(["not", "a", "user"])
