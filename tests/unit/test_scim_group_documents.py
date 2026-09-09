"""Group documents (FR-SCIM-11).

The half of `/Groups` that is a JSON question rather than a SQL one: what a
client's document asks for, what a group looks like projected back, and what a
PATCH operation means before anything is written.

The two cases worth reading are the ones a naive implementation gets wrong in
opposite directions. A `PUT` that never mentions `members` must not empty the
group, and a `PUT` that mentions it as `[]` must. And a member filter has to be
*recognised* rather than approximated: an unfamiliar one returns None so the
caller evaluates it properly, never a guess.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from campusid.scim.errors import ScimError
from campusid.scim.filters import parse_filter, parse_patch_path
from campusid.scim.group_resources import (
    GroupRecord,
    attribute_changes,
    group_etag,
    matches_version,
    member_ids,
    member_target,
    parse_group,
    targets_members,
    to_scim_group,
)
from campusid.scim.models import ScimGroup
from campusid.scim.patch import Op, Operation
from campusid.scim.schemas import CORE_GROUP

ISSUER = "https://broker.test"
GROUP_UUID = uuid.UUID("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")
PERSON_UUID = uuid.UUID("8f14e45f-ceea-467a-9b2e-2b5ea3e2a9c1")
OTHER_UUID = uuid.UUID("c9f0f895-fb98-4b1f-a1a4-1a4b1a4b1a4b")
INSTANT = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


def _group(**overrides: object) -> ScimGroup:
    group = ScimGroup(
        group_uuid=GROUP_UUID,
        display_name="lms-students",
        external_id=None,
        revision=1,
    )
    group.created_at = INSTANT
    group.updated_at = INSTANT
    for name, value in overrides.items():
        setattr(group, name, value)
    return group


def _operation(op: str, path: str | None = None, value: object = None) -> Operation:
    return Operation(op=Op(op), path=parse_patch_path(path) if path else None, value=value)


# --- projection -------------------------------------------------------------


def test_a_group_projects_without_members_by_default() -> None:
    """`returned: "request"`. A group here may have tens of thousands of members
    and serving them by default would make listing groups cost the whole
    membership table."""
    resource = to_scim_group(GroupRecord(group=_group(), member_count=3), issuer=ISSUER)

    assert "members" not in resource
    assert resource["schemas"] == [CORE_GROUP]
    assert resource["displayName"] == "lms-students"


def test_an_empty_membership_is_not_the_same_as_an_unrequested_one() -> None:
    """None means "not asked for" and `[]` means "nobody is in it". Collapsing
    them would have a client believe an unrequested group is empty."""
    unrequested = to_scim_group(GroupRecord(group=_group()), issuer=ISSUER)
    empty = to_scim_group(GroupRecord(group=_group(), members=[]), issuer=ISSUER)

    assert "members" not in unrequested
    assert empty["members"] == []


def test_a_projected_member_carries_a_reference() -> None:
    record = GroupRecord(group=_group(), members=[(PERSON_UUID, "Dana Wu")], member_count=1)

    member = to_scim_group(record, issuer=ISSUER)["members"][0]

    assert member["value"] == str(PERSON_UUID)
    assert member["display"] == "Dana Wu"
    assert member["$ref"] == f"{ISSUER}/scim/v2/Users/{PERSON_UUID}"


def test_the_external_id_is_omitted_rather_than_null() -> None:
    """An absent attribute and one present as null are different to a
    conformance client, and the specification asks for absence."""
    assert "externalId" not in to_scim_group(GroupRecord(group=_group()), issuer=ISSUER)


def test_an_external_id_is_projected_when_the_group_has_one() -> None:
    """The provisioning client's own key, handed back so it can match our
    resource to its record without keeping a mapping table."""
    resource = to_scim_group(GroupRecord(group=_group(external_id="sis-42")), issuer=ISSUER)

    assert resource["externalId"] == "sis-42"


def test_the_meta_block_locates_and_versions_the_group() -> None:
    meta = to_scim_group(GroupRecord(group=_group(revision=7)), issuer=ISSUER)["meta"]

    assert meta["resourceType"] == "Group"
    assert meta["location"] == f"{ISSUER}/scim/v2/Groups/{GROUP_UUID}"
    assert meta["version"] == 'W/"7"'
    assert meta["lastModified"] == "2026-09-09T12:00:00Z"


def test_a_naive_timestamp_is_read_as_utc() -> None:
    """Postgres hands back an aware value, but a fixture or a migration default
    may not, and a projection that raised on one would fail far from the cause."""
    group = _group()
    group.created_at = datetime(2026, 9, 9, 12, 0)

    assert to_scim_group(GroupRecord(group=group), issuer=ISSUER)["meta"]["created"].endswith("Z")


# --- versions ---------------------------------------------------------------


def test_the_version_is_a_counter_not_a_hash() -> None:
    """The whole of why a one-member PATCH stays cheap: answering "has this
    changed" never reads the membership."""
    assert group_etag(1) == 'W/"1"'
    assert group_etag(2) != group_etag(1)


@pytest.mark.parametrize("header", ['W/"4"', '"4"', "*", 'W/"3", W/"4"'])
def test_a_current_version_matches(header: str) -> None:
    """Weak comparison, tolerating a client that strips the prefix. Several do,
    and the specification asks for a weak comparison anyway."""
    assert matches_version('W/"4"', header)


@pytest.mark.parametrize("header", ['W/"3"', '"3"', 'W/"40"'])
def test_a_stale_version_does_not_match(header: str) -> None:
    assert not matches_version('W/"4"', header)


# --- reading a document -----------------------------------------------------


def test_a_document_without_a_display_name_is_refused() -> None:
    with pytest.raises(ScimError) as raised:
        parse_group({"schemas": [CORE_GROUP]})

    assert raised.value.status == 400


def test_a_blank_display_name_is_refused() -> None:
    """Whitespace is not a name. A group called " " is indistinguishable from
    one called "  " to whoever is deciding who gets access."""
    with pytest.raises(ScimError):
        parse_group({"displayName": "   "})


def test_a_display_name_is_trimmed() -> None:
    assert parse_group({"displayName": " lms-students "}).display_name == "lms-students"


def test_an_unmentioned_members_array_parses_as_none() -> None:
    """Which is what makes a PUT that omits it leave the membership alone."""
    assert parse_group({"displayName": "lms"}).members is None


def test_an_explicit_empty_members_array_parses_as_empty() -> None:
    """The client saying so, rather than the client not saying anything."""
    assert parse_group({"displayName": "lms", "members": []}).members == []


def test_a_non_string_external_id_is_refused() -> None:
    with pytest.raises(ScimError):
        parse_group({"displayName": "lms", "externalId": 12345})


def test_members_are_read_in_order_without_duplicates() -> None:
    """A client that lists somebody twice is not making an error worth a 400,
    but the insert must not carry the duplicate into the database."""
    people = member_ids(
        [{"value": str(PERSON_UUID)}, {"value": str(OTHER_UUID)}, {"value": str(PERSON_UUID)}]
    )

    assert people == [PERSON_UUID, OTHER_UUID]


def test_a_bare_string_member_is_accepted() -> None:
    """Several clients send one, and refusing it teaches nobody anything."""
    assert member_ids([str(PERSON_UUID)]) == [PERSON_UUID]


def test_a_single_member_object_is_accepted() -> None:
    assert member_ids({"value": str(PERSON_UUID)}) == [PERSON_UUID]


def test_no_members_at_all_reads_as_an_empty_list() -> None:
    """The store calls this with whatever an operation carried, and an `add`
    with no value is a request that changes nothing rather than an error."""
    assert member_ids(None) == []


def test_a_member_that_is_not_an_id_is_refused() -> None:
    with pytest.raises(ScimError):
        member_ids([{"value": "not-a-uuid"}])


def test_a_member_without_a_value_is_refused() -> None:
    with pytest.raises(ScimError):
        member_ids([{"display": "Dana Wu"}])


def test_members_must_be_an_array() -> None:
    with pytest.raises(ScimError):
        member_ids("everyone")


# --- what an operation targets ----------------------------------------------


def test_a_members_path_targets_membership() -> None:
    assert targets_members(_operation("add", "members", [{"value": str(PERSON_UUID)}]))


def test_a_filtered_members_path_targets_membership() -> None:
    assert targets_members(_operation("remove", f'members[value eq "{PERSON_UUID}"]'))


def test_a_display_name_path_does_not() -> None:
    assert not targets_members(_operation("replace", "displayName", "renamed"))


def test_a_pathless_operation_mentioning_members_targets_membership() -> None:
    """Most clients send bulk updates this way, and one that carried `members`
    into the attribute mapping would be refused as an unknown attribute."""
    assert targets_members(_operation("add", None, {"members": [{"value": str(PERSON_UUID)}]}))


def test_a_pathless_operation_mentioning_nothing_else_does_not() -> None:
    assert not targets_members(_operation("add", None, {"displayName": "renamed"}))


# --- attribute operations ---------------------------------------------------


def test_a_replace_names_the_column_it_changes() -> None:
    assert attribute_changes(_operation("replace", "displayName", "renamed"), 0) == {
        "display_name": "renamed"
    }


def test_a_remove_clears_the_external_id() -> None:
    assert attribute_changes(_operation("remove", "externalId"), 0) == {"external_id": None}


def test_a_display_name_cannot_be_removed() -> None:
    """A group with no name is not addressable by the person administering it."""
    with pytest.raises(ScimError):
        attribute_changes(_operation("remove", "displayName"), 0)


def test_an_unknown_attribute_is_an_invalid_path() -> None:
    with pytest.raises(ScimError) as raised:
        attribute_changes(_operation("replace", "description", "anything"), 3)

    assert raised.value.scim_type == "invalidPath"
    assert "operation 3" in raised.value.detail


def test_a_pathless_operation_applies_each_of_its_keys() -> None:
    changes = attribute_changes(
        _operation("add", None, {"displayName": "renamed", "externalId": "sis-1"}), 0
    )

    assert changes == {"display_name": "renamed", "external_id": "sis-1"}


def test_a_pathless_operation_cannot_rewrite_the_id() -> None:
    """The path form is refused when the operation is parsed, but a pathless one
    carries its attributes in the value — and a client that could rewrite `id`
    could point one group's record at another's."""
    with pytest.raises(ScimError) as raised:
        attribute_changes(_operation("replace", None, {"id": str(OTHER_UUID)}), 0)

    assert raised.value.scim_type == "mutability"


def test_a_pathless_operation_needs_an_object() -> None:
    with pytest.raises(ScimError):
        attribute_changes(_operation("add", None, "renamed"), 0)


def test_a_non_string_external_id_is_refused_in_a_patch() -> None:
    with pytest.raises(ScimError):
        attribute_changes(_operation("replace", "externalId", 12345), 0)


# --- recognising a member filter --------------------------------------------


def test_the_ordinary_member_filter_is_recognised() -> None:
    """`members[value eq "<id>"]`. Recognising it is what keeps a one-member
    removal from a ten-thousand-member group off the collection."""
    path = parse_patch_path(f'members[value eq "{PERSON_UUID}"]')
    assert path.predicate is not None

    assert member_target(path.predicate) == PERSON_UUID


@pytest.mark.parametrize(
    "expression",
    [
        'display eq "Dana Wu"',
        f'value ne "{PERSON_UUID}"',
        'value co "8f14"',
        'value eq "not-a-uuid"',
        "value eq 5",
        'value.type eq "User"',
        f'value eq "{PERSON_UUID}" and display eq "Dana Wu"',
    ],
)
def test_anything_else_is_not_recognised(expression: str) -> None:
    """None, so the caller evaluates the filter properly rather than acting on
    a guess. An approximate answer here would remove the wrong person."""
    assert member_target(parse_filter(expression)) is None
