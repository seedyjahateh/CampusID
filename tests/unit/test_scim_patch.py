"""SCIM PATCH (FR-SCIM-05, RFC 7644 §3.5.2).

The PRD calls this the single most underestimated item in the plan. `PATCH`
looks like "set this field" and is actually a small language for addressing
parts of a document — three operations, optional paths, and filters that select
members of a collection.

Most of these tests are about the ways a naive implementation quietly destroys
data: `add` that overwrites a collection, a filtered `remove` that deletes
everything when the filter matches nothing, a failed operation that leaves the
resource two-thirds changed.
"""

from __future__ import annotations

from typing import Any

import pytest

from campusid.scim.patch import (
    MAX_OPERATIONS,
    PATCH_OP_SCHEMA,
    Op,
    PatchError,
    apply_patch,
    parse_operations,
)


def _resource() -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "2819c223-7f76-453a-919d-413861904646",
        "userName": "sam.obrien",
        "active": True,
        "name": {"givenName": "Samira", "familyName": "O'Brien"},
        "emails": [
            {"type": "work", "value": "sam.obrien@campus.test", "primary": True},
            {"type": "home", "value": "sam@example.test"},
        ],
        "meta": {"version": 'W/"1"'},
    }


def _patch(*operations: dict[str, Any]) -> dict[str, Any]:
    return {"schemas": [PATCH_OP_SCHEMA], "Operations": list(operations)}


def _apply(*operations: dict[str, Any], resource: dict[str, Any] | None = None) -> dict[str, Any]:
    target = resource if resource is not None else _resource()
    return apply_patch(target, parse_operations(_patch(*operations)))


# --- replace ----------------------------------------------------------------


def test_replace_sets_a_simple_attribute() -> None:
    patched = _apply({"op": "replace", "path": "userName", "value": "s.obrien"})

    assert patched["userName"] == "s.obrien"


def test_replace_reaches_a_sub_attribute() -> None:
    patched = _apply({"op": "replace", "path": "name.givenName", "value": "Sam"})

    assert patched["name"]["givenName"] == "Sam"
    assert patched["name"]["familyName"] == "O'Brien"


def test_replace_with_no_path_merges_at_the_top_level() -> None:
    """How most clients send a bulk update: each member of the object is
    applied as if it were its own operation."""
    patched = _apply({"op": "replace", "value": {"userName": "s.obrien", "active": False}})

    assert patched["userName"] == "s.obrien"
    assert patched["active"] is False
    assert patched["name"]["givenName"] == "Samira"


# --- add --------------------------------------------------------------------


def test_add_appends_to_a_multivalued_attribute() -> None:
    """§3.5.2.1, and the rule a naive implementation gets wrong. Treating `add`
    as "set" loses every existing email the moment a client adds a second."""
    patched = _apply(
        {"op": "add", "path": "emails", "value": [{"type": "other", "value": "sam@other.test"}]}
    )

    assert len(patched["emails"]) == 3
    assert {email["value"] for email in patched["emails"]} == {
        "sam.obrien@campus.test",
        "sam@example.test",
        "sam@other.test",
    }


def test_add_appends_a_bare_object_too() -> None:
    """Clients differ about whether the value is wrapped in an array."""
    patched = _apply(
        {"op": "add", "path": "emails", "value": {"type": "other", "value": "x@y.test"}}
    )

    assert len(patched["emails"]) == 3


def test_add_replaces_a_single_valued_attribute() -> None:
    """The other half of §3.5.2.1: `add` to something that is not a collection
    is a replace, not an error."""
    patched = _apply({"op": "add", "path": "userName", "value": "s.obrien"})

    assert patched["userName"] == "s.obrien"


def test_add_creates_a_missing_attribute() -> None:
    patched = _apply({"op": "add", "path": "displayName", "value": "Samira O'Brien"})

    assert patched["displayName"] == "Samira O'Brien"


def test_add_creates_a_missing_parent() -> None:
    """A client adding `name.middleName` to a resource with no `name` at all is
    doing something reasonable."""
    bare: dict[str, Any] = {"schemas": [], "userName": "x"}

    patched = _apply({"op": "add", "path": "name.givenName", "value": "Sam"}, resource=bare)

    assert patched["name"] == {"givenName": "Sam"}


def test_add_with_no_path_merges() -> None:
    patched = _apply({"op": "add", "value": {"displayName": "Sam", "title": "Lecturer"}})

    assert patched["displayName"] == "Sam"
    assert patched["title"] == "Lecturer"


# --- remove -----------------------------------------------------------------


def test_remove_deletes_an_attribute() -> None:
    patched = _apply({"op": "remove", "path": "active"})

    assert "active" not in patched


def test_remove_deletes_a_sub_attribute() -> None:
    patched = _apply({"op": "remove", "path": "name.familyName"})

    assert patched["name"] == {"givenName": "Samira"}


def test_remove_without_a_path_is_refused() -> None:
    """§3.5.2.2. "Remove everything" is what no client means and every client
    would regret."""
    with pytest.raises(PatchError) as raised:
        parse_operations(_patch({"op": "remove"}))

    assert raised.value.scim_type == "noTarget"


def test_removing_something_absent_is_harmless() -> None:
    """A deprovisioning script should not stop on a person who was already
    clean."""
    patched = _apply({"op": "remove", "path": "nickName"})

    assert "nickName" not in patched


# --- value filters, the part that matters -----------------------------------


def test_a_filtered_replace_changes_only_the_matching_member() -> None:
    """`emails[type eq "work"].value` — the shape the PRD calls out, and the one
    clients get wrong."""
    patched = _apply(
        {
            "op": "replace",
            "path": 'emails[type eq "work"].value',
            "value": "new.address@campus.test",
        }
    )

    by_type = {email["type"]: email["value"] for email in patched["emails"]}
    assert by_type["work"] == "new.address@campus.test"
    assert by_type["home"] == "sam@example.test"


def test_a_filtered_replace_keeps_the_rest_of_the_member() -> None:
    """Replacing the value must not drop the `primary` flag the client never
    mentioned."""
    patched = _apply(
        {"op": "replace", "path": 'emails[type eq "work"].value', "value": "x@campus.test"}
    )

    work = next(email for email in patched["emails"] if email["type"] == "work")
    assert work["primary"] is True


def test_a_filtered_replace_without_a_sub_attribute_merges_the_member() -> None:
    """So a client changing an address does not silently drop the `type` it
    never mentioned."""
    patched = _apply(
        {"op": "replace", "path": 'emails[type eq "work"]', "value": {"value": "x@campus.test"}}
    )

    work = next(email for email in patched["emails"] if email.get("type") == "work")
    assert work["value"] == "x@campus.test"
    assert work["primary"] is True


def test_a_filtered_remove_deletes_only_the_matching_member() -> None:
    """The difference between "no work email to remove" and "no emails at
    all"."""
    patched = _apply({"op": "remove", "path": 'emails[type eq "home"]'})

    assert [email["type"] for email in patched["emails"]] == ["work"]


def test_a_filtered_remove_can_delete_a_sub_attribute() -> None:
    patched = _apply({"op": "remove", "path": 'emails[type eq "work"].primary'})

    work = next(email for email in patched["emails"] if email["type"] == "work")
    assert "primary" not in work
    assert work["value"] == "sam.obrien@campus.test"


def test_a_filtered_remove_matching_nothing_removes_nothing() -> None:
    """Not an error, and above all not "remove the collection"."""
    patched = _apply({"op": "remove", "path": 'emails[type eq "other"]'})

    assert len(patched["emails"]) == 2


def test_a_filtered_replace_matching_nothing_changes_nothing() -> None:
    """§3.5.2.3. The client asked to change something that is not there."""
    patched = _apply(
        {"op": "replace", "path": 'emails[type eq "other"].value', "value": "x@y.test"}
    )

    assert patched["emails"] == _resource()["emails"]


def test_a_filter_removing_several_members_removes_them_all() -> None:
    """Removing by index has to walk backwards, or deleting the first member
    shifts the second out from under the loop."""
    resource = _resource()
    resource["emails"].append({"type": "home", "value": "third@example.test"})

    patched = _apply({"op": "remove", "path": 'emails[type eq "home"]'}, resource=resource)

    assert [email["type"] for email in patched["emails"]] == ["work"]


def test_a_filter_on_a_non_collection_is_refused() -> None:
    with pytest.raises(PatchError) as raised:
        _apply({"op": "replace", "path": 'name[givenName eq "x"].value', "value": "y"})

    assert raised.value.scim_type == "noTarget"


# --- atomicity --------------------------------------------------------------


def test_a_failing_operation_leaves_the_resource_untouched() -> None:
    """§3.5.2. A request whose second operation is invalid must leave the
    resource exactly as it was, not two-thirds changed — which is why the work
    happens on a copy that only replaces the original if everything succeeds.
    """
    resource = _resource()

    with pytest.raises(PatchError):
        apply_patch(
            resource,
            parse_operations(
                _patch(
                    {"op": "replace", "path": "userName", "value": "changed"},
                    {"op": "replace", "path": 'name[x eq "y"].z', "value": "boom"},
                )
            ),
        )

    assert resource["userName"] == "sam.obrien"


def test_the_original_is_never_mutated() -> None:
    """Even on success. A caller holding the pre-patch resource for an audit
    record would otherwise find it had changed underneath them."""
    resource = _resource()

    patched = _apply({"op": "replace", "path": "userName", "value": "changed"}, resource=resource)

    assert resource["userName"] == "sam.obrien"
    assert patched["userName"] == "changed"


def test_operations_apply_in_order() -> None:
    patched = _apply(
        {"op": "add", "path": "emails", "value": {"type": "other", "value": "a@b.test"}},
        {"op": "remove", "path": 'emails[type eq "home"]'},
    )

    assert [email["type"] for email in patched["emails"]] == ["work", "other"]


# --- what a PATCH may not do ------------------------------------------------


@pytest.mark.parametrize("attribute", ["id", "meta", "schemas"])
def test_an_immutable_attribute_cannot_be_changed(attribute: str) -> None:
    """A client that could rewrite `id` could point one person's record at
    another's."""
    with pytest.raises(PatchError) as raised:
        parse_operations(_patch({"op": "replace", "path": attribute, "value": "x"}))

    assert raised.value.scim_type == "mutability"


def test_an_immutable_attribute_cannot_be_changed_without_a_path_either() -> None:
    """The pathless merge is the obvious way around the check above."""
    with pytest.raises(PatchError) as raised:
        _apply({"op": "replace", "value": {"id": "somebody-else"}})

    assert raised.value.scim_type == "mutability"


# --- the request body -------------------------------------------------------


def test_a_body_without_the_patch_schema_is_refused() -> None:
    with pytest.raises(PatchError, match="PatchOp"):
        parse_operations({"Operations": [{"op": "replace", "value": {}}]})


def test_a_body_with_no_operations_is_refused() -> None:
    with pytest.raises(PatchError, match="at least one"):
        parse_operations(_patch())


def test_too_many_operations_are_refused() -> None:
    """One request should not be a migration. The bulk endpoint is where a
    client sends a hundred changes, and it has its own error semantics."""
    operation = {"op": "replace", "path": "userName", "value": "x"}

    with pytest.raises(PatchError, match="at most"):
        parse_operations(_patch(*([operation] * (MAX_OPERATIONS + 1))))


def test_an_unknown_operation_is_refused() -> None:
    with pytest.raises(PatchError, match="not add, remove or replace"):
        parse_operations(_patch({"op": "upsert", "path": "userName", "value": "x"}))


def test_the_operation_name_is_case_insensitive() -> None:
    """Azure sends "Add", Okta sends "add". Refusing one over capitalisation
    would be a conformance failure disguised as strictness."""
    operations = parse_operations(_patch({"op": "Add", "path": "userName", "value": "x"}))

    assert operations[0].op is Op.ADD


def test_a_malformed_path_is_refused_as_invalid_path() -> None:
    """`invalidPath` rather than `invalidValue`: a client acts on the
    distinction, because one is a bug in its request builder and the other is a
    bug in its data."""
    with pytest.raises(PatchError) as raised:
        parse_operations(_patch({"op": "replace", "path": "emails[type eq", "value": "x"}))

    assert raised.value.scim_type == "invalidPath"


def test_an_operation_without_a_value_is_refused() -> None:
    with pytest.raises(PatchError, match="requires a value"):
        parse_operations(_patch({"op": "replace", "path": "userName"}))


def test_a_null_value_is_not_a_missing_value() -> None:
    """`{"value": null}` is a client explicitly clearing a field, which is
    different from omitting `value` entirely."""
    operations = parse_operations(_patch({"op": "replace", "path": "title", "value": None}))

    assert operations[0].value is None


def test_a_pathless_operation_needs_an_object() -> None:
    with pytest.raises(PatchError, match="object value"):
        _apply({"op": "add", "value": "not-an-object"})
