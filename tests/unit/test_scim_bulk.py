"""SCIM Bulk (FR-SCIM-10).

Two halves, tested apart because they fail for different reasons. Parsing
decides everything knowable without a database — limits, methods, paths,
duplicate `bulkId`s, cycles, and the order the operations will run in. The runner
then does the work, and its interesting behaviour is what happens when one of a
hundred operations fails.

The case that carries the feature is a person and a group membership in one
request: the client cannot know the person's id, so it invents a `bulkId` and
refers to it. If that resolves, `/Bulk` is worth having; if it does not, the
endpoint is a loop the client could have written itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from campusid.scim.bulk import (
    BULK_REQUEST,
    BULK_RESPONSE,
    parse_bulk,
    referenced_bulk_ids,
    resolve_references,
)
from campusid.scim.bulk_runner import BulkRunner
from campusid.scim.errors import ScimError, ScimType, duplicate, not_found
from campusid.scim.schemas import CORE_GROUP, CORE_USER, MAX_BULK_OPERATIONS

ISSUER = "https://broker.test"
PERSON_ID = "8f14e45f-ceea-467a-9b2e-2b5ea3e2a9c1"
GROUP_ID = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _request(*operations: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"schemas": [BULK_REQUEST], "Operations": list(operations), **extra}


def _post_user(bulk_id: str = "person") -> dict[str, Any]:
    return {
        "method": "POST",
        "path": "/Users",
        "bulkId": bulk_id,
        "data": {"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
    }


def _post_group(bulk_id: str = "group", members: list[Any] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"schemas": [CORE_GROUP], "displayName": "lms-students"}
    if members is not None:
        data["members"] = members
    return {"method": "POST", "path": "/Groups", "bulkId": bulk_id, "data": data}


# --- parsing ----------------------------------------------------------------


def test_a_body_without_the_bulk_schema_is_refused() -> None:
    with pytest.raises(ScimError) as raised:
        parse_bulk({"Operations": [_post_user()]})

    assert raised.value.scim_type == ScimType.INVALID_SYNTAX


def test_a_body_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ScimError):
        parse_bulk([_post_user()])


def test_an_empty_operations_array_is_refused() -> None:
    with pytest.raises(ScimError):
        parse_bulk(_request())


def test_too_many_operations_is_a_413() -> None:
    """413 rather than 400: the request is well formed and simply too big, so
    the client's fix is to split it rather than to correct it. The limit is the
    one ServiceProviderConfig advertises."""
    with pytest.raises(ScimError) as raised:
        parse_bulk(_request(*[_post_user(f"p{i}") for i in range(MAX_BULK_OPERATIONS + 1)]))

    assert raised.value.status == 413


def test_the_advertised_limit_itself_is_accepted() -> None:
    """An off-by-one here would make discovery a lie in the direction clients
    actually hit: they size their batches by exactly this number."""
    parsed = parse_bulk(_request(*[_post_user(f"p{i}") for i in range(MAX_BULK_OPERATIONS)]))

    assert len(parsed.operations) == MAX_BULK_OPERATIONS


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE", ""])
def test_an_unsupported_method_is_refused(method: str) -> None:
    with pytest.raises(ScimError):
        parse_bulk(_request({"method": method, "path": "/Users", "bulkId": "p", "data": {}}))


@pytest.mark.parametrize(
    "path", ["/Schemas", "/Users/a/b", "Users", "", "/", "/ServiceProviderConfig"]
)
def test_a_path_outside_users_and_groups_is_refused(path: str) -> None:
    """`/Bulk` must not become a way to reach what the ordinary surface does not
    expose."""
    with pytest.raises(ScimError):
        parse_bulk(_request({"method": "POST", "path": path, "bulkId": "p", "data": {}}))


def test_a_post_without_a_bulk_id_is_refused() -> None:
    """§3.7.2 requires one, and without it the response has nothing to correlate
    a created resource back to the request that made it."""
    with pytest.raises(ScimError):
        parse_bulk(_request({"method": "POST", "path": "/Users", "data": {}}))


def test_a_post_to_a_resource_is_refused() -> None:
    with pytest.raises(ScimError) as raised:
        parse_bulk(_request({"method": "POST", "path": f"/Users/{PERSON_ID}", "bulkId": "p"}))

    assert raised.value.scim_type == ScimType.INVALID_PATH


def test_a_put_without_a_resource_id_is_refused() -> None:
    with pytest.raises(ScimError):
        parse_bulk(_request({"method": "PUT", "path": "/Users", "data": {}}))


def test_a_write_without_data_is_refused() -> None:
    with pytest.raises(ScimError):
        parse_bulk(_request({"method": "PUT", "path": f"/Users/{PERSON_ID}"}))


def test_a_delete_needs_no_data() -> None:
    parsed = parse_bulk(_request({"method": "DELETE", "path": f"/Users/{PERSON_ID}"}))

    assert parsed.operations[0].method == "DELETE"
    assert parsed.operations[0].resource_id == PERSON_ID


def test_an_operation_version_is_carried_through() -> None:
    """Optimistic concurrency has to survive being batched, or a client gets it
    for single requests and silently loses it for bulk ones."""
    parsed = parse_bulk(
        _request(
            {
                "method": "DELETE",
                "path": f"/Users/{PERSON_ID}",
                "version": 'W/"deadbeef"',
            }
        )
    )

    assert parsed.operations[0].version == 'W/"deadbeef"'


@pytest.mark.parametrize("value", [0, -1, "many", True])
def test_a_nonsensical_fail_on_errors_is_refused(value: Any) -> None:
    with pytest.raises(ScimError):
        parse_bulk(_request(_post_user(), failOnErrors=value))


def test_fail_on_errors_defaults_to_doing_everything() -> None:
    """A single bad record must not silently drop the rest of the night's
    changes; a client that wants to stop early says so."""
    assert parse_bulk(_request(_post_user())).fail_on_errors is None


# --- bulkId references ------------------------------------------------------


def test_a_reference_is_found_wherever_it_appears() -> None:
    """A walk of the whole document rather than of the fields we expect, because
    a reference is legal wherever a resource id is."""
    found = referenced_bulk_ids(
        {"members": [{"value": "bulkId:person"}], "manager": {"value": "bulkId:boss"}}
    )

    assert found == {"person", "boss"}


def test_a_plain_string_is_not_a_reference() -> None:
    assert referenced_bulk_ids({"displayName": "bulk shipments"}) == set()


def test_resolution_replaces_every_reference() -> None:
    resolved = resolve_references(
        {"members": [{"value": "bulkId:person"}, {"value": GROUP_ID}]}, {"person": PERSON_ID}
    )

    assert resolved == {"members": [{"value": PERSON_ID}, {"value": GROUP_ID}]}


def test_resolution_does_not_mutate_the_original() -> None:
    """A retry of the same request has to behave the same way the second time,
    which it would not if the first run rewrote the client's document."""
    original = {"members": [{"value": "bulkId:person"}]}

    resolve_references(original, {"person": PERSON_ID})

    assert original == {"members": [{"value": "bulkId:person"}]}


def test_an_unproduced_reference_is_a_404() -> None:
    with pytest.raises(ScimError) as raised:
        resolve_references({"value": "bulkId:ghost"}, {})

    assert raised.value.status == 404


def test_a_reference_to_nothing_is_refused_at_parse_time() -> None:
    with pytest.raises(ScimError) as raised:
        parse_bulk(_request(_post_group(members=[{"value": "bulkId:nobody"}])))

    assert "nobody" in raised.value.detail


def test_a_duplicate_bulk_id_is_refused() -> None:
    """Two operations sharing one make every reference to it ambiguous, which is
    worse than a failure because it silently picks one."""
    with pytest.raises(ScimError) as raised:
        parse_bulk(_request(_post_user("same"), _post_group("same")))

    assert raised.value.scim_type == ScimType.UNIQUENESS


def test_an_operation_referring_to_itself_is_refused() -> None:
    with pytest.raises(ScimError) as raised:
        parse_bulk(_request(_post_group("group", members=[{"value": "bulkId:group"}])))

    assert raised.value.status == 409


def test_a_cycle_is_refused_rather_than_attempted() -> None:
    """Two operations each naming the other describe something that cannot
    happen, and the specification makes it a 409 rather than a partial result
    the client has to unpick."""
    with pytest.raises(ScimError) as raised:
        parse_bulk(
            _request(
                {
                    "method": "POST",
                    "path": "/Groups",
                    "bulkId": "a",
                    "data": {"displayName": "a", "members": [{"value": "bulkId:b"}]},
                },
                {
                    "method": "POST",
                    "path": "/Groups",
                    "bulkId": "b",
                    "data": {"displayName": "b", "members": [{"value": "bulkId:a"}]},
                },
            )
        )

    assert raised.value.status == 409


# --- ordering ---------------------------------------------------------------


def test_a_referenced_operation_runs_first_even_when_sent_second() -> None:
    """The whole reason execution order is not request order. A client that
    writes the group first is not making a mistake — it cannot know the person's
    id either way."""
    parsed = parse_bulk(
        _request(_post_group("group", members=[{"value": "bulkId:person"}]), _post_user("person"))
    )

    assert [operation.bulk_id for operation in parsed.operations] == ["person", "group"]


def test_independent_operations_keep_the_order_they_were_sent_in() -> None:
    """A stable sort, so a client reading the response is not surprised by an
    order it did not ask for."""
    parsed = parse_bulk(_request(*[_post_user(f"p{index}") for index in range(5)]))

    assert [operation.bulk_id for operation in parsed.operations] == [f"p{i}" for i in range(5)]


def test_a_reference_in_a_path_orders_too() -> None:
    """`PATCH /Groups/bulkId:group` addresses a group the same request creates,
    and the reference is in the path rather than the data."""
    parsed = parse_bulk(
        _request(
            {
                "method": "PATCH",
                "path": "/Groups/bulkId:group",
                "data": {"schemas": [PATCH_OP], "Operations": []},
            },
            _post_group("group"),
        )
    )

    assert [operation.method for operation in parsed.operations] == ["POST", "PATCH"]


# --- running ----------------------------------------------------------------


class _Users:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.raises: ScimError | None = None

    def _resource(self) -> dict[str, Any]:
        if self.raises is not None:
            raise self.raises
        return {
            "id": PERSON_ID,
            "meta": {"location": f"{ISSUER}/scim/v2/Users/{PERSON_ID}", "version": 'W/"1"'},
        }

    async def create(self, parsed: Any, raw: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        self.calls.append("create")
        return self._resource(), True

    async def get(self, resource_id: str) -> dict[str, Any]:
        self.calls.append("get")
        return {"id": PERSON_ID, "userName": "sam.obrien@campus.test", "meta": {"version": 'W/"1"'}}

    async def replace(self, resource_id: str, parsed: Any, raw: Any, **kwargs: Any) -> Any:
        self.calls.append("replace")
        return self._resource()

    async def apply_patched(self, resource_id: str, parsed: Any, raw: Any, **kwargs: Any) -> Any:
        self.calls.append("apply_patched")
        return self._resource()

    async def soft_delete(self, resource_id: str, **kwargs: Any) -> None:
        self.calls.append("soft_delete")
        if self.raises is not None:
            raise self.raises


class _Groups:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.documents: list[Any] = []
        self.raises: ScimError | None = None

    def _resource(self) -> dict[str, Any]:
        if self.raises is not None:
            raise self.raises
        return {
            "id": GROUP_ID,
            "meta": {"location": f"{ISSUER}/scim/v2/Groups/{GROUP_ID}", "version": 'W/"1"'},
        }

    async def create(self, document: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        self.calls.append("create")
        self.documents.append(document)
        return self._resource(), True

    async def replace(self, group_id: str, document: Any, **kwargs: Any) -> Any:
        self.calls.append("replace")
        self.documents.append(document)
        return self._resource()

    async def patch(self, group_id: str, operations: Any, **kwargs: Any) -> Any:
        self.calls.append("patch")
        return self._resource()

    async def delete(self, group_id: str, **kwargs: Any) -> None:
        self.calls.append("delete")
        if self.raises is not None:
            raise self.raises


@pytest.fixture
def users() -> _Users:
    return _Users()


@pytest.fixture
def groups() -> _Groups:
    return _Groups()


@pytest.fixture
def runner(users: _Users, groups: _Groups) -> BulkRunner:
    return BulkRunner(users, groups, issuer=ISSUER)


async def test_a_response_reports_each_operation(runner: BulkRunner) -> None:
    response = await runner.run(parse_bulk(_request(_post_user(), _post_group())))

    assert response["schemas"] == [BULK_RESPONSE]
    assert [entry["status"] for entry in response["Operations"]] == ["201", "201"]
    assert [entry["bulkId"] for entry in response["Operations"]] == ["person", "group"]


async def test_a_created_resource_is_located(runner: BulkRunner) -> None:
    response = await runner.run(parse_bulk(_request(_post_user())))

    assert response["Operations"][0]["location"] == f"{ISSUER}/scim/v2/Users/{PERSON_ID}"


async def test_a_reference_becomes_the_id_the_first_operation_produced(
    runner: BulkRunner, groups: _Groups
) -> None:
    """The case that carries the whole feature: a person and their membership in
    one request, where the client could not have known the id."""
    await runner.run(
        parse_bulk(
            _request(
                _post_user("person"), _post_group("group", members=[{"value": "bulkId:person"}])
            )
        )
    )

    assert groups.documents[0]["members"] == [{"value": PERSON_ID}]


async def test_a_delete_reports_204_and_no_location_of_its_own(
    runner: BulkRunner, users: _Users
) -> None:
    response = await runner.run(
        parse_bulk(_request({"method": "DELETE", "path": f"/Users/{PERSON_ID}"}))
    )

    assert response["Operations"][0]["status"] == "204"
    assert users.calls == ["soft_delete"]


async def test_a_failed_operation_carries_the_ordinary_error_envelope(
    runner: BulkRunner, users: _Users
) -> None:
    """So a client can act on one failure without re-deriving which of its
    hundred changes it was."""
    users.raises = duplicate("userName", "sam.obrien@campus.test")

    response = await runner.run(parse_bulk(_request(_post_user())))

    entry = response["Operations"][0]
    assert entry["status"] == "409"
    assert entry["response"]["scimType"] == ScimType.UNIQUENESS


async def test_one_failure_does_not_stop_the_rest_by_default(
    runner: BulkRunner, groups: _Groups, users: _Users
) -> None:
    """A bulk request is not a transaction. The operations that can succeed do."""
    users.raises = not_found("User", PERSON_ID)

    response = await runner.run(
        parse_bulk(_request({"method": "DELETE", "path": f"/Users/{PERSON_ID}"}, _post_group()))
    )

    assert [entry["status"] for entry in response["Operations"]] == ["404", "201"]
    assert groups.calls == ["create"]


async def test_fail_on_errors_stops_the_run(
    runner: BulkRunner, groups: _Groups, users: _Users
) -> None:
    """And the remaining operations are simply absent, which is honest: a client
    seeing one result out of two knows the other was not attempted."""
    users.raises = not_found("User", PERSON_ID)

    response = await runner.run(
        parse_bulk(
            _request(
                {"method": "DELETE", "path": f"/Users/{PERSON_ID}"},
                _post_group(),
                failOnErrors=1,
            )
        )
    )

    assert len(response["Operations"]) == 1
    assert groups.calls == []


async def test_a_malformed_patch_fails_only_its_own_operation(
    runner: BulkRunner, groups: _Groups
) -> None:
    response = await runner.run(
        parse_bulk(
            _request(
                {
                    "method": "PATCH",
                    "path": f"/Groups/{GROUP_ID}",
                    "data": {"schemas": [PATCH_OP], "Operations": [{"op": "invent"}]},
                },
                _post_group(),
            )
        )
    )

    assert response["Operations"][0]["status"] == "400"
    assert response["Operations"][1]["status"] == "201"


async def test_a_group_patch_reaches_the_store(runner: BulkRunner, groups: _Groups) -> None:
    response = await runner.run(
        parse_bulk(
            _request(
                {
                    "method": "PATCH",
                    "path": f"/Groups/{GROUP_ID}",
                    "data": {
                        "schemas": [PATCH_OP],
                        "Operations": [{"op": "replace", "path": "displayName", "value": "moved"}],
                    },
                }
            )
        )
    )

    assert response["Operations"][0]["status"] == "200"
    assert groups.calls == ["patch"]


async def test_a_user_put_and_patch_reach_the_store(runner: BulkRunner, users: _Users) -> None:
    await runner.run(
        parse_bulk(
            _request(
                {
                    "method": "PUT",
                    "path": f"/Users/{PERSON_ID}",
                    "data": {"schemas": [CORE_USER], "userName": "sam.obrien@campus.test"},
                },
                {
                    "method": "PATCH",
                    "path": f"/Users/{PERSON_ID}",
                    "data": {
                        "schemas": [PATCH_OP],
                        "Operations": [{"op": "replace", "path": "displayName", "value": "Sam"}],
                    },
                },
            )
        )
    )

    assert users.calls == ["replace", "get", "apply_patched"]


async def test_a_group_put_and_delete_reach_the_store(runner: BulkRunner, groups: _Groups) -> None:
    await runner.run(
        parse_bulk(
            _request(
                {
                    "method": "PUT",
                    "path": f"/Groups/{GROUP_ID}",
                    "data": {"schemas": [CORE_GROUP], "displayName": "lms-students"},
                },
                {"method": "DELETE", "path": f"/Groups/{GROUP_ID}"},
            )
        )
    )

    assert groups.calls == ["replace", "delete"]
