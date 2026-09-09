"""SCIM PATCH (FR-SCIM-05, RFC 7644 §3.5.2).

The operation the PRD calls the single most underestimated item in the plan, and
it is right to: `PATCH` looks like "set this field" and is actually a small
language for addressing parts of a document, with three operations, optional
paths, and filters that select members of a collection.

The rules that matter, each of which a naive implementation gets wrong:

**`add` to a multi-valued attribute appends; `add` to a single-valued one
replaces.** RFC 7644 §3.5.2.1. Treating `add` as "set" loses every existing
email the moment a client adds a second one.

**`add` with no path merges at the top level.** The value is an object whose
members are applied as if each were its own operation, which is how most clients
send a bulk update.

**`remove` needs a path, and a filtered `remove` deletes only the members that
match.** Removing a whole collection because the filter selected nothing is the
difference between "no work email to remove" and "no emails at all".

**A `replace` whose filter matches nothing is not an error.** §3.5.2.3 says a
`replace` on a value path that selects no members adds nothing — the client
asked to change something that is not there, and the resource is left alone.

**Every operation is applied to a copy, and the copy replaces the resource only
if all of them succeed.** A PATCH is atomic (§3.5.2): a request with three
operations whose second is invalid must leave the resource exactly as it was,
not two-thirds changed.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from campusid.scim.filters import (
    AttrPath,
    PatchPath,
    ScimFilterError,
    parse_patch_path,
    select_members,
)

PATCH_OP_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

IMMUTABLE: Final[frozenset[str]] = frozenset({"id", "schemas", "meta"})
"""Attributes a client may never change through PATCH.

`id` is ours to assign, `meta` is ours to maintain, and `schemas` describes the
resource rather than the person. A client that could rewrite `id` could point
one person's record at another's.
"""

MAX_OPERATIONS: Final = 100
"""One request should not be a migration. The bulk endpoint (FR-SCIM-10) is
where a client sends a hundred changes, and it has its own error semantics."""


class PatchError(ValueError):
    """A PATCH could not be applied.

    Carries the `scimType` the response needs, because the specification
    distinguishes these and a client acts on the distinction: `invalidPath` is
    a bug in the client, `noTarget` is a race with somebody else's change, and
    `mutability` is a request that will never succeed.
    """

    def __init__(self, detail: str, scim_type: str = "invalidValue") -> None:
        super().__init__(detail)
        self.scim_type = scim_type


class Op(StrEnum):
    ADD = "add"
    REMOVE = "remove"
    REPLACE = "replace"


@dataclass(frozen=True, slots=True)
class Operation:
    """One entry in a PATCH request's `Operations` array."""

    op: Op
    path: PatchPath | None = None
    value: Any = None


def parse_operations(document: Any) -> list[Operation]:
    """Read and validate a `PatchOp` body before touching anything.

    Parsed in full first, so a request whose fourth operation is malformed is
    refused without the first three having been applied — which is what makes
    the atomicity below meaningful rather than accidental.
    """
    if not isinstance(document, dict):
        raise PatchError("a PATCH body must be an object")

    schemas = document.get("schemas")
    if not isinstance(schemas, list) or PATCH_OP_SCHEMA not in schemas:
        raise PatchError(f"a PATCH body must declare {PATCH_OP_SCHEMA}")

    raw = document.get("Operations")
    if not isinstance(raw, list) or not raw:
        raise PatchError("a PATCH body needs at least one operation")
    if len(raw) > MAX_OPERATIONS:
        raise PatchError(f"a PATCH may carry at most {MAX_OPERATIONS} operations")

    return [_parse_one(entry, index) for index, entry in enumerate(raw)]


def _parse_one(entry: Any, index: int) -> Operation:
    if not isinstance(entry, dict):
        raise PatchError(f"operation {index} is not an object")

    # `op` is case-insensitive per §3.5.2, and clients differ: Azure sends
    # "Add", Okta sends "add". Refusing one of them over capitalisation would
    # be a conformance failure disguised as strictness.
    raw_op = entry.get("op")
    if not isinstance(raw_op, str):
        raise PatchError(f"operation {index} has no op")
    try:
        op = Op(raw_op.lower())
    except ValueError as exc:
        raise PatchError(f"operation {index}: {raw_op!r} is not add, remove or replace") from exc

    raw_path = entry.get("path")
    path: PatchPath | None = None
    if raw_path is not None:
        if not isinstance(raw_path, str):
            raise PatchError(f"operation {index} has a non-string path", "invalidPath")
        try:
            path = parse_patch_path(raw_path)
        except ScimFilterError as exc:
            raise PatchError(f"operation {index}: {exc}", "invalidPath") from exc
        if path.path.attribute.lower() in IMMUTABLE:
            raise PatchError(
                f"operation {index}: {path.path.attribute} cannot be changed", "mutability"
            )

    if op is Op.REMOVE and path is None:
        # §3.5.2.2. A `remove` with no path is "remove everything", which no
        # client means and every client would regret.
        raise PatchError(f"operation {index}: remove requires a path", "noTarget")

    if op is not Op.REMOVE and "value" not in entry:
        raise PatchError(f"operation {index}: {op.value} requires a value")

    return Operation(op, path, entry.get("value"))


def apply_patch(resource: dict[str, Any], operations: list[Operation]) -> dict[str, Any]:
    """Apply every operation, or none of them.

    Works on a deep copy and returns it. A PATCH is atomic (§3.5.2): a request
    whose second operation is invalid must leave the resource exactly as it was,
    and the only way to promise that without unwinding partial work is to do the
    work somewhere else first.
    """
    working = copy.deepcopy(resource)
    for index, operation in enumerate(operations):
        try:
            _apply_one(working, operation)
        except PatchError as exc:
            raise PatchError(f"operation {index}: {exc}", exc.scim_type) from exc
    return working


def _apply_one(resource: dict[str, Any], operation: Operation) -> None:
    if operation.path is None:
        _apply_pathless(resource, operation)
        return

    if operation.path.predicate is not None:
        _apply_filtered(resource, operation, operation.path)
        return

    _apply_direct(resource, operation, operation.path)


def _apply_pathless(resource: dict[str, Any], operation: Operation) -> None:
    """`add` or `replace` with no path: merge an object at the top level.

    Each member is applied as if it were its own operation, which is how most
    clients send a bulk update and is what §3.5.2.1 describes.
    """
    if not isinstance(operation.value, dict):
        raise PatchError("an operation without a path needs an object value")

    for name, value in operation.value.items():
        if name.lower() in IMMUTABLE:
            raise PatchError(f"{name} cannot be changed", "mutability")
        _apply_direct(
            resource,
            Operation(operation.op, None, value),
            PatchPath(AttrPath(name)),
        )


def _apply_direct(resource: dict[str, Any], operation: Operation, path: PatchPath) -> None:
    """An unfiltered path: `userName`, `name.givenName`, `emails`."""
    container, name = _target(resource, path)

    if operation.op is Op.REMOVE:
        _delete(container, name)
        return

    existing = _get(container, name)

    if operation.op is Op.ADD and isinstance(existing, list):
        # §3.5.2.1: `add` to a multi-valued attribute appends. Treating it as
        # "set" loses every existing email the moment a client adds a second.
        additions = operation.value if isinstance(operation.value, list) else [operation.value]
        _set(container, name, [*existing, *additions])
        return

    if operation.op is Op.ADD and existing is None and isinstance(operation.value, list):
        _set(container, name, list(operation.value))
        return

    _set(container, name, operation.value)


def _apply_filtered(resource: dict[str, Any], operation: Operation, path: PatchPath) -> None:
    """A value path: `emails[type eq "work"]`, optionally with a sub-attribute."""
    assert path.predicate is not None

    container, name = _target(resource, PatchPath(path.path))
    members = _get(container, name)
    if not isinstance(members, list):
        # There is nothing to filter. A `remove` has already achieved its
        # purpose; an `add` or `replace` has nowhere to put the value.
        if operation.op is Op.REMOVE:
            return
        raise PatchError(f"{path.path} is not a multi-valued attribute", "noTarget")

    selected = select_members(path.predicate, members)

    if operation.op is Op.REMOVE:
        if not selected:
            # Not an error. "Remove the work email" against somebody with no
            # work email has already happened, and failing would make a
            # deprovisioning script stop on a person who was already clean.
            return
        # Reversed, so removing by index does not shift the indices still to go.
        for index in reversed(selected):
            if path.sub_attribute:
                _delete(members[index], path.sub_attribute)
            else:
                del members[index]
        return

    if not selected:
        # §3.5.2.3: a `replace` whose filter selects nothing changes nothing.
        # The client asked to change something that is not there.
        return

    for index in selected:
        member = members[index]
        if path.sub_attribute:
            _set(member, path.sub_attribute, operation.value)
        elif isinstance(operation.value, dict):
            # Replacing a member wholesale still merges rather than overwrites,
            # so a client changing an address does not silently drop the `type`
            # it never mentioned.
            member.update(operation.value)
        else:
            members[index] = operation.value


# --- attribute access -------------------------------------------------------


def _target(resource: dict[str, Any], path: PatchPath) -> tuple[dict[str, Any], str]:
    """The dictionary an operation writes into, and the key inside it.

    Resolves a schema URN and a sub-attribute, creating the intermediate
    containers an `add` needs — a client adding `name.givenName` to a resource
    with no `name` at all is doing something reasonable.
    """
    container: dict[str, Any] = resource

    if path.path.urn:
        extension = _get(container, path.path.urn)
        if not isinstance(extension, dict):
            extension = {}
            container[path.path.urn] = extension
        container = extension

    if path.sub_attribute and path.predicate is None:
        parent = _get(container, path.path.attribute)
        if not isinstance(parent, dict):
            parent = {}
            _set(container, path.path.attribute, parent)
        return parent, path.sub_attribute

    return container, path.path.attribute


def _get(container: dict[str, Any], name: str) -> Any:
    key = _key(container, name)
    return container.get(key) if key else None


def _set(container: dict[str, Any], name: str, value: Any) -> None:
    container[_key(container, name) or name] = value


def _delete(container: dict[str, Any], name: str) -> None:
    key = _key(container, name)
    if key:
        del container[key]


def _key(container: dict[str, Any], name: str) -> str | None:
    """The container's own spelling of an attribute name.

    Attribute names are case-insensitive (RFC 7643 §2.1), so a client sending
    `USERNAME` must update `userName` rather than add a second key beside it —
    which would produce a resource with two user names and no way to say which
    is real.
    """
    if name in container:
        return name
    lowered = name.lower()
    for key in container:
        if key.lower() == lowered:
            return key
    return None
