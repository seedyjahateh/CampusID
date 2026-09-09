"""Executing a parsed bulk request (FR-SCIM-10).

The dispatch half of `/Bulk`. Everything structural — schema, limits, methods,
paths, duplicate `bulkId`s, cycles and the execution order — is settled by
`bulk.parse_bulk` before anything here runs, so a failure at this point is always
about one operation's *data* rather than about the shape of the request. That is
the distinction a client needs to decide whether retrying could ever help.

Two behaviours are worth stating plainly because they surprise people.

**Each operation commits on its own.** A bulk request is not a transaction. A
failure at operation forty leaves the previous thirty-nine in place, which is
what RFC 7644 §3.7 describes and the only thing that can be true of independent
resources. `failOnErrors` is how a client bounds the damage.

**A failed operation still appears in the response.** With its status and the
same error envelope a single request would have produced, so a client can act on
one failure without re-deriving which of its hundred changes it was.
"""

from __future__ import annotations

from typing import Any, Protocol

from campusid.logging import get_logger
from campusid.scim.bulk import BULK_RESPONSE, BulkOperation, BulkRequest, resolve_references
from campusid.scim.errors import ScimError, ScimType
from campusid.scim.patch import PatchError, apply_patch, parse_operations
from campusid.scim.resources import from_scim

log = get_logger(__name__)


class UserOperations(Protocol):
    """What the runner needs of the user store, and nothing more."""

    async def create(self, parsed: Any, raw: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...

    async def get(self, resource_id: str) -> dict[str, Any]: ...

    async def replace(
        self, resource_id: str, parsed: Any, raw: dict[str, Any], *, if_match: str | None = None
    ) -> dict[str, Any]: ...

    async def apply_patched(
        self, resource_id: str, parsed: Any, raw: dict[str, Any], *, if_match: str | None = None
    ) -> dict[str, Any]: ...

    async def soft_delete(self, resource_id: str, *, if_match: str | None = None) -> None: ...


class GroupOperations(Protocol):
    """What the runner needs of the group store."""

    async def create(self, document: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...

    async def replace(
        self, group_id: str, document: dict[str, Any], *, if_match: str | None = None
    ) -> dict[str, Any]: ...

    async def patch(
        self, group_id: str, operations: Any, *, if_match: str | None = None
    ) -> dict[str, Any]: ...

    async def delete(self, group_id: str, *, if_match: str | None = None) -> None: ...


class BulkRunner:
    """Runs the operations of one bulk request, in the order it was sorted into."""

    def __init__(self, users: UserOperations, groups: GroupOperations, *, issuer: str) -> None:
        self._users = users
        self._groups = groups
        self._issuer = issuer

    async def run(self, request: BulkRequest) -> dict[str, Any]:
        resolved: dict[str, str] = {}
        results: list[dict[str, Any]] = []
        errors = 0

        for operation in request.operations:
            try:
                entry = await self._one(operation, resolved)
            except ScimError as exc:
                errors += 1
                entry = _entry(operation, exc.status, response=exc.to_dict())
                log.info(
                    "scim.bulk.operation.failed",
                    method=operation.method,
                    path=operation.path,
                    status=exc.status,
                )
            results.append(entry)

            if request.fail_on_errors is not None and errors >= request.fail_on_errors:
                # The remaining operations are simply absent from the response.
                # §3.7 asks for exactly that, and it is honest: a client seeing
                # forty results out of a hundred knows sixty were not attempted.
                log.info("scim.bulk.stopped", completed=len(results), errors=errors)
                break

        return {"schemas": [BULK_RESPONSE], "Operations": results}

    async def _one(self, operation: BulkOperation, resolved: dict[str, str]) -> dict[str, Any]:
        data = resolve_references(operation.data, resolved)
        resource_id = (
            resolve_references(operation.resource_id, resolved) if operation.resource_id else None
        )

        if operation.resource == "Users":
            resource, status = await self._user(operation, resource_id, data)
        else:
            resource, status = await self._group(operation, resource_id, data)

        if operation.bulk_id and resource is not None:
            resolved[operation.bulk_id] = str(resource["id"])

        location = resource["meta"]["location"] if resource else None
        if location is None and resource_id is not None:
            location = f"{self._issuer}/scim/v2/{operation.resource}/{resource_id}"
        return _entry(operation, status, location=location)

    async def _user(
        self, operation: BulkOperation, resource_id: str | None, data: Any
    ) -> tuple[dict[str, Any] | None, int]:
        if operation.method == "POST":
            resource, created = await self._users.create(from_scim(data), data)
            return resource, 201 if created else 200

        assert resource_id is not None  # parse_bulk refuses anything else

        if operation.method == "PUT":
            return await self._users.replace(
                resource_id, from_scim(data), data, if_match=operation.version
            ), 200

        if operation.method == "PATCH":
            current = await self._users.get(resource_id)
            patched = apply_patch(current, _patch_operations(data))
            return await self._users.apply_patched(
                resource_id, from_scim(patched), patched, if_match=operation.version
            ), 200

        await self._users.soft_delete(resource_id, if_match=operation.version)
        return None, 204

    async def _group(
        self, operation: BulkOperation, resource_id: str | None, data: Any
    ) -> tuple[dict[str, Any] | None, int]:
        if operation.method == "POST":
            resource, created = await self._groups.create(data)
            return resource, 201 if created else 200

        assert resource_id is not None

        if operation.method == "PUT":
            return await self._groups.replace(resource_id, data, if_match=operation.version), 200

        if operation.method == "PATCH":
            return await self._groups.patch(
                resource_id, _patch_operations(data), if_match=operation.version
            ), 200

        await self._groups.delete(resource_id, if_match=operation.version)
        return None, 204


def _patch_operations(data: Any) -> Any:
    """Parse a PATCH body, as the single-request path does.

    The translation of `PatchError` happens here rather than at the route,
    because a bulk PATCH's failure has to become one entry in the response
    instead of failing the whole request.
    """
    try:
        return parse_operations(data)
    except PatchError as exc:
        raise ScimError(400, str(exc), exc.scim_type) from exc


def _entry(
    operation: BulkOperation,
    status: int,
    *,
    location: str | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One entry in the `BulkResponse`.

    `status` is a string for the same reason the error envelope's is: RFC 7644
    quotes it, and a conformance client comparing to `"201"` fails against an
    integer.
    """
    entry: dict[str, Any] = {"method": operation.method, "status": str(status)}
    if operation.bulk_id:
        entry["bulkId"] = operation.bulk_id
    if location:
        entry["location"] = location
    if response is not None:
        entry["response"] = response
    return entry


def payload_too_large(limit: int) -> ScimError:
    """413 for a body bigger than `ServiceProviderConfig` advertises.

    Enforced rather than merely declared: a client sizes its batches by what
    discovery said, so a promise the server does not keep is worse than a
    smaller promise.
    """
    return ScimError(413, f"a bulk request may be at most {limit} bytes", ScimType.TOO_MANY)
