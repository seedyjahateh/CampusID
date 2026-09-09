"""SCIM Bulk (FR-SCIM-10, RFC 7644 §3.7).

One request carrying up to a hundred changes, which is how an SIS sends a
night's worth of joiners rather than a hundred round trips. Four things here are
decisions rather than transcription.

**`bulkId` is a forward reference, so the order in the request is not the order
of execution.** A client creating a person and adding them to a group in the
same request cannot know the person's id — it invents a `bulkId` and refers to
it as `bulkId:qwerty`. That makes the operations a dependency graph, so they are
sorted topologically and run in that order. Executing them in the order sent
would fail on every request whose group operation happens to come first, and
telling clients to sort their own requests would be pushing our problem to them.

**A cycle is refused, not attempted.** Two operations that each name the other's
`bulkId` describe something that cannot happen, and the specification is explicit
that this is a 409 rather than a partial result the client has to unpick.

**A bulk request is not a transaction, and says so.** Each operation commits on
its own, so a failure at operation forty leaves the first thirty-nine in place.
That is what §3.7 describes, and it is the only thing that can be true when the
operations are independent resources — but it means `failOnErrors` matters: a
client that sets it to 1 gets the run stopped at the first failure instead of
thirty-nine more changes it did not want.

**The advertised limits are enforced here.** `ServiceProviderConfig` promises a
hundred operations and a megabyte, and a promise the server does not keep is
worse than a smaller promise: a client sizes its batches by what discovery said.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from campusid.logging import get_logger
from campusid.scim.errors import ScimError, ScimType
from campusid.scim.schemas import MAX_BULK_OPERATIONS

log = get_logger(__name__)

BULK_REQUEST: Final = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
BULK_RESPONSE: Final = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

BULK_ID_PREFIX: Final = "bulkId:"
"""RFC 7644 §3.7.2. Anywhere a resource id may appear, `bulkId:qwerty` stands
for the id of whichever operation declared that `bulkId`."""

METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

RESOURCES: Final[frozenset[str]] = frozenset({"Users", "Groups"})
"""The endpoints a bulk operation may address. A path outside this set is
refused rather than routed, so `/Bulk` cannot be used to reach anything the
ordinary surface does not expose."""


@dataclass(frozen=True, slots=True)
class BulkOperation:
    """One entry in a `BulkRequest`."""

    method: str
    resource: str
    """`Users` or `Groups`."""

    resource_id: str | None = None
    bulk_id: str | None = None
    data: Any = None
    version: str | None = None
    """The operation's own `If-Match`, per §3.7. Optimistic concurrency has to
    survive being batched, or a client gets it for single requests and silently
    loses it for bulk ones."""

    depends_on: frozenset[str] = field(default_factory=frozenset)
    """The `bulkId`s this operation's data refers to."""

    @property
    def path(self) -> str:
        return f"/{self.resource}" + (f"/{self.resource_id}" if self.resource_id else "")


@dataclass(frozen=True, slots=True)
class BulkRequest:
    """A parsed `BulkRequest`, in the order it will be executed."""

    operations: list[BulkOperation]
    fail_on_errors: int | None = None
    """None means "do them all and tell me what happened". A client that wants
    to stop early says so; defaulting to stopping would make a single bad record
    silently drop the rest of the night's changes."""


def parse_bulk(document: Any) -> BulkRequest:
    """Read and validate a whole `BulkRequest` before any of it runs.

    Everything that can be known without touching the database is decided here —
    the schema, the operation count, the methods, the paths, duplicate `bulkId`s
    and cycles. An operation that fails later fails for a reason about *data*,
    which is the distinction a client needs to decide whether retrying is worth
    anything.
    """
    if not isinstance(document, dict):
        raise ScimError(400, "a bulk request must be an object", ScimType.INVALID_SYNTAX)

    schemas = document.get("schemas")
    if not isinstance(schemas, list) or BULK_REQUEST not in schemas:
        raise ScimError(400, f"a bulk request must declare {BULK_REQUEST}", ScimType.INVALID_SYNTAX)

    raw = document.get("Operations")
    if not isinstance(raw, list) or not raw:
        raise ScimError(400, "a bulk request needs at least one operation", ScimType.INVALID_VALUE)
    if len(raw) > MAX_BULK_OPERATIONS:
        # 413, not 400: the request is well formed and simply too big, and the
        # client's fix is to split it rather than to correct it.
        raise ScimError(
            413,
            f"a bulk request may carry at most {MAX_BULK_OPERATIONS} operations",
            ScimType.TOO_MANY,
        )

    fail_on_errors = _fail_on_errors(document.get("failOnErrors"))
    operations = [_parse_one(entry, index) for index, entry in enumerate(raw)]
    _assert_bulk_ids_unique(operations)

    return BulkRequest(operations=_ordered(operations), fail_on_errors=fail_on_errors)


def _fail_on_errors(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ScimError(400, "failOnErrors must be a positive integer", ScimType.INVALID_VALUE)
    return value


def _parse_one(entry: Any, index: int) -> BulkOperation:
    if not isinstance(entry, dict):
        raise ScimError(400, f"operation {index} is not an object", ScimType.INVALID_SYNTAX)

    method = entry.get("method")
    if not isinstance(method, str) or method.upper() not in METHODS:
        raise ScimError(
            400, f"operation {index}: {method!r} is not a bulk method", ScimType.INVALID_VALUE
        )
    method = method.upper()

    resource, resource_id = _parse_path(entry.get("path"), index)

    bulk_id = entry.get("bulkId")
    if bulk_id is not None and not isinstance(bulk_id, str):
        raise ScimError(400, f"operation {index}: bulkId must be a string", ScimType.INVALID_VALUE)
    if method == "POST" and not bulk_id:
        # §3.7.2 requires it, and without one the response has nothing to
        # correlate a created resource back to the request that made it.
        raise ScimError(400, f"operation {index}: a POST needs a bulkId", ScimType.INVALID_VALUE)
    if method != "POST" and resource_id is None:
        raise ScimError(
            400,
            f"operation {index}: {method} needs a resource id in its path",
            ScimType.INVALID_PATH,
        )
    if method == "POST" and resource_id is not None:
        raise ScimError(
            400, f"operation {index}: a POST addresses a collection", ScimType.INVALID_PATH
        )

    version = entry.get("version")
    if version is not None and not isinstance(version, str):
        raise ScimError(400, f"operation {index}: version must be a string", ScimType.INVALID_VALUE)

    data = entry.get("data")
    if method in {"POST", "PUT", "PATCH"} and not isinstance(data, dict):
        raise ScimError(400, f"operation {index}: {method} needs data", ScimType.INVALID_VALUE)

    references = referenced_bulk_ids(data) | (
        {resource_id.removeprefix(BULK_ID_PREFIX)}
        if resource_id and resource_id.startswith(BULK_ID_PREFIX)
        else set()
    )
    if bulk_id is not None and bulk_id in references:
        raise ScimError(
            409, f"operation {index}: bulkId {bulk_id!r} refers to itself", ScimType.INVALID_VALUE
        )

    return BulkOperation(
        method=method,
        resource=resource,
        resource_id=resource_id,
        bulk_id=bulk_id,
        data=data,
        version=version,
        depends_on=frozenset(references),
    )


def _parse_path(path: Any, index: int) -> tuple[str, str | None]:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ScimError(
            400, f"operation {index}: {path!r} is not a bulk path", ScimType.INVALID_PATH
        )

    parts = [part for part in path.split("/") if part]
    if not parts or parts[0] not in RESOURCES or len(parts) > 2:
        raise ScimError(
            400,
            f"operation {index}: {path!r} does not address /Users or /Groups",
            ScimType.INVALID_PATH,
        )
    return parts[0], parts[1] if len(parts) == 2 else None


def _assert_bulk_ids_unique(operations: list[BulkOperation]) -> None:
    """Two operations sharing a `bulkId` make every reference to it ambiguous,
    which is worse than a failure because it silently picks one."""
    seen: set[str] = set()
    for index, operation in enumerate(operations):
        if operation.bulk_id is None:
            continue
        if operation.bulk_id in seen:
            raise ScimError(
                409,
                f"operation {index}: bulkId {operation.bulk_id!r} is used twice",
                ScimType.UNIQUENESS,
            )
        seen.add(operation.bulk_id)


def _ordered(operations: list[BulkOperation]) -> list[BulkOperation]:
    """Sort so that every referenced operation runs before the one referring to it.

    A stable topological sort: among operations that are ready, the one sent
    first goes first, so a request with no references executes in exactly the
    order the client wrote it and a client reading the response is not surprised.
    """
    produced = {op.bulk_id: index for index, op in enumerate(operations) if op.bulk_id}

    unknown = {
        reference
        for operation in operations
        for reference in operation.depends_on
        if reference not in produced
    }
    if unknown:
        raise ScimError(
            400,
            f"no operation declares bulkId {sorted(unknown)}",
            ScimType.INVALID_VALUE,
        )

    remaining = list(range(len(operations)))
    done: set[str] = set()
    ordered: list[BulkOperation] = []

    while remaining:
        ready = [index for index in remaining if operations[index].depends_on <= done]
        if not ready:
            # Every operation left is waiting for another one that is also
            # waiting. §3.7.2 makes this a 409 rather than something to attempt.
            cycle = sorted(str(operations[index].bulk_id) for index in remaining)
            raise ScimError(409, f"bulkId references form a cycle: {cycle}", ScimType.INVALID_VALUE)
        for index in ready:
            ordered.append(operations[index])
            if operations[index].bulk_id:
                done.add(str(operations[index].bulk_id))
            remaining.remove(index)

    return ordered


def referenced_bulk_ids(value: Any) -> set[str]:
    """Every `bulkId:` reference anywhere in an operation's data.

    A walk of the whole document rather than a check of the fields we expect,
    because a reference is legal wherever a resource id is — `members[].value`
    today, and whatever a future extension puts an id in.
    """
    if isinstance(value, str):
        return {value.removeprefix(BULK_ID_PREFIX)} if value.startswith(BULK_ID_PREFIX) else set()
    if isinstance(value, dict):
        return set().union(*(referenced_bulk_ids(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(referenced_bulk_ids(item) for item in value), set())
    return set()


def resolve_references(value: Any, resolved: dict[str, str]) -> Any:
    """Replace every `bulkId:` reference with the id the operation produced.

    Returns a new document. Mutating the client's would make a retry of the same
    request behave differently the second time, which is the kind of bug that
    only appears under the retry it was supposed to survive.
    """
    if isinstance(value, str):
        if value.startswith(BULK_ID_PREFIX):
            key = value.removeprefix(BULK_ID_PREFIX)
            if key not in resolved:
                raise ScimError(404, f"bulkId {key!r} produced no resource", ScimType.INVALID_VALUE)
            return resolved[key]
        return value
    if isinstance(value, dict):
        return {key: resolve_references(item, resolved) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_references(item, resolved) for item in value]
    return value
