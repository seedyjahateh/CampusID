"""Group documents — the half of `/Groups` that is not SQL.

The same split `resources.py` and `store.py` make for people, and for the same
reason: reading a client's document, projecting rows back as one, and working
out what a PATCH operation means are decisions about the *specification*, while
the store's job is rows. Kept together they would need a database to test, which
would be a database standing in for a JSON question.

Two things here are specific to groups and neither is obvious.

**A group's version is a counter.** `/Users` derives its ETag from a hash of the
projected document, which is right for a small representation. A group may have
ten thousand members, and hashing its representation would mean loading all of
them to answer a one-member PATCH — the read FR-SCIM-11 exists to avoid. A weak
ETag only has to change when the resource changes, and a counter does that
without reading anything.

**A member filter is recognised, not evaluated.** `members[value eq "<id>"]` is
the shape every client sends, and `member_target` turns it into the one id it
names so the store can issue a single delete. Anything else returns None and the
caller falls back to evaluating the filter properly against the membership,
which is correct and costs the read.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from campusid.scim.errors import ScimError, ScimType, invalid_value
from campusid.scim.filters import Comparison, Node, Operator
from campusid.scim.models import ScimGroup
from campusid.scim.patch import IMMUTABLE, Op, Operation
from campusid.scim.schemas import CORE_GROUP

MEMBER_ATTRIBUTE: Final = "members"

MAX_MEMBERS_INLINE: Final = 1000
"""How many members a projection will carry.

A group larger than this is not refused — it is answered without its membership,
with the client pointed at `GET /Users?filter=groups.value eq "<id>"`, which
pages. Returning the first thousand of ten thousand would be a truncation the
client has no way to detect.
"""

COLUMNS: Final[dict[str, str]] = {"displayname": "display_name", "externalid": "external_id"}
"""The only two attributes a client may write, and the columns they are.

A short explicit mapping rather than the generic document patcher, because
running that would mean projecting the group first — and the projection is what
this module works to avoid loading.
"""


@dataclass(frozen=True, slots=True)
class GroupRecord:
    """A group and, when the client asked for them, its members."""

    group: ScimGroup
    members: list[tuple[uuid.UUID, str]] | None = None
    """`(person_uuid, display)` pairs, or None when membership was not
    requested. None and `[]` are different answers — "not asked for" against
    "nobody is in it" — and collapsing them would have a client believe an
    unrequested group is empty."""

    member_count: int = 0


@dataclass(frozen=True, slots=True)
class ParsedGroup:
    """What a client's document asks for."""

    display_name: str
    external_id: str | None = None
    members: list[uuid.UUID] | None = None
    """None when the document did not mention `members` at all, which a `PUT`
    treats as "leave the membership alone". `members` is `returned: "request"`,
    so a client that read the group without asking for them never had them to
    send back, and reading the omission as "remove everybody" would empty a
    group on an ordinary rename."""


def to_scim_group(record: GroupRecord, *, issuer: str) -> dict[str, Any]:
    """Project a group as a SCIM Group."""
    group = record.group
    resource: dict[str, Any] = {
        "schemas": [CORE_GROUP],
        "id": str(group.group_uuid),
        "displayName": group.display_name,
    }
    if group.external_id:
        resource["externalId"] = group.external_id

    if record.members is not None:
        resource[MEMBER_ATTRIBUTE] = [
            {
                "value": str(person_uuid),
                "display": display,
                "type": "User",
                "$ref": f"{issuer}/scim/v2/Users/{person_uuid}",
            }
            for person_uuid, display in record.members
        ]

    resource["meta"] = {
        "resourceType": "Group",
        "created": _instant(group.created_at),
        "lastModified": _instant(group.updated_at),
        "location": f"{issuer}/scim/v2/Groups/{group.group_uuid}",
        "version": group_etag(group.revision),
    }
    return resource


def group_etag(revision: int) -> str:
    """The version a client's `If-Match` is compared against.

    See the module docstring: a counter rather than a content hash, so answering
    "has this changed" never costs a read of the membership.
    """
    return f'W/"{revision}"'


def matches_version(current: str, if_match: str) -> bool:
    """Weak comparison, tolerating a client that strips the `W/` prefix.

    Several do, and the specification asks for a weak comparison anyway, so
    refusing over the prefix would be strictness with nothing behind it.
    """
    if if_match.strip() == "*":
        return True
    tags = {tag.strip() for tag in if_match.split(",")}
    candidates = tags | {tag.removeprefix("W/") for tag in tags}
    return current in candidates or current.removeprefix("W/") in candidates


def parse_group(document: dict[str, Any]) -> ParsedGroup:
    """Read a client's Group document."""
    display_name = document.get("displayName")
    if not isinstance(display_name, str) or not display_name.strip():
        raise invalid_value("displayName is required")

    external_id = document.get("externalId")
    if external_id is not None and not isinstance(external_id, str):
        raise invalid_value("externalId must be a string")

    sent = document.get(MEMBER_ATTRIBUTE)
    return ParsedGroup(
        display_name=display_name.strip(),
        external_id=external_id,
        members=None if sent is None else member_ids(sent),
    )


def member_ids(value: Any) -> list[uuid.UUID]:
    """Read a `members` array as person ids, in order and without duplicates.

    A member is `{"value": "<id>"}`; the other sub-attributes are ours to
    produce rather than the client's to set. A bare string is accepted too,
    because several clients send one and refusing it teaches nobody anything.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise invalid_value("members must be an array")

    seen: dict[uuid.UUID, None] = {}
    for entry in value:
        raw = entry.get("value") if isinstance(entry, dict) else entry
        if not isinstance(raw, str):
            raise invalid_value("each member needs a value")
        try:
            seen[uuid.UUID(raw)] = None
        except ValueError as exc:
            raise invalid_value(f"{raw!r} is not a member id") from exc
    return list(seen)


def targets_members(operation: Operation) -> bool:
    """Whether this operation is about membership rather than the group itself."""
    if operation.path is not None:
        return operation.path.path.attribute.lower() == MEMBER_ATTRIBUTE
    # A pathless operation carries an object whose keys are the attributes; it
    # targets membership when one of them is `members`.
    return isinstance(operation.value, dict) and any(
        key.lower() == MEMBER_ATTRIBUTE for key in operation.value
    )


def attribute_changes(operation: Operation, index: int) -> dict[str, str | None]:
    """Translate an attribute operation into the columns it changes.

    Returns column names rather than applying anything, so the whole of a
    request can be validated before any of it is written — which is what makes
    a PATCH that renames a group and adds a bad member leave the name alone.
    """
    if operation.path is None:
        if not isinstance(operation.value, dict):
            raise ScimError(
                400,
                f"operation {index}: a pathless operation needs an object value",
                ScimType.INVALID_VALUE,
            )
        changes: dict[str, str | None] = {}
        for name, value in operation.value.items():
            changes.update(_one_change(name, value, index))
        return changes

    name = operation.path.path.attribute
    value = None if operation.op is Op.REMOVE else operation.value
    return _one_change(name, value, index)


def _one_change(name: str, value: Any, index: int) -> dict[str, str | None]:
    attribute = name.lower()
    if attribute in IMMUTABLE:
        raise ScimError(400, f"operation {index}: {name} cannot be changed", ScimType.MUTABILITY)

    column = COLUMNS.get(attribute)
    if column is None:
        raise ScimError(
            400, f"operation {index}: a Group has no {name!r} attribute", ScimType.INVALID_PATH
        )

    if column == "display_name":
        if not isinstance(value, str) or not value.strip():
            raise invalid_value("displayName cannot be removed or emptied")
        return {column: value.strip()}

    if value is not None and not isinstance(value, str):
        raise invalid_value("externalId must be a string")
    return {column: value}


def member_target(predicate: Node) -> uuid.UUID | None:
    """Recognise `value eq "<id>"`, the filter every client sends.

    Returns the member it names, or None when the filter is anything else — in
    which case the caller evaluates it properly. Recognition rather than
    interpretation: an unrecognised filter is answered correctly and slowly,
    never approximately.
    """
    if not isinstance(predicate, Comparison):
        return None
    if predicate.operator is not Operator.EQ:
        return None
    if predicate.path.attribute.lower() != "value" or predicate.path.sub_attribute:
        return None
    if not isinstance(predicate.value, str):
        return None
    try:
        return uuid.UUID(predicate.value)
    except ValueError:
        return None


def _instant(value: datetime) -> str:
    """RFC 3339, in UTC, with a `Z`."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
