"""SCIM Groups, as rows (FR-SCIM-11).

The requirement that shapes this module is a performance one: a PATCH adding a
single member to a group of ten thousand must not rewrite the collection. Every
decision here follows from it. Reading documents and projecting them lives in
`group_resources`; this is the half that touches Postgres.

**Membership is rows, not a list on the group.** Adding a member is one insert
whose cost does not depend on how many members there already are, and removing
one is one delete. A group document containing a `members` array would mean
reading and writing all of them for every change.

**Only `PUT` pays for a full rewrite.** A `PUT` says the membership is exactly
this, so it costs one. That is the client's choice: PATCH exists precisely so a
change to one member need not be expressed as a restatement of all of them.

**A member filter is answered without a read where it can be.**
`members[value eq "<id>"]` names one person, so it becomes one delete. Anything
more elaborate falls back to loading the membership and evaluating properly,
which is correct and costs the read, and is capped rather than truncated.

**A group DELETE really deletes.** The asymmetry with `/Users` is deliberate: a
person is soft-deleted because the audit trail has to go on naming them and
their identifiers must never be reissued. A group is an access-control grouping,
not somebody's identity; keeping a tombstone of it would only make the name
unusable for the group that replaces it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.identity.models import Person
from campusid.logging import get_logger
from campusid.scim.errors import (
    ScimError,
    ScimType,
    duplicate,
    invalid_value,
    not_found,
    version_mismatch,
)
from campusid.scim.filters import Node, matches, select_members
from campusid.scim.group_resources import (
    MAX_MEMBERS_INLINE,
    GroupRecord,
    ParsedGroup,
    attribute_changes,
    group_etag,
    matches_version,
    member_ids,
    member_target,
    parse_group,
    targets_members,
    to_scim_group,
)
from campusid.scim.models import ScimGroup, ScimGroupMember
from campusid.scim.patch import Op, Operation
from campusid.scim.schemas import MAX_RESULTS
from campusid.scim.store import DEFAULT_COUNT, MAX_SCANNED, Page

log = get_logger(__name__)


class GroupStore:
    """SCIM `/Groups`."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], *, issuer: str) -> None:
        self._sessions = session_factory
        self._issuer = issuer

    # --- create -----------------------------------------------------------

    async def create(self, document: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Create a group, or return the one a replayed request already made.

        Idempotent on `externalId` for the same reason `/Users` is (FR-SCIM-14):
        a provisioning client that lost our response retries, and a second group
        with the same members is worse than no group at all — it is two answers
        to "who has access".
        """
        parsed = parse_group(document)

        async with self._sessions() as session, session.begin():
            if parsed.external_id:
                existing = await session.scalar(
                    select(ScimGroup).where(ScimGroup.external_id == parsed.external_id)
                )
                if existing is not None:
                    log.info("scim.group.create.replayed", external_id=parsed.external_id)
                    return await self._project(session, existing, with_members=True), False

            group = ScimGroup(
                display_name=parsed.display_name, external_id=parsed.external_id, revision=1
            )
            session.add(group)
            try:
                await session.flush()
            except IntegrityError as exc:
                raise _duplicate(exc, parsed) from exc

            await self._add_members(session, group.group_uuid, parsed.members or [])
            await session.refresh(group)
            resource = await self._project(session, group, with_members=True)

        return resource, True

    # --- read -------------------------------------------------------------

    async def get(self, group_id: str, *, with_members: bool = False) -> dict[str, Any]:
        async with self._sessions() as session:
            group = await self._load(session, group_id)
            return await self._project(session, group, with_members=with_members)

    async def search(
        self,
        *,
        predicate: Node | None = None,
        start_index: int = 1,
        count: int = DEFAULT_COUNT,
        sort_by: str | None = None,
        descending: bool = False,
        with_members: bool = False,
    ) -> Page:
        """List groups (FR-SCIM-07, FR-SCIM-08).

        Membership is omitted unless asked for. A hundred groups averaging a
        thousand members each is a hundred thousand rows to answer a page a
        client wanted for the names.
        """
        if start_index < 1:
            start_index = 1
        count = max(0, min(count, MAX_RESULTS))

        async with self._sessions() as session:
            groups = list(
                await session.scalars(
                    select(ScimGroup).order_by(ScimGroup.created_at).limit(MAX_SCANNED + 1)
                )
            )
            if len(groups) > MAX_SCANNED:
                raise ScimError(
                    400,
                    f"more than {MAX_SCANNED} groups would have to be examined; narrow the filter",
                    ScimType.TOO_MANY,
                )
            resources = [
                await self._project(session, group, with_members=with_members) for group in groups
            ]

        if predicate is not None:
            resources = [resource for resource in resources if matches(predicate, resource)]
        if sort_by:
            resources.sort(key=lambda r: str(r.get(sort_by, "￿")).lower(), reverse=descending)

        window = resources[start_index - 1 : start_index - 1 + count]
        return Page(window, len(resources), start_index)

    # --- replace ----------------------------------------------------------

    async def replace(
        self, group_id: str, document: dict[str, Any], *, if_match: str | None = None
    ) -> dict[str, Any]:
        """`PUT` — the group becomes what the client sent.

        With one deliberate exception, carried by `ParsedGroup.members` being
        None: a document that never mentions `members` leaves the membership
        alone. An explicit `"members": []` still clears it, because that is the
        client saying so rather than the client not saying anything.
        """
        parsed = parse_group(document)

        async with self._sessions() as session, session.begin():
            group = await self._load(session, group_id)
            _assert_version(group, if_match)

            group.display_name = parsed.display_name
            group.external_id = parsed.external_id
            group.revision += 1

            if parsed.members is not None:
                await self._replace_members(session, group.group_uuid, parsed.members)

            try:
                await session.flush()
            except IntegrityError as exc:
                raise _duplicate(exc, parsed) from exc

            await session.refresh(group)
            return await self._project(session, group, with_members=parsed.members is not None)

    # --- patch ------------------------------------------------------------

    async def patch(
        self, group_id: str, operations: list[Operation], *, if_match: str | None = None
    ) -> dict[str, Any]:
        """`PATCH` — the operation FR-SCIM-11 measures.

        Membership operations become row-level writes; everything else is an
        attribute change. Both happen in one transaction, so a request that
        renames a group and adds a member either does both or neither.
        """
        async with self._sessions() as session, session.begin():
            group = await self._load(session, group_id)
            _assert_version(group, if_match)

            touched_members = False
            for index, operation in enumerate(operations):
                if targets_members(operation):
                    await self._patch_members(session, group.group_uuid, operation, index)
                    touched_members = True
                else:
                    for column, value in attribute_changes(operation, index).items():
                        setattr(group, column, value)

            group.revision += 1
            try:
                await session.flush()
            except IntegrityError as exc:
                raise _duplicate(exc, ParsedGroup(group.display_name, group.external_id)) from exc

            await session.refresh(group)
            return await self._project(session, group, with_members=touched_members)

    # --- delete -----------------------------------------------------------

    async def delete(self, group_id: str, *, if_match: str | None = None) -> None:
        """`DELETE` — the group goes, and its membership with it."""
        async with self._sessions() as session, session.begin():
            group = await self._load(session, group_id)
            _assert_version(group, if_match)
            await session.delete(group)
            log.info("scim.group.deleted", group_uuid=str(group.group_uuid))

    # --- helpers ----------------------------------------------------------

    async def _load(self, session: AsyncSession, group_id: str) -> ScimGroup:
        try:
            key = uuid.UUID(group_id)
        except ValueError as exc:
            raise not_found("Group", group_id) from exc
        group = await session.get(ScimGroup, key)
        if group is None:
            raise not_found("Group", group_id)
        return group

    async def _project(
        self, session: AsyncSession, group: ScimGroup, *, with_members: bool
    ) -> dict[str, Any]:
        count = await self._member_count(session, group.group_uuid)
        members: list[tuple[uuid.UUID, str]] | None = None
        if with_members and count <= MAX_MEMBERS_INLINE:
            members = await self._members(session, group.group_uuid)
        elif with_members:
            # Answered without the membership rather than with the first
            # thousand of it, which the client could not tell from all of it.
            log.info(
                "scim.group.members.omitted",
                group_uuid=str(group.group_uuid),
                member_count=count,
            )
        return to_scim_group(
            GroupRecord(group=group, members=members, member_count=count), issuer=self._issuer
        )

    async def _member_count(self, session: AsyncSession, group_uuid: uuid.UUID) -> int:
        count = await session.scalar(
            select(func.count())
            .select_from(ScimGroupMember)
            .where(ScimGroupMember.group_uuid == group_uuid)
        )
        return int(count or 0)

    async def _members(
        self, session: AsyncSession, group_uuid: uuid.UUID
    ) -> list[tuple[uuid.UUID, str]]:
        rows = await session.execute(
            select(ScimGroupMember.person_uuid, Person.display_name, Person.edu_person_unique_id)
            .join(Person, Person.person_uuid == ScimGroupMember.person_uuid)
            .where(ScimGroupMember.group_uuid == group_uuid)
            .order_by(ScimGroupMember.added_at)
            .limit(MAX_MEMBERS_INLINE)
        )
        return [(person_uuid, display or unique_id) for person_uuid, display, unique_id in rows]

    async def _add_members(
        self, session: AsyncSession, group_uuid: uuid.UUID, people: list[uuid.UUID]
    ) -> None:
        """Insert memberships, ignoring the ones that already exist.

        `ON CONFLICT DO NOTHING` rather than a read-then-write: adding somebody
        who is already a member is not an error, and checking first would be a
        race with the next request as well as an extra round trip.
        """
        if not people:
            return
        await self._assert_people_exist(session, people)
        await session.execute(
            pg_insert(ScimGroupMember)
            .values(
                [
                    {"group_uuid": group_uuid, "person_uuid": person, "added_at": datetime.now(UTC)}
                    for person in people
                ]
            )
            .on_conflict_do_nothing(index_elements=["group_uuid", "person_uuid"])
        )

    async def _remove_members(
        self, session: AsyncSession, group_uuid: uuid.UUID, people: list[uuid.UUID]
    ) -> None:
        if not people:
            return
        await session.execute(
            delete(ScimGroupMember).where(
                ScimGroupMember.group_uuid == group_uuid,
                ScimGroupMember.person_uuid.in_(people),
            )
        )

    async def _replace_members(
        self, session: AsyncSession, group_uuid: uuid.UUID, people: list[uuid.UUID]
    ) -> None:
        """The expensive one, and the only one that is."""
        await session.execute(
            delete(ScimGroupMember).where(ScimGroupMember.group_uuid == group_uuid)
        )
        await self._add_members(session, group_uuid, people)

    async def _patch_members(
        self, session: AsyncSession, group_uuid: uuid.UUID, operation: Operation, index: int
    ) -> None:
        if operation.op is Op.ADD:
            await self._add_members(session, group_uuid, member_ids(operation.value))
            return

        if (
            operation.op is Op.REPLACE
            and operation.path is not None
            and not operation.path.predicate
        ):
            await self._replace_members(session, group_uuid, member_ids(operation.value))
            return

        if operation.op is Op.REMOVE:
            predicate = operation.path.predicate if operation.path else None
            if predicate is None:
                await self._replace_members(session, group_uuid, [])
                return
            await self._remove_members(
                session, group_uuid, await self._selected(session, group_uuid, predicate)
            )
            return

        raise ScimError(
            400,
            f"operation {index}: {operation.op} on a filtered members path is not supported",
            ScimType.INVALID_PATH,
        )

    async def _selected(
        self, session: AsyncSession, group_uuid: uuid.UUID, predicate: Node
    ) -> list[uuid.UUID]:
        """Which members a value filter selects.

        The recognised shape is answered without reading anything, which is what
        keeps a one-member removal off a ten-thousand-member collection. Anything
        else is evaluated properly against the membership, and the inline cap
        applies — so an elaborate filter over a very large group is refused
        rather than served from a truncated list.
        """
        direct = member_target(predicate)
        if direct is not None:
            return [direct]

        count = await self._member_count(session, group_uuid)
        if count > MAX_MEMBERS_INLINE:
            raise ScimError(
                400,
                (
                    "this filter has to be evaluated against the whole membership, and this "
                    f"group has more than {MAX_MEMBERS_INLINE} members; remove by "
                    'members[value eq "<id>"] instead'
                ),
                ScimType.TOO_MANY,
            )

        projected = [
            {"value": str(person_uuid), "display": display, "type": "User"}
            for person_uuid, display in await self._members(session, group_uuid)
        ]
        return [uuid.UUID(projected[i]["value"]) for i in select_members(predicate, projected)]

    async def _assert_people_exist(self, session: AsyncSession, people: list[uuid.UUID]) -> None:
        """Refuse a membership naming somebody who is not here.

        The foreign key would refuse it too, as an integrity error the client
        would see as a 500. A member who does not exist is the client's mistake
        and deserves a 400 that names them.
        """
        found = set(
            await session.scalars(select(Person.person_uuid).where(Person.person_uuid.in_(people)))
        )
        missing = [str(person) for person in people if person not in found]
        if missing:
            raise invalid_value(f"no such member: {', '.join(sorted(missing))}")


def _duplicate(exc: IntegrityError, parsed: ParsedGroup) -> ScimError:
    """Name the attribute the database actually refused.

    Both unique constraints raise the same exception type, and a 409 saying
    `displayName` when the collision was on `externalId` sends the client to
    reconcile the wrong field. The constraint names are ours, given in the
    migration for exactly this.
    """
    if parsed.external_id is not None and "uq_scim_group_external_id" in str(exc.orig):
        return duplicate("externalId", parsed.external_id)
    return duplicate("displayName", parsed.display_name)


def _assert_version(group: ScimGroup, if_match: str | None) -> None:
    """FR-SCIM-09's 412 for groups.

    Absent `If-Match` means the client is not doing optimistic concurrency,
    which is its choice to make.
    """
    if if_match is None:
        return
    current = group_etag(group.revision)
    if not matches_version(current, if_match):
        raise version_mismatch(current)
