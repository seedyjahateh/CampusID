"""SCIM Users over the identity registry (FR-SCIM-02 to 09, FR-SCIM-14).

Where a SCIM request becomes rows. Four decisions here are not obvious from the
specification and matter more than the CRUD around them.

**A create is idempotent on `externalId`.** An SIS that loses a response retries,
and a broker that makes a second person each time is how one human being ends up
with three records and two ePPNs. A replay returns the existing resource with
200 rather than 201 — the status is the signal that nothing new happened.

**A delete is soft.** FR-SCIM-06: the person becomes `deactivated` and keeps
their row, because the audit trail has to go on naming them and their
identifiers have to go on being un-reissuable. A SCIM client sees a resource
that is gone; the registry sees somebody who left.

**`userName` is an identifier, so changing it releases the old one.** A `PUT`
that changes `userName` does not rewrite the ePPN row — it tombstones it and
issues a new one, because the old value must never be handed to anybody else.
That is the single most consequential difference between this store and a
generic SCIM implementation over a `users` table.

**Filtering happens after projection, and that is a documented limit.** A SCIM
filter can name any attribute of the projected document, including ones assembled
from three tables, so evaluating it means building the document first. Beyond
`MAX_SCANNED` people that stops being reasonable, and the honest answer is
`tooMany` asking the client to narrow — not a silently truncated page. Pushing
the common filters into SQL is the obvious optimisation and is deliberately not
pretended at here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.identity.models import Affiliation, Identifier, Person
from campusid.identity.registry import ID_EPPN, ID_MAIL, new_unique_id
from campusid.logging import get_logger
from campusid.scim.errors import (
    ScimError,
    ScimType,
    duplicate,
    invalid_value,
    not_found,
    version_mismatch,
)
from campusid.scim.filters import Node, matches
from campusid.scim.models import ScimGroup, ScimGroupMember, ScimSourceRecord
from campusid.scim.resources import (
    ParsedUser,
    UserRecord,
    to_scim,
)
from campusid.scim.schemas import MAX_RESULTS

log = get_logger(__name__)

ID_EMPLOYEE: Final = "employee_id"

STATUS_ACTIVE: Final = "active"
STATUS_DEACTIVATED: Final = "deactivated"
"""What a SCIM `DELETE` produces. Not a deleted row: the audit trail has to go
on naming this person, and their identifiers have to go on being
un-reissuable."""

MAX_SCANNED: Final = 5000
"""How many people a filtered list will project before giving up.

See the module docstring: filtering happens after projection, so this is a real
ceiling rather than a tuning knob. Exceeding it returns `tooMany` — an honest
refusal asking the client to narrow — rather than a page that quietly omits
people the filter would have matched.
"""

DEFAULT_COUNT: Final = 100


@dataclass(frozen=True, slots=True)
class Page:
    """One page of a `ListResponse` (FR-SCIM-08)."""

    resources: list[dict[str, Any]]
    total: int
    start_index: int
    """1-based, as RFC 7644 §3.4.2.4 requires. Zero-based here would make a
    client's second page overlap its first by one person."""

    def to_list_response(self) -> dict[str, Any]:
        from campusid.scim.schemas import LIST_RESPONSE

        return {
            "schemas": [LIST_RESPONSE],
            "totalResults": self.total,
            "startIndex": self.start_index,
            "itemsPerPage": len(self.resources),
            "Resources": self.resources,
        }


class UserStore:
    """SCIM `/Users` backed by the identity registry."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        issuer: str,
        scope: str,
    ) -> None:
        self._sessions = session_factory
        self._issuer = issuer
        self._scope = scope

    # --- create -----------------------------------------------------------

    async def create(self, parsed: ParsedUser, raw: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Create a person, or return the one a replayed request already made.

        Returns `(resource, created)`. The flag decides 201 against 200, which
        is the only thing telling a retrying client whether its first attempt
        landed.
        """
        async with self._sessions() as session, session.begin():
            if parsed.external_id:
                existing = await session.scalar(
                    select(ScimSourceRecord).where(
                        ScimSourceRecord.external_id == parsed.external_id
                    )
                )
                if existing is not None:
                    # FR-SCIM-14. The SIS lost our response and asked again; the
                    # person it is asking about already exists.
                    log.info("scim.create.replayed", external_id=parsed.external_id)
                    record = await self._load(session, existing.person_uuid)
                    assert record is not None
                    return to_scim(record, issuer=self._issuer), False

            await self._assert_username_free(session, parsed.user_name)

            person = Person(
                edu_person_unique_id=new_unique_id(self._scope),
                display_name=parsed.display_name,
                given_name=parsed.given_name,
                surname=parsed.surname,
                preferred_language=parsed.preferred_language,
                ferpa_directory_suppressed=parsed.ferpa_directory_suppressed,
                status=parsed.status,
                provisioning_source="sis",
            )
            session.add(person)
            await session.flush()

            await self._write_identifiers(session, person.person_uuid, parsed)
            await self._write_affiliations(session, person.person_uuid, parsed)
            await session.flush()

            record = await self._load(session, person.person_uuid)
            assert record is not None
            resource = to_scim(record, issuer=self._issuer)

            session.add(
                ScimSourceRecord(
                    person_uuid=person.person_uuid,
                    external_id=parsed.external_id,
                    raw_resource=raw,
                    version=resource["meta"]["version"],
                )
            )
            return resource, True

    # --- read -------------------------------------------------------------

    async def get(self, resource_id: str) -> dict[str, Any]:
        async with self._sessions() as session:
            record = await self._load(session, _as_uuid(resource_id))
            if record is None:
                raise not_found("User", resource_id)
            return to_scim(record, issuer=self._issuer)

    async def search(
        self,
        *,
        predicate: Node | None = None,
        start_index: int = 1,
        count: int = DEFAULT_COUNT,
        sort_by: str | None = None,
        descending: bool = False,
    ) -> Page:
        """List users, filtered, sorted and paginated (FR-SCIM-07/08)."""
        if start_index < 1:
            # §3.4.2.4: a value less than 1 is interpreted as 1 rather than
            # refused, because a client counting from zero is making an ordinary
            # off-by-one and a 400 would not tell it which.
            start_index = 1
        count = max(0, min(count, MAX_RESULTS))

        async with self._sessions() as session:
            people = list(
                await session.scalars(
                    select(Person).order_by(Person.created_at).limit(MAX_SCANNED + 1)
                )
            )
            if len(people) > MAX_SCANNED:
                raise ScimError(
                    400,
                    f"more than {MAX_SCANNED} resources would have to be examined; "
                    "narrow the filter",
                    ScimType.TOO_MANY,
                )

            resources = [
                to_scim(record, issuer=self._issuer)
                for record in await self._load_many(session, people)
            ]

        if predicate is not None:
            resources = [resource for resource in resources if matches(predicate, resource)]

        if sort_by:
            resources.sort(key=lambda r: _sort_key(r, sort_by), reverse=descending)

        window = resources[start_index - 1 : start_index - 1 + count]
        return Page(window, len(resources), start_index)

    # --- replace ----------------------------------------------------------

    async def replace(
        self,
        resource_id: str,
        parsed: ParsedUser,
        raw: dict[str, Any],
        *,
        if_match: str | None = None,
    ) -> dict[str, Any]:
        """`PUT` — the resource becomes exactly what the client sent (FR-SCIM-04)."""
        async with self._sessions() as session, session.begin():
            person_uuid = _as_uuid(resource_id)
            person = await session.get(Person, person_uuid)
            if person is None:
                raise not_found("User", resource_id)

            source = await self._source(session, person_uuid)
            _assert_version(source, if_match)

            await self._assert_username_free(session, parsed.user_name, excluding=person_uuid)

            person.display_name = parsed.display_name
            person.given_name = parsed.given_name
            person.surname = parsed.surname
            person.preferred_language = parsed.preferred_language
            person.ferpa_directory_suppressed = parsed.ferpa_directory_suppressed
            person.status = parsed.status

            await self._replace_identifiers(session, person_uuid, parsed)
            await self._replace_affiliations(session, person_uuid, parsed)
            await session.flush()

            # `Person.updated_at` carries `onupdate=func.now()`, so the flush
            # leaves it expired with a value only the database knows. Projecting
            # the record would then touch it from `to_scim`, which is an ordinary
            # synchronous function — the lazy refresh has no greenlet to await in
            # and raises `MissingGreenlet` rather than loading. Fetch it here,
            # where awaiting is possible.
            await session.refresh(person)

            return await self._finish(session, person_uuid, source, raw)

    async def apply_patched(
        self,
        resource_id: str,
        parsed: ParsedUser,
        raw: dict[str, Any],
        *,
        if_match: str | None = None,
    ) -> dict[str, Any]:
        """Store the result of a PATCH.

        The PATCH itself is applied to the *projected document* by
        `scim.patch`, which is what lets `emails[type eq "work"].value` mean
        what it says. This writes the outcome back, so the two halves stay
        separable: the patch engine knows the specification, the store knows the
        registry, and neither has to know the other.
        """
        return await self.replace(resource_id, parsed, raw, if_match=if_match)

    # --- delete -----------------------------------------------------------

    async def soft_delete(self, resource_id: str, *, if_match: str | None = None) -> None:
        """`DELETE` — deactivate, keep the row (FR-SCIM-06).

        The person's identifiers stay tombstoned rather than freed, so a
        deprovisioned ePPN is still un-reissuable. A hard delete exists only in
        the admin API, with a justification, because it destroys the evidence
        that somebody was ever here.
        """
        async with self._sessions() as session, session.begin():
            person_uuid = _as_uuid(resource_id)
            person = await session.get(Person, person_uuid)
            if person is None or person.status == STATUS_DEACTIVATED:
                raise not_found("User", resource_id)

            source = await self._source(session, person_uuid)
            _assert_version(source, if_match)

            person.status = STATUS_DEACTIVATED
            for identifier in await self._identifiers(session, person_uuid):
                if identifier.released_at is None:
                    identifier.released_at = datetime.now(UTC)
                    identifier.is_primary = False

            for affiliation in await self._affiliations(session, person_uuid):
                if affiliation.valid_until is None:
                    affiliation.valid_until = date.today()

            log.info("scim.user.deactivated", person_uuid=str(person_uuid))

    # --- helpers ----------------------------------------------------------

    async def _finish(
        self,
        session: AsyncSession,
        person_uuid: uuid.UUID,
        source: ScimSourceRecord | None,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        record = await self._load(session, person_uuid)
        assert record is not None
        resource = to_scim(record, issuer=self._issuer)

        if source is None:
            session.add(
                ScimSourceRecord(
                    person_uuid=person_uuid,
                    raw_resource=raw,
                    version=resource["meta"]["version"],
                )
            )
        else:
            source.raw_resource = raw
            source.version = resource["meta"]["version"]
            source.last_sync_at = datetime.now(UTC)
        return resource

    async def _assert_username_free(
        self, session: AsyncSession, user_name: str, *, excluding: uuid.UUID | None = None
    ) -> None:
        """FR-SCIM-02's 409.

        Checks *live* identifiers only. A tombstoned ePPN is not available to be
        claimed either, but that refusal comes from the database constraint and
        carries a different meaning — "this belonged to somebody else" rather
        than "this belongs to somebody else" — so the two are not merged.
        """
        existing = await session.scalar(
            select(Identifier).where(
                Identifier.id_type == ID_EPPN,
                Identifier.value == user_name,
                Identifier.released_at.is_(None),
            )
        )
        if existing is not None and existing.person_uuid != excluding:
            raise duplicate("userName", user_name)

    async def _write_identifiers(
        self, session: AsyncSession, person_uuid: uuid.UUID, parsed: ParsedUser
    ) -> None:
        session.add(
            Identifier(
                person_uuid=person_uuid,
                id_type=ID_EPPN,
                value=parsed.user_name,
                scope=_scope_of(parsed.user_name),
                is_primary=True,
            )
        )
        for address, primary in parsed.emails:
            session.add(
                Identifier(
                    person_uuid=person_uuid, id_type=ID_MAIL, value=address, is_primary=primary
                )
            )
        if parsed.employee_number:
            session.add(
                Identifier(
                    person_uuid=person_uuid,
                    id_type=ID_EMPLOYEE,
                    value=parsed.employee_number,
                    is_primary=True,
                )
            )

    async def _replace_identifiers(
        self, session: AsyncSession, person_uuid: uuid.UUID, parsed: ParsedUser
    ) -> None:
        """Reconcile identifiers against what the client sent.

        Anything no longer present is *released*, never deleted. That is the
        difference that matters: a `PUT` changing `userName` tombstones the old
        ePPN so nobody else can ever be given it, where a generic SCIM
        implementation over a users table would simply overwrite the column and
        free the name.
        """
        live = [i for i in await self._identifiers(session, person_uuid) if i.released_at is None]
        wanted: dict[tuple[str, str], bool] = {(ID_EPPN, parsed.user_name): True}
        for address, primary in parsed.emails:
            wanted[(ID_MAIL, address)] = primary
        if parsed.employee_number:
            wanted[(ID_EMPLOYEE, parsed.employee_number)] = True

        for identifier in live:
            key = (identifier.id_type, identifier.value)
            if key in wanted:
                identifier.is_primary = wanted.pop(key)
            elif identifier.id_type in (ID_EPPN, ID_MAIL, ID_EMPLOYEE):
                identifier.released_at = datetime.now(UTC)
                identifier.is_primary = False

        for (id_type, value), primary in wanted.items():
            session.add(
                Identifier(
                    person_uuid=person_uuid,
                    id_type=id_type,
                    value=value,
                    scope=_scope_of(value) if id_type == ID_EPPN else None,
                    is_primary=primary,
                )
            )

    async def _write_affiliations(
        self, session: AsyncSession, person_uuid: uuid.UUID, parsed: ParsedUser
    ) -> None:
        from campusid.policy.normalize import AFFILIATION_VOCABULARY

        for affiliation in parsed.affiliations:
            if affiliation.value not in AFFILIATION_VOCABULARY:
                raise invalid_value(f"{affiliation.value!r} is outside the eduPerson vocabulary")
            session.add(
                Affiliation(
                    person_uuid=person_uuid,
                    affiliation=affiliation.value,
                    is_primary=affiliation.is_primary,
                    org_unit=affiliation.org_unit,
                    valid_from=affiliation.valid_from,
                    valid_until=affiliation.valid_until,
                    source="sis",
                )
            )

    async def _replace_affiliations(
        self, session: AsyncSession, person_uuid: uuid.UUID, parsed: ParsedUser
    ) -> None:
        """Close what the client no longer sends; add what is new.

        Closed rather than deleted, so "was this person a student on
        2024-03-01?" stays answerable after they graduate. A `PUT` that drops an
        affiliation is a graduation, not a correction of the record.
        """
        today = date.today()
        existing = await self._affiliations(session, person_uuid)
        wanted = {(a.value, a.valid_from): a for a in parsed.affiliations}

        for row in existing:
            key = (row.affiliation, row.valid_from)
            if key in wanted:
                sent = wanted.pop(key)
                row.is_primary = sent.is_primary
                row.org_unit = sent.org_unit
                row.valid_until = sent.valid_until
            elif row.valid_until is None:
                row.valid_until = today

        from campusid.policy.normalize import AFFILIATION_VOCABULARY

        for affiliation in wanted.values():
            if affiliation.value not in AFFILIATION_VOCABULARY:
                raise invalid_value(f"{affiliation.value!r} is outside the eduPerson vocabulary")
            session.add(
                Affiliation(
                    person_uuid=person_uuid,
                    affiliation=affiliation.value,
                    is_primary=affiliation.is_primary,
                    org_unit=affiliation.org_unit,
                    valid_from=affiliation.valid_from,
                    valid_until=affiliation.valid_until,
                    source="sis",
                )
            )

    async def _load(self, session: AsyncSession, person_uuid: uuid.UUID) -> UserRecord | None:
        person = await session.get(Person, person_uuid)
        if person is None:
            return None
        source = await self._source(session, person_uuid)
        return UserRecord(
            person=person,
            identifiers=await self._identifiers(session, person_uuid),
            affiliations=await self._affiliations(session, person_uuid),
            external_id=source.external_id if source else None,
            groups=tuple((await self._groups(session, [person_uuid])).get(person_uuid, ())),
        )

    async def _load_many(self, session: AsyncSession, people: list[Person]) -> list[UserRecord]:
        """Load a page's identifiers and affiliations in two queries, not 2N.

        A list of two hundred people is four hundred round trips if each record
        loads its own, which is the difference between a fast endpoint and one
        that times out on the page a client actually asks for.
        """
        if not people:
            return []

        keys = [person.person_uuid for person in people]
        identifiers = list(
            await session.scalars(select(Identifier).where(Identifier.person_uuid.in_(keys)))
        )
        affiliations = list(
            await session.scalars(select(Affiliation).where(Affiliation.person_uuid.in_(keys)))
        )
        sources = list(
            await session.scalars(
                select(ScimSourceRecord).where(ScimSourceRecord.person_uuid.in_(keys))
            )
        )

        by_person: dict[uuid.UUID, list[Identifier]] = {key: [] for key in keys}
        for identifier in identifiers:
            by_person[identifier.person_uuid].append(identifier)

        affiliations_by_person: dict[uuid.UUID, list[Affiliation]] = {key: [] for key in keys}
        for affiliation in affiliations:
            affiliations_by_person[affiliation.person_uuid].append(affiliation)

        external = {source.person_uuid: source.external_id for source in sources}
        groups = await self._groups(session, keys)

        return [
            UserRecord(
                person=person,
                identifiers=by_person[person.person_uuid],
                affiliations=affiliations_by_person[person.person_uuid],
                external_id=external.get(person.person_uuid),
                groups=tuple(groups.get(person.person_uuid, ())),
            )
            for person in people
        ]

    async def _groups(
        self, session: AsyncSession, people: list[uuid.UUID]
    ) -> dict[uuid.UUID, list[tuple[str, str]]]:
        """Which groups each of these people belongs to.

        One query for the whole page, for the same reason identifiers are loaded
        that way. `groups` is read-only on a User (RFC 7643 §4.1.2): membership
        is changed through `/Groups`, and this direction exists so a client can
        see the result of having done so.
        """
        if not people:
            return {}

        rows = await session.execute(
            select(ScimGroupMember.person_uuid, ScimGroup.group_uuid, ScimGroup.display_name)
            .join(ScimGroup, ScimGroup.group_uuid == ScimGroupMember.group_uuid)
            .where(ScimGroupMember.person_uuid.in_(people))
            .order_by(ScimGroup.display_name)
        )

        memberships: dict[uuid.UUID, list[tuple[str, str]]] = {}
        for person_uuid, group_uuid, display_name in rows:
            memberships.setdefault(person_uuid, []).append((str(group_uuid), display_name))
        return memberships

    async def _identifiers(self, session: AsyncSession, person_uuid: uuid.UUID) -> list[Identifier]:
        return list(
            await session.scalars(select(Identifier).where(Identifier.person_uuid == person_uuid))
        )

    async def _affiliations(
        self, session: AsyncSession, person_uuid: uuid.UUID
    ) -> list[Affiliation]:
        return list(
            await session.scalars(select(Affiliation).where(Affiliation.person_uuid == person_uuid))
        )

    async def _source(
        self, session: AsyncSession, person_uuid: uuid.UUID
    ) -> ScimSourceRecord | None:
        source: ScimSourceRecord | None = await session.scalar(
            select(ScimSourceRecord).where(ScimSourceRecord.person_uuid == person_uuid)
        )
        return source


def _assert_version(source: ScimSourceRecord | None, if_match: str | None) -> None:
    """FR-SCIM-09's 412.

    Absent `If-Match` means the client is not doing optimistic concurrency,
    which is its choice to make — requiring the header would break every simple
    client for the benefit of the careful ones.
    """
    if if_match is None:
        return
    if source is None or source.version not in _candidates(if_match):
        raise version_mismatch(source.version if source else "unknown")


def _candidates(if_match: str) -> set[str]:
    """`If-Match` may carry several versions, and `*` matches any.

    Also tolerates a client that strips the `W/` prefix, because several do and
    a weak comparison is what the specification asks for anyway.
    """
    if if_match.strip() == "*":
        return {"*"}
    tags = {tag.strip() for tag in if_match.split(",")}
    return tags | {f"W/{tag}" for tag in tags} | {tag.removeprefix("W/") for tag in tags}


def _sort_key(resource: dict[str, Any], sort_by: str) -> str:
    """Sort by a top-level attribute, missing values last.

    Everything is compared as a string. SCIM's `sortBy` can name any attribute
    and the types are not knowable here, so a consistent order beats a clever
    one that raises on a mixed collection.
    """
    value = resource.get(sort_by)
    if value is None:
        return "￿"
    return str(value).lower()


def _as_uuid(resource_id: str) -> uuid.UUID:
    """A resource id is a `person_uuid`.

    Anything else is a 404 rather than a 400: a client walking ids it was given
    should not be able to tell a malformed id from one that belongs to somebody
    it cannot see.
    """
    try:
        return uuid.UUID(resource_id)
    except ValueError as exc:
        raise not_found("User", resource_id) from exc


def _scope_of(eppn: str) -> str | None:
    _, separator, scope = eppn.rpartition("@")
    return scope.lower() if separator else None
