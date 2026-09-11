"""Everything the broker knows about one person, in one view (FR-ADM-04).

The question this answers is the one a service desk actually asks: somebody says
they cannot reach a system, and the person on the other end needs to see what the
broker believes about them without opening six tables. Identifiers, affiliations,
entitlements, roles, group memberships, registered factors, live sessions, and
what has been released about them lately.

**It composes rather than queries.** Every fact here already has a store that owns
it, and this assembles their answers. A view with its own SQL would be a second
opinion about the same rows — and the moment it drifted, an administrator would be
looking at something no other part of the system agrees with.

**Nothing here is a credential.** A TOTP seed, a recovery code and a session
identifier are all things the broker holds about a person and none of them belong
on a page somebody can screenshot. Factors are listed by label and kind; sessions
by an abbreviated handle that is enough to terminate one and not enough to use it.

**A missing collaborator is an empty section, not an error.** A deployment with no
directory has no group memberships to show, and a view that failed rather than
saying so would make the console unusable for the deployments that need it least.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from campusid.audit.query import Query
from campusid.logging import get_logger

log = get_logger(__name__)

SESSION_HANDLE = 8
"""How much of a session identifier the view shows.

Enough to tell two sessions apart and to name one for termination; far short of
the 256 bits that would let somebody use it. The full value never leaves the
session store, which is the whole reason the identifier is opaque.
"""

RELEASE_HISTORY = 50
"""How many recent releases the view carries.

A page rather than everything: the full history is a query away through the audit
API, and a person detail view that loaded three years of releases would be slow
for the ninety per cent of visits that only want to see today.
"""


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """One live session, described but not usable."""

    handle: str
    idp_entity_id: str
    created_at: datetime
    last_seen_at: datetime
    acr: str | None
    amr: tuple[str, ...]
    impersonated_by: str | None


@dataclass(frozen=True, slots=True)
class PersonView:
    """What the broker believes about one person."""

    person_uuid: str
    status: str
    edu_person_unique_id: str
    identifiers: tuple[dict[str, Any], ...] = ()
    affiliations: tuple[str, ...] = ()
    entitlements: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    groups: tuple[dict[str, str], ...] = ()
    factors: tuple[dict[str, Any], ...] = ()
    sessions: tuple[SessionSummary, ...] = ()
    releases: tuple[dict[str, Any], ...] = ()
    accounts: tuple[dict[str, Any], ...] = field(default_factory=tuple)


class PersonDirectory:
    """Assembles a person view from the stores that own each fact."""

    def __init__(
        self,
        *,
        identity: Any,
        lifecycle: Any,
        roles: Any,
        factors: Any,
        sessions: Any,
        audit: Any,
        groups: Any = None,
    ) -> None:
        self._identity = identity
        self._lifecycle = lifecycle
        self._roles = roles
        self._factors = factors
        self._sessions = sessions
        self._audit = audit
        self._groups = groups

    async def view(self, person_uuid: str, *, on: date | None = None) -> PersonView | None:
        """Everything about one person, or None if there is no such person."""
        person = await self._identity.get(person_uuid)
        if person is None:
            return None

        when = on or date.today()
        return PersonView(
            person_uuid=person_uuid,
            status=str(person.status),
            edu_person_unique_id=str(person.edu_person_unique_id),
            identifiers=await self._identifiers(person_uuid),
            affiliations=tuple(await self._identity.affiliations_on(person_uuid, when)),
            entitlements=tuple(sorted(await self._lifecycle.held(uuid.UUID(person_uuid), on=when))),
            roles=tuple(sorted(await self._roles.roles_for(person_uuid, on=when))),
            groups=await self._group_memberships(person_uuid),
            factors=await self._registered_factors(person_uuid),
            sessions=await self._live_sessions(person_uuid),
            releases=await self._recent_releases(person_uuid),
            accounts=await self._accounts(person_uuid),
        )

    async def terminate(self, person_uuid: str, handle: str | None = None) -> list[str]:
        """End one session or all of them (FR-ADM-06).

        Addressed by the abbreviated handle the view shows rather than by the
        session identifier, because the identifier is a credential and a console
        that had to hold one in a URL would be putting it in a browser history.

        Returns the handles that were ended, so the caller can audit what
        actually happened rather than what was asked for.
        """
        subject_key = person_uuid
        sids = await self._sessions.sids_for(subject_key)

        if handle is None:
            await self._sessions.terminate_subject(subject_key)
            return [sid[:SESSION_HANDLE] for sid in sids]

        matched = [sid for sid in sids if sid.startswith(handle)]
        for sid in matched:
            await self._sessions.destroy(sid)
        return [sid[:SESSION_HANDLE] for sid in matched]

    # --- the pieces -------------------------------------------------------

    async def _identifiers(self, person_uuid: str) -> tuple[dict[str, Any], ...]:
        """Every identifier, tombstoned ones included.

        Released identifiers are shown rather than hidden: "why can this person
        not log in with the name they have always used" is answered by seeing
        that the name was released, and a view that listed only live identifiers
        would answer it with silence (FR-LC-08).
        """
        rows = await self._identity.identifiers(person_uuid, include_released=True)
        return tuple(
            {
                "type": row.id_type,
                "value": row.value,
                "released_at": _iso(row.released_at),
            }
            for row in rows
        )

    async def _group_memberships(self, person_uuid: str) -> tuple[dict[str, str], ...]:
        if self._groups is None:
            return ()
        return tuple(
            {"id": group_id, "display_name": name}
            for group_id, name in await self._groups.groups_for(person_uuid)
        )

    async def _registered_factors(self, person_uuid: str) -> tuple[dict[str, Any], ...]:
        """Factors by label and kind, never by material.

        A seed or a credential id on an administrator's screen is a seed or a
        credential id in a screenshot.
        """
        return tuple(
            {
                "id": str(factor.id),
                "kind": factor.kind,
                "label": factor.label,
                "confirmed": factor.confirmed_at is not None,
                "disabled": factor.disabled_at is not None,
                "last_used": _iso(factor.last_used_at),
            }
            for factor in await self._factors.factors_for(person_uuid)
        )

    async def _live_sessions(self, person_uuid: str) -> tuple[SessionSummary, ...]:
        """Every session this person has open, described but not usable."""
        out: list[SessionSummary] = []
        for sid in await self._sessions.sids_for(person_uuid):
            session = await self._sessions.load(sid)
            if session is None:
                # Expired between the index read and the load. Skipped rather
                # than shown, because a console offering to terminate something
                # that is already gone reports a failure for a success.
                continue
            out.append(
                SessionSummary(
                    handle=sid[:SESSION_HANDLE],
                    idp_entity_id=session.idp_entity_id,
                    created_at=session.created_at,
                    last_seen_at=session.last_seen_at,
                    acr=session.acr,
                    amr=tuple(session.amr),
                    impersonated_by=session.impersonated_by,
                )
            )
        return tuple(out)

    async def _recent_releases(self, person_uuid: str) -> tuple[dict[str, Any], ...]:
        """What has been released about this person lately (US-02).

        Read from the audit trail rather than from a release table, because the
        trail is the record of disclosures FERPA §99.32 asks for and a second
        copy would be a second answer to the same question.
        """
        from campusid.audit.events import EventType

        page = await self._audit.search(
            Query(
                subject=person_uuid,
                event_type=EventType.ATTRIBUTE_RELEASE.value,
                limit=RELEASE_HISTORY,
            )
        )
        return tuple(
            {
                "at": _iso(event.occurred_at),
                "target": event.target,
                "attributes": sorted(event.detail.get("attributes", [])),
                "correlation_id": event.correlation_id,
            }
            for event in page.events
        )

    async def _accounts(self, person_uuid: str) -> tuple[dict[str, Any], ...]:
        """Which upstream identity providers this person has logged in through."""
        return tuple(
            {
                "idp_entity_id": account.idp_entity_id,
                "last_seen_at": _iso(account.last_seen_at),
            }
            for account in await self._identity.accounts(person_uuid)
        )


def as_json(view: PersonView) -> dict[str, Any]:
    """The view, in the shape the API returns."""
    return {
        "person_uuid": view.person_uuid,
        "status": view.status,
        "edu_person_unique_id": view.edu_person_unique_id,
        "identifiers": list(view.identifiers),
        "affiliations": list(view.affiliations),
        "entitlements": list(view.entitlements),
        "roles": list(view.roles),
        "groups": list(view.groups),
        "factors": list(view.factors),
        "accounts": list(view.accounts),
        "sessions": [
            {
                "handle": session.handle,
                "idp_entity_id": session.idp_entity_id,
                "created_at": _iso(session.created_at),
                "last_seen_at": _iso(session.last_seen_at),
                "acr": session.acr,
                "amr": list(session.amr),
                # Shown rather than left out. An administrator looking at a
                # person's sessions should see immediately that one of them is
                # somebody else acting as them (FR-ADM-03).
                "impersonated_by": session.impersonated_by,
            }
            for session in view.sessions
        ],
        "releases": list(view.releases),
    }


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None
