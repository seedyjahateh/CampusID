"""Resolving a login to a person, and allocating identifiers (§8.4, FR-LC-08).

Two operations, and both are places where getting it wrong hands one person
another person's account.

**Linking** answers "is this the same human being we saw before?" from whatever
an IdP just asserted. PRD §8.4 fixes the order and this module follows it
exactly, because the order *is* the policy: strongest evidence first, and the
weakest evidence — a matching email address — deliberately does not link at all.

**Allocation** hands out an ePPN. The rule is that a released one is never
reissued, and the enforcement is a unique constraint that covers tombstoned rows
rather than a check somebody has to remember. This is the ePPN-reuse
grade-disclosure incident that every institution has either had or narrowly
avoided: a student graduates, their `jsmith@campus.edu` is freed, a new J. Smith
arrives, and the LMS hands them the previous one's coursework because the LMS
keys on ePPN and nothing told it the person changed.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.logging import get_logger
from campusid.policy.normalize import AFFILIATION_VOCABULARY

log = get_logger(__name__)

ID_EPPN: Final = "eppn"
ID_MAIL: Final = "mail"
ID_UNIQUE: Final = "unique_id"

STATUS_ACTIVE: Final = "active"

UNIQUE_ID_BYTES: Final = 16
"""128 bits of opaque `eduPersonUniqueId`. It is released to SPs, so it must
carry no information; it is never reused, so it must not collide."""

MAX_EPPN_SUFFIX: Final = 999
"""How far `jsmith`, `jsmith2`, `jsmith3` … will go before an operator has to
choose a name. A thousand collisions on one local part is a data problem, not a
naming problem, and silently allocating `jsmith1000` would hide it."""


class LinkBasis(StrEnum):
    """How a login was matched to a person. Recorded on the account.

    An investigation asks "how confident were we?", and the honest answer is
    different for each of these. Collapsing them into a boolean would throw away
    the only thing that distinguishes a certain match from a plausible one.
    """

    UNIQUE_ID = "unique_id"
    """Rule 1. `eduPersonUniqueId` is never reassigned, so this is certainty."""

    EXISTING_ACCOUNT = "existing_account"
    """Rule 2. We have seen this exact subject at this exact issuer before."""

    EPPN = "eppn"
    """Rule 3. An ePPN match, on a live tombstone-free identifier belonging to
    an active person. Audited as `account.linked_by_eppn` because it is the one
    automatic link made on a reassignable identifier."""

    CREATED = "created"
    """Rule 5. Nothing matched, so this is somebody new — flagged `jit` for SIS
    reconciliation to find later."""

    MANUAL_REVIEW = "manual_review"
    """Rule 4. A matching email address and nothing else. Deliberately *not* a
    link: see `_mail_only_match`."""


@dataclass(frozen=True, slots=True)
class Assertion:
    """What an IdP or OP just told us about somebody."""

    idp_entity_id: str
    protocol: str
    subject: str
    """The `NameID` or `sub`, meaningful only within `idp_entity_id`."""

    unique_id: str | None = None
    eppn: str | None = None
    mail: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None


@dataclass(frozen=True, slots=True)
class Resolution:
    """Who the assertion turned out to be about."""

    person_uuid: str | None
    basis: LinkBasis

    @property
    def linked(self) -> bool:
        """Whether a session may proceed.

        A manual-review outcome resolves to nobody on purpose: there is a person
        it *might* be, and acting on "might" is the account-takeover this refuses
        to perform.
        """
        return self.person_uuid is not None


class IdentityRegistry:
    """Reads and writes the identity registry."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], *, scope: str) -> None:
        self._sessions = session_factory
        self._scope = scope

    # --- linking ----------------------------------------------------------

    async def resolve(self, assertion: Assertion, *, now: datetime | None = None) -> Resolution:
        """Match an assertion to a person, in §8.4's order.

        The order is the policy. Each rule below is strictly weaker evidence
        than the one above it, and the sequence stops at the first that fires —
        so a person with a matching `eduPersonUniqueId` is never linked on the
        strength of their email address instead.
        """
        now = now or datetime.now(UTC)

        async with self._sessions() as session, session.begin():
            # 1. `eduPersonUniqueId` — never reassigned, so a match is certainty.
            person = await self._by_asserted_unique_id(session, assertion.unique_id)
            if person is not None:
                await self._touch_account(session, person, assertion, LinkBasis.UNIQUE_ID, now)
                return Resolution(str(person.person_uuid), LinkBasis.UNIQUE_ID)

            # 2. A subject we have seen at this issuer before.
            account = await session.scalar(
                select(Account).where(
                    Account.idp_entity_id == assertion.idp_entity_id,
                    Account.subject_at_idp == assertion.subject,
                )
            )
            if account is not None:
                account.last_login_at = now
                return Resolution(str(account.person_uuid), LinkBasis.EXISTING_ACCOUNT)

            # 3. A live ePPN belonging to an active person.
            person = await self._by_live_eppn(session, assertion.eppn)
            if person is not None:
                await self._touch_account(session, person, assertion, LinkBasis.EPPN, now)
                # Audited by name because it is the one automatic link made on a
                # reassignable identifier.
                log.info(
                    "account.linked_by_eppn",
                    idp=assertion.idp_entity_id,
                    person_uuid=str(person.person_uuid),
                )
                return Resolution(str(person.person_uuid), LinkBasis.EPPN)

            # 4. An email address and nothing else. Never links.
            if await self._mail_only_match(session, assertion.mail):
                log.warning(
                    "account.link_needs_review",
                    idp=assertion.idp_entity_id,
                    reason="mail matched an existing person and nothing stronger did",
                )
                return Resolution(None, LinkBasis.MANUAL_REVIEW)

            # 5. Nobody. This is somebody new.
            person = await self._create(session, assertion, now)
            await self._touch_account(session, person, assertion, LinkBasis.CREATED, now)
            return Resolution(str(person.person_uuid), LinkBasis.CREATED)

    async def _by_asserted_unique_id(
        self, session: AsyncSession, unique_id: str | None
    ) -> Person | None:
        """Rule 1, matched against the `identifier` table rather than `person`.

        An IdP's `eduPersonUniqueId` is what *that IdP* calls somebody; our
        `person.edu_person_unique_id` is what *we* call them and is what we
        release. Storing an asserted value in our column would mean releasing a
        partner's identifier as our own, so it lives as an identifier row and
        this rule matches on that — which also lets one person carry the values
        several IdPs know them by, which is the situation a broker exists for.
        """
        if not unique_id:
            return None

        identifier = await session.scalar(
            select(Identifier).where(
                Identifier.id_type == ID_UNIQUE,
                Identifier.value == unique_id,
                Identifier.released_at.is_(None),
            )
        )
        if identifier is None:
            return None
        return await session.get(Person, identifier.person_uuid)

    async def _by_live_eppn(self, session: AsyncSession, eppn: str | None) -> Person | None:
        """Rule 3's three conditions, all required.

        The ePPN must match, must not be tombstoned, and must belong to a person
        who is currently active. Dropping any one of them re-opens the reuse
        incident: a tombstoned ePPN belongs to somebody who left, and a
        suspended person's ePPN is exactly the one an attacker would assert.
        """
        if not eppn:
            return None

        identifier = await session.scalar(
            select(Identifier).where(
                Identifier.id_type == ID_EPPN,
                Identifier.value == eppn.lower(),
                Identifier.released_at.is_(None),
            )
        )
        if identifier is None:
            return None

        person = await session.get(Person, identifier.person_uuid)
        if person is None or person.status != STATUS_ACTIVE:
            return None
        return person

    async def _mail_only_match(self, session: AsyncSession, mail: str | None) -> bool:
        """Whether an email address alone points at somebody.

        Reached only after every stronger rule has failed, and it returns a
        *flag*, never a person. Email-based auto-linking is an account-takeover
        vector — anyone who can receive mail at an address a directory once
        recorded can claim the account behind it — and a broker that does it has
        made every partner IdP's address-verification policy into its own
        authentication policy. This project refuses it deliberately.
        """
        if not mail:
            return False
        found = await session.scalar(
            select(Identifier.id).where(
                Identifier.id_type == ID_MAIL,
                Identifier.value == mail.lower(),
                Identifier.released_at.is_(None),
            )
        )
        return found is not None

    async def _create(self, session: AsyncSession, assertion: Assertion, now: datetime) -> Person:
        """Rule 5: somebody we have never seen."""
        person = Person(
            edu_person_unique_id=new_unique_id(self._scope),
            display_name=assertion.display_name,
            given_name=assertion.given_name,
            surname=assertion.surname,
            provisioning_source="jit",
            created_at=now,
            updated_at=now,
        )
        session.add(person)
        await session.flush()

        if assertion.unique_id:
            # What the asserting IdP calls them, kept alongside what we call
            # them so rule 1 can match this person again next time.
            session.add(
                Identifier(
                    person_uuid=person.person_uuid,
                    id_type=ID_UNIQUE,
                    value=assertion.unique_id,
                    scope=_scope_of(assertion.unique_id),
                    issued_at=now,
                )
            )

        # Everybody gets a principal name, including somebody whose IdP asserted
        # none. A person without one cannot be named in SCIM, where `userName` is
        # required, and cannot be released to an SP that asks for `eduPersonPrincipalName` —
        # so "the IdP sent no ePPN" would become "this person is invisible to
        # half the system". When there is nothing to base one on, it is derived
        # from the `eduPersonUniqueId` we have just minted, which is ours and
        # unique by construction.
        await self._claim_eppn(session, person, assertion.eppn or person.edu_person_unique_id, now)

        if assertion.mail and not await self._identifier_taken(
            session, ID_MAIL, assertion.mail.lower()
        ):
            # An address that belongs to somebody else — including somebody who
            # has left — is simply not recorded. Unlike an ePPN there is no
            # suffixed variant to fall back on: inventing `sam2@campus.test`
            # would be inventing a mailbox that does not exist.
            session.add(
                Identifier(
                    person_uuid=person.person_uuid,
                    id_type=ID_MAIL,
                    value=assertion.mail.lower(),
                    is_primary=True,
                    issued_at=now,
                )
            )

        await session.flush()
        return person

    async def _claim_eppn(
        self, session: AsyncSession, person: Person, asserted: str, now: datetime
    ) -> None:
        """Give a new person an ePPN, never one that is already spoken for.

        This is the reuse incident at the moment it would happen. The asserted
        ePPN reached rule 5, which means rule 3 refused it — it is tombstoned,
        or it belongs to somebody suspended. Either way it is not this person's,
        so they get a suffixed variant instead: the new J. Smith becomes
        `jsmith2@campus.edu` and the graduate's `jsmith@campus.edu` stays theirs
        forever.
        """
        value = asserted.lower()
        scope = _scope_of(value)

        if not await self._identifier_taken(session, ID_EPPN, value):
            session.add(
                Identifier(
                    person_uuid=person.person_uuid,
                    id_type=ID_EPPN,
                    value=value,
                    scope=scope,
                    is_primary=True,
                    issued_at=now,
                )
            )
            return

        local, _, _ = value.rpartition("@")
        for suffix in range(2, MAX_EPPN_SUFFIX + 1):
            candidate = f"{local}{suffix}@{scope}" if scope else f"{local}{suffix}"
            if not await self._identifier_taken(session, ID_EPPN, candidate):
                log.info(
                    "identifier.eppn_suffixed",
                    asserted=value,
                    allocated=candidate,
                    reason="the asserted ePPN belongs to another person",
                )
                session.add(
                    Identifier(
                        person_uuid=person.person_uuid,
                        id_type=ID_EPPN,
                        value=candidate,
                        scope=scope,
                        is_primary=True,
                        issued_at=now,
                    )
                )
                return

        # Deliberately not fatal to the login. The person exists and can
        # authenticate; they simply have no ePPN until an operator resolves a
        # data problem that a thousand collisions represents.
        log.error("identifier.eppn_exhausted", asserted=value)

    async def _identifier_taken(self, session: AsyncSession, id_type: str, value: str) -> bool:
        """Whether any row holds this value — including a tombstoned one.

        Released rows count. That is the whole of FR-LC-08, and asking the
        question this way is what keeps the answer the same as the database's.
        """
        found = await session.scalar(
            select(Identifier.id).where(Identifier.id_type == id_type, Identifier.value == value)
        )
        return found is not None

    async def _touch_account(
        self,
        session: AsyncSession,
        person: Person,
        assertion: Assertion,
        basis: LinkBasis,
        now: datetime,
    ) -> None:
        """Record that this subject at this issuer belongs to this person."""
        session.add(
            Account(
                person_uuid=person.person_uuid,
                idp_entity_id=assertion.idp_entity_id,
                protocol=assertion.protocol,
                subject_at_idp=assertion.subject,
                link_confidence="medium" if basis is LinkBasis.EPPN else "high",
                linked_at=now,
                last_login_at=now,
            )
        )
        await session.flush()

    # --- identifiers ------------------------------------------------------

    async def allocate_eppn(self, person_uuid: str, local_part: str) -> str:
        """Issue an ePPN, never reusing one that has been released.

        Collisions are resolved by suffixing rather than by reusing, and the
        candidate is checked against *every* row including tombstones — which is
        the whole point. `jsmith@campus.edu` released in 2019 is still taken in
        2026, so the next J. Smith becomes `jsmith2@campus.edu` and no LMS keyed
        on ePPN hands them somebody else's coursework.
        """
        base = local_part.strip().lower()
        if not base:
            raise ValueError("an ePPN needs a local part")

        async with self._sessions() as session, session.begin():
            for suffix in range(1, MAX_EPPN_SUFFIX + 1):
                candidate = (
                    f"{base}@{self._scope}" if suffix == 1 else f"{base}{suffix}@{self._scope}"
                )
                taken = await session.scalar(
                    select(Identifier.id).where(
                        Identifier.id_type == ID_EPPN,
                        Identifier.value == candidate,
                    )
                )
                if taken is not None:
                    continue

                session.add(
                    Identifier(
                        person_uuid=person_uuid,
                        id_type=ID_EPPN,
                        value=candidate,
                        scope=self._scope,
                        is_primary=True,
                    )
                )
                return candidate

        raise ValueError(
            f"{base!r} has collided {MAX_EPPN_SUFFIX} times; this is a data problem, not a "
            "naming one, and an operator should choose"
        )

    async def release_identifier(self, person_uuid: str, id_type: str, value: str) -> None:
        """Tombstone an identifier (FR-LC-08).

        The row stays forever. Deleting it would free the value for reissue,
        which is the incident this whole design exists to prevent — so there is
        deliberately no method here that removes one.
        """
        async with self._sessions() as session, session.begin():
            identifier = await session.scalar(
                select(Identifier).where(
                    Identifier.person_uuid == person_uuid,
                    Identifier.id_type == id_type,
                    Identifier.value == value.lower(),
                    Identifier.released_at.is_(None),
                )
            )
            if identifier is not None:
                identifier.released_at = datetime.now(UTC)
                identifier.is_primary = False

    async def identifiers(
        self, person_uuid: str, *, include_released: bool = False
    ) -> list[Identifier]:
        """Everything this person is or was known by."""
        async with self._sessions() as session:
            statement = select(Identifier).where(Identifier.person_uuid == person_uuid)
            if not include_released:
                statement = statement.where(Identifier.released_at.is_(None))
            return list(await session.scalars(statement.order_by(Identifier.issued_at)))

    # --- people -----------------------------------------------------------

    async def get(self, person_uuid: str) -> Person | None:
        async with self._sessions() as session:
            return await session.get(Person, person_uuid)

    async def set_status(self, person_uuid: str, status: str) -> None:
        """Suspend, deactivate or reinstate somebody.

        Never deletes. A person who authenticated has to stay nameable in the
        audit trail for as long as the trail does.
        """
        async with self._sessions() as session, session.begin():
            person = await session.get(Person, person_uuid)
            if person is None:
                raise ValueError(f"no such person: {person_uuid}")
            person.status = status

    async def accounts(self, person_uuid: str) -> list[Account]:
        """Every way this person signs in.

        The answer to FR-RP-03: one person, several accounts, one record.
        """
        async with self._sessions() as session:
            return list(
                await session.scalars(
                    select(Account)
                    .where(Account.person_uuid == person_uuid)
                    .order_by(Account.linked_at)
                )
            )

    # --- affiliations -----------------------------------------------------

    async def add_affiliation(
        self,
        person_uuid: str,
        affiliation: str,
        *,
        valid_from: date | None = None,
        org_unit: str | None = None,
        is_primary: bool = False,
        source: str = "sis",
    ) -> None:
        """Record a relationship starting today, or on a given date."""
        if affiliation not in AFFILIATION_VOCABULARY:
            # The same vocabulary the release engine enforces. A value that
            # could never be released should not be storable either — otherwise
            # the registry accumulates data that silently does nothing.
            raise ValueError(f"{affiliation!r} is outside the eduPerson vocabulary")

        async with self._sessions() as session, session.begin():
            session.add(
                Affiliation(
                    person_uuid=person_uuid,
                    affiliation=affiliation,
                    is_primary=is_primary,
                    org_unit=org_unit,
                    valid_from=valid_from or date.today(),
                    source=source,
                )
            )

    async def end_affiliation(
        self, person_uuid: str, affiliation: str, *, on: date | None = None
    ) -> None:
        """Close an affiliation rather than deleting it.

        "Was this person a student on 2024-03-01?" has to stay answerable, and
        a deleted row answers it wrongly and silently.
        """
        async with self._sessions() as session, session.begin():
            rows = await session.scalars(
                select(Affiliation).where(
                    Affiliation.person_uuid == person_uuid,
                    Affiliation.affiliation == affiliation,
                    Affiliation.valid_until.is_(None),
                )
            )
            for row in rows:
                row.valid_until = on or date.today()

    async def affiliations_on(self, person_uuid: str, when: date) -> list[str]:
        """What this person was, on that date."""
        async with self._sessions() as session:
            rows = await session.scalars(
                select(Affiliation).where(
                    Affiliation.person_uuid == person_uuid,
                    Affiliation.valid_from <= when,
                )
            )
            return sorted(
                {
                    row.affiliation
                    for row in rows
                    if row.valid_until is None or row.valid_until > when
                }
            )


def new_unique_id(scope: str) -> str:
    """A fresh `eduPersonUniqueId`.

    Opaque because it is released: a value derived from a name or a student
    number would disclose exactly what the identifier exists to avoid
    disclosing. Scoped because REFEDS says so, and because two institutions'
    opaque values must not be confusable.
    """
    return f"{secrets.token_hex(UNIQUE_ID_BYTES)}@{scope}"


def _scope_of(eppn: str) -> str | None:
    _, separator, scope = eppn.rpartition("@")
    return scope.lower() if separator else None
