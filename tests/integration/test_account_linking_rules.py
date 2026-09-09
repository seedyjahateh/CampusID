"""Resolving a login to a person (§8.4, FR-RP-03).

Nine cases, and the order between them is the policy. Each rule is strictly
weaker evidence than the one above, the sequence stops at the first that fires,
and the weakest evidence of all — a matching email address — deliberately does
not link at all.

Integration rather than unit because the behaviour under test *is* the
persistence: the unique constraints, the tombstones, and the transaction that
creates a person and their identifiers together.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.identity.registry import (
    Assertion,
    IdentityRegistry,
    LinkBasis,
    new_unique_id,
)

pytestmark = pytest.mark.integration

SCOPE = "campus.test"
CAMPUS_IDP = "https://idp.campus.test/saml"
PARTNER_OP = "https://partner.test"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Remove only the people this test created.

    Snapshot-and-delete, and in dependency order: accounts and identifiers point
    at people, so the children go first or the foreign keys refuse.
    """
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(Person.person_uuid)))

    yield factory

    async with factory() as session, session.begin():
        keep = pre_existing or {uuid.UUID(int=0)}
        for table in (Account, Identifier, Affiliation):
            await session.execute(delete(table).where(table.person_uuid.not_in(keep)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep)))


@pytest.fixture
def registry(sessions: async_sessionmaker[AsyncSession]) -> IdentityRegistry:
    return IdentityRegistry(sessions, scope=SCOPE)


async def _existing_person(
    sessions: async_sessionmaker[AsyncSession],
    *,
    eppn: str | None = None,
    mail: str | None = None,
    unique_id: str | None = None,
    status: str = "active",
    eppn_released: bool = False,
) -> str:
    """Seed a person directly, so a test can set up a state the registry would
    not produce on its own — a tombstoned ePPN, a suspended account."""
    async with sessions() as session, session.begin():
        person = Person(
            edu_person_unique_id=unique_id or new_unique_id(SCOPE),
            display_name="Seeded Person",
            status=status,
            provisioning_source="sis",
        )
        session.add(person)
        await session.flush()

        if eppn:
            session.add(
                Identifier(
                    person_uuid=person.person_uuid,
                    id_type="eppn",
                    value=eppn.lower(),
                    scope=SCOPE,
                    is_primary=not eppn_released,
                    released_at=datetime.now(UTC) if eppn_released else None,
                )
            )
        if mail:
            session.add(
                Identifier(
                    person_uuid=person.person_uuid,
                    id_type="mail",
                    value=mail.lower(),
                    is_primary=True,
                )
            )
        await session.flush()
        return str(person.person_uuid)


# --- rule 1: eduPersonUniqueId ---------------------------------------------


async def test_a_unique_id_match_links_with_certainty(registry: IdentityRegistry) -> None:
    """Never reassigned, so a match is not evidence — it is identity.

    Matched against the `identifier` table rather than `person.edu_person_
    unique_id`: an IdP's value is what *that IdP* calls somebody, while our
    column is what we call them and is what we release. Keeping them apart is
    what lets one person carry the values several IdPs know them by.
    """
    asserted = f"idp-side-{new_unique_id(SCOPE)}"
    first = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "name-id-1", unique_id=asserted))

    second = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "different-sub", unique_id=asserted)
    )

    assert second.person_uuid == first.person_uuid
    assert second.basis is LinkBasis.UNIQUE_ID


async def test_an_asserted_unique_id_is_not_released_as_our_own(
    registry: IdentityRegistry,
) -> None:
    """Storing a partner's identifier in our column would mean releasing their
    value as ours."""
    asserted = f"partner-side-{new_unique_id(SCOPE)}"

    resolved = await registry.resolve(Assertion(PARTNER_OP, "oidc", "sub", unique_id=asserted))

    person = await registry.get(resolved.person_uuid or "")
    assert person is not None
    assert person.edu_person_unique_id != asserted


async def test_a_unique_id_match_beats_a_conflicting_eppn(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The order is the policy. Stronger evidence wins outright rather than
    being weighed against weaker evidence pointing elsewhere."""
    asserted = f"idp-side-{new_unique_id(SCOPE)}"
    right = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "sub-1", unique_id=asserted))
    wrong = await _existing_person(sessions, eppn=f"someone.else@{SCOPE}")

    resolved = await registry.resolve(
        Assertion(
            PARTNER_OP,
            "oidc",
            "sub-2",
            unique_id=asserted,
            eppn=f"someone.else@{SCOPE}",
        )
    )

    assert resolved.person_uuid == right.person_uuid
    assert resolved.person_uuid != wrong


# --- rule 2: an account we have seen before --------------------------------


async def test_a_returning_subject_links_to_its_account(registry: IdentityRegistry) -> None:
    first = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "stable-name-id", eppn=f"sam@{SCOPE}")
    )

    second = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "stable-name-id"))

    assert second.person_uuid == first.person_uuid
    assert second.basis is LinkBasis.EXISTING_ACCOUNT


async def test_the_same_subject_at_a_different_issuer_is_a_different_account(
    registry: IdentityRegistry,
) -> None:
    """A `NameID` is meaningful only within the IdP that minted it. Matching on
    the subject alone would merge two people who happen to share one."""
    await registry.resolve(Assertion(CAMPUS_IDP, "saml", "shared-subject"))

    other = await registry.resolve(Assertion(PARTNER_OP, "oidc", "shared-subject"))

    assert other.basis is LinkBasis.CREATED


# --- rule 3: a live ePPN ---------------------------------------------------


async def test_a_live_eppn_links_and_is_audited(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The one automatic link made on a reassignable identifier, which is why it
    is recorded at medium confidence rather than high."""
    person_uuid = await _existing_person(sessions, eppn=f"sam.obrien@{SCOPE}")

    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "partner-sub", eppn=f"sam.obrien@{SCOPE}")
    )

    assert resolved.person_uuid == person_uuid
    assert resolved.basis is LinkBasis.EPPN
    accounts = await registry.accounts(person_uuid)
    assert accounts[0].link_confidence == "medium"


async def test_a_tombstoned_eppn_does_not_link(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The incident this design exists to prevent. A released ePPN belongs to
    somebody who has left; matching on it would hand their record to whoever
    asserts the name next."""
    departed = await _existing_person(sessions, eppn=f"jsmith@{SCOPE}", eppn_released=True)

    resolved = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "new-arrival", eppn=f"jsmith@{SCOPE}")
    )

    assert resolved.person_uuid != departed
    assert resolved.basis is LinkBasis.CREATED


async def test_a_suspended_persons_eppn_does_not_link(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Exactly the ePPN an attacker would assert: one belonging to somebody
    whose access has already been taken away."""
    suspended = await _existing_person(sessions, eppn=f"suspended@{SCOPE}", status="suspended")

    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "sub", eppn=f"suspended@{SCOPE}")
    )

    assert resolved.person_uuid != suspended


# --- rule 4: mail never auto-links -----------------------------------------


async def test_a_mail_match_alone_never_links(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Anyone who can receive mail at an address a directory once recorded could
    otherwise claim the account behind it — and a broker that auto-links on mail
    has adopted every partner IdP's address-verification policy as its own."""
    person_uuid = await _existing_person(sessions, mail=f"sam.obrien@{SCOPE}")

    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "attacker-sub", mail=f"sam.obrien@{SCOPE}")
    )

    assert resolved.person_uuid is None
    assert resolved.basis is LinkBasis.MANUAL_REVIEW
    assert not resolved.linked
    assert await registry.accounts(person_uuid) == []


async def test_a_mail_collision_between_two_people_creates_no_link(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Two distinct people, one address — a real situation at any institution
    that has ever merged a department. Guessing which is worse than refusing."""
    await _existing_person(sessions, mail=f"shared@{SCOPE}", eppn=f"first@{SCOPE}")

    resolved = await registry.resolve(Assertion(PARTNER_OP, "oidc", "sub", mail=f"shared@{SCOPE}"))

    assert not resolved.linked


async def test_mail_does_not_block_a_stronger_match(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The mail rule refuses to *link*; it must not refuse a login that a
    stronger rule already resolved."""
    person_uuid = await _existing_person(sessions, eppn=f"sam@{SCOPE}", mail=f"sam@{SCOPE}")

    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "sub", eppn=f"sam@{SCOPE}", mail=f"sam@{SCOPE}")
    )

    assert resolved.person_uuid == person_uuid
    assert resolved.basis is LinkBasis.EPPN


# --- rule 5: somebody new --------------------------------------------------


async def test_an_unknown_person_is_created_and_flagged(registry: IdentityRegistry) -> None:
    """Flagged `jit` so SIS reconciliation can find and merge the record later,
    rather than leaving a second person nobody knows is a duplicate."""
    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "brand-new", eppn=f"newcomer@{SCOPE}")
    )

    person = await registry.get(resolved.person_uuid or "")

    assert resolved.basis is LinkBasis.CREATED
    assert person is not None
    assert person.provisioning_source == "jit"


async def test_a_new_person_asserting_a_tombstoned_eppn_gets_a_suffixed_one(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The reuse incident at the exact moment it would happen.

    Rule 3 refused the ePPN because it is tombstoned, so rule 5 must not then
    claim it for the new person. They get `jsmith2@campus.test`; the graduate's
    `jsmith@campus.test` stays theirs forever.
    """
    await _existing_person(sessions, eppn=f"jsmith@{SCOPE}", eppn_released=True)

    resolved = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "new-arrival", eppn=f"jsmith@{SCOPE}")
    )

    identifiers = await registry.identifiers(resolved.person_uuid or "")
    assert [i.value for i in identifiers if i.id_type == "eppn"] == [f"jsmith2@{SCOPE}"]


async def test_a_new_person_asserting_a_suspended_persons_eppn_gets_a_suffixed_one(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A live ePPN belonging to somebody suspended is still not free."""
    await _existing_person(sessions, eppn=f"suspended@{SCOPE}", status="suspended")

    resolved = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "sub", eppn=f"suspended@{SCOPE}")
    )

    identifiers = await registry.identifiers(resolved.person_uuid or "")
    assert [i.value for i in identifiers if i.id_type == "eppn"] == [f"suspended2@{SCOPE}"]


async def test_a_tombstoned_mail_is_not_recorded_rather_than_suffixed(
    registry: IdentityRegistry, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Unlike an ePPN there is no suffixed variant to fall back on: inventing
    `sam2@campus.test` would be inventing a mailbox that does not exist.

    The collision has to be with a *released* address to reach this path at all.
    A live one is caught by rule 4 first, which returns manual review rather
    than creating anybody — the first version of this test assumed otherwise and
    was asserting against a scenario the resolver cannot produce.
    """
    departed = await _existing_person(sessions, mail=f"shared@{SCOPE}")
    await registry.release_identifier(departed, "mail", f"shared@{SCOPE}")

    resolved = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "sub", eppn=f"newcomer@{SCOPE}", mail=f"shared@{SCOPE}")
    )

    assert resolved.basis is LinkBasis.CREATED
    identifiers = await registry.identifiers(resolved.person_uuid or "")
    assert [i.value for i in identifiers if i.id_type == "mail"] == []
    assert [i.value for i in identifiers if i.id_type == "eppn"] == [f"newcomer@{SCOPE}"]


async def test_a_new_person_gets_an_opaque_unique_id(registry: IdentityRegistry) -> None:
    """Released to SPs, so it must carry no information: a value derived from a
    name or a student number would disclose what the identifier exists to
    avoid disclosing."""
    resolved = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "sub", eppn=f"sam.obrien@{SCOPE}")
    )

    person = await registry.get(resolved.person_uuid or "")

    assert person is not None
    assert person.edu_person_unique_id.endswith(f"@{SCOPE}")
    assert "sam" not in person.edu_person_unique_id


# --- FR-RP-03: one person, two protocols -----------------------------------


async def test_a_saml_login_then_an_oidc_login_is_one_person(
    registry: IdentityRegistry,
) -> None:
    """FR-RP-03, as the requirement states it: one `person_uuid`, two `account`
    rows. This is the whole point of a broker — the same human being arriving
    over two protocols is one record, not two."""
    over_saml = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "campus-name-id", eppn=f"sam.obrien@{SCOPE}")
    )

    over_oidc = await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "partner-sub", eppn=f"sam.obrien@{SCOPE}")
    )

    assert over_oidc.person_uuid == over_saml.person_uuid
    accounts = await registry.accounts(over_saml.person_uuid or "")
    assert len(accounts) == 2
    assert {account.protocol for account in accounts} == {"saml", "oidc"}


async def test_the_link_records_how_it_was_made(registry: IdentityRegistry) -> None:
    """A link made on an ePPN match is a weaker claim than one made on a
    never-reassigned identifier, and an investigation needs to know which."""
    asserted = f"idp-side-{new_unique_id(SCOPE)}"
    first = await registry.resolve(
        Assertion(CAMPUS_IDP, "saml", "sub-1", unique_id=asserted, eppn=f"sam@{SCOPE}")
    )
    await registry.resolve(
        Assertion(PARTNER_OP, "oidc", "sub-2", unique_id=asserted, eppn=f"sam@{SCOPE}")
    )

    confidences = {a.link_confidence for a in await registry.accounts(first.person_uuid or "")}

    assert confidences == {"high"}


# --- affiliations are temporal ---------------------------------------------


async def test_an_affiliation_can_be_asked_about_a_past_date(
    registry: IdentityRegistry,
) -> None:
    """§8.1's third principle: "was this person a student on 2024-03-01?" is a
    query, not an archaeology exercise."""
    resolved = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "sub"))
    person_uuid = resolved.person_uuid or ""
    await registry.add_affiliation(
        person_uuid, "student", valid_from=date(2022, 9, 1), is_primary=True
    )
    await registry.end_affiliation(person_uuid, "student", on=date(2026, 6, 30))
    await registry.add_affiliation(person_uuid, "alum", valid_from=date(2026, 7, 1))

    assert await registry.affiliations_on(person_uuid, date(2024, 3, 1)) == ["student"]
    assert await registry.affiliations_on(person_uuid, date(2026, 12, 1)) == ["alum"]


async def test_an_ended_affiliation_is_closed_not_deleted(
    registry: IdentityRegistry,
) -> None:
    """A deleted row answers "was this person a student?" wrongly and
    silently."""
    resolved = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "sub"))
    person_uuid = resolved.person_uuid or ""
    await registry.add_affiliation(person_uuid, "student", valid_from=date(2022, 9, 1))

    await registry.end_affiliation(person_uuid, "student", on=date(2026, 6, 30))

    assert await registry.affiliations_on(person_uuid, date(2023, 1, 1)) == ["student"]
    assert await registry.affiliations_on(person_uuid, date(2027, 1, 1)) == []


async def test_an_affiliation_outside_the_vocabulary_is_refused(
    registry: IdentityRegistry,
) -> None:
    """The same vocabulary the release engine enforces. A value that could never
    be released should not be storable either, or the registry accumulates data
    that silently does nothing."""
    resolved = await registry.resolve(Assertion(CAMPUS_IDP, "saml", "sub"))

    with pytest.raises(ValueError, match="vocabulary"):
        await registry.add_affiliation(resolved.person_uuid or "", "adjunct-faculty")
