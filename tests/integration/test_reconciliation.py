"""Finding and closing drift (FR-LC-07).

The test the requirement asks for is an out-of-band change: mutate the directory
behind the broker's back, then prove the job notices and can put it right.

Against live Postgres and a live OpenLDAP, because drift is a disagreement
between two real systems and a test with both ends mocked would only be proving
that two fakes were written to match.

The behaviour worth reading is that a dry run changes nothing. A reconciliation
that fixes things by default is one nobody dares schedule, and the report is the
product — the fixing is what an operator does once they have read it and agree.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from ldap3 import ALL, MODIFY_REPLACE, Connection, Server
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.directory.client import DirectoryClient
from campusid.directory.connection import LOCKED_FOREVER, Connector
from campusid.directory.profiles import OPENLDAP
from campusid.directory.writes import DirectoryWriter, PersonSpec
from campusid.identity.models import Identifier, Person
from campusid.lifecycle.reconciliation import DriftKind, Reconciler
from campusid.lifecycle.targets import LdapTarget

pytestmark = [pytest.mark.integration, pytest.mark.directory]

LDAP_URL = os.environ.get("DIRECTORY_LDAP_URL", "ldap://openldap:389")
BASE = "dc=campus,dc=test"
PEOPLE = f"ou=people,{BASE}"
ADMIN = f"cn=admin,{BASE}"
PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "change-me-local-only")


@pytest.fixture
def connector() -> Connector:
    return Connector(
        url=LDAP_URL,
        bind_dn=ADMIN,
        bind_password=PASSWORD,
        start_tls=False,
        allow_plaintext=True,
    )


@pytest.fixture
def client(connector: Connector) -> DirectoryClient:
    return DirectoryClient(profile=OPENLDAP, url=LDAP_URL, base_dn=BASE, connector=connector)


@pytest.fixture
def writer(connector: Connector) -> DirectoryWriter:
    return DirectoryWriter(profile=OPENLDAP, base_dn=BASE, connector=connector)


@pytest.fixture
def admin() -> Any:
    server = Server(LDAP_URL, get_info=ALL, connect_timeout=10)
    connection = Connection(
        server, user=ADMIN, password=PASSWORD, auto_bind=True, raise_exceptions=True
    )
    yield connection
    connection.unbind()


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(engine)


@pytest.fixture
def reconciler(
    sessions: async_sessionmaker[AsyncSession],
    client: DirectoryClient,
    writer: DirectoryWriter,
) -> Reconciler:
    return Reconciler(sessions, client=client, target=LdapTarget(client=client, writer=writer))


class _Fixture:
    """One person, in both systems, with a knob for each side's opinion."""

    def __init__(self, uid: str, person_uuid: str) -> None:
        self.uid = uid
        self.person_uuid = person_uuid


@pytest.fixture
async def provisioned(
    sessions: async_sessionmaker[AsyncSession], writer: DirectoryWriter, admin: Any
) -> AsyncIterator[_Fixture]:
    """Somebody the broker and the directory both know about and agree on."""
    uid = f"recon-{uuid.uuid4().hex[:8]}"
    login = f"{uid}@campus.test"

    async with sessions() as session, session.begin():
        person = Person(
            edu_person_unique_id=f"{uuid.uuid4().hex}@campus.test",
            status="active",
            provisioning_source="sis",
        )
        session.add(person)
        await session.flush()
        session.add(
            Identifier(
                person_uuid=person.person_uuid,
                id_type="eppn",
                value=login,
                scope="campus.test",
                is_primary=True,
            )
        )
        created = str(person.person_uuid)

    # The principal name goes into the entry, because that is what the broker
    # knows them by and what the profile searches on. An entry without it is
    # findable only by `uid`, which is the short name rather than the login.
    await writer.ensure_person(
        PersonSpec(
            uid=uid,
            given_name="Recon",
            surname="Subject",
            mail=f"{uid}@campus.test",
            principal_name=login,
        )
    )

    yield _Fixture(uid=uid, person_uuid=created)

    admin.delete(writer.dn_for(uid))
    async with sessions() as session, session.begin():
        key = uuid.UUID(created)
        await session.execute(delete(Identifier).where(Identifier.person_uuid == key))
        await session.execute(delete(Person).where(Person.person_uuid == key))


async def _deactivate(sessions: async_sessionmaker[AsyncSession], person_uuid: str) -> None:
    async with sessions() as session, session.begin():
        person = await session.get(Person, uuid.UUID(person_uuid))
        assert person is not None
        person.status = "deactivated"


def _locked(admin: Any, dn: str) -> bool:
    admin.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["pwdAccountLockedTime"])
    return bool(admin.response[0]["attributes"].get("pwdAccountLockedTime"))


def _drifts_for(report: Any, person_uuid: str) -> list[Any]:
    return [drift for drift in report.drifts if drift.person_uuid == person_uuid]


# --- agreement --------------------------------------------------------------


async def test_two_systems_that_agree_produce_no_drift(
    reconciler: Reconciler, provisioned: _Fixture
) -> None:
    report = await reconciler.run()

    assert _drifts_for(report, provisioned.person_uuid) == []
    assert report.scanned > 0


# --- the case the requirement names -----------------------------------------


async def test_an_account_re_enabled_out_of_band_is_drift(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
) -> None:
    """The security finding. The broker says this person has left; the directory
    still lets them in, because somebody re-enabled the account by hand or a
    restore undid the write."""
    await _deactivate(sessions, provisioned.person_uuid)

    report = await reconciler.run()

    drift = _drifts_for(report, provisioned.person_uuid)[0]
    assert drift.kind is DriftKind.SHOULD_BE_DISABLED
    assert drift.remediable


async def test_a_dry_run_changes_nothing(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
    writer: DirectoryWriter,
    admin: Any,
) -> None:
    """A reconciliation that fixes things by default is one nobody dares
    schedule."""
    await _deactivate(sessions, provisioned.person_uuid)

    report = await reconciler.run()

    assert not report.applied
    assert report.remediated == ()
    assert not _locked(admin, writer.dn_for(provisioned.uid))


async def test_apply_closes_the_drift(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
    writer: DirectoryWriter,
    admin: Any,
) -> None:
    """And closes it with the ordinary disable, so it inherits the idempotency
    and the retries rather than being a second provisioning path."""
    await _deactivate(sessions, provisioned.person_uuid)

    report = await reconciler.run(apply=True)

    assert report.applied
    assert len(report.remediated) >= 1
    assert _locked(admin, writer.dn_for(provisioned.uid))


async def test_a_second_run_finds_nothing_left(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
) -> None:
    """Remediation that did not actually remediate is the failure this catches:
    a job that reports the same drift every night looks like it is working."""
    await _deactivate(sessions, provisioned.person_uuid)
    await reconciler.run(apply=True)

    report = await reconciler.run()

    assert _drifts_for(report, provisioned.person_uuid) == []


# --- the kinds it will not fix ----------------------------------------------


async def test_a_person_with_no_directory_account_is_reported_not_created(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
    writer: DirectoryWriter,
    admin: Any,
) -> None:
    """Usually somebody created just-in-time by a federated login. Creating an
    account is a decision with a password policy attached, so it is reported
    rather than done."""
    admin.delete(writer.dn_for(provisioned.uid))

    report = await reconciler.run(apply=True)

    drift = _drifts_for(report, provisioned.person_uuid)[0]
    assert drift.kind is DriftKind.MISSING_DOWNSTREAM
    assert not drift.remediable
    assert drift not in report.remediated

    # Put it back so the fixture's own teardown has something to delete.
    await writer.ensure_person(
        PersonSpec(
            uid=provisioned.uid,
            given_name="Recon",
            surname="Subject",
            principal_name=f"{provisioned.uid}@campus.test",
        )
    )


async def test_a_deactivated_person_already_locked_is_not_drift(
    reconciler: Reconciler,
    sessions: async_sessionmaker[AsyncSession],
    provisioned: _Fixture,
    writer: DirectoryWriter,
    admin: Any,
) -> None:
    """The two ends agree that this person is gone, which is the state a
    successful deprovisioning leaves behind."""
    await _deactivate(sessions, provisioned.person_uuid)
    admin.modify(
        writer.dn_for(provisioned.uid),
        {"pwdAccountLockedTime": [(MODIFY_REPLACE, [LOCKED_FOREVER])]},
    )

    report = await reconciler.run()

    assert _drifts_for(report, provisioned.person_uuid) == []


async def test_an_active_person_who_is_enabled_is_not_drift(
    reconciler: Reconciler, provisioned: _Fixture
) -> None:
    """The ordinary case, asserted so a job that flagged everybody would fail
    here rather than in somebody's inbox."""
    report = await reconciler.run()

    assert _drifts_for(report, provisioned.person_uuid) == []
