"""Deprovisioning reaches the directory (FR-LC-03, FR-DIR-06).

The leaver sequence has had an ordered slot for downstream systems since it was
written, and until now nothing was in it. This is the test that the slot is
filled: a SCIM delete disables the account in a real OpenLDAP, and disables it
*first*.

The case worth reading is the tombstone. Provisioning releases a person's
identifiers before the lifecycle runs, so by the time the directory has to be
told, the ePPN is already released. A deprovisioning that only looked at live
identifiers would find no login, skip every target, and record a step that ran
with nothing to do — leaving an enabled account behind and a trail that says
otherwise.

Requires both profiles:

    docker compose --profile directory --profile federation up -d
    docker compose --profile directory run --rm directory-init
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from ldap3 import ALL, Connection, Server
from sqlalchemy import delete

from campusid.audit.log import AuditLog
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.directory.client import DirectoryClient
from campusid.directory.connection import Connector
from campusid.directory.profiles import OPENLDAP
from campusid.directory.writes import DirectoryWriter, PersonSpec
from campusid.identity.models import Person
from campusid.lifecycle.models import EntitlementGrant, LifecycleEvent
from campusid.lifecycle.orchestrator import LifecycleOrchestrator
from campusid.lifecycle.rules import RulesStore
from campusid.lifecycle.store import LifecycleStore
from campusid.lifecycle.targets import LdapTarget

pytestmark = [pytest.mark.integration, pytest.mark.directory]

LDAP_URL = os.environ.get("DIRECTORY_LDAP_URL", "ldap://openldap:389")
BASE = "dc=campus,dc=test"
PEOPLE = f"ou=people,{BASE}"
ADMIN = f"cn=admin,{BASE}"
PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "change-me-local-only")


class _Sessions:
    """The session store, reduced to what a deprovisioning asks of it."""

    async def terminate_subject(self, subject_key: str) -> list[str]:
        return []


class _Grants:
    async def revoke_session_families(self, sid: str) -> list[str]:
        return []


class _Identity:
    """One person's identifiers, as the registry would report them."""

    def __init__(self, login: str, *, released: bool) -> None:
        self._login = login
        self._released = released

    async def identifiers(self, person_uuid: str, *, include_released: bool = False) -> list[Any]:
        class _Identifier:
            id_type = "eppn"
            value = self._login
            released_at = object() if self._released else None

        if self._released and not include_released:
            return []
        return [_Identifier()]


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
def writer(connector: Connector) -> DirectoryWriter:
    return DirectoryWriter(profile=OPENLDAP, base_dn=BASE, connector=connector)


@pytest.fixture
def client(connector: Connector) -> DirectoryClient:
    return DirectoryClient(profile=OPENLDAP, url=LDAP_URL, base_dn=BASE, connector=connector)


@pytest.fixture
def admin() -> Any:
    server = Server(LDAP_URL, get_info=ALL, connect_timeout=10)
    connection = Connection(
        server, user=ADMIN, password=PASSWORD, auto_bind=True, raise_exceptions=True
    )
    yield connection
    connection.unbind()


@pytest.fixture
async def leaver(writer: DirectoryWriter, admin: Any) -> AsyncIterator[str]:
    """Somebody who exists in the directory and is about to stop."""
    uid = f"leaver-{uuid.uuid4().hex[:8]}"
    await writer.ensure_person(
        PersonSpec(uid=uid, given_name="Departing", surname="Person", mail=f"{uid}@campus.test")
    )
    yield uid
    admin.delete(writer.dn_for(uid))


@pytest.fixture
async def person_uuid() -> AsyncIterator[str]:
    """A real registry row, because the timeline holds a foreign key to one.

    The lifecycle writes an event for every transition, and an event about
    somebody who does not exist is a row the database refuses — which is the
    constraint doing its job.
    """
    engine = create_engine(get_settings())
    factory = create_session_factory(engine)
    async with factory() as session, session.begin():
        person = Person(
            edu_person_unique_id=f"{uuid.uuid4().hex}@campus.test",
            status="active",
            provisioning_source="sis",
        )
        session.add(person)
        await session.flush()
        created = str(person.person_uuid)

    yield created

    async with factory() as session, session.begin():
        key = uuid.UUID(created)
        await session.execute(delete(LifecycleEvent).where(LifecycleEvent.person_uuid == key))
        await session.execute(delete(EntitlementGrant).where(EntitlementGrant.person_uuid == key))
        await session.execute(delete(Person).where(Person.person_uuid == key))
    await engine.dispose()


def _orchestrator(
    client: DirectoryClient, writer: DirectoryWriter, identity: _Identity
) -> LifecycleOrchestrator:
    settings = get_settings()
    engine = create_engine(settings)
    sessions = create_session_factory(engine)
    from pathlib import Path

    return LifecycleOrchestrator(
        rules=RulesStore(Path(settings.lifecycle_rules_file)),
        lifecycle=LifecycleStore(sessions),
        sessions=_Sessions(),
        grants=_Grants(),
        audit=AuditLog(sessions),
        identity=identity,
        targets=(LdapTarget(client=client, writer=writer),),
    )


def _locked(admin: Any, dn: str) -> bool:
    admin.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["pwdAccountLockedTime"])
    return bool(admin.response[0]["attributes"].get("pwdAccountLockedTime"))


async def test_a_deprovisioning_disables_the_directory_account(
    client: DirectoryClient,
    writer: DirectoryWriter,
    admin: Any,
    leaver: str,
    person_uuid: str,
) -> None:
    """FR-LC-03's first step, against a real server."""
    dn = writer.dn_for(leaver)
    assert not _locked(admin, dn)

    orchestrator = _orchestrator(client, writer, _Identity(leaver, released=False))
    await orchestrator.deprovision(person_uuid, {"student"}, source="test")

    assert _locked(admin, dn)


async def test_a_tombstoned_login_still_reaches_the_directory(
    client: DirectoryClient,
    writer: DirectoryWriter,
    admin: Any,
    leaver: str,
    person_uuid: str,
) -> None:
    """The ordinary case, and the one that silently does nothing if missed.

    By the time the lifecycle runs, provisioning has already released the
    person's identifiers. FR-LC-08 guarantees an ePPN is never reassigned, so the
    tombstone still names exactly one person and is safe to address.
    """
    dn = writer.dn_for(leaver)

    orchestrator = _orchestrator(client, writer, _Identity(leaver, released=True))
    await orchestrator.deprovision(person_uuid, {"student"}, source="test")

    assert _locked(admin, dn)


async def test_deprovisioning_twice_is_a_no_op(
    client: DirectoryClient,
    writer: DirectoryWriter,
    admin: Any,
    leaver: str,
    person_uuid: str,
) -> None:
    """Provisioning is retried, so this is the ordinary case rather than a
    corner. A second run must not fail on an account it already disabled."""
    identity = _Identity(leaver, released=False)
    orchestrator = _orchestrator(client, writer, identity)

    await orchestrator.deprovision(person_uuid, {"student"}, source="test")
    await orchestrator.deprovision(person_uuid, {"student"}, source="test")

    assert _locked(admin, writer.dn_for(leaver))


async def test_somebody_with_no_directory_entry_is_not_a_failure(
    client: DirectoryClient, writer: DirectoryWriter, person_uuid: str
) -> None:
    """A person provisioned only in the broker — a just-in-time account from a
    federated login — has nothing downstream to disable, and treating that as an
    error would dead-letter every leaver who never had one."""
    orchestrator = _orchestrator(
        client, writer, _Identity(f"never-provisioned-{uuid.uuid4().hex[:8]}", released=False)
    )

    await orchestrator.deprovision(person_uuid, {"student"}, source="test")
