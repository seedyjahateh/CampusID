"""Against a real OpenLDAP (FR-DIR-03, 04, 05, 06, 07).

The unit tests inject a connection and prove the logic around a search. This
runs the searches. It is the test that catches the difference between "our
client agrees with our fake" and "our client talks to a directory": filter
syntax the server actually parses, a paged control it actually honours, and DNs
in whatever form it actually returns them.

Requires the directory profile:

    docker compose --profile directory up -d
    docker compose --profile directory run --rm directory-init
    docker compose run --rm tests tests/integration -m directory
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from ldap3 import ALL, Connection, Server

from campusid.directory.client import DirectoryClient, DirectoryUnavailable
from campusid.directory.connection import Connector
from campusid.directory.profiles import OPENLDAP
from campusid.directory.writes import DirectoryWriter, PersonSpec

pytestmark = [pytest.mark.integration, pytest.mark.directory]

LDAP_URL = os.environ.get("DIRECTORY_LDAP_URL", "ldap://openldap:389")
BASE = "dc=campus,dc=test"
PEOPLE = f"ou=people,{BASE}"
GROUPS = f"ou=groups,{BASE}"
ADMIN = f"cn=admin,{BASE}"
PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "change-me-local-only")

SAM = f"uid=sam.obrien,{PEOPLE}"
LMS_STUDENTS = f"cn=lms-students,{GROUPS}"
ALL_STUDENTS = f"cn=all-students,{GROUPS}"
CAMPUS_MEMBERS = f"cn=campus-members,{GROUPS}"


@pytest.fixture
def client() -> DirectoryClient:
    return DirectoryClient(
        profile=OPENLDAP,
        url=LDAP_URL,
        base_dn=BASE,
        bind_dn=ADMIN,
        bind_password=PASSWORD,
        start_tls=False,
        allow_plaintext=True,
    )


@pytest.fixture
def admin() -> Any:
    """A raw connection, for the tests that need to change the tree."""
    server = Server(LDAP_URL, get_info=ALL, connect_timeout=10)
    connection = Connection(
        server, user=ADMIN, password=PASSWORD, auto_bind=True, raise_exceptions=True
    )
    yield connection
    connection.unbind()


@pytest.fixture
async def many_people(admin: Any) -> AsyncIterator[int]:
    """Enough entries that a single page cannot hold them (FR-DIR-05).

    Six hundred against a page size of five hundred, so the second page is small
    and a client that silently kept only the first would be visibly short rather
    than plausibly complete.
    """
    count = 600
    marker = uuid.uuid4().hex[:8]
    created = []
    for index in range(count):
        dn = f"uid=paged-{marker}-{index},{PEOPLE}"
        admin.add(
            dn,
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {"uid": f"paged-{marker}-{index}", "cn": f"Paged {index}", "sn": "Test"},
        )
        created.append(dn)

    yield count

    for dn in created:
        admin.delete(dn)


# --- finding a person -------------------------------------------------------


async def test_a_person_is_found_by_their_login(client: DirectoryClient) -> None:
    user = await client.find_user("sam.obrien")

    assert user is not None
    assert user.dn.lower() == SAM.lower()
    assert user.mail == "sam.obrien@campus.test"
    assert user.display_name == "Samira O'Brien"


async def test_the_immutable_id_is_the_one_the_server_assigns(
    client: DirectoryClient,
) -> None:
    """`entryUUID` is operational: the server maintains it and it survives a
    rename, which is exactly why the profile names it rather than `uid`."""
    user = await client.find_user("sam.obrien")

    assert user is not None
    assert user.immutable_id
    assert user.immutable_id != user.login
    uuid.UUID(user.immutable_id)


async def test_somebody_who_is_not_there_is_not_an_error(client: DirectoryClient) -> None:
    assert await client.find_user("nobody.here") is None


# --- injection, against a server that actually parses -----------------------


@pytest.mark.parametrize(
    "payload",
    ["*", "*)(uid=*", "sam.obrien)(objectClass=*", "\\", "sam.obrien\x00"],
)
async def test_an_injection_payload_matches_nobody(client: DirectoryClient, payload: str) -> None:
    """The unit tests prove the escaped string has no filter syntax in it. This
    proves the server agrees — an escaping scheme that produced something the
    server parsed differently would pass those and fail here."""
    assert await client.find_user(payload) is None


async def test_a_wildcard_does_not_match_everybody(client: DirectoryClient) -> None:
    """The failure this whole requirement exists to prevent. Unescaped, `*`
    matches every person in the tree, and a bind-then-search login would then
    authenticate against whichever entry came back first."""
    assert await client.find_user("*") is None


# --- membership -------------------------------------------------------------


async def test_nested_membership_is_resolved(client: DirectoryClient) -> None:
    """Three levels: the student is directly in `lms-students`, and the access
    is granted on `campus-members`. A broker reading only direct membership
    finds nothing here."""
    user = await client.find_user("sam.obrien")
    assert user is not None

    result = await client.groups_for(user)

    lowered = {group.lower() for group in result.groups}
    assert LMS_STUDENTS.lower() in lowered
    assert ALL_STUDENTS.lower() in lowered
    assert CAMPUS_MEMBERS.lower() in lowered


async def test_direct_membership_is_distinguishable(client: DirectoryClient) -> None:
    user = await client.find_user("sam.obrien")
    assert user is not None

    result = await client.groups_for(user)

    lowered = {group.lower() for group in result.direct}
    assert lowered == {LMS_STUDENTS.lower()}


async def test_the_reverse_search_is_what_answers_here(client: DirectoryClient) -> None:
    """The fixture's entries carry no `memberOf`, so this exercises the fallback.

    Which is the point of having it. `memberOf` is maintained by an overlay, and
    whether a given deployment has it configured — and whether it was configured
    before the groups were created — is not something the broker gets to assume.
    A client that only read the attribute would work against one campus
    directory and find nobody in anything at the next.
    """
    user = await client.find_user("sam.obrien")

    assert user is not None
    assert user.member_of == ()


async def test_somebody_in_no_groups_gets_an_empty_answer(
    client: DirectoryClient, admin: Any
) -> None:
    """Distinct from a failure, which is the distinction FR-DIR-08 turns on."""
    dn = f"uid=loner-{uuid.uuid4().hex[:8]},{PEOPLE}"
    admin.add(
        dn,
        ["inetOrgPerson", "organizationalPerson", "person", "top"],
        {"uid": dn.split(",")[0].split("=")[1], "cn": "Loner", "sn": "Test"},
    )
    try:
        user = await client.find_user(dn.split(",")[0].split("=")[1])
        assert user is not None

        result = await client.groups_for(user)

        assert result.groups == frozenset()
        assert not result.degraded
    finally:
        admin.delete(dn)


# --- paging (FR-DIR-05) -----------------------------------------------------


async def test_a_result_larger_than_one_page_is_complete(
    client: DirectoryClient, many_people: int
) -> None:
    """Six hundred entries against a five-hundred page size. Without the paged
    control the server answers with its own `sizelimit` and the result looks
    complete, which is the failure mode worth a container to catch."""
    entries = await client._search(BASE, "(objectClass=inetOrgPerson)", ["uid"])

    assert len(entries) >= many_people


# --- health -----------------------------------------------------------------


async def test_a_live_directory_is_healthy(client: DirectoryClient) -> None:
    assert await client.healthy()


async def test_an_unreachable_directory_is_unhealthy() -> None:
    """Port 1 is reserved and nothing listens there, so this is a connection
    failure rather than a slow one — the timeout path is a unit test's job."""
    unreachable = DirectoryClient(
        profile=OPENLDAP,
        url="ldap://openldap:1",
        base_dn=BASE,
        start_tls=False,
        allow_plaintext=True,
    )

    assert not await unreachable.healthy()


# --- writing (FR-DIR-06) ----------------------------------------------------


@pytest.fixture
def writer() -> DirectoryWriter:
    return DirectoryWriter(
        profile=OPENLDAP,
        base_dn=BASE,
        connector=Connector(
            url=LDAP_URL,
            bind_dn=ADMIN,
            bind_password=PASSWORD,
            start_tls=False,
            allow_plaintext=True,
        ),
    )


@pytest.fixture
async def joiner(writer: DirectoryWriter, admin: Any) -> AsyncIterator[PersonSpec]:
    spec = PersonSpec(
        uid=f"joiner-{uuid.uuid4().hex[:8]}",
        given_name="New",
        surname="Joiner",
        mail="new.joiner@campus.test",
        display_name="New Joiner",
    )
    yield spec
    admin.delete(writer.dn_for(spec.uid))


async def test_a_person_is_created_in_the_directory(
    writer: DirectoryWriter, joiner: PersonSpec
) -> None:
    result = await writer.ensure_person(joiner)

    assert result.changed


async def test_creating_the_same_person_twice_is_a_no_op(
    writer: DirectoryWriter, joiner: PersonSpec
) -> None:
    """FR-DIR-06 against a server that really refuses a duplicate DN. The unit
    test proves we check first; this proves the server agrees about what
    "already there" means."""
    first = await writer.ensure_person(joiner)
    second = await writer.ensure_person(joiner)

    assert first.changed
    assert not second.changed


async def test_a_modify_writes_only_what_differs(
    writer: DirectoryWriter, joiner: PersonSpec
) -> None:
    await writer.ensure_person(joiner)
    dn = writer.dn_for(joiner.uid)

    changed = await writer.modify(dn, {"mail": ["moved@campus.test"]})
    again = await writer.modify(dn, {"mail": ["moved@campus.test"]})

    assert changed.changed
    assert not again.changed


async def test_disabling_locks_the_account(
    writer: DirectoryWriter, joiner: PersonSpec, admin: Any
) -> None:
    """OpenLDAP's half of FR-LC-03's first step. The ppolicy sentinel means
    locked with no expiry — a real timestamp would unlock the account when it
    passed, which for a deprovisioning is precisely wrong."""
    await writer.ensure_person(joiner)
    dn = writer.dn_for(joiner.uid)

    result = await writer.disable(dn)

    assert result.changed
    admin.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["pwdAccountLockedTime"])
    assert admin.response[0]["attributes"]["pwdAccountLockedTime"]


async def test_disabling_twice_is_a_no_op(writer: DirectoryWriter, joiner: PersonSpec) -> None:
    """Deprovisioning is retried, so this is the ordinary case rather than a
    corner."""
    await writer.ensure_person(joiner)
    dn = writer.dn_for(joiner.uid)

    await writer.disable(dn)
    second = await writer.disable(dn)

    assert not second.changed


async def test_a_disabled_entry_is_still_there(
    writer: DirectoryWriter, joiner: PersonSpec, client: DirectoryClient
) -> None:
    """Nothing is deleted. The audit trail has to go on naming them, and an
    entry that is gone cannot be shown to have been disabled."""
    await writer.ensure_person(joiner)
    await writer.disable(writer.dn_for(joiner.uid))

    assert await client.find_user(joiner.uid) is not None


async def test_disabling_somebody_who_is_not_there_is_refused(
    writer: DirectoryWriter,
) -> None:
    """Reporting success would let a deprovisioning claim to have disabled
    somebody who was never provisioned."""
    with pytest.raises(DirectoryUnavailable):
        await writer.disable(f"uid=never-existed-{uuid.uuid4().hex[:8]},{PEOPLE}")


async def test_an_unreachable_directory_raises_rather_than_answering() -> None:
    unreachable = DirectoryClient(
        profile=OPENLDAP,
        url="ldap://openldap:1",
        base_dn=BASE,
        start_tls=False,
        allow_plaintext=True,
    )

    with pytest.raises(DirectoryUnavailable):
        await unreachable.find_user("sam.obrien")
