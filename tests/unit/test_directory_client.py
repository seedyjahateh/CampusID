"""Reading the directory (FR-DIR-04, 05, 08).

The connection is injected, so these run without a server. What they are about
is the behaviour around the search rather than the search itself: which of two
membership mechanisms is used, what happens when the server is not there, and
the distinction between "nobody matched" and "we could not ask".

That last one is the whole of FR-DIR-08. An outage that answers "no groups" is
a silent campus-wide deprovisioning, and it looks exactly like a successful
lookup all the way downstream.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fakeredis import aioredis

from campusid.directory.client import (
    CACHE_PREFIX,
    PAGE_SIZE,
    DirectoryClient,
    DirectoryUnavailable,
    DirectoryUser,
)
from campusid.directory.profiles import OPENLDAP

BASE = "dc=campus,dc=test"
SAM = "uid=sam.obrien,ou=people,dc=campus,dc=test"
STUDENTS = "cn=lms-students,ou=groups,dc=campus,dc=test"
MEMBERS = "cn=campus-members,ou=groups,dc=campus,dc=test"


class _Extend:
    def __init__(self, connection: _Connection) -> None:
        self.standard = _Standard(connection)


class _Standard:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def paged_search(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self._connection.answer(kwargs)


class _Connection:
    """A directory that answers from a fixed table of filter to entries."""

    def __init__(self, answers: dict[str, list[dict[str, Any]]], *, fail: bool = False) -> None:
        self._answers = answers
        self._fail = fail
        self.searches: list[dict[str, Any]] = []
        self.unbound = False
        self.extend = _Extend(self)

    def answer(self, kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        self.searches.append(kwargs)
        if self._fail:
            raise OSError("connection refused")
        return self._answers.get(kwargs["search_filter"], [])

    def unbind(self) -> None:
        self.unbound = True


def _entry(dn: str, **attributes: Any) -> dict[str, Any]:
    return {"type": "searchResEntry", "dn": dn, "attributes": attributes}


def _client(connection: _Connection, cache: Any = None) -> DirectoryClient:
    return DirectoryClient(
        profile=OPENLDAP,
        url="ldap://directory.test:389",
        base_dn=BASE,
        cache=cache,
        connector=lambda: connection,
    )


@pytest.fixture
def cache() -> aioredis.FakeRedis:
    return aioredis.FakeRedis(decode_responses=True)


# --- finding a person -------------------------------------------------------


async def test_a_person_is_converted_into_our_vocabulary() -> None:
    """Nothing above the client sees an ldap3 type or a directory's attribute
    name, which is what keeps the untyped dependency one file wide."""
    connection = _Connection(
        {
            OPENLDAP.user_filter("sam.obrien"): [
                _entry(
                    SAM,
                    entryUUID="8f14e45f-ceea",
                    uid="sam.obrien",
                    mail=["sam.obrien@campus.test"],
                    displayName="Samira O'Brien",
                    memberOf=[STUDENTS],
                )
            ]
        }
    )

    user = await _client(connection).find_user("sam.obrien")

    assert user is not None
    assert user.immutable_id == "8f14e45f-ceea"
    assert user.mail == "sam.obrien@campus.test"
    assert user.member_of == (STUDENTS,)


async def test_a_bare_string_attribute_is_read_as_one_value() -> None:
    """LDAP has no single-valued reads: everything is a list, except when a
    server sends a bare string, which several do."""
    connection = _Connection(
        {OPENLDAP.user_filter("sam"): [_entry(SAM, entryUUID="id", uid="sam", mail="s@c.test")]}
    )

    user = await _client(connection).find_user("sam")

    assert user is not None
    assert user.mail == "s@c.test"


async def test_a_byte_valued_attribute_is_decoded() -> None:
    """`objectGUID` and friends arrive as bytes, and a DN or an id that reached
    the registry as `b'...'` would be a different value every time it was
    formatted."""
    connection = _Connection(
        {OPENLDAP.user_filter("sam"): [_entry(SAM, entryUUID=b"binary-id", uid=b"sam")]}
    )

    user = await _client(connection).find_user("sam")

    assert user is not None
    assert user.immutable_id == "binary-id"


async def test_nobody_matching_is_not_an_error() -> None:
    """A person who is not in the directory is an answer. Raising here would
    make every unknown login look like an outage."""
    assert await _client(_Connection({})).find_user("ghost") is None


async def test_two_entries_answering_to_one_login_resolve_to_nobody() -> None:
    """A directory that cannot say who somebody is has not answered the
    question, and picking the first would pick differently on a different day."""
    connection = _Connection(
        {
            OPENLDAP.user_filter("sam"): [
                _entry(SAM, entryUUID="one", uid="sam"),
                _entry("uid=sam,ou=other,dc=campus,dc=test", entryUUID="two", uid="sam"),
            ]
        }
    )

    assert await _client(connection).find_user("sam") is None


async def test_an_unreachable_directory_raises_rather_than_returning_nobody() -> None:
    """The distinction FR-DIR-08 turns on. "Not there" and "could not ask" have
    to reach the caller differently or an outage becomes a departure."""
    with pytest.raises(DirectoryUnavailable):
        await _client(_Connection({}, fail=True)).find_user("sam")


async def test_the_connection_is_released_even_when_the_search_fails() -> None:
    """A connection per search only works if every search returns one."""
    connection = _Connection({}, fail=True)

    with pytest.raises(DirectoryUnavailable):
        await _client(connection).find_user("sam")

    assert connection.unbound


async def test_every_search_is_paged() -> None:
    """FR-DIR-05. A directory with fifty thousand people answers an unpaged
    search by truncating it at the server's own limit, and the answer looks
    complete."""
    connection = _Connection({})

    await _client(connection).find_user("sam")

    assert connection.searches[0]["paged_size"] == PAGE_SIZE


async def test_a_search_asks_only_for_the_attributes_it_needs() -> None:
    connection = _Connection({})

    await _client(connection).find_user("sam")

    requested = connection.searches[0]["attributes"]
    assert "entryUUID" in requested
    assert "jpegPhoto" not in requested


# --- membership -------------------------------------------------------------


async def test_member_of_is_used_when_the_directory_maintains_it() -> None:
    connection = _Connection({OPENLDAP.group_members_filter(STUDENTS): []})
    user = DirectoryUser(dn=SAM, immutable_id="id", login="sam", member_of=(STUDENTS,))

    result = await _client(connection).groups_for(user)

    assert result.direct == {STUDENTS}
    assert not result.degraded


async def test_a_reverse_search_is_used_when_it_does_not() -> None:
    """The `memberof` overlay is optional in OpenLDAP and many deployments do
    not enable it, so this is the common case rather than a corner."""
    connection = _Connection(
        {
            OPENLDAP.group_members_filter(SAM): [_entry(STUDENTS)],
            OPENLDAP.group_members_filter(STUDENTS): [_entry(MEMBERS)],
            OPENLDAP.group_members_filter(MEMBERS): [],
        }
    )
    user = DirectoryUser(dn=SAM, immutable_id="id", login="sam")

    result = await _client(connection).groups_for(user)

    assert result.groups == {STUDENTS, MEMBERS}
    assert result.direct == {STUDENTS}


async def test_nested_membership_is_expanded() -> None:
    connection = _Connection(
        {
            OPENLDAP.group_members_filter(STUDENTS): [_entry(MEMBERS)],
            OPENLDAP.group_members_filter(MEMBERS): [],
        }
    )
    user = DirectoryUser(dn=SAM, immutable_id="id", login="sam", member_of=(STUDENTS,))

    result = await _client(connection).groups_for(user)

    assert result.groups == {STUDENTS, MEMBERS}


# --- degrading (FR-DIR-08) --------------------------------------------------


async def test_a_successful_lookup_is_cached(cache: aioredis.FakeRedis) -> None:
    connection = _Connection({OPENLDAP.group_members_filter(STUDENTS): []})
    user = DirectoryUser(dn=SAM, immutable_id="person-1", login="sam", member_of=(STUDENTS,))

    await _client(connection, cache).groups_for(user)

    stored = json.loads(await cache.get(f"{CACHE_PREFIX}person-1"))
    assert stored == [STUDENTS]


async def test_an_outage_is_answered_from_the_cache(cache: aioredis.FakeRedis) -> None:
    """A directory restart must not log out the campus."""
    await cache.set(f"{CACHE_PREFIX}person-1", json.dumps([STUDENTS, MEMBERS]))
    user = DirectoryUser(dn=SAM, immutable_id="person-1", login="sam", member_of=(STUDENTS,))

    result = await _client(_Connection({}, fail=True), cache).groups_for(user)

    assert result.groups == {STUDENTS, MEMBERS}
    assert result.degraded


async def test_an_outage_with_no_cached_answer_raises(cache: aioredis.FakeRedis) -> None:
    """A miss during an outage means we do not know, and "we do not know" must
    not be answered as "no groups" — that is a silent revocation of everybody's
    access the moment the directory blinks."""
    user = DirectoryUser(dn=SAM, immutable_id="unseen", login="sam", member_of=(STUDENTS,))

    with pytest.raises(DirectoryUnavailable):
        await _client(_Connection({}, fail=True), cache).groups_for(user)


async def test_an_unreadable_cache_entry_is_a_miss(cache: aioredis.FakeRedis) -> None:
    """The directory is the source of truth and this is a shortcut; a shortcut
    that raises is worse than no shortcut."""
    await cache.set(f"{CACHE_PREFIX}person-1", "not json")
    user = DirectoryUser(dn=SAM, immutable_id="person-1", login="sam")

    with pytest.raises(DirectoryUnavailable):
        await _client(_Connection({}, fail=True), cache).groups_for(user)


async def test_a_truncated_expansion_is_not_cached(cache: aioredis.FakeRedis) -> None:
    """It is an incomplete answer, and caching it would keep somebody's missing
    memberships missing for fifteen minutes after the cause was fixed."""
    chain = {
        OPENLDAP.group_members_filter(f"cn=g{level},dc=test"): [_entry(f"cn=g{level + 1},dc=test")]
        for level in range(20)
    }
    connection = _Connection(chain)
    user = DirectoryUser(dn=SAM, immutable_id="deep", login="sam", member_of=("cn=g0,dc=test",))

    result = await _client(connection, cache).groups_for(user)

    assert result.truncated
    assert await cache.get(f"{CACHE_PREFIX}deep") is None


async def test_a_client_with_no_cache_still_works() -> None:
    """Caching is an availability feature, not a correctness one, and a
    deployment without Redis reachable should still resolve groups."""
    connection = _Connection({OPENLDAP.group_members_filter(STUDENTS): []})
    user = DirectoryUser(dn=SAM, immutable_id="id", login="sam", member_of=(STUDENTS,))

    result = await _client(connection).groups_for(user)

    assert result.groups == {STUDENTS}


# --- health -----------------------------------------------------------------


async def test_health_is_a_search_rather_than_a_connect() -> None:
    """A server that accepts TCP and refuses to bind is down for every purpose
    we have, and a probe that only connected would call it healthy."""
    connection = _Connection({"(objectClass=*)": [_entry(BASE)]})

    assert await _client(connection).healthy()
    assert connection.searches[0]["search_filter"] == "(objectClass=*)"


async def test_an_unreachable_directory_is_unhealthy() -> None:
    assert not await _client(_Connection({}, fail=True)).healthy()
