"""Writing to the directory (FR-DIR-06).

The requirement is idempotency, and it is not a convenience: provisioning is
retried with backoff, so every write here happens twice sooner or later. A create
that failed the second time would dead-letter a joiner who is already in the
directory.

The test worth reading is the Active Directory disable. `userAccountControl` is
a bit field, and assigning `2` to it disables the account *and clears every other
flag* — the account that was set never to expire quietly starts expiring, and
nobody finds out until somebody is re-enabled.
"""

from __future__ import annotations

from typing import Any

import pytest

from campusid.directory.connection import LOCKED_FOREVER, DirectoryUnavailable
from campusid.directory.profiles import ACCOUNT_DISABLED_BIT, ACTIVE_DIRECTORY, OPENLDAP
from campusid.directory.writes import DirectoryWriter, PersonSpec

BASE = "dc=campus,dc=test"
SAM = f"uid=sam.obrien,ou=people,{BASE}"


class _Connection:
    """A directory that holds entries in a dictionary."""

    def __init__(self, entries: dict[str, dict[str, Any]] | None = None) -> None:
        self.entries = entries or {}
        self.added: list[tuple[str, list[str], dict[str, Any]]] = []
        self.modified: list[tuple[str, dict[str, Any]]] = []
        self.response: list[dict[str, Any]] = []
        self.unbound = False

    def search(self, **kwargs: Any) -> bool:
        dn = kwargs["search_base"]
        if dn not in self.entries:
            self.response = []
            return False
        self.response = [{"dn": dn, "attributes": self.entries[dn]}]
        return True

    def add(self, dn: str, object_classes: list[str], attributes: dict[str, Any]) -> None:
        self.added.append((dn, object_classes, attributes))
        self.entries[dn] = dict(attributes)

    def modify(self, dn: str, changes: dict[str, Any]) -> None:
        self.modified.append((dn, changes))
        for name, operations in changes.items():
            self.entries[dn][name] = operations[0][1]

    def unbind(self) -> None:
        self.unbound = True


def _writer(connection: _Connection, profile: Any = OPENLDAP) -> DirectoryWriter:
    return DirectoryWriter(profile=profile, base_dn=BASE, connector=lambda: connection)


SPEC = PersonSpec(
    uid="sam.obrien",
    given_name="Samira",
    surname="O'Brien",
    mail="sam.obrien@campus.test",
    display_name="Samira O'Brien",
)


# --- creating ---------------------------------------------------------------


async def test_a_person_is_created() -> None:
    connection = _Connection()

    result = await _writer(connection).ensure_person(SPEC)

    assert result.changed
    assert result.dn == SAM
    assert connection.added[0][2]["uid"] == "sam.obrien"


async def test_a_repeated_create_is_a_no_op_that_succeeds() -> None:
    """FR-DIR-06 in one line. Provisioning is retried, so this happens."""
    connection = _Connection({SAM: {"uid": "sam.obrien"}})

    result = await _writer(connection).ensure_person(SPEC)

    assert not result.changed
    assert connection.added == []


async def test_already_present_and_just_created_are_distinguishable() -> None:
    """Which is what a reconciliation report is made of. A writer that returned
    success for both would make drift invisible."""
    empty = _Connection()
    populated = _Connection({SAM: {"uid": "sam.obrien"}})

    first = await _writer(empty).ensure_person(SPEC)
    second = await _writer(populated).ensure_person(SPEC)

    assert (first.changed, second.changed) == (True, False)


async def test_a_concurrent_create_is_not_an_error() -> None:
    """Somebody else created it between the check and the write. The outcome
    the caller wanted is the outcome they got."""
    from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult

    class _Racing(_Connection):
        def add(self, dn: str, object_classes: list[str], attributes: dict[str, Any]) -> None:
            raise LDAPEntryAlreadyExistsResult(result=68, description="entryAlreadyExists")

    result = await _writer(_Racing()).ensure_person(SPEC)

    assert not result.changed


async def test_a_dn_component_is_escaped_for_a_dn() -> None:
    """Not for a filter. They share a backslash and nothing else, and a comma
    unescaped here splits the DN into somebody else's subtree."""
    connection = _Connection()

    result = await _writer(connection).ensure_person(
        PersonSpec(uid="obrien,sam", given_name="Sam", surname="O'Brien")
    )

    assert result.dn.startswith("uid=obrien\\,sam,")


async def test_the_object_classes_follow_the_profile() -> None:
    """The same writer creates an inetOrgPerson in OpenLDAP and a user in
    Active Directory without knowing which it is talking to."""
    openldap, active_directory = _Connection(), _Connection()

    await _writer(openldap).ensure_person(SPEC)
    await _writer(active_directory, ACTIVE_DIRECTORY).ensure_person(SPEC)

    assert "inetOrgPerson" in openldap.added[0][1]
    assert "user" in active_directory.added[0][1]


# --- modifying --------------------------------------------------------------


async def test_only_what_differs_is_written() -> None:
    """A modify that rewrites unchanged values still bumps every replicated
    attribute's timestamp, which turns one login into directory replication
    traffic across the estate."""
    connection = _Connection({SAM: {"mail": ["sam@campus.test"], "sn": ["O'Brien"]}})

    result = await _writer(connection).modify(SAM, {"mail": ["new@campus.test"], "sn": ["O'Brien"]})

    assert result.changed
    assert list(connection.modified[0][1]) == ["mail"]


async def test_a_modify_to_the_current_values_is_a_no_op() -> None:
    connection = _Connection({SAM: {"mail": ["sam@campus.test"]}})

    result = await _writer(connection).modify(SAM, {"mail": ["sam@campus.test"]})

    assert not result.changed
    assert connection.modified == []


async def test_value_order_does_not_count_as_a_difference() -> None:
    """LDAP attributes are sets, and a server is free to return them in any
    order. Comparing as sequences would rewrite them on every run."""
    connection = _Connection({SAM: {"member": ["b", "a"]}})

    result = await _writer(connection).modify(SAM, {"member": ["a", "b"]})

    assert not result.changed


async def test_modifying_something_that_is_not_there_is_refused() -> None:
    with pytest.raises(DirectoryUnavailable):
        await _writer(_Connection()).modify(SAM, {"mail": ["x@campus.test"]})


# --- disabling --------------------------------------------------------------


async def test_openldap_locks_the_account_forever() -> None:
    """A real timestamp would unlock the account when it passed, which for a
    deprovisioning is precisely wrong."""
    connection = _Connection({SAM: {}})

    result = await _writer(connection).disable(SAM)

    assert result.changed
    assert connection.entries[SAM]["pwdAccountLockedTime"] == [LOCKED_FOREVER]


async def test_disabling_an_already_locked_account_is_a_no_op() -> None:
    connection = _Connection({SAM: {"pwdAccountLockedTime": [LOCKED_FOREVER]}})

    result = await _writer(connection).disable(SAM)

    assert not result.changed
    assert connection.modified == []


async def test_active_directory_preserves_the_other_flags() -> None:
    """The mistake this is here to prevent. `userAccountControl` is a bit field:
    assigning 2 disables the account and clears NORMAL_ACCOUNT and
    DONT_EXPIRE_PASSWORD in the same write."""
    existing = 0x200 | 0x10000  # NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
    connection = _Connection({SAM: {"userAccountControl": [str(existing)]}})

    result = await _writer(connection, ACTIVE_DIRECTORY).disable(SAM)

    assert result.changed
    written = int(connection.entries[SAM]["userAccountControl"][0])
    assert written & ACCOUNT_DISABLED_BIT
    assert written & 0x10000, "DONT_EXPIRE_PASSWORD must survive"
    assert written & 0x200, "NORMAL_ACCOUNT must survive"


async def test_an_already_disabled_active_directory_account_is_a_no_op() -> None:
    connection = _Connection({SAM: {"userAccountControl": [str(0x200 | ACCOUNT_DISABLED_BIT)]}})

    result = await _writer(connection, ACTIVE_DIRECTORY).disable(SAM)

    assert not result.changed
    assert connection.modified == []


async def test_an_integer_valued_flag_is_read_the_same_as_a_string() -> None:
    """Some servers send `userAccountControl` as an integer and some as a
    string, and a comparison that only handled one would silently re-disable an
    already-disabled account every run."""
    connection = _Connection({SAM: {"userAccountControl": 0x200 | ACCOUNT_DISABLED_BIT}})

    result = await _writer(connection, ACTIVE_DIRECTORY).disable(SAM)

    assert not result.changed


async def test_an_unreadable_flag_falls_back_to_a_normal_account() -> None:
    """Rather than raising. A garbage value is a directory problem, and refusing
    to disable somebody because of it is the wrong direction to fail in."""
    connection = _Connection({SAM: {"userAccountControl": ["not-a-number"]}})

    result = await _writer(connection, ACTIVE_DIRECTORY).disable(SAM)

    assert result.changed
    assert int(connection.entries[SAM]["userAccountControl"][0]) & ACCOUNT_DISABLED_BIT


async def test_disabling_somebody_who_is_not_there_is_refused() -> None:
    """Reporting success would let a deprovisioning claim to have disabled
    somebody who was never provisioned."""
    with pytest.raises(DirectoryUnavailable):
        await _writer(_Connection()).disable(SAM)


async def test_nothing_is_ever_deleted() -> None:
    """A leaver's entry is disabled, not removed, for the same reason their
    identifiers are tombstoned: a directory entry that is gone cannot be shown
    to have been disabled."""
    assert not hasattr(DirectoryWriter, "delete")


async def test_the_connection_is_released_on_every_path() -> None:
    connection = _Connection({SAM: {}})

    await _writer(connection).disable(SAM)

    assert connection.unbound
