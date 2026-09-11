"""Writing to the directory (FR-DIR-06).

Three operations — create, modify, disable — and the requirement on all of them
is idempotency: a repeated create is a no-op that returns success. That is not a
convenience. Provisioning is retried (FR-LC-09), so every write here will happen
twice sooner or later, and a create that failed the second time would dead-letter
a joiner who is already in the directory.

**Idempotent means "compare, then write", not "write and ignore the error".**
Swallowing an `entryAlreadyExists` makes a second create succeed and tells the
caller nothing; comparing first distinguishes "created" from "already correct",
which is what a reconciliation report is made of (FR-LC-07).

**Disabling is the operation with two implementations and one meaning.** Active
Directory sets a bit in `userAccountControl`; OpenLDAP sets `pwdAccountLockedTime`
to the ppolicy sentinel. The bit is the one that gets written wrong: assigning
`2` disables the account *and clears every other flag on it*, so an account that
was set never to expire quietly starts expiring. It is read, or-ed and written
back.

**Nothing is deleted.** A leaver's entry is disabled, never removed, for the same
reason their identifiers are tombstoned: the audit trail has to go on naming
them, and a directory entry that is gone cannot be shown to have been disabled.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from campusid.directory.connection import LOCKED_FOREVER, DirectoryUnavailable
from campusid.directory.escaping import escape_dn
from campusid.directory.profiles import (
    ACCOUNT_DISABLED_BIT,
    DEFAULT_ACCOUNT_CONTROL,
    DirectoryProfile,
)
from campusid.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class WriteResult:
    """What a write did, which is not always what it was asked to do."""

    dn: str
    changed: bool
    """False when the directory already said what we were about to tell it.

    The distinction a reconciliation report is made of: "we created this" and
    "this was already right" are different findings, and a writer that returned
    success for both would make drift invisible.
    """

    detail: str = ""


@dataclass(frozen=True, slots=True)
class PersonSpec:
    """The entry to create, in our vocabulary rather than the directory's."""

    uid: str
    given_name: str
    surname: str
    mail: str | None = None
    display_name: str | None = None
    principal_name: str | None = None


class DirectoryWriter:
    """Creates, modifies and disables entries in one directory."""

    def __init__(
        self,
        *,
        profile: DirectoryProfile,
        base_dn: str,
        people_ou: str = "ou=people",
        connector: Any,
    ) -> None:
        self._profile = profile
        self._base_dn = base_dn
        self._people = f"{people_ou},{base_dn}"
        self._connector = connector

    def dn_for(self, uid: str) -> str:
        """Where an entry for this person lives.

        The uid is DN-escaped, not filter-escaped. They share a backslash and
        nothing else, and a comma in a name unescaped here silently splits the
        DN into an entry somebody else's subtree.
        """
        return f"uid={escape_dn(uid)},{self._people}"

    async def ensure_person(self, spec: PersonSpec) -> WriteResult:
        """Create the entry, or report that it is already there (FR-DIR-06)."""
        return await self._run(self._ensure_person_blocking, spec)

    async def modify(self, dn: str, changes: dict[str, list[str]]) -> WriteResult:
        """Set attributes to these values, writing only what differs."""
        return await self._run(self._modify_blocking, dn, changes)

    async def disable(self, dn: str) -> WriteResult:
        """Disable the account, whatever this directory means by that."""
        return await self._run(self._disable_blocking, dn)

    # --- the wire ---------------------------------------------------------

    async def _run(self, operation: Any, *args: Any) -> WriteResult:
        try:
            return await asyncio.to_thread(operation, *args)
        except DirectoryUnavailable:
            raise
        except Exception as exc:
            log.warning("directory.write_failed", error=str(exc))
            raise DirectoryUnavailable(str(exc)) from exc

    def _ensure_person_blocking(self, spec: PersonSpec) -> WriteResult:
        from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult

        dn = self.dn_for(spec.uid)
        connection = self._connector()
        try:
            if self._exists(connection, dn):
                # Compared rather than attempted-and-forgiven: "already there"
                # and "just created" are different findings to a reconciliation
                # report, and only one of them is drift.
                return WriteResult(dn=dn, changed=False, detail="already present")
            try:
                connection.add(dn, self._object_classes(), self._attributes(spec))
            except LDAPEntryAlreadyExistsResult:
                # Somebody else created it between the check and the write. The
                # outcome the caller wanted is the outcome they got.
                return WriteResult(dn=dn, changed=False, detail="created concurrently")
            log.info("directory.person.created", dn=dn)
            return WriteResult(dn=dn, changed=True, detail="created")
        finally:
            connection.unbind()

    def _modify_blocking(self, dn: str, changes: dict[str, list[str]]) -> WriteResult:
        from ldap3 import MODIFY_REPLACE

        connection = self._connector()
        try:
            current = self._read(connection, dn, list(changes))
            if current is None:
                raise DirectoryUnavailable(f"{dn} is not in the directory")

            differing = {
                name: values
                for name, values in changes.items()
                if sorted(_strings(current.get(name))) != sorted(values)
            }
            if not differing:
                return WriteResult(dn=dn, changed=False, detail="already correct")

            connection.modify(
                dn, {name: [(MODIFY_REPLACE, values)] for name, values in differing.items()}
            )
            log.info("directory.person.modified", dn=dn, attributes=sorted(differing))
            return WriteResult(dn=dn, changed=True, detail=",".join(sorted(differing)))
        finally:
            connection.unbind()

    def _disable_blocking(self, dn: str) -> WriteResult:
        from ldap3 import MODIFY_REPLACE

        flag = self._profile.disabled_flag
        connection = self._connector()
        try:
            attribute = flag or self._profile.lock_attribute
            current = self._read(connection, dn, [attribute])
            if current is None:
                # An entry that is not there cannot be disabled, and pretending
                # otherwise would let a deprovisioning report success for
                # somebody who was never provisioned.
                raise DirectoryUnavailable(f"{dn} is not in the directory")

            if flag:
                value = self._disabled_account_control(current.get(flag))
                if value is None:
                    return WriteResult(dn=dn, changed=False, detail="already disabled")
                connection.modify(dn, {flag: [(MODIFY_REPLACE, [str(value)])]})
            else:
                if _strings(current.get(attribute)):
                    return WriteResult(dn=dn, changed=False, detail="already locked")
                connection.modify(dn, {attribute: [(MODIFY_REPLACE, [LOCKED_FOREVER])]})

            log.info("directory.person.disabled", dn=dn)
            return WriteResult(dn=dn, changed=True, detail="disabled")
        finally:
            connection.unbind()

    def _disabled_account_control(self, current: Any) -> int | None:
        """The new `userAccountControl`, or None when the bit is already set.

        Read, or, write. Assigning the bare bit would clear every other flag on
        the account, and the damage only appears when somebody is re-enabled.
        """
        values = _strings(current)
        try:
            existing = int(values[0]) if values else DEFAULT_ACCOUNT_CONTROL
        except ValueError:
            existing = DEFAULT_ACCOUNT_CONTROL

        if existing & ACCOUNT_DISABLED_BIT:
            return None
        return existing | ACCOUNT_DISABLED_BIT

    # --- helpers ----------------------------------------------------------

    def _exists(self, connection: Any, dn: str) -> bool:
        return self._read(connection, dn, ["1.1"]) is not None

    def _read(self, connection: Any, dn: str, attributes: list[str]) -> dict[str, Any] | None:
        """One entry by DN, or None.

        A base-scoped search rather than a compare: it answers "is it there" and
        "what does it say" in one round trip, and the writer needs both.
        """
        from ldap3.core.exceptions import LDAPNoSuchObjectResult

        try:
            found = connection.search(
                search_base=dn,
                search_scope="BASE",
                search_filter="(objectClass=*)",
                attributes=attributes,
            )
        except LDAPNoSuchObjectResult:
            return None
        if not found or not connection.response:
            return None

        entry = connection.response[0]
        result: dict[str, Any] = entry.get("attributes", {})
        return result

    def _object_classes(self) -> list[str]:
        """What a new person is.

        Taken from the profile so the same writer creates an `inetOrgPerson` in
        OpenLDAP and a `user` in Active Directory without knowing which it is
        talking to — and so the auxiliary class its login attribute needs comes
        along with it.
        """
        return list(self._profile.create_object_classes)

    def _attributes(self, spec: PersonSpec) -> dict[str, Any]:
        profile = self._profile
        attributes: dict[str, Any] = {
            "cn": f"{spec.given_name} {spec.surname}".strip(),
            profile.surname: spec.surname,
            profile.given_name: spec.given_name,
        }
        if "uid" in profile.login_attributes or profile.name == "openldap":
            attributes["uid"] = spec.uid
        if spec.mail:
            attributes[profile.mail] = spec.mail
        if spec.display_name:
            attributes[profile.display_name] = spec.display_name
        if spec.principal_name:
            attributes[profile.login_attributes[0]] = spec.principal_name
        return attributes


def _strings(value: Any) -> list[str]:
    """Whatever the server sent, as a list of strings.

    LDAP has no single-valued reads, except when a server sends a bare value,
    which several do — and `userAccountControl` in particular arrives as an
    integer from some servers and a string from others.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [
        item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
        for item in value
        if item is not None and item != ""
    ]
