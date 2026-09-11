"""Seed the development directory (FR-DIR-03, FR-DIR-04).

Creates the tree the integration tests read: two organisational units, three
people from NFR-OPS-04's fixture set, and a group hierarchy three levels deep so
nested expansion has something to expand.

Seeded over LDAP rather than through the image's bootstrap directory, which is
the same choice federation-init makes about Keycloak and for the same reason:
the fixture is created the way a real one would be, and the seeding is not
coupled to one image's conventions. Swapping OpenLDAP for a samba-AD container
then costs a profile change rather than a rewrite.

Idempotent. It runs on every `up` of the directory profile, and an entry that
already exists is left alone — re-adding it would either fail the run or
overwrite whatever a test just did.

The group shape is the interesting part:

    lms-students  ->  all-students  ->  campus-members

Nobody is a direct member of `campus-members`, so a broker that reads only
direct membership finds nothing for a student — which is the failure FR-DIR-04
is about, and it is here so the test can prove it does not happen.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult, LDAPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from docker.openldap.eduperson import SCHEMA_DN, schema_entry

LDAP_URL = os.environ.get("DIRECTORY_LDAP_URL", "ldap://openldap:389")
BASE_DN = os.environ.get("CAMPUSID_LDAP_BASE_DN", "dc=campus,dc=test")
ADMIN_DN = f"cn=admin,{BASE_DN}"
ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "")

CONFIG_DN = "cn=admin,cn=config"
CONFIG_PASSWORD = os.environ.get("LDAP_CONFIG_PASSWORD", "") or ADMIN_PASSWORD

PEOPLE = f"ou=people,{BASE_DN}"
GROUPS = f"ou=groups,{BASE_DN}"


def log(message: str) -> None:
    print(f"directory-init: {message}", flush=True)


def _config_connection() -> Any:
    """A connection to `cn=config`, with client-side schema checking off.

    `get_info=NONE` rather than `ALL` on purpose. ldap3 otherwise caches the
    schema at bind time and validates object classes against it — and the schema
    it reads is the *data* subschema, which does not describe `cn=config` at all.
    Loading a module also adds object classes that a connection bound before it
    has no way to know about. The server validates either way, and it is the
    authority.
    """
    from ldap3 import NONE

    server = Server(LDAP_URL, get_info=NONE, connect_timeout=10)
    return Connection(
        server, user=CONFIG_DN, password=CONFIG_PASSWORD, auto_bind=True, raise_exceptions=True
    )


def enable_password_policy() -> None:
    """Load the ppolicy overlay, which is what makes an account lockable.

    `pwdAccountLockedTime` is not part of `ppolicy.schema` — that file defines
    the *policy* object class and its `pwdMaxAge`-style attributes. The
    operational attributes a lock actually uses come from the overlay module,
    so a directory with the schema and without the overlay rejects a lock with
    `invalid attribute type`, which reads as a typo rather than as a missing
    feature.

    A campus OpenLDAP that locks accounts has this overlay. The fixture has it
    for the same reason it has the eduPerson schema: a development directory
    unlike the one the code is written for proves nothing.
    """
    from ldap3 import MODIFY_ADD
    from ldap3.core.exceptions import LDAPAttributeOrValueExistsResult

    connection = _config_connection()
    try:
        try:
            connection.modify(
                "cn=module{0},cn=config", {"olcModuleLoad": [(MODIFY_ADD, ["ppolicy.la"])]}
            )
            log("loaded the ppolicy module")
        except LDAPAttributeOrValueExistsResult:
            log("ppolicy module already loaded")

        database = _database_dn(connection)
        if database is None:
            log("no database found for the suffix; skipping the ppolicy overlay")
            return

        try:
            connection.add(
                f"olcOverlay=ppolicy,{database}",
                ["olcOverlayConfig", "olcPPolicyConfig"],
                {"olcOverlay": "ppolicy"},
            )
            log("enabled the ppolicy overlay")
        except LDAPEntryAlreadyExistsResult:
            log("ppolicy overlay present")
    finally:
        connection.unbind()


def _database_dn(connection: Any) -> str | None:
    """Which `cn=config` database serves our suffix.

    Discovered rather than hardcoded as `olcDatabase={1}mdb`. The index depends
    on how many databases the image defines, and an overlay attached to the
    wrong one is configured, reported as configured, and does nothing.
    """
    connection.search(
        search_base="cn=config",
        search_filter=f"(olcSuffix={BASE_DN})",
        attributes=["olcSuffix"],
    )
    if not connection.response:
        return None
    dn: str = connection.response[0]["dn"]
    return dn


def add_schema() -> None:
    """Load the eduPerson attributes into `cn=config` (FR-DIR-03).

    Not optional and not cosmetic. An LDAP server rejects a whole filter that
    names an attribute type it does not know, so the OpenLDAP profile — which
    searches on `eduPersonPrincipalName` — fails *every* search against a
    directory without the schema, with `invalid attribute type` rather than an
    empty result. A fixture without it would be proving the client works against
    a server unlike the one it is written for.
    """
    connection = _config_connection()
    try:
        # Checked rather than attempted-and-forgiven. Re-adding a schema entry
        # fails with a *generic* error naming a duplicate attribute type, not
        # with `entryAlreadyExists`: the server parses the definitions before it
        # looks at the DN. Catching that by message would be a string match on
        # somebody else's wording.
        if _schema_present(connection):
            log("eduPerson schema present")
            return
        connection.add(SCHEMA_DN, ["olcSchemaConfig"], schema_entry())
        log("added the eduPerson schema")
    finally:
        connection.unbind()


def _schema_present(connection: Any) -> bool:
    connection.search(
        search_base="cn=schema,cn=config",
        search_filter="(cn=*eduperson)",
        attributes=["cn"],
    )
    return bool(connection.response)


def person(
    uid: str, given: str, surname: str, mail: str, *, affiliations: list[str]
) -> tuple[str, dict[str, Any]]:
    """One `inetOrgPerson`, decorated with the eduPerson auxiliary class.

    Auxiliary rather than structural: eduPerson describes what a directory
    additionally knows about a person, not what kind of thing they are.
    """
    return (
        f"uid={uid},{PEOPLE}",
        {
            "objectClass": [
                "inetOrgPerson",
                "organizationalPerson",
                "person",
                "eduPerson",
                "top",
            ],
            "uid": uid,
            "cn": f"{given} {surname}",
            "sn": surname,
            "givenName": given,
            "displayName": f"{given} {surname}",
            "mail": mail,
            "eduPersonPrincipalName": f"{uid}@campus.test",
            "eduPersonAffiliation": affiliations,
            "eduPersonScopedAffiliation": [f"{value}@campus.test" for value in affiliations],
        },
    )


def group(name: str, members: list[str]) -> tuple[str, dict[str, Any]]:
    """A `groupOfNames`, which requires at least one member.

    The schema will not accept an empty one, so a group with no people in it
    lists the admin DN. That is a fixture artefact rather than a design
    statement, and it is why the tests assert on membership of named people
    rather than on group size.
    """
    return (
        f"cn={name},{GROUPS}",
        {
            "objectClass": ["groupOfNames", "top"],
            "cn": name,
            "member": members or [ADMIN_DN],
        },
    )


def main() -> int:
    if not ADMIN_PASSWORD:
        log("LDAP_ADMIN_PASSWORD is not set")
        return 1

    add_schema()
    enable_password_policy()

    server = Server(LDAP_URL, get_info=ALL, connect_timeout=10)
    connection = Connection(
        server, user=ADMIN_DN, password=ADMIN_PASSWORD, auto_bind=True, raise_exceptions=True
    )

    sam = f"uid=sam.obrien,{PEOPLE}"
    dana = f"uid=dana.wu,{PEOPLE}"
    marcus = f"uid=marcus.reed,{PEOPLE}"

    entries: list[tuple[str, dict[str, Any]]] = [
        (PEOPLE, {"objectClass": ["organizationalUnit", "top"], "ou": "people"}),
        (GROUPS, {"objectClass": ["organizationalUnit", "top"], "ou": "groups"}),
        person(
            "sam.obrien",
            "Samira",
            "O'Brien",
            "sam.obrien@campus.test",
            affiliations=["student", "member"],
        ),
        person("dana.wu", "Dana", "Wu", "dana.wu@campus.test", affiliations=["student", "member"]),
        person(
            "marcus.reed",
            "Marcus",
            "Reed",
            "marcus.reed@campus.test",
            affiliations=["staff", "member"],
        ),
        # Three levels. Nobody is a direct member of `campus-members`, so a
        # broker reading only direct membership finds nothing for a student.
        group("lms-students", [sam, dana]),
        group("staff", [marcus]),
        group("all-students", [f"cn=lms-students,{GROUPS}"]),
        group("campus-members", [f"cn=all-students,{GROUPS}", f"cn=staff,{GROUPS}"]),
    ]

    created = 0
    for dn, attributes in entries:
        object_class = attributes.pop("objectClass")
        try:
            connection.add(dn, object_class, attributes)
            created += 1
            log(f"added {dn}")
        except LDAPEntryAlreadyExistsResult:
            # Idempotent: this runs on every `up`, and overwriting an entry
            # would undo whatever a test had just done to it.
            log(f"present {dn}")
        except LDAPException as exc:
            log(f"failed {dn}: {exc}")
            return 1

    connection.unbind()
    log(f"seeded {created} new entries under {BASE_DN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
