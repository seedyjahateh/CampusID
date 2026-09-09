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


def add_schema() -> None:
    """Load the eduPerson attributes into `cn=config` (FR-DIR-03).

    Not optional and not cosmetic. An LDAP server rejects a whole filter that
    names an attribute type it does not know, so the OpenLDAP profile — which
    searches on `eduPersonPrincipalName` — fails *every* search against a
    directory without the schema, with `invalid attribute type` rather than an
    empty result. A fixture without it would be proving the client works against
    a server unlike the one it is written for.
    """
    server = Server(LDAP_URL, get_info=ALL, connect_timeout=10)
    connection = Connection(
        server, user=CONFIG_DN, password=CONFIG_PASSWORD, auto_bind=True, raise_exceptions=True
    )
    try:
        connection.add(SCHEMA_DN, ["olcSchemaConfig"], schema_entry())
        log("added the eduPerson schema")
    except LDAPEntryAlreadyExistsResult:
        log("eduPerson schema present")
    finally:
        connection.unbind()


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
