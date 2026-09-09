"""Directory profiles: the same question, asked two ways (FR-DIR-03).

Active Directory and OpenLDAP hold the same facts under different names.
"Who is this person?" is `sAMAccountName` in one and `uid` in the other; their
immutable key is `objectGUID` against `entryUUID`; group membership is `memberOf`
in both, except when it is not. A broker that hardcodes either set works at
exactly one institution.

So the names are data. A profile is a small record of what this directory calls
things, and every query is built from one — which also means adding a third
convention is a new profile rather than a new branch in the search code.

**The immutable key is the one that matters.** `sAMAccountName` and `uid` are
reassignable: a leaver's login is freed and a joiner gets it, which is the same
reuse incident the identity registry exists to prevent, arriving from the other
side. `objectGUID` and `entryUUID` are not reassignable, so a profile that names
them lets an account be followed through a rename and lets a rename be
distinguished from a different person.

**No profile guesses.** A directory is configured to a profile, never detected
from what it answers. Detection is a probe that succeeds against a hostile
server too, and picking the attribute names an attacker's directory suggested is
a strange place to end up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from campusid.directory.escaping import all_of, any_of, equality


@dataclass(frozen=True, slots=True)
class DirectoryProfile:
    """What one flavour of directory calls things."""

    name: str

    login_attributes: tuple[str, ...]
    """What somebody types, or what an assertion carries. Several, because a
    directory often answers to more than one and an integration that picks the
    wrong single name fails for the users who only have the other."""

    immutable_id: str
    """The attribute that survives a rename and is never reassigned."""

    member_of: str
    """The reverse-membership attribute, when the directory maintains one."""

    member: str
    """The forward-membership attribute on the group, for the fallback search."""

    group_name: str
    user_object_class: str
    group_object_class: str

    mail: str = "mail"
    display_name: str = "displayName"
    given_name: str = "givenName"
    surname: str = "sn"

    disabled_flag: str | None = None
    """How this directory says an account is disabled, when it says so with a
    flag. `None` means disabling is expressed some other way — see
    `campusid.directory.writes`."""

    def user_filter(self, login: str) -> str:
        """Find one person by whatever this directory calls a login.

        Constrained by object class as well as by name. Without it a search for
        `uid=admin` can be answered by a group, a computer account or anything
        else somebody put in the tree, and the caller has no way to tell.
        """
        return all_of(
            equality("objectClass", self.user_object_class),
            any_of(self.login_attributes, login),
        )

    def user_by_id_filter(self, immutable_id: str) -> str:
        return all_of(
            equality("objectClass", self.user_object_class),
            equality(self.immutable_id, immutable_id),
        )

    def group_members_filter(self, member_dn: str) -> str:
        """The fallback for a directory with no `memberOf` (FR-DIR-04).

        Asked of the groups rather than of the person: "which groups list this
        DN?". Slower than reading an attribute off the user, which is why it is
        the fallback, but it is the only way when the directory does not
        maintain the reverse index.
        """
        return all_of(
            equality("objectClass", self.group_object_class),
            equality(self.member, member_dn),
        )

    def attributes(self) -> tuple[str, ...]:
        """What to ask for on a user search.

        Named explicitly rather than fetching everything. A directory entry can
        carry photographs, certificates and a decade of operational cruft, and
        pulling all of it on every login is both slow and a disclosure we did
        not intend.
        """
        wanted = [
            self.immutable_id,
            self.member_of,
            self.mail,
            self.display_name,
            self.given_name,
            self.surname,
            *self.login_attributes,
        ]
        if self.disabled_flag:
            wanted.append(self.disabled_flag)
        return tuple(dict.fromkeys(wanted))


ACTIVE_DIRECTORY: Final = DirectoryProfile(
    name="active-directory",
    # `userPrincipalName` first: it is the one that looks like an email address
    # and the one a federated assertion is most likely to carry.
    login_attributes=("userPrincipalName", "sAMAccountName"),
    immutable_id="objectGUID",
    member_of="memberOf",
    member="member",
    group_name="cn",
    user_object_class="user",
    group_object_class="group",
    disabled_flag="userAccountControl",
)
"""Active Directory.

`userAccountControl` is a bit field rather than a boolean, which is why
disabling is a separate module: setting it to 2 disables the account and also
clears every other flag on it.
"""

OPENLDAP: Final = DirectoryProfile(
    name="openldap",
    login_attributes=("eduPersonPrincipalName", "uid"),
    immutable_id="entryUUID",
    member_of="memberOf",
    member="member",
    group_name="cn",
    user_object_class="inetOrgPerson",
    group_object_class="groupOfNames",
    disabled_flag=None,
)
"""OpenLDAP with the eduPerson schema.

`memberOf` is present only when the `memberof` overlay is configured, which many
deployments do not do — so the reverse search is not a theoretical fallback here,
it is the common case.

No disabled flag: OpenLDAP expresses a locked account through
`pwdAccountLockedTime` from the password-policy overlay, which is a value rather
than a bit and belongs with the write operations.
"""

PROFILES: Final[dict[str, DirectoryProfile]] = {
    ACTIVE_DIRECTORY.name: ACTIVE_DIRECTORY,
    OPENLDAP.name: OPENLDAP,
}


def profile(name: str) -> DirectoryProfile:
    """Look up a configured profile, refusing an unknown one.

    Refused rather than defaulted. A typo in the profile name would otherwise
    silently select Active Directory's attribute names against an OpenLDAP
    server, and every search would return nothing — which reads as "the
    directory has no users" rather than as a configuration error.
    """
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown directory profile {name!r}; known profiles are {sorted(PROFILES)}"
        ) from None
