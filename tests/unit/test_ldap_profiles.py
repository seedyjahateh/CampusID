"""Directory profiles (FR-DIR-03).

Active Directory and OpenLDAP hold the same facts under different names, and a
broker that hardcodes either set works at exactly one institution. The names are
data, and these tests are mostly about what each profile promises rather than
about clever behaviour.

The one that matters is the immutable identifier. `sAMAccountName` and `uid` are
reassignable — a leaver's login is freed and a joiner gets it, which is the ePPN
reuse incident arriving from the directory side.
"""

from __future__ import annotations

import pytest

from campusid.directory.profiles import (
    ACTIVE_DIRECTORY,
    OPENLDAP,
    PROFILES,
    DirectoryProfile,
    profile,
)


@pytest.mark.parametrize("directory", list(PROFILES.values()), ids=list(PROFILES))
def test_a_profile_names_a_non_reassignable_identifier(directory: DirectoryProfile) -> None:
    """Not a login. A profile whose immutable id was `uid` would follow a
    reassigned name onto the wrong person."""
    assert directory.immutable_id not in directory.login_attributes


def test_active_directory_uses_its_own_vocabulary() -> None:
    assert ACTIVE_DIRECTORY.login_attributes == ("userPrincipalName", "sAMAccountName")
    assert ACTIVE_DIRECTORY.immutable_id == "objectGUID"
    assert ACTIVE_DIRECTORY.user_object_class == "user"


def test_openldap_uses_the_edu_person_vocabulary() -> None:
    assert OPENLDAP.login_attributes == ("eduPersonPrincipalName", "uid")
    assert OPENLDAP.immutable_id == "entryUUID"
    assert OPENLDAP.user_object_class == "inetOrgPerson"


def test_the_principal_name_is_tried_before_the_short_name() -> None:
    """A federated assertion carries something that looks like an email address,
    and matching it against `sAMAccountName` first would miss."""
    assert ACTIVE_DIRECTORY.login_attributes[0] == "userPrincipalName"
    assert OPENLDAP.login_attributes[0] == "eduPersonPrincipalName"


@pytest.mark.parametrize("directory", list(PROFILES.values()), ids=list(PROFILES))
def test_a_search_asks_for_named_attributes_only(directory: DirectoryProfile) -> None:
    """A directory entry can carry photographs, certificates and a decade of
    operational cruft. Fetching all of it on every login is both slow and a
    disclosure nobody intended."""
    wanted = directory.attributes()

    assert directory.immutable_id in wanted
    assert directory.member_of in wanted
    assert all(attribute in wanted for attribute in directory.login_attributes)


@pytest.mark.parametrize("directory", list(PROFILES.values()), ids=list(PROFILES))
def test_the_attribute_list_has_no_duplicates(directory: DirectoryProfile) -> None:
    """`mail` appearing twice is harmless and also means the list was assembled
    without anybody checking, which is how the disclosure above creeps back."""
    wanted = directory.attributes()

    assert len(wanted) == len(set(wanted))


def test_an_unknown_profile_is_refused_rather_than_defaulted() -> None:
    """A typo would otherwise select Active Directory's names against an
    OpenLDAP server, and every search would return nothing — which reads as "the
    directory has no users" rather than as a configuration error."""
    with pytest.raises(ValueError, match="unknown directory profile"):
        profile("openldp")


def test_the_error_names_the_profiles_that_do_exist() -> None:
    """The reader is an operator who just mistyped something, which is the
    opposite audience from a protocol rejection."""
    with pytest.raises(ValueError, match="active-directory"):
        profile("nonsense")


@pytest.mark.parametrize("name", list(PROFILES))
def test_every_registered_profile_resolves(name: str) -> None:
    assert profile(name).name == name


def test_only_active_directory_has_a_disabled_flag() -> None:
    """OpenLDAP expresses a locked account through `pwdAccountLockedTime`, which
    is a value rather than a bit — so "how do I disable this" is a different
    question per directory and not a field either can share."""
    assert ACTIVE_DIRECTORY.disabled_flag == "userAccountControl"
    assert OPENLDAP.disabled_flag is None
