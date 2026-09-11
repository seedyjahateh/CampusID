"""Roles, their derivation, and what may not be held together (FR-AZ-01, 07).

A role is a name for a job somebody does. Entitlements say what they may reach;
a role says why. At review time that is the whole difference: "this person has
`lms:access`" invites the question, and "this person is a course administrator"
answers it.

**Most roles are derived, not assigned.** Being a student makes you a student,
and somebody re-typing that fact into a role table is somebody who will one day
forget to un-type it. Derivation gives every assignment an origin, so losing the
origin loses the role — the same rule entitlements follow, for the same reason.

**A role held from two origins survives losing one.** Somebody who is a course
administrator because they teach *and* because an administrator granted it
directly keeps the role when they stop teaching. That is why an assignment is
one row per origin rather than one row per person and role, and it is the case
FR-AZ-01 names.

**Separation of duties is refused at assignment time.** One person who can both
raise a payment and approve it can pay themselves, and no amount of logging
turns that back into a control. The refusal names the conflict, because the
person doing the assigning is the one who can undo it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from campusid.logging import get_logger

log = get_logger(__name__)


class Origin(StrEnum):
    """Why somebody holds a role (FR-AZ-01).

    Recorded on every assignment. An investigation asks "how did they get
    this?", and the honest answer is different for each — a derived role is a
    fact about the person, while a direct one is a decision somebody made and
    should be able to be asked about.
    """

    AFFILIATION = "affiliation"
    GROUP = "group"
    DIRECT = "direct"


class RoleError(ValueError):
    """A role file could not be trusted, or an assignment was refused."""


@dataclass(frozen=True, slots=True)
class Role:
    id: str
    display_name: str
    description: str = ""
    requires_aal2: bool = False
    """A role whose holder must have authenticated with two factors. Carried
    here rather than on each rule that mentions it, for the same reason a
    resource carries one: a policy author cannot forget it next year."""


@dataclass(frozen=True, slots=True)
class Derivation:
    """A fact about somebody that gives them a role."""

    role: str
    origin: Origin
    value: str
    """The affiliation or the group name that fires it."""


@dataclass(frozen=True, slots=True)
class Conflict:
    """Two roles that may not be held at once."""

    roles: frozenset[str]
    reason: str

    def __str__(self) -> str:
        return f"{sorted(self.roles)}: {self.reason}"


@dataclass(frozen=True, slots=True)
class Assignment:
    """One reason somebody holds one role."""

    role: str
    origin: Origin
    reference: str
    """What produced it — the affiliation, the group, or who granted it."""


@dataclass(frozen=True, slots=True)
class RoleCatalogue:
    """The roles, their derivations, and the pairs that conflict."""

    roles: dict[str, Role] = field(default_factory=dict)
    derivations: tuple[Derivation, ...] = ()
    conflicts: tuple[Conflict, ...] = ()

    def derive(
        self, *, affiliations: set[str] | None = None, groups: set[str] | None = None
    ) -> tuple[Assignment, ...]:
        """Which roles these facts produce, each with the fact that produced it.

        Returns assignments rather than role names so the caller can store the
        origin. A derivation that returned bare names would make "they are an
        instructor" unfalsifiable the moment the affiliation changed.
        """
        held_affiliations = affiliations or set()
        held_groups = groups or set()

        return tuple(
            Assignment(role=rule.role, origin=rule.origin, reference=rule.value)
            for rule in self.derivations
            if (rule.origin is Origin.AFFILIATION and rule.value in held_affiliations)
            or (rule.origin is Origin.GROUP and rule.value in held_groups)
        )

    def conflicting(self, roles: set[str]) -> tuple[Conflict, ...]:
        """Every separation-of-duties pair this set of roles violates.

        All of them rather than the first: an assignment that fixed one conflict
        and hit another on the next attempt would take as many rounds as there
        are conflicts to discover a role somebody cannot have.
        """
        return tuple(conflict for conflict in self.conflicts if conflict.roles <= roles)

    def assert_compatible(self, roles: set[str]) -> None:
        """Refuse a set of roles that violates separation of duties (FR-AZ-07)."""
        violations = self.conflicting(roles)
        if violations:
            raise RoleError(
                "separation of duties refuses this combination — "
                + "; ".join(str(conflict) for conflict in violations)
            )

    def requires_aal2(self, roles: set[str]) -> bool:
        """Whether any of these roles demands a second factor."""
        return any(self.roles[role].requires_aal2 for role in roles if role in self.roles)


VALID_ORIGINS: Final[frozenset[str]] = frozenset({"affiliation", "group"})
"""What a *derivation* may name. `direct` is not one: a direct assignment is
somebody's decision, not a fact that can be derived from the registry, and a
derivation rule producing one would grant it to everybody who matched."""


def load_roles(path: Path) -> RoleCatalogue:
    """Read and validate a role file.

    Everything checked at load time, where a human is looking. A derivation
    naming a role that does not exist is the failure that matters: it produces
    an assignment nothing can interpret, and the access it was meant to grant
    simply never arrives.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RoleError(f"{path}: {exc}") from exc

    if not isinstance(document, dict):
        raise RoleError(f"{path}: a role file must be a mapping")

    roles = _roles(document.get("roles"), path)
    derivations = _derivations(document.get("derivations"), roles, path)
    conflicts = _conflicts(document.get("separation_of_duties"), roles, path)

    return RoleCatalogue(roles=roles, derivations=derivations, conflicts=conflicts)


def _roles(raw: Any, path: Path) -> dict[str, Role]:
    if not isinstance(raw, list) or not raw:
        raise RoleError(f"{path}: needs a non-empty `roles` list")

    catalogue: dict[str, Role] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            raise RoleError(f"{path}: every role must be a mapping")
        role_id = entry.get("id")
        if not isinstance(role_id, str) or not role_id:
            raise RoleError(f"{path}: every role needs an id")
        if role_id in catalogue:
            # Ids appear on every assignment and in every decision; two roles
            # sharing one makes an access review unable to say which is held.
            raise RoleError(f"{path}: role id {role_id!r} is used twice")

        display = entry.get("display_name")
        if not isinstance(display, str) or not display:
            raise RoleError(f"{path}: {role_id}: needs a display_name")

        catalogue[role_id] = Role(
            id=role_id,
            display_name=display,
            description=str(entry.get("description", "")),
            requires_aal2=bool(entry.get("requires_aal2", False)),
        )
    return catalogue


def _derivations(raw: Any, roles: dict[str, Role], path: Path) -> tuple[Derivation, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise RoleError(f"{path}: derivations must be a list")

    derived: list[Derivation] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise RoleError(f"{path}: every derivation must be a mapping")

        role = entry.get("role")
        if role not in roles:
            raise RoleError(f"{path}: derivation names undeclared role {role!r}")

        named = {key for key in VALID_ORIGINS if key in entry}
        if len(named) != 1:
            raise RoleError(
                f"{path}: {role}: a derivation names exactly one of {sorted(VALID_ORIGINS)}"
            )

        origin = named.pop()
        value = entry[origin]
        if not isinstance(value, str) or not value:
            raise RoleError(f"{path}: {role}: {origin} must be a non-empty string")

        derived.append(Derivation(role=role, origin=Origin(origin), value=value))
    return tuple(derived)


def _conflicts(raw: Any, roles: dict[str, Role], path: Path) -> tuple[Conflict, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise RoleError(f"{path}: separation_of_duties must be a list")

    conflicts: list[Conflict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise RoleError(f"{path}: every conflict must be a mapping")

        pair = entry.get("roles")
        if not isinstance(pair, list) or len(pair) < 2:
            raise RoleError(f"{path}: a conflict needs at least two roles")

        unknown = [role for role in pair if role not in roles]
        if unknown:
            # A conflict naming a role that does not exist can never fire, so
            # the control somebody believes is in place is not.
            raise RoleError(f"{path}: conflict names undeclared roles {unknown}")

        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason:
            # The reason is what the refusal says back. Without it an
            # administrator is told no and has nobody to argue with.
            raise RoleError(f"{path}: conflict {pair} needs a reason")

        conflicts.append(Conflict(roles=frozenset(pair), reason=reason))
    return tuple(conflicts)


class RoleStore:
    """Holds the loaded catalogue and reloads it when the file changes.

    Last known good on failure, like every other policy store here: an empty
    catalogue derives no roles at all, which silently removes everybody's access
    rather than failing loudly.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fingerprint: float | None = None
        self._current = RoleCatalogue()
        self.reload()

    @property
    def current(self) -> RoleCatalogue:
        if self._mtime() != self._fingerprint:
            self.reload()
        return self._current

    def reload(self) -> None:
        try:
            loaded = load_roles(self._path)
        except RoleError as exc:
            log.error("authz.roles.rejected", path=str(self._path), error=str(exc))
            return
        self._current = loaded
        self._fingerprint = self._mtime()
        log.info(
            "authz.roles.loaded",
            path=str(self._path),
            roles=len(loaded.roles),
            derivations=len(loaded.derivations),
            conflicts=len(loaded.conflicts),
        )

    def _mtime(self) -> float | None:
        try:
            return self._path.stat().st_mtime
        except OSError:
            return None
