"""Deciding who must enrol a second factor (FR-MFA-07).

Somebody who holds an entitlement marked `requires_aal2` will be challenged the
first time they reach it. If they have no factor, that challenge is not a prompt
— it is a dead end, and the person's experience is a system that asks for
something it never offered them a way to have.

Forced enrolment closes that: the requirement is computed at login, from what the
person is entitled to, so the prompt arrives before the wall rather than at it.

**Entitlements and roles both count.** The requirement names entitlements, and
they are the operative case — but a role marked `requires_aal2` is the same
statement about the same person, made in the other file. Honouring only one would
make an administrator who has no `requires_aal2` entitlement walk into the wall
this exists to prevent.

**Enrolled means confirmed.** A TOTP secret issued and never proved is a factor
that cannot be used, so treating it as enrolment would leave the person holding a
row instead of a credential — worse than being asked again, because nothing asks
again.

**This decides, it does not enforce.** The result is a flag on the session, read
by whatever is rendering the login. Refusing the session outright would lock out
the person whose phone broke the day their new role landed, which is a helpdesk
call rather than a security improvement.

**It is recomputed at every login rather than stored.** A role granted this
morning has to count this afternoon, and a stored flag is a copy of a fact that
changes in a different file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Requirement:
    """Whether enrolment is required, and what made it so."""

    required: bool
    reasons: tuple[str, ...] = ()
    """The entitlements and roles that demand a second factor.

    Named rather than counted, because "you must enrol" with no reason reads as
    an arbitrary imposition, and because the operator diagnosing "why is this
    person being asked?" is otherwise left comparing two config files by hand.
    """


def requirement(
    *,
    entitlements: set[str],
    roles: set[str],
    rules: Any,
    catalogue: Any,
    has_factor: bool,
) -> Requirement:
    """Whether this person must enrol before going any further (FR-MFA-07).

    `rules` is the lifecycle rule set and `catalogue` the role catalogue, taken
    as arguments rather than read from module state so this stays a function of
    its inputs — which is what makes the reasons testable without a database.
    """
    reasons = tuple(sorted(_demanding(entitlements, rules) | _roles_demanding(roles, catalogue)))
    # The reasons are reported whether or not enrolment is required, so an
    # operator can see that somebody is *already* covered rather than only that
    # nothing is being asked of them.
    return Requirement(required=bool(reasons) and not has_factor, reasons=reasons)


def _demanding(held: set[str], rules: Any) -> set[str]:
    """Entitlements the person holds that are marked `requires_aal2`.

    An entitlement the rules file does not describe demands nothing. It is a
    grant from an older version of the file or from another system, and inventing
    a requirement for it would force enrolment on a row nobody can explain.
    """
    known = getattr(rules, "entitlements", {})
    return {urn for urn in held if getattr(known.get(urn), "requires_aal2", False)}


def _roles_demanding(held: set[str], catalogue: Any) -> set[str]:
    """Roles the person holds that are marked `requires_aal2`."""
    known = getattr(catalogue, "roles", {})
    return {role for role in held if getattr(known.get(role), "requires_aal2", False)}
