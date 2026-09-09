"""Affiliation transition rules (FR-LC-04).

What a person's affiliations entitle them to, and what changes when those
affiliations do. Declarative and in a file for the same reason release policy is:
whether a graduating student keeps their email alias is a registrar's decision,
asked once a year and answered by somebody who does not deploy the broker.

Three ideas carry the whole module.

**An entitlement exists because something justifies it.** A person's entitlement
set is the union of what their *current* affiliations grant — never a set that
accumulates. That is what makes the mover case correct without any code that
knows about movers: recompute, and anything whose justification went away is
simply not in the new set. PRD §8.1 puts it as "removal is a matter of removing
the justification", and it is the difference between an access review that ends
and one that runs forever.

**A grace period delays a revocation; it does not withhold it.** `grace_days: 30`
on LMS access means the access ends thirty days after the affiliation did,
whether or not anybody remembers. The transition returns *when* each revocation
falls due, so the caller can schedule it durably rather than hoping a process
stays alive (FR-LC-05).

**The delta is the answer, not the new state.** A transition returns what was
granted, what was revoked now, and what is revoked later — because that is what
has to be applied downstream, audited, and shown on a timeline. Handing back a
new set and leaving the caller to diff it would put the interesting part of the
lifecycle in whichever caller wrote the subtraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Final

import yaml

from campusid.logging import get_logger
from campusid.policy.normalize import AFFILIATION_VOCABULARY

log = get_logger(__name__)

CLASSIFICATIONS: Final[frozenset[str]] = frozenset(
    {"public", "directory", "internal", "restricted"}
)
"""PRD §8.3's four levels. An entitlement carries one so the release policy and
the log redaction can both read it without a second catalogue."""

MAX_GRACE_DAYS: Final = 365
"""A grace period longer than a year is not a grace period, it is a decision not
to deprovision. Refused at load time, where a human is looking at the file."""


class LifecycleRulesError(ValueError):
    """A rules file could not be trusted.

    Names the offending rule, because the reader is the analyst who just edited
    it — the opposite audience from a protocol rejection, where saying less is
    the whole point.
    """


@dataclass(frozen=True, slots=True)
class Entitlement:
    """One thing a person may be entitled to."""

    urn: str
    display_name: str
    classification: str = "internal"

    grace_days: int = 0
    """How long the entitlement survives the affiliation that justified it.

    Zero means it ends with the affiliation. Anything else is a deliberate
    decision by somebody who owns the consequence, which is why it lives in the
    file rather than in a scheduler's configuration.
    """

    requires_aal2: bool = False
    """FR-AZ-05. Reaching it from a single-factor session is a step-up challenge
    rather than a denial."""


@dataclass(frozen=True, slots=True)
class Rule:
    """Which affiliations justify which entitlements."""

    id: str
    affiliations: frozenset[str]
    grants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Grant:
    """One entitlement a person holds, and why.

    The justification is the point. An entitlement without one cannot be
    reviewed, cannot be removed for a reason, and outlives whatever it was for.
    """

    urn: str
    rule_id: str
    affiliation: str


@dataclass(frozen=True, slots=True)
class Revocation:
    """An entitlement that is going away, and when."""

    urn: str
    effective: date
    """Today for an immediate revocation, later for one inside its grace period.
    A caller schedules against this rather than deciding for itself."""

    grace_days: int = 0


@dataclass(frozen=True, slots=True)
class Delta:
    """What a transition changes."""

    granted: tuple[Grant, ...] = ()
    retained: tuple[Grant, ...] = ()
    """Still justified afterwards. Named rather than implied, because "kept the
    mail alias" is the interesting half of the graduation case and a timeline
    that showed only additions and removals would not record it."""

    revoked: tuple[Revocation, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.granted and not self.revoked

    @property
    def immediate(self) -> tuple[Revocation, ...]:
        return tuple(revocation for revocation in self.revoked if revocation.grace_days == 0)

    @property
    def deferred(self) -> tuple[Revocation, ...]:
        """Revocations inside a grace period, which a caller has to schedule.

        Separated from the immediate ones because forgetting to schedule these
        is the failure mode that leaves access in place forever, and a caller
        that has to ask for them separately is a caller that noticed.
        """
        return tuple(revocation for revocation in self.revoked if revocation.grace_days > 0)


@dataclass(frozen=True, slots=True)
class LifecycleRules:
    """The rules as of one load."""

    entitlements: dict[str, Entitlement] = field(default_factory=dict)
    rules: tuple[Rule, ...] = ()

    def grants_for(self, affiliations: set[str]) -> tuple[Grant, ...]:
        """Everything these affiliations justify, each with the reason.

        One entitlement may be justified twice — a person who is both student
        and faculty holds the LMS through two rules — and both justifications
        are returned. Collapsing them here would make losing one affiliation
        look like losing the entitlement.
        """
        return tuple(
            Grant(urn=urn, rule_id=rule.id, affiliation=affiliation)
            for rule in self.rules
            for affiliation in sorted(rule.affiliations & affiliations)
            for urn in rule.grants
        )

    def transition(self, before: set[str], after: set[str], *, on: date | None = None) -> Delta:
        """What changes when a person's affiliations change.

        The joiner case is `before` empty, the leaver case is `after` empty, and
        the mover case is neither — one method rather than three, because they
        are the same computation and three would eventually disagree.
        """
        today = on or date.today()
        held = self.grants_for(before)
        now = self.grants_for(after)

        held_urns = {grant.urn for grant in held}
        current_urns = {grant.urn for grant in now}

        granted = tuple(grant for grant in now if grant.urn not in held_urns)
        retained = tuple(grant for grant in now if grant.urn in held_urns)

        revoked = tuple(self._revocation(urn, today) for urn in sorted(held_urns - current_urns))
        return Delta(granted=granted, retained=retained, revoked=revoked)

    def _revocation(self, urn: str, today: date) -> Revocation:
        entitlement = self.entitlements.get(urn)
        grace = entitlement.grace_days if entitlement else 0
        return Revocation(urn=urn, effective=today + timedelta(days=grace), grace_days=grace)


def load_rules(path: Path) -> LifecycleRules:
    """Read and validate a rules file.

    `yaml.safe_load`, never `yaml.load`: the full loader constructs arbitrary
    Python objects, and this is a file edited by the most people under the most
    time pressure.

    Everything is checked here rather than at runtime — unknown affiliations,
    grants naming an entitlement that does not exist, duplicate URNs. Deferring
    those means the failure appears as "somebody did not get their access", and
    the reflex fix for that is a broader rule.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LifecycleRulesError(f"{path}: {exc}") from exc

    if not isinstance(document, dict):
        raise LifecycleRulesError(f"{path}: a rules file must be a mapping")

    entitlements = _entitlements(document.get("entitlements"), path)
    rules = _rules(document.get("rules"), entitlements, path)
    return LifecycleRules(entitlements=entitlements, rules=rules)


def _entitlements(raw: Any, path: Path) -> dict[str, Entitlement]:
    if not isinstance(raw, list) or not raw:
        raise LifecycleRulesError(f"{path}: needs a non-empty `entitlements` list")

    catalogue: dict[str, Entitlement] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            raise LifecycleRulesError(f"{path}: every entitlement must be a mapping")

        urn = entry.get("urn")
        if not isinstance(urn, str) or not urn.startswith("urn:"):
            raise LifecycleRulesError(f"{path}: {urn!r} is not a URN")
        if urn in catalogue:
            # Two definitions of one entitlement mean two grace periods, and
            # whichever loses is the one somebody thought they had set.
            raise LifecycleRulesError(f"{path}: {urn} is declared twice")

        classification = entry.get("classification", "internal")
        if classification not in CLASSIFICATIONS:
            raise LifecycleRulesError(f"{path}: {urn}: unknown classification {classification!r}")

        grace_days = entry.get("grace_days", 0)
        if not isinstance(grace_days, int) or isinstance(grace_days, bool) or grace_days < 0:
            raise LifecycleRulesError(f"{path}: {urn}: grace_days must be a whole number of days")
        if grace_days > MAX_GRACE_DAYS:
            raise LifecycleRulesError(
                f"{path}: {urn}: {grace_days} days is not a grace period, it is a decision "
                "not to deprovision"
            )

        display_name = entry.get("display_name")
        if not isinstance(display_name, str) or not display_name:
            raise LifecycleRulesError(f"{path}: {urn}: needs a display_name")

        catalogue[urn] = Entitlement(
            urn=urn,
            display_name=display_name,
            classification=classification,
            grace_days=grace_days,
            requires_aal2=bool(entry.get("requires_aal2", False)),
        )
    return catalogue


def _rules(raw: Any, catalogue: dict[str, Entitlement], path: Path) -> tuple[Rule, ...]:
    if not isinstance(raw, list) or not raw:
        raise LifecycleRulesError(f"{path}: needs a non-empty `rules` list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise LifecycleRulesError(f"{path}: every rule must be a mapping")

        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise LifecycleRulesError(f"{path}: every rule needs an id")
        if rule_id in seen:
            # Ids appear in every grant's justification and on the timeline; two
            # rules sharing one makes an access review unable to say which fired.
            raise LifecycleRulesError(f"{path}: rule id {rule_id!r} is used twice")
        seen.add(rule_id)

        affiliations = entry.get("affiliations")
        if not isinstance(affiliations, list) or not affiliations:
            raise LifecycleRulesError(f"{path}: {rule_id}: needs at least one affiliation")
        unknown = {a for a in affiliations if a not in AFFILIATION_VOCABULARY}
        if unknown:
            # An affiliation outside eduPerson's vocabulary can never match a
            # normalised value, so the rule would silently never fire.
            raise LifecycleRulesError(
                f"{path}: {rule_id}: {sorted(unknown)} are outside the eduPerson vocabulary"
            )

        grants = entry.get("grants")
        if not isinstance(grants, list):
            raise LifecycleRulesError(f"{path}: {rule_id}: grants must be a list")
        missing = [urn for urn in grants if urn not in catalogue]
        if missing:
            raise LifecycleRulesError(f"{path}: {rule_id}: undeclared entitlements {missing}")

        rules.append(
            Rule(
                id=rule_id,
                affiliations=frozenset(affiliations),
                grants=tuple(grants),
            )
        )
    return tuple(rules)


class RulesStore:
    """Holds the loaded rules and reloads them when the file changes.

    The same last-known-good behaviour the release policy has, for the same
    reason: on a syntax error, an empty rule set would revoke every entitlement
    on campus at once and a permissive default would grant them. Keeping what
    was working and shouting about the file is the only failure anybody can
    recover from.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fingerprint: float | None = None
        self._current = LifecycleRules()
        self.reload()

    @property
    def current(self) -> LifecycleRules:
        if self._changed():
            self.reload()
        return self._current

    def reload(self) -> None:
        try:
            loaded = load_rules(self._path)
        except LifecycleRulesError as exc:
            log.error("lifecycle.rules.rejected", path=str(self._path), error=str(exc))
            return

        self._current = loaded
        self._fingerprint = self._mtime()
        log.info(
            "lifecycle.rules.loaded",
            path=str(self._path),
            entitlements=len(loaded.entitlements),
            rules=len(loaded.rules),
        )

    def _changed(self) -> bool:
        return self._mtime() != self._fingerprint

    def _mtime(self) -> float | None:
        try:
            return self._path.stat().st_mtime
        except OSError:
            return None
