"""Loading authorization policy from YAML (FR-AZ-03).

The same trust-boundary discipline the release policy and the lifecycle rules
have, because it is the same kind of file: declarative, edited by people who are
not deploying the broker, and load-bearing for who can reach what.

**`yaml.safe_load`, never `yaml.load`.** The full loader constructs arbitrary
Python objects. A policy file is the last place to hand somebody that.

**Everything is validated at load time.** An unknown effect, a malformed time
window, a rule with no id — refused here, where a human is looking at the file
they just changed. A rule that silently never matches is worse than a rejected
file: the access it was meant to deny stays open and the policy looks right.

**A duplicate rule id is refused.** Ids appear in every audit record, and two
rules sharing one makes "which rule decided this" unanswerable — which is the
question FR-AZ-04 exists to make answerable.
"""

from __future__ import annotations

from datetime import time
from pathlib import Path
from typing import Any, Final

import yaml

from campusid.authz.engine import AAL1, AAL2, Effect, PolicySet, Rule
from campusid.logging import get_logger

log = get_logger(__name__)

VALID_ASSURANCE: Final[frozenset[str]] = frozenset({"", AAL1, AAL2})


class AuthorizationPolicyError(ValueError):
    """A policy file could not be trusted.

    Names the offending rule, because the reader is the analyst who just edited
    it — the opposite audience from a protocol rejection, where saying less is
    the point.
    """


def load_policies(path: Path) -> PolicySet:
    """Read and validate an authorization policy file."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AuthorizationPolicyError(f"{path}: {exc}") from exc

    if not isinstance(document, dict):
        raise AuthorizationPolicyError(f"{path}: a policy file must be a mapping")

    raw = document.get("rules")
    if not isinstance(raw, list) or not raw:
        raise AuthorizationPolicyError(f"{path}: needs a non-empty `rules` list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in raw:
        rule = _rule(entry, path)
        if rule.id in seen:
            raise AuthorizationPolicyError(f"{path}: rule id {rule.id!r} is used twice")
        seen.add(rule.id)
        rules.append(rule)

    return PolicySet(tuple(rules))


def _rule(entry: Any, path: Path) -> Rule:
    if not isinstance(entry, dict):
        raise AuthorizationPolicyError(f"{path}: every rule must be a mapping")

    rule_id = entry.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise AuthorizationPolicyError(f"{path}: every rule needs an id")

    effect = entry.get("effect")
    if effect not in (Effect.PERMIT.value, Effect.DENY.value):
        # `challenge` is deliberately not writable. It is an *outcome* the
        # engine reaches when a permit's assurance falls short, not a decision a
        # policy author makes — one written by hand would challenge somebody the
        # policy never intended to permit at all.
        raise AuthorizationPolicyError(
            f"{path}: {rule_id}: effect must be permit or deny, not {effect!r}"
        )

    assurance = entry.get("assurance", "")
    if assurance not in VALID_ASSURANCE:
        raise AuthorizationPolicyError(f"{path}: {rule_id}: unknown assurance {assurance!r}")

    return Rule(
        id=rule_id,
        effect=Effect(effect),
        description=_text(entry.get("description"), rule_id, "description", path),
        entitlements=_names(entry.get("entitlements"), rule_id, "entitlements", path),
        affiliations=_names(entry.get("affiliations"), rule_id, "affiliations", path),
        roles=_names(entry.get("roles"), rule_id, "roles", path),
        actions=_names(entry.get("actions"), rule_id, "actions", path),
        resources=_names(entry.get("resources"), rule_id, "resources", path),
        resource_prefix=_text(entry.get("resource_prefix"), rule_id, "resource_prefix", path),
        classifications=_names(entry.get("classifications"), rule_id, "classifications", path),
        networks=_names(entry.get("networks"), rule_id, "networks", path),
        between=_window(entry.get("between"), rule_id, path),
        assurance=assurance,
    )


def _names(value: Any, rule_id: str, field: str, path: Path) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AuthorizationPolicyError(f"{path}: {rule_id}: {field} must be a list of strings")
    return frozenset(value)


def _text(value: Any, rule_id: str, field: str, path: Path) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise AuthorizationPolicyError(f"{path}: {rule_id}: {field} must be a string")
    return value


def _window(value: Any, rule_id: str, path: Path) -> tuple[time, time] | None:
    """A `["08:00", "18:00"]` pair, or nothing.

    Parsed here so a malformed one fails the load rather than the request. A
    rule with an unreadable window would otherwise match nothing, and a rule
    that matches nothing is a denial somebody believes is in place.
    """
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 2:
        raise AuthorizationPolicyError(
            f"{path}: {rule_id}: between must be two times, like ['08:00', '18:00']"
        )
    try:
        start = time.fromisoformat(str(value[0]))
        end = time.fromisoformat(str(value[1]))
    except ValueError as exc:
        raise AuthorizationPolicyError(f"{path}: {rule_id}: {exc}") from exc
    return (start, end)


class PolicyEngineStore:
    """Holds the loaded policy set and reloads it when the file changes.

    Last known good on a failed reload, for the reason every other policy store
    in this project keeps one: on a syntax error, an empty policy set denies
    everything at once and a permissive default grants everything at once.
    Neither is a state to be in at three in the morning.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fingerprint: float | None = None
        self._current = PolicySet()
        self.reload()

    @property
    def current(self) -> PolicySet:
        if self._mtime() != self._fingerprint:
            self.reload()
        return self._current

    def reload(self) -> None:
        try:
            loaded = load_policies(self._path)
        except AuthorizationPolicyError as exc:
            log.error("authz.policy.rejected", path=str(self._path), error=str(exc))
            return
        self._current = loaded
        self._fingerprint = self._mtime()
        log.info("authz.policy.loaded", path=str(self._path), rules=len(loaded.rules))

    def _mtime(self) -> float | None:
        try:
            return self._path.stat().st_mtime
        except OSError:
            return None
