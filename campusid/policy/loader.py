"""Loading release policy from YAML, with hot reload (FR-ARP-01).

Policy is declarative and lives in files rather than in code, because the people
who decide what an SP may see are IAM analysts, not the people who deploy the
broker. A new app federating should be a reviewed pull request against a policy
directory, not a release.

That makes the loader a trust boundary, and it behaves like one.

**`yaml.safe_load`, never `yaml.load`.** The full loader constructs arbitrary
Python objects from a document; a policy file would become a code-execution
surface, and policy files are exactly the thing that gets edited by the most
people under the most time pressure.

**Everything is validated at load time.** An unknown attribute name, an
unrecognised rule kind, a restricted attribute somebody tried to allow — all
refused here, where a human is looking at the file they just changed. Deferring
those to runtime means the failure appears as "the app doesn't get the
attribute", and the reflex fix for that is to add a broader rule.

**A failed reload keeps the last known good policy.** The alternative is
choosing between two bad outcomes on a syntax error: an empty policy locks
everyone out of every app at once, and a default-permissive one is a disclosure.
Keeping what was already working and shouting about the file is the only option
that fails in a direction someone can recover from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, get_args

import yaml

from campusid.logging import get_logger
from campusid.policy.attributes import (
    RESEARCH_AND_SCHOLARSHIP,
    Classification,
    definition,
)
from campusid.policy.release import Effect, ReleasePolicy, ReleaseRule, SubjectIdMode

log = get_logger(__name__)

VALID_EFFECTS: Final[frozenset[str]] = frozenset(get_args(Effect))
VALID_SUBJECT_ID_MODES: Final[frozenset[str]] = frozenset(get_args(SubjectIdMode))
KNOWN_CATEGORIES: Final[frozenset[str]] = frozenset({RESEARCH_AND_SCHOLARSHIP})

POLICY_SUFFIXES: Final[tuple[str, ...]] = (".yaml", ".yml")


class PolicyError(ValueError):
    """A policy file could not be trusted.

    Its message names the file and the offending line's subject, because the
    reader is an analyst who just edited it — the opposite audience from a
    protocol rejection, where saying less is the whole point.
    """


@dataclass(frozen=True, slots=True)
class PolicySet:
    """Every SP's policy, as of one load."""

    policies: dict[str, ReleasePolicy]
    default_scope: str

    def get(self, sp_entity_id: str) -> ReleasePolicy:
        """The policy for an SP, or an empty one.

        An SP with no policy file gets a policy with no rules, which under
        default-deny releases nothing but the subject identifier. That is the
        right answer for an unconfigured SP: it can authenticate people, and it
        learns nothing about them until somebody decides what it may see.

        Aliases resolve here too, so an application federated over both SAML and
        OIDC reaches the same policy under either name.
        """
        return self.policies.get(sp_entity_id) or ReleasePolicy(sp_entity_id=sp_entity_id)


class PolicyStore:
    """Holds the loaded policy set and reloads it when the files change.

    Hot reload is by modification time rather than a filesystem watch: one
    `stat` per file on a request that is already doing signature verification is
    not the cost worth engineering around, and a watch adds a background thread
    whose failure mode is silently serving stale policy.
    """

    def __init__(self, directory: Path, *, default_scope: str) -> None:
        self._directory = directory
        self._default_scope = default_scope
        self._fingerprint: tuple[tuple[str, float], ...] = ()
        self._current = PolicySet(policies={}, default_scope=default_scope)
        self.reload()

    @property
    def current(self) -> PolicySet:
        """The policy set as of the last successful load."""
        return self._current

    def get(self, sp_entity_id: str) -> ReleasePolicy:
        """Reload if the files changed, then answer."""
        if self._changed():
            self.reload()
        return self._current.get(sp_entity_id)

    def reload(self) -> PolicySet:
        """Re-read the directory, keeping the previous set if anything is wrong."""
        fingerprint = self._fingerprint_now()
        try:
            policies = load_directory(self._directory)
        except (PolicyError, OSError) as exc:
            # Deliberately does not re-raise. A broken file must not take the
            # broker down or empty the policy set; the previous one keeps
            # working while somebody fixes the commit that caused this.
            log.error(
                "policy_reload_failed",
                directory=str(self._directory),
                error=str(exc),
                keeping="last known good",
            )
            self._fingerprint = fingerprint
            return self._current

        self._current = PolicySet(policies=policies, default_scope=self._default_scope)
        self._fingerprint = fingerprint
        log.info("policy_loaded", directory=str(self._directory), entities=len(policies))
        return self._current

    def _changed(self) -> bool:
        return self._fingerprint_now() != self._fingerprint

    def _fingerprint_now(self) -> tuple[tuple[str, float], ...]:
        """Name and mtime of every policy file, sorted.

        Includes the names, not just the times, so deleting a file is a change
        even when nothing else was touched — a removed policy must stop
        applying, and an mtime-only fingerprint would not notice.
        """
        if not self._directory.is_dir():
            return ()
        return tuple(
            sorted(
                (path.name, path.stat().st_mtime)
                for path in self._directory.iterdir()
                if path.suffix in POLICY_SUFFIXES
            )
        )


def load_directory(directory: Path) -> dict[str, ReleasePolicy]:
    """Load every policy file in a directory, keyed by SP entityID and alias.

    An application federated over both protocols has one policy and several
    names for it: a SAML entityID and an OIDC `client_id`. Both resolve to the
    same `ReleasePolicy`, which is what makes "the same app, two protocols,
    identical release" true rather than a matter of keeping two files in step.
    """
    policies: dict[str, ReleasePolicy] = {}
    if not directory.is_dir():
        raise PolicyError(f"{directory} is not a policy directory")

    for path in sorted(directory.iterdir()):
        if path.suffix not in POLICY_SUFFIXES:
            continue
        policy, aliases = load_file(path)
        for name in (policy.sp_entity_id, *aliases):
            if name in policies:
                # Two files claiming one name means whichever loaded last
                # silently wins, and which that is depends on filenames.
                raise PolicyError(f"{path.name}: {name!r} is already defined")
            policies[name] = policy
    return policies


def load_file(path: Path) -> tuple[ReleasePolicy, tuple[str, ...]]:
    """Parse and validate one policy file, with the other names it answers to."""
    try:
        # safe_load, always. See the module docstring.
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name}: not valid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise PolicyError(f"{path.name}: expected a mapping at the top level")
    policy = parse_policy(document, source=path.name)
    aliases = tuple(_string_list(document.get("aliases", []), path.name, "aliases"))
    return policy, aliases


def parse_policy(document: dict[str, Any], *, source: str) -> ReleasePolicy:
    """Turn a parsed document into a policy, refusing anything questionable."""
    entity_id = document.get("sp_entity_id")
    if not isinstance(entity_id, str) or not entity_id:
        raise PolicyError(f"{source}: sp_entity_id is required")

    unknown_keys = set(document) - {
        "sp_entity_id",
        "aliases",
        "display_name",
        "entity_categories",
        "subject_id_mode",
        "internal_school_official",
        "require_encrypted_assertion",
        "rules",
    }
    if unknown_keys:
        # A typo in a key name is otherwise silent, and the setting it was
        # meant to be stays at its default — which for `internal_school_official`
        # is the difference between a working LMS and a FERPA finding.
        raise PolicyError(f"{source}: unknown keys {sorted(unknown_keys)}")

    categories = frozenset(
        _string_list(document.get("entity_categories", []), source, "entity_categories")
    )
    unknown_categories = categories - KNOWN_CATEGORIES
    if unknown_categories:
        raise PolicyError(f"{source}: unknown entity categories {sorted(unknown_categories)}")

    mode = document.get("subject_id_mode", "pairwise")
    if mode not in VALID_SUBJECT_ID_MODES:
        raise PolicyError(
            f"{source}: subject_id_mode {mode!r} is not one of {sorted(VALID_SUBJECT_ID_MODES)}"
        )

    return ReleasePolicy(
        sp_entity_id=entity_id,
        display_name=str(document.get("display_name") or ""),
        entity_categories=categories,
        subject_id_mode=mode,
        internal_school_official=_bool(document.get("internal_school_official", False), source),
        require_encrypted_assertion=_bool(
            document.get("require_encrypted_assertion", False), source
        ),
        rules=tuple(_parse_rules(document.get("rules", []), source)),
    )


def _parse_rules(raw: Any, source: str) -> list[ReleaseRule]:
    if not isinstance(raw, list):
        raise PolicyError(f"{source}: rules must be a list")

    rules: list[ReleaseRule] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise PolicyError(f"{source}: rule {index} is not a mapping")
        rule = _parse_rule(entry, source, index)
        if rule.id in seen_ids:
            # Rule ids end up in audit records answering "why does this app see
            # my name?". Two rules sharing one makes that answer ambiguous.
            raise PolicyError(f"{source}: duplicate rule id {rule.id!r}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules


def _parse_rule(entry: dict[str, Any], source: str, index: int) -> ReleaseRule:
    unknown = set(entry) - {"id", "effect", "attribute", "value_filter", "precedence"}
    if unknown:
        raise PolicyError(f"{source}: rule {index} has unknown keys {sorted(unknown)}")

    rule_id = entry.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyError(f"{source}: rule {index} needs an id")

    effect = entry.get("effect")
    if effect not in VALID_EFFECTS:
        raise PolicyError(
            f"{source}: rule {rule_id!r} has effect {effect!r}, not one of {sorted(VALID_EFFECTS)}"
        )

    attribute = entry.get("attribute")
    if not isinstance(attribute, str):
        raise PolicyError(f"{source}: rule {rule_id!r} needs an attribute")

    known = definition(attribute)
    if known is None:
        # A typo here would produce a rule that never matches, and the reflex
        # fix for "the attribute isn't being released" is a broader rule.
        raise PolicyError(f"{source}: rule {rule_id!r} names unknown attribute {attribute!r}")
    if known.classification is Classification.RESTRICTED:
        # The engine refuses these anyway. Refusing at load time as well means
        # the mistake is caught by the person who made it rather than never
        # being noticed, since a rule that silently does nothing looks fine.
        raise PolicyError(
            f"{source}: rule {rule_id!r} tries to release {attribute!r}, "
            "which is an education record and is never releasable"
        )

    value_filter = entry.get("value_filter")
    if value_filter is not None:
        if effect != "allow-value":
            raise PolicyError(
                f"{source}: rule {rule_id!r} has a value_filter but effect {effect!r}"
            )
        _validate_filter(value_filter, rule_id, source)
    elif effect == "allow-value":
        raise PolicyError(f"{source}: rule {rule_id!r} is allow-value with no value_filter")

    precedence = entry.get("precedence", 100)
    if not isinstance(precedence, int) or isinstance(precedence, bool):
        raise PolicyError(f"{source}: rule {rule_id!r} has a non-integer precedence")

    return ReleaseRule(
        id=rule_id,
        effect=effect,
        attribute=attribute,
        value_filter=value_filter,
        precedence=precedence,
    )


def _validate_filter(value_filter: Any, rule_id: str, source: str) -> None:
    """Compile the pattern now, so a bad one fails at load rather than at login.

    The engine matches with `re.fullmatch`, so the pattern is anchored whatever
    it looks like. Compiling here catches the other failure: a pattern that
    raises, which at request time would be an unhandled exception in the middle
    of a release decision.
    """
    if not isinstance(value_filter, str):
        raise PolicyError(f"{source}: rule {rule_id!r} has a non-string value_filter")
    try:
        re.compile(value_filter)
    except re.error as exc:
        raise PolicyError(f"{source}: rule {rule_id!r} has an invalid value_filter: {exc}") from exc


def _string_list(raw: Any, source: str, field: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PolicyError(f"{source}: {field} must be a list of strings")
    return list(raw)


def _bool(raw: Any, source: str) -> bool:
    if not isinstance(raw, bool):
        # YAML turns `yes`, `on` and `true` into booleans but leaves `"true"` a
        # string. Accepting the string would make a quoted value mean the
        # opposite of what it reads as.
        raise PolicyError(f"{source}: expected a boolean, got {raw!r}")
    return raw
