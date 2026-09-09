"""Loading release policy from YAML (FR-ARP-01).

The loader is a trust boundary: policy files are edited by the most people under
the most time pressure, and a rule that silently does nothing is worse than one
that fails, because the reflex fix for "the app isn't getting the attribute" is
a broader rule.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from campusid.policy.attributes import (
    MAIL,
    RESEARCH_AND_SCHOLARSHIP,
    SCOPED_AFFILIATION,
    STUDENT_ID,
)
from campusid.policy.loader import PolicyError, PolicyStore, load_directory, load_file

VALID = """
sp_entity_id: https://portal.campus.test/sp
display_name: Campus Portal
entity_categories:
  - http://refeds.org/category/research-and-scholarship
subject_id_mode: pairwise
internal_school_official: true
rules:
  - id: portal-mail
    effect: allow
    attribute: urn:oid:0.9.2342.19200300.100.1.3
  - id: portal-students-only
    effect: allow-value
    attribute: urn:oid:1.3.6.1.4.1.5923.1.1.1.9
    value_filter: student@campus\\.test
    precedence: 10
"""


def _write(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def test_a_valid_policy_loads(tmp_path: Path) -> None:
    policy, _ = load_file(_write(tmp_path, "portal.yaml", VALID))

    assert policy.sp_entity_id == "https://portal.campus.test/sp"
    assert policy.display_name == "Campus Portal"
    assert policy.entity_categories == frozenset({RESEARCH_AND_SCHOLARSHIP})
    assert policy.internal_school_official is True
    assert {rule.id for rule in policy.rules} == {"portal-mail", "portal-students-only"}
    assert policy.rules[1].precedence == 10


def test_a_directory_loads_every_policy(tmp_path: Path) -> None:
    _write(tmp_path, "portal.yaml", VALID)
    _write(
        tmp_path,
        "analytics.yml",
        """
        sp_entity_id: https://analytics.campus.test/sp
        rules: []
        """,
    )
    _write(tmp_path, "notes.txt", "not a policy")

    policies = load_directory(tmp_path)

    assert set(policies) == {
        "https://portal.campus.test/sp",
        "https://analytics.campus.test/sp",
    }


def test_two_files_cannot_claim_one_sp(tmp_path: Path) -> None:
    """Whichever loaded last would silently win, and which that is depends on
    filenames."""
    _write(tmp_path, "a.yaml", VALID)
    _write(tmp_path, "b.yaml", VALID)

    with pytest.raises(PolicyError, match="already defined"):
        load_directory(tmp_path)


def test_an_alias_reaches_the_same_policy(tmp_path: Path) -> None:
    """One application, two protocols, one policy.

    The portal is a SAML entityID to Shibboleth and a `client_id` to an OIDC
    library. Duplicating its policy into two files is how the two drift, and the
    drift is invisible until somebody notices an app sees more over one protocol
    than the other.
    """
    _write(
        tmp_path,
        "portal.yaml",
        f"""
        sp_entity_id: https://portal.campus.test/sp
        aliases:
          - campus-portal
        rules:
          - id: r
            effect: allow
            attribute: {MAIL}
        """,
    )
    store = PolicyStore(tmp_path, default_scope="campus.test")

    by_entity_id = store.get("https://portal.campus.test/sp")
    by_client_id = store.get("campus-portal")

    assert by_client_id is by_entity_id
    assert by_client_id.sp_entity_id == "https://portal.campus.test/sp"


def test_an_alias_cannot_collide_with_another_policy(tmp_path: Path) -> None:
    """Whichever file loaded last would silently win the name."""
    _write(tmp_path, "a.yaml", "sp_entity_id: campus-portal\nrules: []\n")
    _write(
        tmp_path,
        "b.yaml",
        "sp_entity_id: https://portal.test/sp\naliases: [campus-portal]\nrules: []\n",
    )

    with pytest.raises(PolicyError, match="already defined"):
        load_directory(tmp_path)


def test_an_sp_with_no_policy_gets_an_empty_one(tmp_path: Path) -> None:
    """Which under default-deny releases nothing but the subject identifier: an
    unconfigured SP can authenticate people and learns nothing about them."""
    store = PolicyStore(tmp_path, default_scope="campus.test")

    policy = store.get("https://unknown.test/sp")

    assert policy.sp_entity_id == "https://unknown.test/sp"
    assert policy.rules == ()


# --- what the loader refuses -----------------------------------------------


def test_a_restricted_attribute_cannot_be_allowed(tmp_path: Path) -> None:
    """The engine refuses these anyway. Refusing at load time means the mistake
    is caught by the person who made it, rather than living on as a rule that
    looks fine and does nothing."""
    path = _write(
        tmp_path,
        "bad.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: oops
            effect: allow
            attribute: {STUDENT_ID}
        """,
    )

    with pytest.raises(PolicyError, match="education record"):
        load_file(path)


def test_an_unknown_attribute_is_refused(tmp_path: Path) -> None:
    """A typo produces a rule that never matches, and the reflex fix for that is
    a broader rule."""
    path = _write(
        tmp_path,
        "typo.yaml",
        """
        sp_entity_id: https://sp.test
        rules:
          - id: typo
            effect: allow
            attribute: urn:oid:0.9.2342.19200300.100.1.33
        """,
    )

    with pytest.raises(PolicyError, match="unknown attribute"):
        load_file(path)


def test_an_unknown_rule_effect_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "effect.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: permit
            attribute: {MAIL}
        """,
    )

    with pytest.raises(PolicyError, match="effect"):
        load_file(path)


def test_an_unknown_top_level_key_is_refused(tmp_path: Path) -> None:
    """A typo in a key name is otherwise silent, and the setting it was meant to
    be stays at its default — which for `internal_school_official` is the
    difference between a working LMS and a FERPA finding."""
    path = _write(
        tmp_path,
        "key.yaml",
        """
        sp_entity_id: https://sp.test
        internal_school_offical: true
        rules: []
        """,
    )

    with pytest.raises(PolicyError, match="unknown keys"):
        load_file(path)


def test_a_quoted_boolean_is_refused(tmp_path: Path) -> None:
    """YAML turns `yes`, `on` and `true` into booleans but leaves `"true"` a
    string. Accepting the string would make a quoted value mean the opposite of
    what it reads as."""
    path = _write(
        tmp_path,
        "quoted.yaml",
        """
        sp_entity_id: https://sp.test
        internal_school_official: "false"
        rules: []
        """,
    )

    with pytest.raises(PolicyError, match="boolean"):
        load_file(path)


def test_an_invalid_value_filter_is_refused(tmp_path: Path) -> None:
    """Compiled at load time. At request time a bad pattern is an unhandled
    exception in the middle of a release decision."""
    path = _write(
        tmp_path,
        "regex.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: allow-value
            attribute: {SCOPED_AFFILIATION}
            value_filter: "student@(campus"
        """,
    )

    with pytest.raises(PolicyError, match="invalid value_filter"):
        load_file(path)


def test_allow_value_without_a_filter_is_refused(tmp_path: Path) -> None:
    """It would release everything while reading as though it filtered."""
    path = _write(
        tmp_path,
        "novalue.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: allow-value
            attribute: {MAIL}
        """,
    )

    with pytest.raises(PolicyError, match="no value_filter"):
        load_file(path)


def test_a_filter_on_a_plain_allow_is_refused(tmp_path: Path) -> None:
    """It would be ignored, so the rule releases every value while looking as
    though it restricted them."""
    path = _write(
        tmp_path,
        "ignored.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: allow
            attribute: {MAIL}
            value_filter: ".*@campus\\\\.test"
        """,
    )

    with pytest.raises(PolicyError, match="value_filter but effect"):
        load_file(path)


def test_duplicate_rule_ids_are_refused(tmp_path: Path) -> None:
    """Rule ids end up in audit records answering "why does this app see my
    name?". Two rules sharing one makes that answer ambiguous."""
    path = _write(
        tmp_path,
        "dupe.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: allow
            attribute: {MAIL}
          - id: r
            effect: deny
            attribute: {SCOPED_AFFILIATION}
        """,
    )

    with pytest.raises(PolicyError, match="duplicate rule id"):
        load_file(path)


def test_an_unknown_entity_category_is_refused(tmp_path: Path) -> None:
    """A category the broker does not implement releases nothing, so an SP
    tagged with it would appear configured and receive an empty set."""
    path = _write(
        tmp_path,
        "cat.yaml",
        """
        sp_entity_id: https://sp.test
        entity_categories:
          - http://refeds.org/category/anonymous-access
        rules: []
        """,
    )

    with pytest.raises(PolicyError, match="unknown entity categories"):
        load_file(path)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("rules: not-a-list", "rules must be a list"),
        ("rules:\n  - just a string", "not a mapping"),
        (f"rules:\n  - effect: allow\n    attribute: {MAIL}", "needs an id"),
        ("rules:\n  - id: r\n    effect: allow", "needs an attribute"),
        (
            f"rules:\n  - id: r\n    effect: allow-value\n    attribute: {MAIL}\n"
            "    value_filter: 42",
            "non-string value_filter",
        ),
        (
            f"rules:\n  - id: r\n    effect: allow\n    attribute: {MAIL}\n    precedence: high",
            "non-integer precedence",
        ),
        (
            f"rules:\n  - id: r\n    effect: allow\n    attribute: {MAIL}\n    weight: 3",
            "unknown keys",
        ),
        ("entity_categories: research-and-scholarship", "list of strings"),
        ("entity_categories:\n  - 7", "list of strings"),
        ("subject_id_mode: transient", "subject_id_mode"),
    ],
)
def test_a_malformed_rule_is_refused(tmp_path: Path, body: str, expected: str) -> None:
    """Each of these would otherwise be a rule that silently does nothing, or a
    setting quietly left at its default."""
    path = _write(tmp_path, "bad.yaml", f"sp_entity_id: https://sp.test\n{body}\n")

    with pytest.raises(PolicyError, match=expected):
        load_file(path)


def test_a_boolean_precedence_is_refused(tmp_path: Path) -> None:
    """`True` is an `int` in Python, so an unguarded `isinstance` check accepts
    `precedence: yes` and silently means 1 — the highest priority there is."""
    path = _write(
        tmp_path,
        "boolprec.yaml",
        f"""
        sp_entity_id: https://sp.test
        rules:
          - id: r
            effect: allow
            attribute: {MAIL}
            precedence: yes
        """,
    )

    with pytest.raises(PolicyError, match="non-integer precedence"):
        load_file(path)


def test_a_missing_entity_id_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "anon.yaml", "rules: []\n")

    with pytest.raises(PolicyError, match="sp_entity_id"):
        load_file(path)


def test_malformed_yaml_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "broken.yaml", "sp_entity_id: [unclosed\n")

    with pytest.raises(PolicyError, match="not valid YAML"):
        load_file(path)


def test_a_scalar_document_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "scalar.yaml", "just a string\n")

    with pytest.raises(PolicyError, match="mapping"):
        load_file(path)


def test_a_yaml_tag_does_not_construct_an_object(tmp_path: Path) -> None:
    """`safe_load`, never `load`.

    The full loader builds arbitrary Python objects from a document, which would
    make a policy file a code-execution surface — and policy files are precisely
    what gets edited most often by the most people.
    """
    path = _write(
        tmp_path,
        "tagged.yaml",
        """
        sp_entity_id: !!python/object/apply:os.system ["echo pwned"]
        rules: []
        """,
    )

    with pytest.raises(PolicyError, match="not valid YAML"):
        load_file(path)


# --- hot reload ------------------------------------------------------------


def test_an_edited_file_is_picked_up(tmp_path: Path) -> None:
    _write(tmp_path, "portal.yaml", VALID)
    store = PolicyStore(tmp_path, default_scope="campus.test")
    assert len(store.get("https://portal.campus.test/sp").rules) == 2

    _write(
        tmp_path,
        "portal.yaml",
        """
        sp_entity_id: https://portal.campus.test/sp
        rules: []
        """,
    )
    _bump_mtimes(tmp_path)

    assert store.get("https://portal.campus.test/sp").rules == ()


def test_a_deleted_file_stops_applying(tmp_path: Path) -> None:
    """The fingerprint includes filenames, not just modification times: deleting
    a policy is a change even when nothing else was touched."""
    _write(tmp_path, "portal.yaml", VALID)
    store = PolicyStore(tmp_path, default_scope="campus.test")
    assert store.get("https://portal.campus.test/sp").rules

    (tmp_path / "portal.yaml").unlink()

    assert store.get("https://portal.campus.test/sp").rules == ()


def test_a_broken_edit_keeps_the_last_known_good(tmp_path: Path) -> None:
    """The only option that fails in a direction anybody can recover from.

    An empty policy set locks every user out of every app at once; a permissive
    fallback is a disclosure. Keeping what was already working, and logging
    loudly, leaves the broker serving correct policy while somebody reverts the
    commit.
    """
    _write(tmp_path, "portal.yaml", VALID)
    store = PolicyStore(tmp_path, default_scope="campus.test")

    _write(tmp_path, "portal.yaml", "sp_entity_id: [unclosed\n")
    _bump_mtimes(tmp_path)

    assert len(store.get("https://portal.campus.test/sp").rules) == 2


def test_a_repaired_file_is_picked_up_again(tmp_path: Path) -> None:
    """The failure is not sticky: once the file parses, the new policy applies
    without a restart."""
    _write(tmp_path, "portal.yaml", VALID)
    store = PolicyStore(tmp_path, default_scope="campus.test")
    _write(tmp_path, "portal.yaml", "sp_entity_id: [unclosed\n")
    _bump_mtimes(tmp_path)
    store.get("https://portal.campus.test/sp")

    _write(
        tmp_path,
        "portal.yaml",
        """
        sp_entity_id: https://portal.campus.test/sp
        rules: []
        """,
    )
    _bump_mtimes(tmp_path)

    assert store.get("https://portal.campus.test/sp").rules == ()


def test_a_missing_directory_is_survivable(tmp_path: Path) -> None:
    """A volume that failed to mount must not take the broker down at import
    time. It serves an empty set, which is default-deny."""
    store = PolicyStore(tmp_path / "absent", default_scope="campus.test")

    assert store.get("https://sp.test").rules == ()


def _bump_mtimes(directory: Path) -> None:
    """Advance every file's mtime.

    Filesystem timestamp granularity is coarse enough that a rewrite within the
    same test can land on the same mtime, which would make the reload test pass
    or fail depending on how fast the machine is.
    """
    import os
    import time

    future = time.time() + 10
    for path in directory.iterdir():
        os.utime(path, (future, future))
