"""Container least privilege (NFR-SEC-09).

Four properties: a non-root user, a read-only root filesystem, every Linux
capability dropped, and no path to regaining privilege. Together they mean that
an attacker who achieves code execution inside the broker lands as uid 10001 in a
filesystem they cannot write, holding none of the capabilities that make a
container escape interesting.

**This file reads the declarations; CI reads the running container.** Both halves
are needed and neither substitutes for the other. A test that only parsed these
files would pass against a deployment that never applied them, and a CI step that
only inspected a container would not say which line to restore when somebody
deletes one. So the compose smoke job runs `docker inspect` against the live
broker and asserts the same four properties as effective runtime values, and this
file is what fails in a pull request the moment a line goes missing — before
anything is built.

The split matters for a second reason. `read_only` and `cap_drop` are *runtime*
settings that live in the orchestration, not in the image, so a Kubernetes
deployment written from this repository gets them from a securityContext that
nothing here can see. Naming them in a test is what makes them a documented
requirement of running this image rather than a property somebody assumes it has.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
CI_OVERLAY = ROOT / "docker-compose.ci.yml"
DOCKERFILE = ROOT / "Dockerfile"

UID = "10001"
"""Well above the 0-999 range distributions reserve for system accounts, so the
broker cannot collide with a user the base image adds in a later release."""


def _tagged(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    """Read a compose-specific tag as the value it decorates.

    Compose defines `!override` and `!reset`, which change how a list in an
    overlay merges with the base. They mean nothing to a YAML parser, so
    `safe_load` refuses the document outright.
    """
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    raise TypeError(f"unexpected node under a compose tag: {type(node).__name__}")


class ComposeLoader(yaml.SafeLoader):
    """`SafeLoader`, plus the tags compose invented.

    A subclass rather than the full loader. `yaml.load` constructs arbitrary
    Python objects, which would make a compose file a code-execution surface in
    the one repository that should not have a casual one. Everything this adds is
    a constructor that returns the value it was given.
    """


# Untyped in the PyYAML stubs, so `--strict` refuses the call rather than the
# argument. Registered on the subclass, never on `SafeLoader` itself: that would
# teach every `safe_load` in the project to accept unknown tags.
ComposeLoader.add_multi_constructor("!", _tagged)  # type: ignore[no-untyped-call]


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    # S506 flags `yaml.load` with a loader that is not `safe_load`, which is the
    # right default and wrong here: `ComposeLoader` derives from `SafeLoader` and
    # adds one constructor that returns the value it is handed. No document read
    # through it can construct a Python object.
    loaded: dict[str, Any] = yaml.load(text, Loader=ComposeLoader)  # noqa: S506
    return loaded


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return _read(COMPOSE)


@pytest.fixture(scope="module")
def broker(compose: dict[str, Any]) -> dict[str, Any]:
    service: dict[str, Any] = compose["services"]["broker"]
    return service


def test_the_root_filesystem_is_read_only(broker: dict[str, Any]) -> None:
    """The property that turns most code execution into a dead end.

    Nothing can be dropped on disk and nothing already there can be rewritten, so
    the usual next steps — a web shell, a modified entrypoint, a poisoned
    dependency — all fail at the write.
    """
    assert broker["read_only"] is True


def test_every_capability_is_dropped(broker: dict[str, Any]) -> None:
    """ALL, then nothing added back.

    Dropping a list of the dangerous ones is the version of this that ages badly:
    the kernel keeps adding capabilities and a denylist written today does not
    know about them.
    """
    assert broker["cap_drop"] == ["ALL"]
    assert "cap_add" not in broker


def test_privilege_cannot_be_regained(broker: dict[str, Any]) -> None:
    """`no-new-privileges` is what makes the dropped capabilities stay dropped.

    Without it a setuid binary inside the image is a way back up, and the base
    image ships several. This is also why the broker never runs `privileged` or
    shares the host's namespaces.
    """
    assert "no-new-privileges:true" in broker["security_opt"]
    assert broker.get("privileged") is not True
    assert "network_mode" not in broker
    assert "pid" not in broker


def test_the_writable_paths_are_named_and_bounded(broker: dict[str, Any]) -> None:
    """A read-only filesystem still needs somewhere to write, and the exceptions
    are the part worth reviewing.

    Two: a size-capped tmpfs for scratch, and the volume holding the SP keypair.
    The keypair cannot be a tmpfs because the certificate is what peers have been
    told to trust, and losing it means re-doing the metadata exchange with every
    one of them. A third exception appearing here without a reason is the finding.
    """
    # S108 warns about writing to a shared /tmp. This is the assertion that the
    # broker's /tmp is a private, size-capped tmpfs rather than a shared one.
    assert [mount.split(":")[0] for mount in broker["tmpfs"]] == ["/tmp"]  # noqa: S108
    assert "size=" in broker["tmpfs"][0]
    assert [volume.split(":")[1] for volume in broker["volumes"]] == ["/var/lib/campusid/saml"]


def test_the_ci_overlay_does_not_relax_any_of_it() -> None:
    """The overlay exists to remove published ports and persistent storage.

    Asserted because an overlay is the easy place to loosen something for a job
    that was failing, and the loosening would then be invisible to every test
    above — which reads the base file.
    """
    broker = _read(CI_OVERLAY)["services"]["broker"]

    assert not {"read_only", "cap_drop", "cap_add", "security_opt", "privileged"} & set(broker)


# --- the image ---------------------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_the_runtime_image_ends_as_an_unprivileged_user(dockerfile: str) -> None:
    """The last `USER` wins, so it is the last one that has to be right.

    Checked as the final directive of the file rather than merely present: a
    `USER root` added later for a build step and not switched back is exactly how
    an image that once ran unprivileged stops doing so.
    """
    users = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("USER ")]

    assert users, "the image never switches away from root"
    assert set(users) == {"campusid"}


def test_the_account_has_no_way_to_log_in(dockerfile: str) -> None:
    """No home directory and no shell.

    Neither is a boundary on its own — the process runs as this user regardless —
    but both remove the affordances an attacker reaches for first, and their
    absence in a diff is a question worth asking.
    """
    assert "--no-create-home" in dockerfile
    assert "--shell /usr/sbin/nologin" in dockerfile


def test_the_account_is_outside_the_system_uid_range(dockerfile: str) -> None:
    """Fixed rather than assigned, so a file written to the key volume by one
    release is still owned by the broker in the next."""
    assert f"--uid {UID}" in dockerfile
