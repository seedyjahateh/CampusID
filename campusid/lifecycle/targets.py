"""Downstream systems a person's account exists in (FR-LC-01, FR-LC-03).

The orchestrator has held an ordered slot for these since the leaver sequence
was written: disable the account *first*, because a directory that still
authenticates is a way back in that revoking our own tokens does nothing about.
This fills the slot.

**A target is addressed by login, not by our own identifier.** The directory has
never heard of a `person_uuid`. Resolving the person to a directory entry is the
target's job, and it is done by search rather than by constructing a DN, because
a DN is a location and people move between organisational units.

**Somebody who is not in the directory is not a failure.** A person provisioned
only in the broker — a just-in-time account from a federated login, say — has no
directory entry to disable, and reporting that as an error would dead-letter
every leaver who never had one. It is reported as nothing to do.

**An unreachable directory *is* a failure, and it propagates.** The retry and
dead-letter machinery (FR-LC-09) exists for exactly this, and a target that
swallowed the outage would leave an enabled account behind with a trail saying
it was disabled.
"""

from __future__ import annotations

from typing import Any

from campusid.directory.client import DirectoryUnavailable
from campusid.directory.writes import PersonSpec
from campusid.logging import get_logger

log = get_logger(__name__)


class LdapTarget:
    """The campus directory, as a provisioning and deprovisioning target."""

    name = "ldap"

    def __init__(self, *, client: Any, writer: Any) -> None:
        self._client = client
        self._writer = writer

    async def provision(self, spec: PersonSpec) -> None:
        """Make sure this person has a directory account (FR-LC-01).

        The other half of the slot, and it was empty for longer than the disable
        half: `ensure_person` existed, was tested, and was called by nothing in
        the application — so a joiner arriving over SCIM never reached the
        directory at all, and NFR-PROV-01's chain had a missing link rather than
        a slow one.

        Idempotent by construction. The writer reports whether it changed
        anything, which is what makes a re-run of a provisioning batch safe and
        what keeps "we created this" distinguishable from "this was already
        right" in a reconciliation report.
        """
        result = await self._writer.ensure_person(spec)
        log.info(
            "directory.provision.applied",
            uid=spec.uid,
            dn=result.dn,
            created=result.changed,
        )

    async def disable(self, login: str) -> None:
        """Disable this person's directory account, if they have one.

        Takes the login rather than the `person_uuid`: the directory has never
        heard of ours. The caller resolves one to the other, because it is the
        caller that holds the identity registry.
        """
        user = await self._client.find_user(login)
        if user is None:
            # Not an error. A person provisioned only in the broker has no
            # directory entry, and treating that as a failure would dead-letter
            # every leaver who never had one.
            log.info("directory.disable.no_entry", login=login)
            return

        result = await self._writer.disable(user.dn)
        log.info(
            "directory.disable.applied",
            login=login,
            dn=user.dn,
            changed=result.changed,
        )


class TargetUnavailable(DirectoryUnavailable):
    """Re-exported under a lifecycle name.

    The orchestrator should not have to import a directory exception to know
    that a downstream step could not be completed — the next target will not be
    LDAP, and the retry machinery cares about the category rather than the
    system.
    """
