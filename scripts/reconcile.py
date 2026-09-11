"""Run a reconciliation and print what it found (FR-LC-07).

    docker compose run --rm tests python scripts/reconcile.py
    docker compose run --rm tests python scripts/reconcile.py --apply

Dry run unless `--apply` is given, and the flag is spelled out rather than
abbreviated on purpose: the difference between the two is the difference between
a report and a change to every account the report names.

The output is grouped by kind rather than listed flat, because what an operator
does about each is different. Accounts that should be disabled are a security
finding to close today; people missing downstream are a provisioning gap to look
into; unreachable entries mean the run is incomplete and the number at the bottom
should not be trusted as a clean result.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.directory.client import DirectoryClient
from campusid.directory.connection import Connector
from campusid.directory.profiles import profile as directory_profile
from campusid.directory.writes import DirectoryWriter
from campusid.lifecycle.reconciliation import DriftKind, Reconciler, Report
from campusid.lifecycle.targets import LdapTarget


def _report(report: Report, *, applied: bool) -> None:
    print(f"scanned {report.scanned} people")

    counts = Counter(drift.kind for drift in report.drifts)
    if not report.drifts:
        print("no drift")
        return

    for kind in DriftKind:
        found = report.of_kind(kind)
        if not found:
            continue
        print(f"\n{kind.value} ({counts[kind]}):")
        for drift in found:
            print(f"  {drift.login}  {drift.detail}")

    if applied:
        print(f"\nremediated {len(report.remediated)}, failed {len(report.failed)}")
    else:
        remediable = sum(1 for drift in report.drifts if drift.remediable)
        print(f"\ndry run. {remediable} of these would be closed by --apply")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="close the drift this job can close, instead of only reporting it",
    )
    arguments = parser.parse_args()

    settings = get_settings()
    if not settings.ldap_enabled:
        print("no directory is configured; nothing to reconcile against")
        return 1

    engine = create_engine(settings)
    try:
        profile = directory_profile(settings.ldap_profile)
        connector = Connector(
            url=settings.ldap_url,
            bind_dn=settings.ldap_bind_dn,
            bind_password=settings.ldap_bind_password,
            start_tls=settings.ldap_start_tls,
            allow_plaintext=settings.ldap_allow_plaintext,
        )
        client = DirectoryClient(
            profile=profile,
            url=settings.ldap_url,
            base_dn=settings.ldap_base_dn,
            connector=connector,
        )
        writer = DirectoryWriter(
            profile=profile, base_dn=settings.ldap_base_dn, connector=connector
        )
        reconciler = Reconciler(
            create_session_factory(engine),
            client=client,
            target=LdapTarget(client=client, writer=writer),
        )

        report = await reconciler.run(apply=arguments.apply)
        _report(report, applied=arguments.apply)
    finally:
        await engine.dispose()

    # Non-zero when something is outstanding, so this can be a scheduled check
    # whose failure is the alert rather than something that has to be parsed.
    return 1 if report.drifts and not report.applied else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
