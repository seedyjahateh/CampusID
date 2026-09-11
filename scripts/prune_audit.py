"""Apply the audit retention policy (FR-AUD-08).

    docker compose exec broker python scripts/prune_audit.py \
        --to /var/lib/campusid/exports --reason "quarterly retention pass"

Exports everything older than the retention window to newline-delimited JSON,
then removes it and writes an anchor so the surviving chain still verifies.
Nothing is deleted that has not been written to the export file first: if the
export fails, the trail is intact, which is the direction this failure has to
fall.

It connects as the schema *owner*, not as the application role. The broker itself
cannot delete from the audit trail — that is FR-AUD-04 and the point of it — so
pruning is a deliberate operation somebody runs, with a reason recorded against
their name, rather than something that happens while requests are being served.

`--dry-run` reports what a pass would remove and changes nothing, which is how
anybody should meet a command that deletes audit records.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path

from campusid.audit.events import EventType, Outcome
from campusid.audit.log import AuditLog
from campusid.audit.models import AuditEventRecord
from campusid.audit.query import as_json
from campusid.audit.retention import RetentionStore
from campusid.config import get_settings
from campusid.db import create_owner_engine, create_session_factory


def _parse(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prune the audit trail.")
    parser.add_argument(
        "--days",
        type=int,
        default=0,
        help="keep events newer than this many days (default: the configured policy)",
    )
    parser.add_argument("--to", type=Path, help="directory to write the export into")
    parser.add_argument("--reason", default="", help="why this pass is being run")
    parser.add_argument("--by", default="operator", help="who is running it")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be removed and change nothing",
    )
    return parser.parse_args(argv)


async def main(argv: list[str] | None = None) -> int:
    options = _parse(argv)
    settings = get_settings()
    # The flag wins over the configured policy, so an operator handling an
    # unusual case does not have to change a deployment's configuration to do it
    # once — but the default is the policy rather than a number in this file.
    window = timedelta(days=options.days or settings.audit_retention_days)

    engine = create_owner_engine(settings)
    try:
        sessions = create_session_factory(engine)
        retention = RetentionStore(sessions)
        audit = AuditLog(sessions)

        due = await retention.due(older_than=window)
        if options.dry_run:
            print(f"{due} events are older than {options.days} days")
            return 0

        # Refused rather than defaulted, for the reason every other mutation in
        # this project is: a default reason is a field everybody stops reading,
        # and this is the one command that destroys audit records.
        if not options.reason.strip():
            print("--reason is required", file=sys.stderr)
            return 2
        if options.to is None:
            print(
                "--to is required: nothing is deleted that has not been exported", file=sys.stderr
            )
            return 2

        options.to.mkdir(parents=True, exist_ok=True)
        destination = options.to / f"campusid-audit-pruned-{options.days}d.ndjson"

        with destination.open("w", encoding="utf-8") as handle:

            async def sink(rows: list[AuditEventRecord]) -> None:
                for row in rows:
                    handle.write(json.dumps(as_json(row), separators=(",", ":"), sort_keys=True))
                    handle.write("\n")
                # Flushed per batch, so a crash loses at most one batch rather
                # than the whole export — and the delete has not run yet either
                # way.
                handle.flush()

            pruned = await retention.prune(
                older_than=window,
                sink=sink,
                performed_by=options.by,
                reason=options.reason.strip(),
            )

        if pruned.anchored:
            # The pass records itself in the trail it just shortened, so the
            # surviving events carry their own explanation for where they begin.
            await audit.record(
                EventType.AUDIT_PRUNED,
                Outcome.SUCCESS,
                actor=options.by,
                reason=options.reason.strip(),
                detail={
                    "removed": pruned.removed,
                    "through_seq": pruned.through_seq,
                    "export": str(destination),
                    "retention_days": options.days,
                },
            )

        broken = await audit.verify_chain()
    finally:
        await engine.dispose()

    print(f"removed {pruned.removed} events, exported to {destination}")
    if broken is not None:
        print(f"audit chain BROKEN after pruning: {broken}", file=sys.stderr)
        return 1
    print("audit chain verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
