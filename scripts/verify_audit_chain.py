"""Verify the audit hash chain (FR-AUD-05).

    docker compose exec broker python scripts/verify_audit_chain.py

Exits 0 if the trail verifies and 1 if it does not, so it can be a cron job that
pages somebody rather than a thing an operator remembers to run. On failure it
names the exact event where the chain breaks — the first one, because every link
after a tamper is broken as a consequence and listing them all would bury the
row an investigator needs.

It also prints the head hash. That value is the one part of this that cannot live
in code: published somewhere the database's owner does not control, it turns
"partial tampering is detectable" into "tampering is detectable", because
rewriting the whole trail from a tamper point forward would then produce a head
that no longer matches what was published.
"""

from __future__ import annotations

import asyncio
import sys

from campusid.audit.log import AuditLog
from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory


async def main() -> int:
    engine = create_engine(get_settings())
    try:
        audit = AuditLog(create_session_factory(engine))
        broken = await audit.verify_chain()
        head = await audit.chain_head()
    finally:
        await engine.dispose()

    if broken is not None:
        print(f"audit chain BROKEN: {broken}", file=sys.stderr)
        print(f"head: {head}", file=sys.stderr)
        return 1

    print("audit chain verified")
    print(f"head: {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
