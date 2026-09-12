"""What a person can see about themselves (FR-ARP-07).

`GET /me/releases` shows somebody the applications that have received their
attributes and what was released to each. It is a self-service view of the same
record the console shows an administrator, and that is the point: FERPA §99.10
gives a student the right to inspect their own records, and a right that requires
filing a request with somebody who has a console is a right in name.

**It is the audit trail, filtered to the caller.** Not a summary, not a separate
table. The trail is the record of disclosures §99.32 requires the institution to
keep, and a second copy would eventually disagree with it — at which point the
student is being shown something the institution's own record does not say.

**The subject comes from the session and nowhere else.** There is no parameter to
name a person, so "read somebody else's release history" is unexpressible rather
than refused. That matters more here than on an administrative route, because
this one is reachable by everybody.

**Ninety days, as the requirement asks.** Long enough to cover a term's worth of
sign-ins and short enough that the page loads. The full history is not hidden —
it is available through the console to somebody with a reason to ask — and the
window is stated in the response so nobody mistakes a bounded view for the whole.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from campusid.audit.events import EventType
from campusid.audit.query import Query
from campusid.logging import get_logger
from campusid.saml.stores import utcnow
from campusid.session.cookies import SESSION_COOKIE

log = get_logger(__name__)

router = APIRouter(tags=["self-service"])

WINDOW: Final = timedelta(days=90)
"""FR-ARP-07's window. Stated in the response, so a bounded view is not mistaken
for the whole history."""

LIMIT: Final = 200
"""How many releases one page carries.

A busy term produces a few hundred, and a page that loaded three years of them
would be slow for everybody to answer a question almost nobody asks.
"""

NO_STORE: Final = {"Cache-Control": "no-store"}


@router.get("/me/releases")
async def my_releases(request: Request) -> JSONResponse:
    """Which applications have received this person's attributes, and what.

    Grouped by application rather than listed as raw events, because the question
    somebody asks of this page is "who has my data", not "what happened at 14:07
    on Tuesday". The individual releases are kept under each application, so the
    second question is still answerable without a second page.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    session = await request.app.state.sessions.load(sid) if sid else None
    if session is None:
        return JSONResponse({"authenticated": False}, status_code=401, headers=NO_STORE)

    if session.person_uuid is None:
        # A session the identity registry has not matched yet. The trail is keyed
        # on the person, so there is nothing to show rather than nothing to find.
        return JSONResponse({"window_days": WINDOW.days, "applications": []}, headers=NO_STORE)

    since = utcnow() - WINDOW
    page = await request.app.state.audit_query.search(
        Query(
            subject=session.person_uuid,
            event_type=EventType.ATTRIBUTE_RELEASE.value,
            since=since,
            limit=LIMIT,
        )
    )

    return JSONResponse(
        {
            "window_days": WINDOW.days,
            "since": since.isoformat(),
            "applications": _by_application(page.events),
        },
        headers=NO_STORE,
    )


def _by_application(events: list[Any]) -> list[dict[str, Any]]:
    """One entry per application, newest first, with what it has ever seen.

    The union of attributes across the window is the honest answer to "what does
    this application know about me": a service that received an email address
    once has it, whether or not the most recent sign-in included it.
    """
    grouped: dict[str, dict[str, Any]] = {}

    for event in events:
        target = str(event.target or "unknown")
        entry = grouped.setdefault(
            target,
            {
                "target": target,
                "releases": 0,
                "first_seen": event.occurred_at,
                "last_seen": event.occurred_at,
                "attributes": set(),
            },
        )
        entry["releases"] += 1
        # The page arrives newest first, so the earliest event is the last one
        # seen for each application.
        entry["first_seen"] = event.occurred_at
        entry["attributes"].update(event.detail.get("attributes", []))

    return [
        {
            "target": entry["target"],
            "releases": entry["releases"],
            "first_seen": entry["first_seen"].isoformat(),
            "last_seen": entry["last_seen"].isoformat(),
            # Sorted so two loads of the same page list them the same way.
            "attributes": sorted(entry["attributes"]),
        }
        for entry in grouped.values()
    ]
