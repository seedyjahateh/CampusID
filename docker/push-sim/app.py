"""A simulated push-approval service (FR-MFA-03).

**This is not a second factor.** It stands in for Duo, Okta Verify or Microsoft
Authenticator so the broker's push flow can be built and demonstrated end to end,
and it makes none of the guarantees a real one does: there is no device
registration, no cryptographic binding to a phone, and no channel an attacker
cannot simply open a browser tab onto. Anybody who can reach this service can
approve anybody's request.

That boundary is the point of the service existing at all. A push factor has real
shape — a request that is sent, waited on, and resolved as approved, denied or
timed out — and the broker's handling of each of those outcomes is worth building
correctly whether the phone is real. What is *not* worth doing is pretending the
simulation is the thing.

The approval page says all of this, because a reviewer clicking Approve should
not have to read the source to know what they are looking at.

State is in memory and dies with the process. Persisting it would imply a
durability this has no business claiming, and a restart clearing every pending
request is the correct behaviour for something whose requests live sixty seconds.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Final

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

WINDOW: Final = 60.0
"""Seconds a request waits before it times out (FR-MFA-03).

Long enough to find a phone, short enough that an unapproved request is not left
sitting where somebody else can reach it.
"""

PENDING: Final = "pending"
APPROVED: Final = "approved"
DENIED: Final = "denied"
EXPIRED: Final = "expired"

MAX_REQUESTS: Final = 1000
"""A ceiling, so a simulator left running does not grow without bound."""


@dataclass
class Request:
    id: str
    subject: str
    context: str
    created_at: float
    state: str = PENDING
    resolved_at: float | None = None

    def status(self, now: float) -> str:
        """Expiry is computed on read rather than swept.

        A sweeper would be a second thing to get wrong, and the only question
        anybody asks of a request is what it is *now*.
        """
        if self.state == PENDING and now - self.created_at > WINDOW:
            return EXPIRED
        return self.state


@dataclass
class Store:
    requests: dict[str, Request] = field(default_factory=dict)

    def add(self, subject: str, context: str) -> Request:
        if len(self.requests) >= MAX_REQUESTS:
            oldest = min(self.requests.values(), key=lambda r: r.created_at)
            del self.requests[oldest.id]
        request = Request(
            id=secrets.token_urlsafe(16),
            subject=subject,
            context=context,
            created_at=time.monotonic(),
        )
        self.requests[request.id] = request
        return request


store = Store()
app = FastAPI(title="CampusID push simulator")

BANNER: Final = """
<p class="warn"><strong>This is a simulator.</strong> It stands in for a real
push-approval service so the broker's flow can be demonstrated end to end. There
is no registered device and no cryptographic binding to a phone: anybody who can
reach this page can approve anybody's request. It is not a second factor.</p>
"""

PAGE: Final = """<!doctype html>
<meta charset="utf-8">
<title>Push simulator</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 44rem; }}
 .warn {{ background: #fff3cd; border-left: 4px solid #c9971c; padding: .75rem 1rem; }}
 li {{ margin: .75rem 0; }}
 form {{ display: inline; }}
 code {{ background: #f2f2f2; padding: .1rem .3rem; }}
</style>
<h1>Push simulator</h1>
{banner}
<h2>Pending requests</h2>
{items}
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """The approval page a reviewer clicks, banner and all."""
    now = time.monotonic()
    pending = [r for r in store.requests.values() if r.status(now) == PENDING]
    if not pending:
        items = "<p>Nothing waiting.</p>"
    else:
        items = "<ul>" + "".join(_item(request, now) for request in pending) + "</ul>"
    return HTMLResponse(PAGE.format(banner=BANNER, items=items))


def _item(request: Request, now: float) -> str:
    remaining = int(WINDOW - (now - request.created_at))
    return (
        f"<li><code>{request.subject}</code> — {request.context} "
        f"({remaining}s left)<br>"
        f'<form method="post" action="/push/{request.id}/approve"><button>Approve</button></form> '
        f'<form method="post" action="/push/{request.id}/deny"><button>Deny</button></form>'
        "</li>"
    )


@app.post("/push")
async def send(body: dict[str, Any]) -> JSONResponse:
    """Raise a request. Called by the broker, never by a browser."""
    subject = str(body.get("subject") or "")
    if not subject:
        return JSONResponse({"error": "subject is required"}, status_code=400)
    request = store.add(subject, str(body.get("context") or "sign-in"))
    return JSONResponse(
        {"id": request.id, "expires_in": int(WINDOW), "status": PENDING}, status_code=201
    )


@app.get("/push/{request_id}")
async def status(request_id: str) -> JSONResponse:
    """What happened to a request, if anything has."""
    request = store.requests.get(request_id)
    if request is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"id": request.id, "status": request.status(time.monotonic())})


@app.post("/push/{request_id}/approve")
async def approve(request_id: str) -> Any:
    return _resolve(request_id, APPROVED)


@app.post("/push/{request_id}/deny")
async def deny(request_id: str) -> Any:
    return _resolve(request_id, DENIED)


def _resolve(request_id: str, outcome: str) -> Any:
    """Settle a request, refusing to settle one that is already over.

    An expired request cannot be approved afterwards. That is the one behaviour
    here that matters to the broker, because "approved at second 61" is exactly
    the case a timeout exists to refuse.
    """
    request = store.requests.get(request_id)
    if request is None:
        return JSONResponse({"error": "not found"}, status_code=404)

    now = time.monotonic()
    if request.status(now) != PENDING:
        return JSONResponse(
            {"id": request.id, "status": request.status(now), "error": "already settled"},
            status_code=409,
        )

    request.state = outcome
    request.resolved_at = now
    return HTMLResponse(
        f"{PAGE.format(banner=BANNER, items=f'<p>Request {outcome}. You can close this.</p>')}"
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
