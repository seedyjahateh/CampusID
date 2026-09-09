"""HTTP middleware.

Security headers are applied from the first commit rather than retrofitted:
NFR-SEC-03 asserts them on *every* route, so a route added in a later milestone
inherits them by default instead of needing to remember.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from structlog.contextvars import bind_contextvars, clear_contextvars

from campusid.audit.log import new_correlation_id, set_correlation_id
from campusid.saml.parser import MAX_DOCUMENT_BYTES

SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
    # The broker serves no third-party script or style. Endpoints that later
    # render interactive pages (admin console, MFA enrolment) tighten this
    # further rather than loosening it.
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}

DOCS_PATHS = frozenset({"/docs", "/openapi.json"})


class BodySizeLimitMiddleware:
    """Refuse an oversized request body before anything buffers it.

    A pure ASGI middleware rather than a `BaseHTTPMiddleware`, because the cap
    has to apply while the body is still being received. Checking
    `Content-Length` alone would not do: it is absent under chunked transfer
    encoding and, being a header, is exactly as trustworthy as the body it
    describes. This counts the bytes as they arrive and stops at the ceiling.

    Returns 413 without the reason code the gate would use — the request never
    reached the gate, and telling an anonymous caller which limit they hit is
    free reconnaissance (FR-AUD-06).
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_DOCUMENT_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = 0
        exceeded = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    # Truncate rather than raise: the app may still be awaiting
                    # a body, and an exception here would surface as a 500.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Message) -> None:
            if exceeded and message["type"] == "http.response.start":
                message = {**message, "status": 413}
            await send(message)

        await self.app(scope, counting_receive, guarded_send)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Give every request a correlation id, and bind it to the logs (FR-AUD-02).

    One id per request, shared by every audit event the request produces, so an
    investigator pulls the whole chain — authorization request, upstream SSO,
    attribute release, token issuance — with one query rather than reconstructing
    it from timestamps.

    Set here rather than passed down through call signatures: a parameter
    threaded through fifteen functions is one somebody forgets at the sixteenth,
    and an event with no correlation id is present but unjoinable.

    An inbound `X-Correlation-ID` is deliberately **not** honoured. It would let
    a caller merge their requests into somebody else's chain, or flood one id
    until the trail for it is unreadable — and the broker is not behind a trusted
    mesh that would have set one.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        reference = new_correlation_id()
        set_correlation_id(reference)
        bind_contextvars(correlation_id=reference)
        try:
            response = await call_next(request)
        finally:
            # Cleared even on an exception: contextvars outlive the request in a
            # worker, and a leaked id would silently attribute the next
            # request's events to this one's chain.
            clear_contextvars()

        # Echoed so a user quoting the reference on the error page and an
        # operator reading a proxy log are talking about the same request.
        response.headers.setdefault("X-Correlation-ID", reference)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the standard security header set to every response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)

        if request.url.path in DOCS_PATHS:
            # Swagger UI loads its bundle from a CDN; the strict policy would
            # blank the page. Non-production only (see create_app).
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'"
            )
        return response
