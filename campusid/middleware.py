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
