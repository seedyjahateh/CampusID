"""Counting SCIM requests at the boundary rather than in each handler.

The SCIM surface is twenty-odd routes plus a bulk runner, and several of its
responses are produced by error helpers rather than by the handler that failed.
Instrumenting each handler would therefore miss exactly the responses worth
counting — a 401 from the scope check, a 413 from the bulk cap, a 409 from a
version conflict — and would need a line adding to every route somebody writes
next year.

Sitting in front of the router catches all of them, including the ones that never
reach a handler at all.

**The label is derived from an allowlist, not from the path.** This is the part
that matters. A label taken from the URL is a label an anonymous caller chooses,
and a few thousand requests to `/scim/v2/<random>` would then create a few
thousand time series in whatever is scraping us — a denial of service against the
monitoring system, mounted through a 404. Anything not recognised becomes
`unknown`, so probing produces one series no matter how creative it is.
"""

from __future__ import annotations

from typing import Final

from starlette.types import ASGIApp, Message, Receive, Scope, Send

PREFIX: Final = "/scim/v2/"

RESOURCES: Final = {
    "users": "users",
    "groups": "groups",
    "bulk": "bulk",
    "serviceproviderconfig": "config",
    "resourcetypes": "resourcetypes",
    "schemas": "schemas",
}
"""The collections this server publishes, matched case-insensitively.

Case-insensitively because SCIM paths are conventionally capitalised and a client
that sends `/scim/v2/users` is talking about the same collection as one that
sends `/scim/v2/Users`. Folding them here keeps one series for one collection;
the router's own matching is a separate question this does not answer.
"""

VERBS: Final = {
    "GET": "read",
    "POST": "create",
    "PUT": "replace",
    "PATCH": "patch",
    "DELETE": "delete",
}

UNKNOWN: Final = "unknown"


class ScimMetricsMiddleware:
    """Count every SCIM request by operation and response status class.

    Pure ASGI rather than a `BaseHTTPMiddleware`, for the same reason the body
    cap is: this needs the status line as it goes out, and wrapping `send` is the
    cheapest way to see it without buffering a response.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith(PREFIX):
            await self.app(scope, receive, send)
            return

        op = operation(scope["path"], scope.get("method", ""))
        metrics = scope["app"].state.metrics

        async def counting_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                metrics.scim_request(op=op, status=int(message["status"]))
            await send(message)

        await self.app(scope, receive, counting_send)


def operation(path: str, method: str) -> str:
    """Name the operation, using nothing the caller invented.

    Bulk is its own name rather than `bulk.create`: a bulk request is a batch of
    other operations and calling it a create would make the one series that
    should stand out read like part of the ordinary write traffic.
    """
    segments = path[len(PREFIX) :].split("/")
    resource = RESOURCES.get(segments[0].lower(), UNKNOWN)
    if resource == "bulk":
        return "bulk"

    verb = VERBS.get(method.upper(), UNKNOWN)
    return f"{resource}.{verb}"
