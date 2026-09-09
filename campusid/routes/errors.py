"""The one way this broker tells a browser something went wrong.

Every rejection returns the same status and the same body, differing only in a
correlation id. Varying the response by reason would let an attacker enumerate
the gate's checks by observation, and the distinction is worthless to a real
user, who can only quote the reference anyway (NFR-UX-02).

The reason code is not lost — it is logged here, and becomes an audit record in
M2. It just never reaches the person who caused it.
"""

from __future__ import annotations

import secrets
from typing import Final

from fastapi.responses import HTMLResponse
from starlette.responses import Response

from campusid.errors import ReasonCode
from campusid.logging import get_logger

log = get_logger(__name__)

ERROR_PAGE: Final = """<!doctype html>
<meta charset="utf-8">
<title>Sign-in failed</title>
<h1>Sign-in failed</h1>
<p>We could not complete your sign-in. Please try again.</p>
<p>If you contact support, quote reference <code>{correlation_id}</code>.</p>
"""


def correlation_id() -> str:
    """A short reference a user can quote and an operator can search for."""
    return secrets.token_hex(8)


def reject(reason: ReasonCode, detail: str, reference: str | None = None) -> Response:
    """Audit the reason; show the user a page that reveals none of it."""
    reference = reference or correlation_id()
    log.warning("request.rejected", reason=reason.value, detail=detail, correlation_id=reference)
    return HTMLResponse(
        ERROR_PAGE.format(correlation_id=reference),
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )
