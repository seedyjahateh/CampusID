"""OAuth 2.0 protocol errors.

Two vocabularies meet here, and keeping them apart is the point of the module.

`ReasonCode` is internal: precise, audited, never shown to anyone. The OAuth
`error` parameter is the opposite — it is defined by RFC 6749 §4.1.2.1 and
§5.2, it goes to the client, and it is deliberately coarse. `invalid_grant`
covers an expired code, a replayed code, a code issued to a different client and
a failed PKCE check, because telling a caller which of those it was is free
reconnaissance for whoever is holding a stolen code.

So every refusal carries both: the public `error` the client receives and the
`ReasonCode` the audit log records.

The second thing this module carries is `NEVER_REDIRECTED`, which decides
whether an error may be sent *back to the client's redirect URI* or must be
shown on the broker's own error page. That is not presentation. Returning an
error to an unvalidated `redirect_uri` is an open redirect with the broker's
name on it.

It is a set of reason codes rather than a flag on each refusal, and that took a
correction to arrive at. A flag set at the raise site says the wrong thing,
because whether there is somewhere safe to send an error is a property of *where
in the flow you are*, not of the check: `pkce.verify` fails identically at the
authorization endpoint, where the client's URI is known and an error belongs
there, and at the token endpoint, where there is no redirect at all. What is
genuinely intrinsic is narrower — an error *about* the destination cannot be
sent to that destination — and that is exactly these two codes.
"""

from __future__ import annotations

from typing import Final

from campusid.errors import BrokerError, ReasonCode

INVALID_REQUEST: Final = "invalid_request"
INVALID_CLIENT: Final = "invalid_client"
INVALID_GRANT: Final = "invalid_grant"
UNAUTHORIZED_CLIENT: Final = "unauthorized_client"
UNSUPPORTED_GRANT_TYPE: Final = "unsupported_grant_type"
UNSUPPORTED_RESPONSE_TYPE: Final = "unsupported_response_type"
INVALID_SCOPE: Final = "invalid_scope"
ACCESS_DENIED: Final = "access_denied"
SERVER_ERROR: Final = "server_error"


NEVER_REDIRECTED: Final[frozenset[ReasonCode]] = frozenset(
    {ReasonCode.UNKNOWN_CLIENT, ReasonCode.REDIRECT_URI_MISMATCH}
)
"""Refusals that can never be reported to a client's redirect URI.

Both are errors *about* the destination: we do not know which client this is, or
the URI supplied is not one we recognise. Sending "your redirect_uri is wrong"
to that redirect_uri forwards the user to the attacker's URL with the broker's
blessing, which is the open redirect the exact-match rule exists to prevent.
They belong on our own error page, which is also the only place the user can see
who was asking.
"""


class OAuthError(BrokerError):
    """A request was refused by the OIDC provider.

    `error` is what the client is told. `reason` is what the audit trail
    records. They are not the same granularity and are not meant to be.
    """

    def __init__(self, error: str, reason: ReasonCode, detail: str | None = None) -> None:
        super().__init__(reason, detail)
        self.error = error


def may_be_redirected(exc: OAuthError) -> bool:
    """Whether this refusal may be reported to the client's redirect URI.

    Only meaningful once that URI has been matched against a registration — the
    caller knows which phase it is in, and this answers the narrower question of
    whether the error is about the destination itself.
    """
    return exc.reason not in NEVER_REDIRECTED
