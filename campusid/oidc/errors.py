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

The second thing this module carries is `redirectable`, which decides whether an
error may be sent *back to the client's redirect URI* or must be shown on the
broker's own error page. That is not presentation. Returning an error to an
unvalidated `redirect_uri` is an open redirect with the broker's name on it, so
the flag defaults to False and is raised only once the URI has been matched
against a registration.
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


class OAuthError(BrokerError):
    """A request was refused by the OIDC provider.

    `error` is what the client is told. `reason` is what the audit trail
    records. They are not the same granularity and are not meant to be.
    """

    def __init__(
        self,
        error: str,
        reason: ReasonCode,
        detail: str | None = None,
        *,
        redirectable: bool = False,
    ) -> None:
        super().__init__(reason, detail)
        self.error = error
        self.redirectable = redirectable
        """Whether this may be reported to the client's redirect URI.

        False until the URI has been validated against a registration. An error
        about a `redirect_uri` can never be sent to that `redirect_uri` — doing
        so is exactly the open redirect the exact-match rule exists to prevent.
        """
