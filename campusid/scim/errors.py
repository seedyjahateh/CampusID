"""SCIM error responses (FR-SCIM-12, RFC 7644 §3.12).

Every SCIM failure returns the same envelope — `status`, `scimType`, `detail` —
and the `scimType` is the part that matters. A provisioning client is a program,
not a person: it acts on the distinction between "this request will never
succeed" and "this request lost a race", and prose in `detail` is for whoever
reads the log afterwards.

That makes SCIM the opposite of the SAML and OIDC surfaces, where a uniform
opaque rejection is the right answer. The audiences differ: there, the caller
may be forging assertions and every distinction is reconnaissance. Here the
caller is an authenticated SIS that we *want* to succeed, and telling it exactly
what was wrong is the difference between a fixed integration and a support
ticket.
"""

from __future__ import annotations

from typing import Any, Final

ERROR_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimType:
    """The `scimType` values RFC 7644 §3.12 defines, and what each tells a client."""

    INVALID_FILTER: Final = "invalidFilter"
    """The filter or path did not parse. A bug in the client's request builder."""

    TOO_MANY: Final = "tooMany"
    """The filter matched more than the server will return. Narrow it."""

    UNIQUENESS: Final = "uniqueness"
    """A uniqueness constraint was violated — a duplicate `userName`. The client
    should reconcile rather than retry, because retrying will fail identically."""

    MUTABILITY: Final = "mutability"
    """An attempt to change something immutable. Never succeeds, so a client
    that retries is wasting both our time and its own."""

    INVALID_SYNTAX: Final = "invalidSyntax"
    INVALID_PATH: Final = "invalidPath"
    NO_TARGET: Final = "noTarget"
    """The path was valid but selected nothing to operate on. Often a race with
    another change rather than a bug, which is why it is distinct from
    `invalidPath`."""

    INVALID_VALUE: Final = "invalidValue"
    INVALID_VERS: Final = "invalidVers"
    SENSITIVE: Final = "sensitive"
    """The request would have put a sensitive value somewhere it could be
    logged — a credential in a query string, for instance."""


class ScimError(Exception):
    """A SCIM operation failed.

    Carries the HTTP status alongside the `scimType` because the two are chosen
    together: a `uniqueness` failure is a 409 and nothing else, and letting a
    caller pick the status separately is how they drift apart.
    """

    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def to_dict(self) -> dict[str, Any]:
        """The response body.

        `status` is a string, which looks like a mistake and is not: RFC 7644
        §3.12's example carries it quoted, and a conformance client comparing it
        to `"404"` fails against an integer.
        """
        body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(self.status)}
        if self.scim_type:
            body["scimType"] = self.scim_type
        body["detail"] = self.detail
        return body


def not_found(resource_type: str, resource_id: str) -> ScimError:
    """404. Names the id because a client managing thousands needs to know which
    one, and an id it supplied is not a disclosure."""
    return ScimError(404, f"{resource_type} {resource_id} not found")


def duplicate(attribute: str, value: str) -> ScimError:
    """409 `uniqueness` — the FR-SCIM-02 case.

    A duplicate `userName` is the single most common SCIM error in practice,
    because an SIS that lost a response retries a create. The client's correct
    response is to reconcile, not to retry, and `uniqueness` is what tells it so.
    """
    return ScimError(409, f"{attribute} {value!r} is already in use", ScimType.UNIQUENESS)


def version_mismatch(expected: str) -> ScimError:
    """412 (FR-SCIM-09).

    Somebody else changed the resource since the client read it. Not an error in
    either party — it is optimistic concurrency doing its job, and the client
    re-reads and re-applies.
    """
    return ScimError(412, f"the resource has changed; current version is {expected}")


def invalid_filter(detail: str) -> ScimError:
    return ScimError(400, detail, ScimType.INVALID_FILTER)


def invalid_value(detail: str, scim_type: str = ScimType.INVALID_VALUE) -> ScimError:
    return ScimError(400, detail, scim_type)


def unauthorized() -> ScimError:
    """401 with no `scimType`.

    Deliberately says nothing about *why*. This is the one SCIM response whose
    caller may not be a legitimate client, so it is the one place the surface
    behaves like the SAML gate rather than like a helpful API.
    """
    return ScimError(401, "authentication required")


def forbidden(scope: str) -> ScimError:
    """403 (FR-SCIM-13). Names the scope, because an authenticated client that
    holds the wrong one has a fixable configuration problem."""
    return ScimError(403, f"this token does not carry the {scope} scope")
