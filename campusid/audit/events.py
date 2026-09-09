"""What an audit event is, and what may appear in one (FR-AUD-01, FR-AUD-06).

One shape for every event, because the alternative — each subsystem inventing
its own fields — is what makes an audit trail unqueryable three months later.
The field list is FR-AUD-01's, and the meanings are worth stating because two of
them get confused constantly:

- **actor** is who *did* it. For a login that is the person; for an
  administrator ending somebody's sessions it is the administrator.
- **subject** is who it was *about*. For that same administrative action it is
  the person whose sessions ended.

Collapsing the two loses the only question an incident review actually asks:
not "was this account touched" but "who touched it".

**Redaction is structural, not editorial.** `detail` accepts attribute *names*
freely and attribute *values* only when the catalogue classifies them `public`.
That is enforced here rather than trusted to each call site, because the failure
mode of getting it wrong is a `studentID` sitting in the disclosure record that
exists to prove studentIDs are never disclosed. A caller that hands over a
restricted value gets it replaced by a marker, and the marker is deliberately
visible: a redaction that happened silently would look like an attribute that
was never released.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from campusid.policy.attributes import Classification, definition

REDACTED: Final = "[redacted]"
"""What replaces a value that may not be recorded. Visible on purpose — a silent
drop would read as an attribute that was never released."""


class EventType(StrEnum):
    """Every kind of thing worth recording.

    A closed enumeration rather than free text, so `test_audit_query.py` can
    filter by type and a dashboard panel can count by it without string
    matching. Adding a type is a deliberate edit here.
    """

    # --- authentication ---------------------------------------------------
    AUTH_REQUEST = "auth.request"
    """The broker asked an IdP to authenticate somebody."""

    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    """Carries the gate's `ReasonCode`. This is the event `test_audit_query.py`
    aggregates for "all authentication failures for one subject"."""

    # --- sessions ----------------------------------------------------------
    SESSION_CREATED = "session.created"
    SESSION_ENDED = "session.ended"
    SESSION_TERMINATED = "session.terminated"
    """Ended by an administrator rather than by the person. A different event
    from `session.ended` because the actor differs, and an investigation reads
    the two very differently."""

    # --- authorization ------------------------------------------------------
    AUTHZ_CODE_ISSUED = "authz.code_issued"
    AUTHZ_DENIED = "authz.denied"
    # Event-type names, not credentials. The bandit rule fires on the word
    # "token"; renaming them to satisfy it would make the audit vocabulary worse
    # to read for no security gain.
    TOKEN_ISSUED = "token.issued"  # noqa: S105
    TOKEN_REFRESHED = "token.refreshed"  # noqa: S105
    TOKEN_REVOKED = "token.revoked"  # noqa: S105
    GRANT_REUSE_DETECTED = "grant.reuse_detected"
    """The one event here that is a security incident rather than a record of
    normal operation: a credential was presented twice, so one of the two
    presentations was not the client."""

    # --- disclosure ---------------------------------------------------------
    ATTRIBUTE_RELEASE = "attribute.release"
    """FR-ARP-06 and FERPA §99.32. Every attribute considered, released or not,
    with the rule that decided it."""

    # --- lifecycle ----------------------------------------------------------
    LIFECYCLE_JOINER = "lifecycle.joiner"
    LIFECYCLE_MOVER = "lifecycle.mover"
    LIFECYCLE_LEAVER = "lifecycle.leaver"
    """The three transitions, separate types rather than one with a field.

    An investigation into a termination reads nothing like one into a role
    change, and a dashboard counting deprovisionings should not have to filter a
    generic type by a detail key to find them.
    """

    ENTITLEMENT_GRANTED = "entitlement.granted"
    ENTITLEMENT_REVOKED = "entitlement.revoked"
    """Both, because "when did they get it" and "when did they lose it" are the
    two questions an access review asks, and neither is answerable from the
    other."""

    DEPROVISION_STEP = "deprovision.step"
    """One step of FR-LC-03's ordered sequence. Recorded per step, so an
    incomplete deprovisioning shows which step it got to rather than simply
    being absent."""

    # --- administration -----------------------------------------------------
    ADMIN_ACTION = "admin.action"
    CONFIG_CHANGE = "config.change"
    LOGOUT_DELIVERY_FAILED = "logout.delivery_failed"


class Outcome(StrEnum):
    """Whether the thing succeeded. Three values, not two.

    `DENIED` is separate from `FAILURE` because they mean opposite things to
    whoever reads the trail: a denial is the system working — a policy said no —
    while a failure is the system not working, or being attacked.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One record. FR-AUD-01's field list, and nothing outside it."""

    event_type: EventType
    outcome: Outcome
    timestamp: datetime
    correlation_id: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    actor: str | None = None
    """Who did it."""

    subject: str | None = None
    """Who it was about."""

    target: str | None = None
    """What it was done to or through — an SP entityID, a client_id, an IdP."""

    reason: str | None = None
    """A `ReasonCode` value where one applies. Internal vocabulary: it is
    recorded here and still never shown to the browser."""

    source_ip: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    """Event-specific structure, already redacted by `redact`."""


def redact(detail: dict[str, Any]) -> dict[str, Any]:
    """Strip anything that may not be recorded (FR-AUD-06).

    Two rules, applied to the whole structure:

    1. A key that names a credential is replaced outright. The list is
       deliberately about *shapes of secret* rather than exact field names,
       because the next credential somebody adds will not be called
       `client_secret`.
    2. Under `attributes`, values survive only for attributes the catalogue
       classifies `public`. Attribute *names* are always kept: knowing that
       `mail` was released is the point of the record, and knowing what the
       address was is not.
    """
    cleaned: dict[str, Any] = {}
    for key, value in detail.items():
        if _is_secret(key):
            cleaned[key] = REDACTED
        elif key == "attributes" and isinstance(value, dict):
            cleaned[key] = _redact_attributes(value)
        else:
            cleaned[key] = value
    return cleaned


SECRET_MARKERS: Final[tuple[str, ...]] = (
    "token",
    "secret",
    "password",
    "assertion",
    "cookie",
    "verifier",
    "challenge",
    "code",
    "key",
    "credential",
    "salt",
)
"""Substrings that make a field a credential.

Matched as substrings and not as an exact list, because a field named
`refresh_token_hint` or `saml_response_assertion` is exactly as disclosing as
one named `token`, and an exact list only ever catches the names somebody
thought of. False positives here cost a redacted debugging aid; false negatives
cost a credential in a table that is never deleted from.
"""


def _is_secret(key: str) -> bool:
    return any(marker in key.lower() for marker in SECRET_MARKERS)


def _redact_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Keep every name; keep values only for `public` attributes."""
    kept: dict[str, Any] = {}
    for name, values in attributes.items():
        attribute = definition(name)
        if attribute is not None and attribute.classification is Classification.PUBLIC:
            kept[name] = values
        else:
            # Includes attributes the catalogue does not know. An unrecognised
            # name is exactly the case where we cannot say the value is safe.
            kept[name] = REDACTED
    return kept
