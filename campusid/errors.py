"""Rejection reason codes and the broker's error hierarchy.

Every path that refuses a request names *why* with a `ReasonCode`. This module is
the single registry of those names, which is what makes two things possible:

1. `tests/security/test_negative_suite_completeness.py` asserts that every code
   defined here is exercised by at least one test. Without a single registry the
   negative suite silently falls behind the code it is meant to guard.
2. The audit layer (M2) can aggregate by reason without string-matching log text.

Reason codes are internal. They are logged and audited; they are never shown to
the browser, which gets a generic error page and a correlation id (NFR-UX-02).
Telling an attacker *which* of ten checks rejected their forgery is free
reconnaissance.
"""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    """Why the broker refused. Values are stable identifiers — audit records and
    dashboards key on them, so renaming one is a breaking change."""

    # --- Transport and XML hardening ------------------------------------
    PAYLOAD_TOO_LARGE = "payload_too_large"
    MALFORMED_RESPONSE = "malformed_response"
    XML_HARDENING_VIOLATION = "xml_hardening_violation"
    DUPLICATE_ELEMENT_ID = "duplicate_element_id"

    # --- Structural integrity / signature wrapping ----------------------
    SIGNATURE_WRAPPING_DETECTED = "signature_wrapping_detected"

    # --- Protocol-level ---------------------------------------------------
    IDP_ERROR_STATUS = "idp_error_status"
    UNKNOWN_ISSUER = "unknown_issuer"
    ISSUER_MISMATCH = "issuer_mismatch"

    # --- Signature ---------------------------------------------------------
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    WEAK_ALGORITHM = "weak_algorithm"

    # --- Encryption (M2; see NOT_YET_REACHABLE) --------------------------
    DECRYPTION_FAILED = "decryption_failed"
    UNSUPPORTED_ENCRYPTION_ALGORITHM = "unsupported_encryption_algorithm"

    # --- Binding and delivery ---------------------------------------------
    DESTINATION_MISMATCH = "destination_mismatch"
    UNKNOWN_INRESPONSETO = "unknown_inresponseto"
    UNSOLICITED_RESPONSE = "unsolicited_response"
    REQUEST_BINDING_INVALID = "request_binding_invalid"
    SUBJECT_CONFIRMATION_INVALID = "subject_confirmation_invalid"

    # --- Assertion conditions ---------------------------------------------
    AUDIENCE_MISMATCH = "audience_mismatch"
    ASSERTION_NOT_YET_VALID = "assertion_not_yet_valid"
    ASSERTION_EXPIRED = "assertion_expired"
    UNSUPPORTED_CONDITION = "unsupported_condition"
    MISSING_AUTHN_STATEMENT = "missing_authn_statement"

    # --- Replay -------------------------------------------------------------
    REPLAY_DETECTED = "replay_detected"


NOT_YET_REACHABLE: frozenset[ReasonCode] = frozenset(
    {
        # Assertion decryption lands in M2 alongside the release policy that
        # actually mandates it (FR-SAML-03, ADR-003 D3). The codes are declared
        # now so the audit vocabulary is stable, and exempted here so the
        # completeness meta-test stays honest rather than being weakened.
        #
        # This entry MUST be gone by the end of M2.
        ReasonCode.DECRYPTION_FAILED,
        ReasonCode.UNSUPPORTED_ENCRYPTION_ALGORITHM,
        # Raised when the request-binding cookie does not match the RelayState
        # record — the login-CSRF defence. Lands with the session cookies later
        # in M1; declared now because the ACS already reasons about RelayState.
        ReasonCode.REQUEST_BINDING_INVALID,
    }
)
"""Codes with no reachable code path yet, exempt from the completeness test.

An escape hatch, so it is enumerated in `test_negative_suite_completeness.py`
and every entry names the milestone that removes it. Adding a code here to
silence a failing build, rather than to record deliberately deferred work,
defeats the purpose of the check."""


class BrokerError(Exception):
    """Base for every deliberate refusal in the broker."""

    def __init__(self, reason: ReasonCode, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


class SamlRejected(BrokerError):
    """A SAML message failed the validation gate.

    `detail` is for operators — it may name the offending value and is written
    to the audit record. It never reaches the browser.
    """
