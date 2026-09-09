"""Pairwise subject identifiers (FR-ARP-04).

A pairwise identifier gives each service provider a different, stable name for
the same person, so two SPs comparing notes cannot tell they are talking about
one individual. It is the difference between "the analytics service knows a
user came back" and "the analytics service can join its records to the health
centre's".

Derived rather than stored: `HMAC-SHA256(salt, person_key || sp_entity_id)`.
Deriving means no table to keep consistent and no migration when an SP is
added; the cost is that the salt becomes load-bearing.

**The salt cannot be rotated in place.** Changing it changes every identifier
at every SP simultaneously, and each SP sees its entire user base replaced by
strangers. It is a restore-critical secret — backed up with the database, first
item in the disaster-recovery runbook — and rotating it is a coordinated
migration, not an operation.

The separator matters more than it looks. Without it,
`person_key="ab" + sp="cd"` and `person_key="a" + sp="bcd"` hash identically,
so one SP could predict another's identifier for a chosen user.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Final

SEPARATOR: Final = b"\x00"
"""A byte that cannot occur in either input, so the concatenation is
unambiguous. See the module docstring for why that is a security property and
not tidiness."""


def pairwise_id(salt: bytes, person_key: str, sp_entity_id: str, scope: str) -> str:
    """Derive this person's identifier at this SP.

    Returns the REFEDS `pairwise-id` form, `opaque@scope`, which is what makes
    it recognisable to a federation partner as an identifier rather than a
    name.
    """
    if not salt:
        raise ValueError("a pairwise salt is required; an empty salt derives nothing secret")

    digest = hmac.new(
        salt,
        person_key.encode("utf-8") + SEPARATOR + sp_entity_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    # Truncated to 128 bits: still far beyond guessing, and short enough that
    # the value fits comfortably in a log line and a database column.
    opaque = base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("=")
    return f"{opaque}@{scope}"


def subject_id(person_key: str, scope: str) -> str:
    """The shared `subject-id`: the same value at every SP.

    Released only to SPs whose policy asks for it. Correlatable by design,
    which is exactly why `pairwise` is the default.
    """
    return f"{person_key}@{scope}"
