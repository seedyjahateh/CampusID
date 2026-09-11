"""What `amr` and `acr` are allowed to say (FR-MFA-08).

These two claims are the whole of what a relying party learns about *how*
somebody authenticated, and the requirement is unusually blunt about them: `amr`
must reflect the methods actually used, and `acr` may be `aal2` only when two
distinct factor categories were used. Both halves are easy to get wrong in the
generous direction, and a broker that is generous here is lying to every service
that trusts it.

**Two distinct categories, not two factors.** Somebody with the same TOTP seed on
a phone and a tablet has one factor on two devices, and counting them separately
would let a single stolen seed reach `aal2`. The categories are what NIST calls
the authenticator types — something you know and something you have — and the
whole point of a second factor is that the second one is a different *kind* of
thing.

**`mfa` is a marker, not a method.** RFC 8176 defines it as "multiple factors
were used", so it is derived from the rest of the list rather than asserted
alongside it. Emitting it on a single-factor session is the most common way this
claim becomes untrue, because it is the value most relying parties actually read.

**Both factors have to belong to the same authentication.** Twelve hours is the
bound, matching NIST SP 800-63B's reauthentication limit for AAL2 and the
session's own absolute timeout. In practice the session store enforces it first —
a session older than that no longer exists — so this is the check that survives
somebody changing that timeout without thinking about assurance.

**`auth_time` moves when the assurance does.** A relying party using `max_age` to
demand a recent authentication is asking when the person last proved something,
and a step-up is exactly that. Leaving it at the primary login would make a
freshly-elevated session look stale.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from campusid.authz.engine import AAL1, AAL2

# The linter reads this name as a credential. It is RFC 8176's identifier for
# "a password was used", which is the opposite: a record that one existed.
PWD: Final = "pwd"  # noqa: S105
OTP: Final = "otp"
HWK: Final = "hwk"
PUSH: Final = "push"
RECOVERY: Final = "recovery"
MFA: Final = "mfa"

FACTOR_CATEGORIES: Final = frozenset({PWD, OTP, HWK, PUSH, RECOVERY})
"""What counts towards a second factor.

`push` and `recovery` are not in RFC 8176's registry. They are emitted anyway
rather than folded into `otp`, because a push approval and a printed sheet are
different kinds of evidence and calling either a one-time password would be the
generous lie this module exists to avoid. A relying party is also more likely to
notice an unfamiliar value than a familiar one, which matters here: the push
service is simulated, and a recovery code is a standing bypass of every other
factor that a careful service may want to treat differently.
"""

MAX_SPAN: Final = timedelta(hours=12)
"""How far apart the two factors may be. See the module docstring."""


@dataclass(frozen=True, slots=True)
class Assurance:
    """What a session may claim after an authentication event."""

    acr: str
    amr: tuple[str, ...]
    auth_time: datetime


def primary(methods: tuple[str, ...], *, at: datetime) -> Assurance:
    """The assurance of a session that has only been through primary login.

    Always AAL1, whatever the IdP asserted. An upstream `AuthnContextClassRef`
    is a claim by somebody else about a ceremony this broker did not witness, and
    promoting it would make our `acr` only as honest as the least careful IdP in
    the federation.
    """
    return Assurance(acr=AAL1, amr=_normalise(methods), auth_time=at)


def elevated(
    *,
    methods: tuple[str, ...],
    category: str,
    since: datetime,
    now: datetime,
    max_span: timedelta = MAX_SPAN,
) -> Assurance:
    """The assurance after a second factor has been presented (FR-MFA-04).

    `methods` is what the session already recorded, `category` is what was just
    used, and `since` is when the first factor was presented. The result is AAL2
    only when those add up to two distinct categories close enough together to be
    one authentication.
    """
    combined = _normalise((*methods, category))
    categories = {method for method in combined if method in FACTOR_CATEGORIES}

    if len(categories) < 2 or now - since > max_span:
        # Not a failure — the factor was still presented and belongs in `amr`.
        # It simply does not amount to a second category, which is the case a
        # generous implementation would round up.
        return Assurance(acr=AAL1, amr=combined, auth_time=now)

    # Added after normalising rather than through it, because normalising is
    # what strips a stale marker — passing it back in would just remove it again.
    return Assurance(acr=AAL2, amr=tuple(sorted({*combined, MFA})), auth_time=now)


def satisfies_aal2(amr: tuple[str, ...]) -> bool:
    """Whether a recorded `amr` actually supports an AAL2 claim.

    Exists so the claim can be checked against the evidence rather than against
    the stored `acr`, which is what a test of this requirement has to do: an
    `acr` that agrees with itself proves nothing.
    """
    return len({method for method in amr if method in FACTOR_CATEGORIES}) >= 2


def _normalise(methods: tuple[str, ...]) -> tuple[str, ...]:
    """Sorted, deduplicated, and with `mfa` stripped.

    Stripped because it is derived: carrying a stale `mfa` forward would let a
    session that was once AAL2 keep claiming multiple factors after the reason
    for it was gone.
    """
    return tuple(sorted({method for method in methods if method and method != MFA}))
