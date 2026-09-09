"""What one client learns about the person in a session (FR-OP-11, FR-ARP-04).

The single place the OIDC side asks "who is this, and how much of it may this
application see". It answers by calling the *same* release engine, with the
*same* policy object, that the SAML side uses — so the promise that both
protocols release identical sets is a consequence of there being one
implementation rather than an agreement between two.

The order is fixed and each step narrows:

1. **Normalise.** The session holds attributes as the IdP asserted them.
   Everything downstream compares them as strings, so they are normalised once,
   here, rather than at each comparison.
2. **Release.** The policy decides what this SP is entitled to, knowing nothing
   about OIDC.
3. **Map.** Scopes select from what was released, and the result becomes claims.

The subject identifier is derived last and from the *policy's* canonical
entityID rather than from the `client_id`. That is what makes the same person
receive the same `sub` whether they arrive at an application over SAML or OIDC —
the point of the whole broker — and it is why a policy may carry aliases.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from campusid.oidc.claims import claims_for
from campusid.policy.normalize import normalize
from campusid.policy.pairwise import pairwise_id, subject_id
from campusid.policy.release import Decision, ReleasePolicy, Subject, evaluate
from campusid.session.store import Session


@dataclass(frozen=True, slots=True)
class ReleasedIdentity:
    """Everything one client may be told about one session."""

    subject: str
    """The `sub` claim: pairwise unless this SP's policy asks for shared."""

    claims: dict[str, Any]
    decisions: tuple[Decision, ...]
    """Every attribute considered, released or not, with the rule that decided
    it. Carried alongside the claims because the audit record (FR-ARP-06) is
    written from the same evaluation that produced the token — reconstructing it
    later would be a second implementation of the policy."""


def release_to(
    session: Session,
    policy: ReleasePolicy,
    scopes: frozenset[str],
    *,
    pairwise_salt: bytes,
    scope: str,
    ferpa_directory_suppressed: bool = False,
    consented: frozenset[str] = frozenset(),
) -> ReleasedIdentity:
    """Decide what this client sees of this session."""
    subject = Subject(
        person_key=session.subject_key,
        ferpa_directory_suppressed=ferpa_directory_suppressed,
    )

    normalised = normalize(session.attributes, scope=scope)
    result = evaluate(policy, subject, normalised.attributes, consented=consented)

    return ReleasedIdentity(
        subject=_subject_identifier(policy, subject, pairwise_salt=pairwise_salt, scope=scope),
        claims=claims_for(scopes, result.attributes),
        decisions=result.decisions,
    )


def _subject_identifier(
    policy: ReleasePolicy, subject: Subject, *, pairwise_salt: bytes, scope: str
) -> str:
    """The `sub` claim.

    Derived from `policy.sp_entity_id`, never from the `client_id`. An
    application reachable as both a SAML entityID and an OIDC client has one
    policy and therefore one canonical name, so the identifier it receives is
    the same on both paths. Deriving from `client_id` would give the same person
    two identities at one application and silently break account linking in the
    application itself.
    """
    if policy.subject_id_mode == "shared":
        return subject_id(subject.person_key, scope)
    return pairwise_id(pairwise_salt, subject.person_key, policy.sp_entity_id, scope)
