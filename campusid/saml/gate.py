"""The assertion validation gate.

An ordered sequence of named checks, each with its own reason code. This is the
part of a SAML SP that decides whether an unauthenticated stranger becomes an
authenticated user, so it is written to be read.

Four ordering rules are security decisions rather than style.

**Structure is checked before verification.** A wrapped document must be
*rejected*, not merely survived. Processing only the verified element makes
wrapping ineffective, but the request would then succeed; refusing it is what
lets the event be audited as the attack it is.

**Replay is checked after verification.** Recording assertion IDs before the
signature is checked would let an unauthenticated attacker POST forged
responses carrying observed IDs, poisoning the cache so the legitimate
assertion is rejected as a replay. That is a denial of service on login.

**The outstanding request is consumed after verification**, for the same
reason: consuming it earlier would let a forged response burn a real user's
in-flight login.

**Only the verified element is read.** After `_verify`, everything comes from
the copy signxml returned. The original tree is deliberately not passed on —
see the note in `_verify` about why the obvious identity check does not work.

The assertion's own validity window is checked *before* the delivery binding,
because when a clock is wrong both expire together and `assertion_expired` is
the diagnosis an operator can act on. Clock skew is the single most common
cause of a working SAML integration failing in production, so it gets the
clearer message.

One asymmetry is worth understanding. `Response`-level attributes
(`Destination`, `InResponseTo`) are *unprotected* when only the assertion is
signed, which is the common case. The authoritative equivalents live inside
`SubjectConfirmationData` (`Recipient`, `InResponseTo`), within the signature.
Both are checked; only the latter is trustworthy, and the code says so where it
matters.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, overload

from lxml import etree

from campusid.errors import ReasonCode, SamlRejected
from campusid.saml.namespaces import (
    BEARER_CONFIRMATION_METHOD,
    Q_ASSERTION,
    Q_ATTRIBUTE,
    Q_ATTRIBUTE_STATEMENT,
    Q_ATTRIBUTE_VALUE,
    Q_AUDIENCE,
    Q_AUDIENCE_RESTRICTION,
    Q_AUTHN_CONTEXT_CLASS_REF,
    Q_AUTHN_STATEMENT,
    Q_CONDITIONS,
    Q_ISSUER,
    Q_NAME_ID,
    Q_ONE_TIME_USE,
    Q_PROXY_RESTRICTION,
    Q_STATUS_CODE,
    Q_SUBJECT,
    Q_SUBJECT_CONFIRMATION,
    Q_SUBJECT_CONFIRMATION_DATA,
    STATUS_SUCCESS,
)
from campusid.saml.parser import parse_saml, text_of
from campusid.saml.signature import (
    ASSERTION_SIGNATURE_LOCATION,
    RESPONSE_SIGNATURE_LOCATION,
    find_signature,
    verify_signature,
)
from campusid.saml.stores import OutstandingRequest, ReplayCache, RequestStore, utcnow
from campusid.saml.xsw import assert_no_wrapping

RECOGNISED_CONDITIONS: frozenset[str] = frozenset(
    {Q_AUDIENCE_RESTRICTION, Q_ONE_TIME_USE, Q_PROXY_RESTRICTION}
)
"""SAML 2.0 core 2.5.1: an assertion carrying a condition the SP does not
understand MUST be treated as invalid. `OneTimeUse` counts as understood
because the replay cache is exactly its contract."""


@dataclass(frozen=True, slots=True)
class TrustedIdP:
    """An IdP the broker has been configured to trust.

    Supplied by the federation registry in production; constructed directly in
    tests. Certificates come from that IdP's metadata and nowhere else — trust
    is metadata-pinned, not PKIX.
    """

    entity_id: str
    signing_certificates: tuple[str, ...]
    want_assertions_signed: bool = True
    allow_unsolicited: bool = False


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """What this broker will accept."""

    audience: str
    """Our own entityID. Assertions must be addressed to it."""

    destination: str
    """Our ACS URL. Must match `Destination` and `Recipient`."""

    clock_skew: timedelta = timedelta(seconds=180)
    max_authn_age: timedelta | None = None


@dataclass(frozen=True, slots=True)
class AssertionFacts:
    """What the gate extracted, once everything passed."""

    issuer: str
    assertion_id: str
    name_id: str
    name_id_format: str | None
    not_on_or_after: datetime
    authn_instant: datetime
    authn_context: str | None
    session_index: str | None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    relay_state: str | None = None


class AssertionGate:
    """Validates a SAML Response and returns the facts it asserts."""

    def __init__(
        self,
        policy: GatePolicy,
        resolve_idp: Callable[[str], TrustedIdP | None],
        replay_cache: ReplayCache,
        request_store: RequestStore,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._policy = policy
        self._resolve_idp = resolve_idp
        self._replay = replay_cache
        self._requests = request_store
        self._now = now

    async def validate(self, document: bytes) -> AssertionFacts:
        """Run every check in order, or raise `SamlRejected`."""
        root = parse_saml(document)  # 1. hardened parse
        assert_no_wrapping(root)  # 2. structural integrity
        self._check_status(root)  # 3. protocol status
        idp = self._resolve_issuer(root)  # 4. issuer -> trusted entity

        # 5-7. algorithms, reference binding, signature.
        assertion = self._verify(root, idp)

        self._check_destination(root)  # 8. unprotected, defence in depth
        request = await self._consume_request(root, idp)  # 9. correlation
        self._check_audience(assertion)  # 10.
        not_on_or_after = self._check_conditions(assertion)  # 11.
        self._check_subject_confirmation(assertion, request)  # 12. authoritative
        authn_instant, authn_context, session_index = self._check_authn_statement(assertion)
        await self._check_replay(assertion, not_on_or_after)  # 14.

        return AssertionFacts(
            issuer=idp.entity_id,
            assertion_id=_required_attribute(assertion, "ID"),
            name_id=self._name_id(assertion),
            name_id_format=self._name_id_format(assertion),
            not_on_or_after=not_on_or_after,
            authn_instant=authn_instant,
            authn_context=authn_context,
            session_index=session_index,
            attributes=_attributes(assertion),
            relay_state=request.relay_state if request else None,
        )

    # --- 3. status ---------------------------------------------------------

    def _check_status(self, root: etree._Element) -> None:
        """Reject a non-Success response before looking for an assertion.

        An IdP reporting `AuthnFailed` sends no assertion at all, so without
        this the gate would fail later with a confusing `signature_missing`
        and the operator would debug the wrong thing.
        """
        status_code = root.find(f".//{Q_STATUS_CODE}")
        value = status_code.get("Value") if status_code is not None else None
        if value != STATUS_SUCCESS:
            raise SamlRejected(ReasonCode.IDP_ERROR_STATUS, f"IdP returned status {value!r}")

    # --- 4. issuer ---------------------------------------------------------

    def _resolve_issuer(self, root: etree._Element) -> TrustedIdP:
        """Resolve the issuing IdP, and require both issuers to agree.

        Binding the certificate to the `Issuer` is what stops one registered
        IdP minting assertions in another's name. Verifying against "any
        registered certificate" would make every peer able to impersonate every
        other peer — the defining multi-IdP broker bug.
        """
        issuer = text_of(root.find(Q_ISSUER)).strip()
        assertion = root.find(Q_ASSERTION)
        if assertion is not None:
            assertion_issuer = text_of(assertion.find(Q_ISSUER)).strip()
            if assertion_issuer and issuer and assertion_issuer != issuer:
                raise SamlRejected(
                    ReasonCode.ISSUER_MISMATCH,
                    f"Response issuer {issuer!r} != Assertion issuer {assertion_issuer!r}",
                )
            issuer = assertion_issuer or issuer

        if not issuer:
            raise SamlRejected(ReasonCode.UNKNOWN_ISSUER, "no Issuer element")

        idp = self._resolve_idp(issuer)
        if idp is None:
            raise SamlRejected(ReasonCode.UNKNOWN_ISSUER, f"issuer {issuer!r} is not registered")
        return idp

    # --- 5-7. signature ----------------------------------------------------

    def _verify(self, root: etree._Element, idp: TrustedIdP) -> etree._Element:
        """Verify signatures and return the verified assertion.

        The returned element is signxml's own copy. Everything after this point
        reads from it and never from `root`, because `root` is the document an
        attacker sent and only this subtree has been proven authentic.
        """
        if find_signature(root) is not None:
            verify_signature(
                root,
                root,
                location=RESPONSE_SIGNATURE_LOCATION,
                certificates=idp.signing_certificates,
            )

        assertion = root.find(Q_ASSERTION)
        if assertion is None:
            raise SamlRejected(ReasonCode.MALFORMED_RESPONSE, "response contains no Assertion")

        if not idp.want_assertions_signed and find_signature(assertion) is None:
            # Only reachable for an IdP explicitly configured to sign the
            # Response instead. The assertion is then covered by that
            # signature, which was verified above.
            if find_signature(root) is None:
                raise SamlRejected(
                    ReasonCode.SIGNATURE_MISSING,
                    "neither the Response nor the Assertion is signed",
                )
            return assertion

        return verify_signature(
            root,
            assertion,
            location=ASSERTION_SIGNATURE_LOCATION,
            certificates=idp.signing_certificates,
        ).element

    # --- 8. destination ----------------------------------------------------

    def _check_destination(self, root: etree._Element) -> None:
        """Confirm the response was addressed to our ACS URL.

        Read from the unsigned `Response`, so this is defence in depth only.
        `SubjectConfirmationData/@Recipient` carries the same fact inside the
        signature and is the check that actually binds delivery.
        """
        destination = root.get("Destination")
        if destination is not None and destination != self._policy.destination:
            raise SamlRejected(
                ReasonCode.DESTINATION_MISMATCH,
                f"Destination {destination!r} != {self._policy.destination!r}",
            )

    # --- 9. correlation ----------------------------------------------------

    async def _consume_request(
        self, root: etree._Element, idp: TrustedIdP
    ) -> OutstandingRequest | None:
        """Match the response to an outstanding request, and consume it.

        Runs after verification so a forged response cannot burn a real user's
        in-flight login — the same denial-of-service shape as replay poisoning.
        """
        in_response_to = root.get("InResponseTo")
        if in_response_to is None:
            if not idp.allow_unsolicited:
                raise SamlRejected(
                    ReasonCode.UNSOLICITED_RESPONSE,
                    "response has no InResponseTo and unsolicited SSO is disabled",
                )
            return None

        request = await self._requests.consume(in_response_to)
        if request is None:
            raise SamlRejected(
                ReasonCode.UNKNOWN_INRESPONSETO,
                f"InResponseTo {in_response_to!r} matches no outstanding request",
            )
        if request.idp_entity_id != idp.entity_id:
            raise SamlRejected(
                ReasonCode.UNKNOWN_INRESPONSETO,
                f"request was sent to {request.idp_entity_id!r}, answered by {idp.entity_id!r}",
            )
        return request

    # --- 12. subject confirmation ------------------------------------------

    def _check_subject_confirmation(
        self, assertion: etree._Element, request: OutstandingRequest | None
    ) -> None:
        """Validate bearer `SubjectConfirmationData`.

        The Web Browser SSO profile puts the binding checks here, not on the
        `Response`, because this element is inside the signature. `Recipient`
        is what actually stops an assertion minted for another SP being
        replayed at ours.
        """
        subject = assertion.find(Q_SUBJECT)
        if subject is None:
            raise SamlRejected(ReasonCode.SUBJECT_CONFIRMATION_INVALID, "assertion has no Subject")

        for confirmation in subject.findall(Q_SUBJECT_CONFIRMATION):
            if confirmation.get("Method") != BEARER_CONFIRMATION_METHOD:
                continue
            data = confirmation.find(Q_SUBJECT_CONFIRMATION_DATA)
            if data is None:
                continue

            recipient = data.get("Recipient")
            if recipient != self._policy.destination:
                raise SamlRejected(
                    ReasonCode.SUBJECT_CONFIRMATION_INVALID,
                    f"Recipient {recipient!r} != {self._policy.destination!r}",
                )

            expiry = _instant(data, "NotOnOrAfter", required=True)
            if self._now() >= expiry + self._policy.clock_skew:
                raise SamlRejected(
                    ReasonCode.SUBJECT_CONFIRMATION_INVALID,
                    "SubjectConfirmationData has expired",
                )

            confirmed_in_response_to = data.get("InResponseTo")
            expected = request.request_id if request else None
            if confirmed_in_response_to != expected:
                raise SamlRejected(
                    ReasonCode.SUBJECT_CONFIRMATION_INVALID,
                    f"signed InResponseTo {confirmed_in_response_to!r} != {expected!r}",
                )
            return

        raise SamlRejected(
            ReasonCode.SUBJECT_CONFIRMATION_INVALID,
            "no bearer SubjectConfirmation with usable SubjectConfirmationData",
        )

    # --- 10. audience ------------------------------------------------------

    def _check_audience(self, assertion: etree._Element) -> None:
        conditions = assertion.find(Q_CONDITIONS)
        if conditions is None:
            raise SamlRejected(ReasonCode.AUDIENCE_MISMATCH, "assertion has no Conditions")

        audiences = [
            text_of(audience).strip()
            for restriction in conditions.findall(Q_AUDIENCE_RESTRICTION)
            for audience in restriction.findall(Q_AUDIENCE)
        ]
        if not audiences:
            raise SamlRejected(ReasonCode.AUDIENCE_MISMATCH, "no AudienceRestriction")
        if self._policy.audience not in audiences:
            raise SamlRejected(
                ReasonCode.AUDIENCE_MISMATCH,
                f"{self._policy.audience!r} not in {audiences!r}",
            )

    # --- 11. conditions ----------------------------------------------------

    def _check_conditions(self, assertion: etree._Element) -> datetime:
        conditions = assertion.find(Q_CONDITIONS)
        if conditions is None:
            raise SamlRejected(ReasonCode.ASSERTION_EXPIRED, "assertion has no Conditions")

        for child in conditions:
            if child.tag not in RECOGNISED_CONDITIONS:
                raise SamlRejected(
                    ReasonCode.UNSUPPORTED_CONDITION,
                    f"unrecognised condition {etree.QName(child).localname!r}",
                )

        now = self._now()
        skew = self._policy.clock_skew

        not_before = _instant(conditions, "NotBefore", required=False)
        if not_before is not None and now < not_before - skew:
            raise SamlRejected(
                ReasonCode.ASSERTION_NOT_YET_VALID,
                f"NotBefore {not_before.isoformat()} is beyond the {skew} skew allowance",
            )

        not_on_or_after = _instant(conditions, "NotOnOrAfter", required=True)
        if now >= not_on_or_after + skew:
            raise SamlRejected(
                ReasonCode.ASSERTION_EXPIRED,
                f"NotOnOrAfter {not_on_or_after.isoformat()} has passed",
            )
        return not_on_or_after

    # --- 13. authn statement -----------------------------------------------

    def _check_authn_statement(
        self, assertion: etree._Element
    ) -> tuple[datetime, str | None, str | None]:
        """Require an AuthnStatement and record the context it asserts.

        The context class is *recorded, not enforced*, in M1. Keycloak does not
        satisfy the REFEDS MFA profile and answers with `unspecified`, so
        rejecting on a mismatch would break every real login. Enforcement
        belongs with step-up (FR-SAML-11, M4), where there is somewhere to
        escalate to.
        """
        statement = assertion.find(Q_AUTHN_STATEMENT)
        if statement is None:
            raise SamlRejected(
                ReasonCode.MISSING_AUTHN_STATEMENT, "assertion has no AuthnStatement"
            )

        authn_instant = _instant(statement, "AuthnInstant", required=True)

        max_age = self._policy.max_authn_age
        if max_age is not None and self._now() - authn_instant > max_age + self._policy.clock_skew:
            raise SamlRejected(
                ReasonCode.ASSERTION_EXPIRED,
                f"AuthnInstant {authn_instant.isoformat()} is older than {max_age}",
            )

        class_ref = statement.find(f".//{Q_AUTHN_CONTEXT_CLASS_REF}")
        context = text_of(class_ref).strip() or None if class_ref is not None else None
        return authn_instant, context, statement.get("SessionIndex")

    # --- 14. replay --------------------------------------------------------

    async def _check_replay(self, assertion: etree._Element, expiry: datetime) -> None:
        """Refuse an assertion ID already seen.

        Last, and after verification, so an unauthenticated attacker cannot
        seed the cache with IDs and have the genuine assertion rejected.

        The entry lives until the assertion could no longer be accepted anyway
        — its expiry plus the skew allowance — because keeping it longer wastes
        memory and dropping it sooner reopens the window.
        """
        assertion_id = _required_attribute(assertion, "ID")
        ttl = (expiry - self._now()) + self._policy.clock_skew
        if not await self._replay.remember(assertion_id, ttl):
            raise SamlRejected(
                ReasonCode.REPLAY_DETECTED, f"assertion {assertion_id!r} has been seen"
            )

    # --- extraction --------------------------------------------------------

    def _name_id(self, assertion: etree._Element) -> str:
        name_id = assertion.find(f"{Q_SUBJECT}/{Q_NAME_ID}")
        value = text_of(name_id).strip()
        if not value:
            raise SamlRejected(ReasonCode.SUBJECT_CONFIRMATION_INVALID, "assertion has no NameID")
        return value

    def _name_id_format(self, assertion: etree._Element) -> str | None:
        name_id = assertion.find(f"{Q_SUBJECT}/{Q_NAME_ID}")
        return name_id.get("Format") if name_id is not None else None


def _required_attribute(element: etree._Element, name: str) -> str:
    value = element.get(name)
    if value is None:
        raise SamlRejected(
            ReasonCode.MALFORMED_RESPONSE,
            f"{etree.QName(element).localname} has no {name} attribute",
        )
    return value


@overload
def _instant(element: etree._Element, name: str, *, required: Literal[True]) -> datetime: ...


@overload
def _instant(
    element: etree._Element, name: str, *, required: Literal[False]
) -> datetime | None: ...


def _instant(element: etree._Element, name: str, *, required: bool) -> datetime | None:
    """Parse an `xs:dateTime` attribute into an aware datetime.

    Overloaded so `required=True` is typed as returning a `datetime`. Without
    that, every call site needs an `assert ... is not None` whose only purpose
    is to satisfy the checker, and asserts-as-type-hints are how a real None
    check eventually gets deleted by mistake.
    """
    raw = element.get(name)
    if raw is None:
        if required:
            raise SamlRejected(
                ReasonCode.MALFORMED_RESPONSE,
                f"{etree.QName(element).localname} has no {name} attribute",
            )
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise SamlRejected(
            ReasonCode.MALFORMED_RESPONSE, f"{name}={raw!r} is not a valid xs:dateTime"
        ) from exc
    if parsed.tzinfo is None:
        raise SamlRejected(
            ReasonCode.MALFORMED_RESPONSE,
            f"{name}={raw!r} has no timezone; xs:dateTime in SAML must be UTC-qualified",
        )
    return parsed


def _attributes(assertion: etree._Element) -> dict[str, list[str]]:
    """Collect released attributes, keyed by `Name`."""
    collected: dict[str, list[str]] = {}
    for statement in assertion.findall(Q_ATTRIBUTE_STATEMENT):
        for attribute in statement.findall(Q_ATTRIBUTE):
            name = attribute.get("Name")
            if name is None:
                continue
            values = [text_of(value) for value in attribute.findall(Q_ATTRIBUTE_VALUE)]
            collected.setdefault(name, []).extend(values)
    return collected
