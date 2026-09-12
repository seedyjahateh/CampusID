"""Prometheus metrics (NFR-OBS-03).

The requirement asks that each of six named metrics be present and incrementing,
so these tests do exactly that and then go after the two things a metrics layer
gets wrong in ways nobody notices until production:

**Cardinality.** Every label here comes from a closed set, and the one derived
from a URL is folded through an allowlist. A test that only proved the counters
count would happily pass on a design where an anonymous caller can create a time
series per request.

**Privacy.** No label carries a person. It is asserted rather than assumed,
because the failure is invisible: the scrape looks perfectly healthy while a
monitoring system nobody thinks of as holding identity fills up with subjects.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from campusid.authz.cache import CachingDecider, DecisionCache
from campusid.authz.engine import (
    Effect,
    Environment,
    PolicySet,
    Request,
    Resource,
    Rule,
    Subject,
)
from campusid.lifecycle.orchestrator import LifecycleOrchestrator
from campusid.lifecycle.rules import Delta
from campusid.observability.metrics import MAX_LABEL, Metrics
from campusid.observability.middleware import operation
from tests.support.audit import RecordingAuditLog

NAMES = (
    "campusid_auth_total",
    "campusid_assertion_validation_failures_total",
    "campusid_provisioning_latency_seconds",
    "campusid_scim_requests_total",
    "campusid_mfa_challenges_total",
    "campusid_authz_decisions_total",
)
"""The six the requirement names, spelled out rather than read off the module,
so a rename shows up here as a failure instead of being followed silently."""

PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
IDP = "https://idp.test/saml"


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


def value(metrics: Metrics, name: str, **labels: str) -> float | None:
    return metrics.registry.get_sample_value(name, labels)


# --- present ----------------------------------------------------------------


async def test_the_scrape_names_every_metric_the_requirement_asks_for(
    client: AsyncClient,
) -> None:
    """Present before anything has happened.

    A counter that only appears once it has been incremented is a counter an
    alert cannot be written against: `rate()` over a series that does not exist
    yet is not zero, it is nothing, and the alert silently never fires.
    """
    response = await client.get("/metrics")

    assert response.status_code == 200
    body = response.text
    for name in NAMES:
        assert f"# HELP {name} " in body


async def test_the_scrape_is_served_in_the_format_a_scraper_reads(
    client: AsyncClient,
) -> None:
    """Not `application/openmetrics-text`, which has different rules about
    `_total` suffixes and would be parsed differently."""
    response = await client.get("/metrics")

    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")


# --- incrementing -----------------------------------------------------------


def test_authentications_are_counted_by_provider_protocol_and_outcome(
    metrics: Metrics,
) -> None:
    metrics.authenticated(idp=IDP, protocol="saml", outcome="success")
    metrics.authenticated(idp=IDP, protocol="saml", outcome="success")
    metrics.authenticated(idp=IDP, protocol="saml", outcome="failure")

    assert value(metrics, "campusid_auth_total", idp=IDP, protocol="saml", outcome="success") == 2
    assert value(metrics, "campusid_auth_total", idp=IDP, protocol="saml", outcome="failure") == 1


def test_a_refused_assertion_is_counted_under_its_reason_code(metrics: Metrics) -> None:
    """The most useful series here. A spike in one reason names the
    misconfiguration, which a single `failures_total` cannot."""
    metrics.assertion_refused("signature_invalid")
    metrics.assertion_refused("audience_mismatch")
    metrics.assertion_refused("signature_invalid")

    name = "campusid_assertion_validation_failures_total"
    assert value(metrics, name, reason="signature_invalid") == 2
    assert value(metrics, name, reason="audience_mismatch") == 1


def test_provisioning_latency_is_observed(metrics: Metrics) -> None:
    metrics.provisioned(0.4)
    metrics.provisioned(12.0)

    assert value(metrics, "campusid_provisioning_latency_seconds_count") == 2
    assert value(metrics, "campusid_provisioning_latency_seconds_sum") == pytest.approx(12.4)


def test_the_latency_buckets_cover_the_numbers_the_slos_are_written_about(
    metrics: Metrics,
) -> None:
    """NFR-PROV-01 is 30 s at p95 and NFR-PROV-02 is 15 s. A histogram with no
    edge near the threshold can only say the run was somewhere between 10 and
    60 seconds, which is not an answer to either."""
    metrics.provisioned(12.0)

    name = "campusid_provisioning_latency_seconds_bucket"
    assert value(metrics, name, le="10.0") == 0
    assert value(metrics, name, le="30.0") == 1


def test_scim_requests_are_counted_by_operation_and_status_class(metrics: Metrics) -> None:
    metrics.scim_request(op="users.create", status=201)
    metrics.scim_request(op="users.create", status=409)

    name = "campusid_scim_requests_total"
    assert value(metrics, name, op="users.create", status="2xx") == 1
    assert value(metrics, name, op="users.create", status="4xx") == 1


def test_status_codes_are_folded_into_classes(metrics: Metrics) -> None:
    """404 and 409 are both "the client asked for something that is not there",
    and a chart with forty lines is a chart nobody reads."""
    metrics.scim_request(op="users.read", status=404)
    metrics.scim_request(op="users.read", status=422)

    assert value(metrics, "campusid_scim_requests_total", op="users.read", status="4xx") == 2


def test_second_factor_challenges_are_counted_by_factor_and_outcome(metrics: Metrics) -> None:
    metrics.mfa_challenge(factor="totp", outcome="success")
    metrics.mfa_challenge(factor="totp", outcome="failure")
    metrics.mfa_challenge(factor="webauthn", outcome="success")

    name = "campusid_mfa_challenges_total"
    assert value(metrics, name, factor="totp", outcome="success") == 1
    assert value(metrics, name, factor="totp", outcome="failure") == 1
    assert value(metrics, name, factor="webauthn", outcome="success") == 1


def test_authorization_decisions_are_counted_by_effect(metrics: Metrics) -> None:
    metrics.authz_decision("permit")
    metrics.authz_decision("deny")
    metrics.authz_decision("deny")

    assert value(metrics, "campusid_authz_decisions_total", decision="permit") == 1
    assert value(metrics, "campusid_authz_decisions_total", decision="deny") == 2


# --- cardinality ------------------------------------------------------------


def test_an_absent_provider_becomes_one_named_series(metrics: Metrics) -> None:
    """`unknown` rather than the empty string.

    An empty label renders as a series with a blank name, which reads on a
    dashboard like a real provider whose name somebody forgot to configure.
    """
    metrics.authenticated(idp=None, protocol="saml", outcome="failure")

    assert (
        value(metrics, "campusid_auth_total", idp="unknown", protocol="saml", outcome="failure")
        == 1
    )


def test_a_long_entity_id_is_truncated(metrics: Metrics) -> None:
    """An entityID is a URL somebody else chose. Letting a peer decide how much
    memory a scrape costs is worse than an ugly label."""
    metrics.authenticated(idp="https://idp.test/" + "x" * 500, protocol="saml", outcome="success")

    labels = [
        sample.labels
        for metric in metrics.registry.collect()
        for sample in metric.samples
        if sample.name == "campusid_auth_total"
    ]
    assert [len(label["idp"]) for label in labels] == [MAX_LABEL]


@pytest.mark.parametrize(
    ("path", "method", "expected"),
    [
        ("/scim/v2/Users", "POST", "users.create"),
        ("/scim/v2/Users/abc-123", "GET", "users.read"),
        ("/scim/v2/Users/abc-123", "PATCH", "users.patch"),
        ("/scim/v2/Users/abc-123", "PUT", "users.replace"),
        ("/scim/v2/Users/abc-123", "DELETE", "users.delete"),
        ("/scim/v2/Groups", "GET", "groups.read"),
        ("/scim/v2/ServiceProviderConfig", "GET", "config.read"),
        # Case-folded: a client sending the lowercase form is talking about the
        # same collection and should not create a second series.
        ("/scim/v2/users", "POST", "users.create"),
        # Bulk is its own name. It is a batch of other operations, and calling it
        # a create would hide the one series that should stand out.
        ("/scim/v2/Bulk", "POST", "bulk"),
    ],
)
def test_the_operation_label_names_the_collection_and_the_verb(
    path: str, method: str, expected: str
) -> None:
    assert operation(path, method) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/scim/v2/Whatever",
        "/scim/v2/../etc/passwd",
        "/scim/v2/" + "a" * 200,
    ],
)
def test_an_unrecognised_collection_cannot_create_a_series(path: str) -> None:
    """The cardinality attack, and the reason the allowlist exists.

    A label taken from the path is a label an anonymous caller picks. A few
    thousand requests to invented URLs would otherwise create a few thousand
    series in whatever is scraping us — a denial of service against the
    monitoring system, mounted through a 404.
    """
    assert operation(path, "GET") == "unknown.read"


def test_an_unrecognised_method_cannot_create_a_series() -> None:
    """The collection is still named, because it is still known. Only the half
    that came from the caller is folded away."""
    assert operation("/scim/v2/Users", "TRACE") == "users.unknown"


# --- wired up ---------------------------------------------------------------


async def test_a_scim_request_is_counted_without_the_handler_knowing(
    app: FastAPI, client: AsyncClient
) -> None:
    await client.get("/scim/v2/ServiceProviderConfig")

    assert (
        value(app.state.metrics, "campusid_scim_requests_total", op="config.read", status="2xx")
        == 1
    )


async def test_a_request_no_handler_matched_is_still_counted(
    app: FastAPI, client: AsyncClient
) -> None:
    """The reason this sits in front of the router rather than in the handlers.

    A client whose every request is 404ing against a misspelled collection is
    exactly the case somebody wants a chart of, and no handler ever runs.
    """
    await client.get("/scim/v2/Whatever")

    assert (
        value(app.state.metrics, "campusid_scim_requests_total", op="unknown.read", status="4xx")
        == 1
    )


async def test_every_authorization_decision_is_counted_including_cached_ones() -> None:
    """Decisions rather than evaluations.

    One that counted only cache misses would report a well-cached hour as a drop
    in traffic, which is the same argument `CachedDecision` makes about the
    audit record.
    """
    metrics = Metrics()
    decider = CachingDecider(
        _Policies(PolicySet((Rule(id="open", effect=Effect.PERMIT, resource_prefix="lms:"),))),
        DecisionCache(None),
        metrics=metrics,
    )

    await decider.decide(_ask())
    await decider.decide(_ask())

    assert value(metrics, "campusid_authz_decisions_total", decision="permit") == 2


async def test_a_denial_is_counted_under_its_own_effect() -> None:
    metrics = Metrics()
    decider = CachingDecider(_Policies(PolicySet(())), DecisionCache(None), metrics=metrics)

    result = await decider.decide(_ask())

    assert result.decision.effect is Effect.DENY
    assert value(metrics, "campusid_authz_decisions_total", decision="deny") == 1


async def test_a_provisioning_chain_is_timed() -> None:
    metrics = Metrics()
    orchestrator = _orchestrator(metrics)

    await orchestrator.transitioned(PERSON, set(), {"student"})

    assert value(metrics, "campusid_provisioning_latency_seconds_count") == 1


async def test_a_leaver_produces_one_observation_not_two() -> None:
    """`transitioned` routes an emptied affiliation set to `deprovision`, and
    both would otherwise time the same chain — halving the apparent rate and
    reporting the leaver sequence twice."""
    metrics = Metrics()
    orchestrator = _orchestrator(metrics)

    await orchestrator.transitioned(PERSON, {"student"}, set())

    assert value(metrics, "campusid_provisioning_latency_seconds_count") == 1


async def test_a_failed_chain_is_still_timed() -> None:
    """Excluding failures would make the latency chart look healthiest exactly
    when provisioning is worst."""
    metrics = Metrics()
    orchestrator = _orchestrator(metrics, lifecycle=_Broken())

    with pytest.raises(ConnectionError):
        await orchestrator.transitioned(PERSON, set(), {"student"})

    assert value(metrics, "campusid_provisioning_latency_seconds_count") == 1


# --- isolation --------------------------------------------------------------


def test_two_instances_do_not_share_counters() -> None:
    """Why the registry is owned rather than the library's global one.

    With the default registry, two tests in one session would increment the same
    collector and an assertion about a count would depend on what ran before it.
    """
    first, second = Metrics(), Metrics()

    first.authz_decision("permit")

    assert value(first, "campusid_authz_decisions_total", decision="permit") == 1
    assert value(second, "campusid_authz_decisions_total", decision="permit") is None


# --- helpers ----------------------------------------------------------------


class _Policies:
    def __init__(self, policies: PolicySet) -> None:
        self.current = policies


def _ask() -> Request:
    return Request(
        subject=Subject(person_uuid=PERSON, assurance="urn:campusid:aal1"),
        resource=Resource(id="lms:course/101"),
        action="read",
        environment=Environment(network="campus"),
    )


class _Rules:
    """The rules, reduced to a transition that changes nothing.

    What the transition decides is not what these tests are about; that it was
    timed is.
    """

    def __init__(self) -> None:
        self.current = self

    def transition(self, before: set[str], after: set[str], *, on: Any = None) -> Delta:
        return Delta()


class _Lifecycle:
    async def apply(self, person_uuid: Any, delta: Any, **kwargs: Any) -> None:
        return None


class _Broken(_Lifecycle):
    async def apply(self, person_uuid: Any, delta: Any, **kwargs: Any) -> None:
        raise ConnectionError("the database went away mid-transition")


class _Sessions:
    async def terminate_subject(self, subject_key: str) -> list[str]:
        return []


class _Grants:
    async def revoke_session_families(self, sid: str) -> list[str]:  # pragma: no cover
        return []


def _orchestrator(metrics: Metrics, *, lifecycle: Any = None) -> LifecycleOrchestrator:
    return LifecycleOrchestrator(
        rules=_Rules(),
        lifecycle=lifecycle or _Lifecycle(),  # type: ignore[arg-type]
        sessions=_Sessions(),
        grants=_Grants(),
        audit=RecordingAuditLog(),
        metrics=metrics,
    )
