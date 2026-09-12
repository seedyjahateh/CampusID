"""Prometheus metrics (NFR-OBS-03).

Six series, chosen because each answers a question somebody asks at three in the
morning: are logins working, which check is refusing them, is provisioning
keeping up, is the SCIM client erroring, are second factors failing, and is the
authorization engine denying more than it did yesterday.

**No label here can carry a person.** That is the rule the label sets are built
around, and it does two jobs at once. A metric labelled by subject is personal
data in a system with no retention policy, scraped into a store nobody thinks of
as holding identity — and it is also unbounded cardinality, which is how a
monitoring system falls over. Every label below has a small fixed range: a
handful of IdPs, the reason-code registry, two protocols, a few outcomes.

**Metrics are not the audit trail and do not try to be.** A counter says how many
and the trail says which; a counter that could answer "which" would be a second
record of the same events with none of the trail's guarantees. When somebody
wants to know who, the answer is a query against the trail, and the dashboard
already reads from there.

**The registry is explicit rather than global.** `prometheus_client`'s default
registry is process-wide, so two tests in one session would share counters and a
test asserting an increment would depend on what ran before it. An owned registry
makes each instance independent, which is also what lets the application hold one
without anything else in the process registering into it by accident.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client.core import CollectorRegistry as Registry

CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"
"""What a Prometheus scraper expects. Not `application/openmetrics-text`, which
is a different format with different rules about `_total` suffixes."""

PROVISIONING_BUCKETS: Final = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
"""Bucket edges for provisioning latency, in seconds.

Chosen around the numbers that matter rather than a default ladder: a joiner
inside a second is healthy, ten seconds is somebody waiting, and sixty is the
deprovisioning target. Buckets nobody would act on are buckets that cost storage
in every scrape forever.
"""


class Metrics:
    """The six series NFR-OBS-03 names, and nothing else.

    Deliberately a small closed set. A metrics module that grows a counter per
    curiosity becomes a cardinality problem nobody owns, and the audit trail is
    already the place to go for a question this cannot answer.
    """

    def __init__(self, registry: Registry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()

        self.auth = Counter(
            "campusid_auth_total",
            "Authentication outcomes by upstream provider and protocol.",
            labelnames=("idp", "protocol", "outcome"),
            registry=self.registry,
        )
        self.validation_failures = Counter(
            "campusid_assertion_validation_failures_total",
            "Assertions refused by the validation gate, by reason code.",
            # The reason-code registry is closed and small, which is what makes
            # this safe to label. It is also the single most useful series here:
            # a spike in one reason names the misconfiguration.
            labelnames=("reason",),
            registry=self.registry,
        )
        self.provisioning_latency = Histogram(
            "campusid_provisioning_latency_seconds",
            "End-to-end time for a provisioning chain.",
            buckets=PROVISIONING_BUCKETS,
            registry=self.registry,
        )
        self.scim_requests = Counter(
            "campusid_scim_requests_total",
            "SCIM requests by operation and HTTP status.",
            labelnames=("op", "status"),
            registry=self.registry,
        )
        self.mfa_challenges = Counter(
            "campusid_mfa_challenges_total",
            "Second-factor challenges by factor kind and outcome.",
            labelnames=("factor", "outcome"),
            registry=self.registry,
        )
        self.authz_decisions = Counter(
            "campusid_authz_decisions_total",
            "Authorization decisions by effect.",
            labelnames=("decision",),
            registry=self.registry,
        )

    # --- recording --------------------------------------------------------
    #
    # Thin wrappers rather than exposing the collectors, so a call site cannot
    # pass labels in the wrong order — which produces a series that scrapes
    # cleanly and means something else entirely.

    def authenticated(self, *, idp: str | None, protocol: str, outcome: str) -> None:
        self.auth.labels(idp=_bounded(idp), protocol=protocol, outcome=outcome).inc()

    def assertion_refused(self, reason: str) -> None:
        self.validation_failures.labels(reason=reason).inc()

    def provisioned(self, seconds: float) -> None:
        self.provisioning_latency.observe(seconds)

    def scim_request(self, *, op: str, status: int) -> None:
        # The status *class* rather than the code: 404 and 409 are both "the
        # client asked for something that is not there", and a chart with forty
        # lines is a chart nobody reads.
        self.scim_requests.labels(op=op, status=f"{status // 100}xx").inc()

    def mfa_challenge(self, *, factor: str, outcome: str) -> None:
        self.mfa_challenges.labels(factor=factor, outcome=outcome).inc()

    def authz_decision(self, decision: str) -> None:
        self.authz_decisions.labels(decision=decision).inc()

    def render(self) -> bytes:
        """The current values, in the exposition format a scraper reads."""
        return bytes(generate_latest(self.registry))


UNKNOWN: Final = "unknown"
MAX_LABEL: Final = 128
"""How long a label value may be.

An entityID is a URL somebody else chose, and a label is a dimension in a time
series database. Truncating is ugly; letting a peer decide how much memory a
scrape costs is worse.
"""


def _bounded(value: str | None) -> str:
    """A label value that cannot surprise the monitoring system.

    Empty becomes `unknown` rather than an empty string, because an empty label
    silently merges every unattributable event into one series that looks like a
    real provider with a missing name.
    """
    if not value:
        return UNKNOWN
    return value[:MAX_LABEL]
