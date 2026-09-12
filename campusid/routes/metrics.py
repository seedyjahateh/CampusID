"""The scrape endpoint (NFR-OBS-03).

``GET /metrics`` in the exposition format Prometheus reads. One route, and the
only thing worth arguing about is who gets to call it.

**It is unauthenticated, like `/healthz` and `/readyz`, and that is a deployment
boundary rather than an oversight.** A scraper is infrastructure: giving it a
credential means the credential lives in the monitoring system's configuration,
which is a worse place for one than a network rule. The exposure this accepts is
bounded by the rule the metrics themselves are built around — no label carries a
person, so the worst an unauthorised reader learns is aggregate traffic volume
and which validation checks are refusing assertions. That is operational
information, not identity data, and `/readyz` already names our dependencies.

The corollary is that the label rule is load-bearing. The day somebody adds a
label carrying a subject, this endpoint becomes a directory. That argument is in
`campusid/observability/metrics.py` where the labels are declared, so it is in
front of whoever would add one.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from campusid.observability.metrics import CONTENT_TYPE

router = APIRouter(tags=["ops"])


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    """Current values of every collector this process owns.

    Out of the OpenAPI schema deliberately: it is not part of the broker's API
    and its format is a scraper's contract rather than a client's.
    """
    return Response(
        content=request.app.state.metrics.render(),
        media_type=CONTENT_TYPE,
    )
