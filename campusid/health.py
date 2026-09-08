"""Liveness and readiness endpoints (NFR-AVAIL-02).

The two are deliberately different:

``/healthz`` answers "is this process alive?" and never touches a dependency.
An orchestrator restarting the broker because Postgres blipped would turn a
recoverable data-tier problem into an outage.

``/readyz`` answers "should this instance receive traffic?" and reports every
dependency individually. Components register a probe at startup; as the broker
grows, LDAP and upstream IdP metadata freshness join the same registry.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel

from campusid import __version__

Probe = Callable[[], Awaitable[None]]
"""A readiness check: returns normally when healthy, raises when not."""


class LivenessResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


class ComponentStatus(BaseModel):
    status: Literal["ok", "error"]
    detail: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ok", "not_ready"]
    service: str
    version: str
    checks: dict[str, ComponentStatus]


router = APIRouter(tags=["ops"])


@router.get("/healthz", response_model=LivenessResponse)
async def healthz(request: Request) -> LivenessResponse:
    """Liveness: the process is running and serving. No dependency checks."""
    return LivenessResponse(
        status="ok",
        service=request.app.state.settings.service_name,
        version=__version__,
    )


@router.get("/readyz", response_model=ReadinessResponse)
async def readyz(request: Request, response: Response) -> ReadinessResponse:
    """Readiness: every registered dependency probe must pass."""
    probes: dict[str, Probe] = request.app.state.readiness_probes
    checks = await _run_probes(probes)

    ready = all(check.status == "ok" for check in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ok" if ready else "not_ready",
        service=request.app.state.settings.service_name,
        version=__version__,
        checks=checks,
    )


async def _run_probes(probes: dict[str, Probe]) -> dict[str, ComponentStatus]:
    """Run all probes concurrently; a slow dependency must not serialise the rest."""
    if not probes:
        return {}

    names = list(probes)
    results = await asyncio.gather(
        *(probes[name]() for name in names),
        return_exceptions=True,
    )
    return {name: _to_status(result) for name, result in zip(names, results, strict=True)}


def _to_status(result: BaseException | None) -> ComponentStatus:
    """Map a probe outcome to a component status.

    The detail is the exception type, never its message: connection errors
    routinely carry credentials and internal hostnames (FR-AUD-06, NFR-UX-02).
    """
    if isinstance(result, BaseException):
        return ComponentStatus(status="error", detail=type(result).__name__)
    return ComponentStatus(status="ok")
