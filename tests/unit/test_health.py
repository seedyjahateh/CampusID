"""Liveness and readiness behaviour (NFR-AVAIL-02)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from campusid import __version__


async def test_healthz_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "campusid-broker",
        "version": __version__,
    }


async def test_healthz_ignores_failing_dependencies(app: FastAPI, client: AsyncClient) -> None:
    """Liveness must not depend on the data tier.

    A Postgres blip should not make an orchestrator kill every broker replica.
    """

    async def failing() -> None:
        raise ConnectionError("postgres is down")

    app.state.readiness_probes = {"database": failing}

    assert (await client.get("/healthz")).status_code == 200


async def test_readyz_ok_when_all_probes_pass(app: FastAPI, client: AsyncClient) -> None:
    async def passing() -> None:
        return None

    app.state.readiness_probes = {"database": passing, "redis": passing}

    response = await client.get("/readyz")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {
        "database": {"status": "ok", "detail": None},
        "redis": {"status": "ok", "detail": None},
    }


async def test_readyz_503_when_a_probe_fails(app: FastAPI, client: AsyncClient) -> None:
    async def passing() -> None:
        return None

    async def failing() -> None:
        raise ConnectionError("connection refused")

    app.state.readiness_probes = {"database": failing, "redis": passing}

    response = await client.get("/readyz")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"]["status"] == "error"
    assert body["checks"]["redis"]["status"] == "ok"


async def test_readyz_does_not_leak_probe_messages(app: FastAPI, client: AsyncClient) -> None:
    """Connection errors routinely carry credentials and internal hostnames.

    The probe detail reports the exception type only (FR-AUD-06, NFR-UX-02).
    """
    secret = "postgresql://campusid:hunter2@postgres.internal:5432/campusid"

    async def failing() -> None:
        raise ConnectionError(secret)

    app.state.readiness_probes = {"database": failing}

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"]["database"]["detail"] == "ConnectionError"
    assert "hunter2" not in response.text
    assert "postgres.internal" not in response.text


async def test_readyz_runs_probes_concurrently(app: FastAPI, client: AsyncClient) -> None:
    """A slow dependency must not serialise the others past the probe timeout."""
    delay = 0.2

    async def slow() -> None:
        await asyncio.sleep(delay)

    app.state.readiness_probes = {f"dep{i}": slow for i in range(5)}

    loop = asyncio.get_running_loop()
    started = loop.time()
    response = await client.get("/readyz")
    elapsed = loop.time() - started

    assert response.status_code == 200
    assert elapsed < delay * 3, f"probes appear to run serially ({elapsed:.2f}s)"


async def test_readyz_with_no_probes_registered(client: AsyncClient) -> None:
    """Before lifespan runs there are no probes; readiness must not crash."""
    response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["checks"] == {}


@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
async def test_ops_endpoints_carry_security_headers(client: AsyncClient, path: str) -> None:
    """NFR-SEC-03: applied on every route, including the ops endpoints."""
    response = await client.get(path)

    headers = response.headers
    assert headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
