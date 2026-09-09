# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # The app runs from source rather than as an installed distribution, so
    # /app must be importable however a process is started. Without this, a
    # script under scripts/ gets its own directory on sys.path and not the
    # package root.
    PYTHONPATH=/app

WORKDIR /app


# --- Dependency layer -------------------------------------------------------
# Copied separately so a source change does not invalidate the wheel cache.
FROM base AS deps
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt


# --- Development / CI image (adds the test toolchain) -----------------------
FROM deps AS dev
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
RUN chmod +x /app/scripts/entrypoint.sh \
    && useradd --uid 10001 --no-create-home --no-user-group --gid users campusid \
    && chown -R campusid:users /app
USER campusid
EXPOSE 8000
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["serve"]


# --- Runtime image ----------------------------------------------------------
FROM deps AS runtime
COPY alembic.ini ./
COPY campusid/ ./campusid/
COPY migrations/ ./migrations/
COPY scripts/entrypoint.sh ./scripts/entrypoint.sh
# The shipped release policies. Baked into the image so a deployment that
# mounts nothing still has working, reviewed policy rather than an empty
# directory — which under default-deny would release nothing to anybody.
COPY policies/ ./policies/
# The affiliation transition rules, for the same reason: a deployment that
# mounts nothing still derives entitlements from reviewed rules rather than
# from an empty file, which would revoke everybody's access at once.
COPY config/ ./config/

# Runs unprivileged with no home directory and no login shell (NFR-SEC-09).
RUN chmod +x /app/scripts/entrypoint.sh \
    && useradd --uid 10001 --no-create-home --no-user-group --gid users \
       --shell /usr/sbin/nologin campusid \
    && chown -R campusid:users /app \
    # The SAML key directory is created here, not just mounted, because Docker
    # copies ownership from the image path when a named volume is first
    # populated. Without this the volume arrives root-owned and the
    # unprivileged broker cannot write its keypair.
    && mkdir -p /var/lib/campusid/saml \
    && chown -R campusid:users /var/lib/campusid \
    && chmod 700 /var/lib/campusid/saml
USER campusid

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"]

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["serve"]
