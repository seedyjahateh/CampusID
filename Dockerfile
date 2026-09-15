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
COPY requirements.lock requirements-dev.lock ./
# --require-hashes (NFR-SEC-08). Every direct and transitive dependency is
# fetched by digest, so a compromised index, a re-uploaded artifact or a
# dependency-confusion package is a build failure rather than a running process.
# It also makes pip refuse any requirement that is not fully pinned, which is
# what keeps a hand-edited lock from quietly reopening the hole.
#
# The lock files, not requirements.txt: pip cannot mix hashed and unhashed
# requirements, and requirements.txt is the human document that says *why* each
# direct dependency is here. `scripts/lock-dependencies.sh` turns one into the
# other.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock


# --- Development / CI image (adds the test toolchain) -----------------------
FROM deps AS dev
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.lock
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

# The timeout is 6s rather than 3s because most of the budget is spent starting
# a Python interpreter rather than answering the request: on a loaded host the
# probe was timing out while `/healthz` was replying in milliseconds, which reads
# as an unhealthy broker and is really a slow `python -c`. Detection is still
# fast — five failures at a ten-second interval.
HEALTHCHECK --interval=10s --timeout=6s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"]

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["serve"]
