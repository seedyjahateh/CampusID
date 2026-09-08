#!/usr/bin/env sh
# Week 0 acceptance check: the broker answers 200 on /healthz.
#
#   ./scripts/smoke.sh [base-url]
#
# Later milestones extend this with one full SSO round trip and one SCIM
# lifecycle (PRD NFR-OPS-01).
set -eu

BASE_URL="${1:-http://localhost:8000}"
ATTEMPTS=30
DELAY=2

echo "smoke: waiting for ${BASE_URL}/healthz"

attempt=1
while [ "${attempt}" -le "${ATTEMPTS}" ]; do
    status="$(curl -s -o /tmp/smoke-body -w '%{http_code}' "${BASE_URL}/healthz" || echo 000)"
    if [ "${status}" = "200" ]; then
        echo "smoke: /healthz -> 200"
        cat /tmp/smoke-body
        echo

        # Readiness proves Postgres and Redis are both reachable from the broker.
        ready="$(curl -s -o /tmp/smoke-ready -w '%{http_code}' "${BASE_URL}/readyz" || echo 000)"
        echo "smoke: /readyz -> ${ready}"
        cat /tmp/smoke-ready
        echo
        [ "${ready}" = "200" ] || { echo "smoke: FAIL - broker is not ready"; exit 1; }

        echo "smoke: PASS"
        exit 0
    fi
    echo "smoke: attempt ${attempt}/${ATTEMPTS} -> ${status}"
    attempt=$((attempt + 1))
    sleep "${DELAY}"
done

echo "smoke: FAIL - no 200 from ${BASE_URL}/healthz after $((ATTEMPTS * DELAY))s"
exit 1
