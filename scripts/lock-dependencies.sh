#!/usr/bin/env sh
# Regenerate the hash-pinned lock files (NFR-SEC-08).
#
#   ./scripts/lock-dependencies.sh
#
# Run this after editing requirements.txt or requirements-dev.txt, and commit the
# lock files alongside the change. CI installs from the locks, so a dependency
# edit that does not reach them has no effect on anything that runs.
#
# Inside a container matching the runtime image, deliberately. A resolution is
# specific to a Python version and a platform: running pip-compile on a laptop
# can pin a wheel that does not exist for the image, and the failure appears at
# `docker build` on somebody else's machine rather than here.
#
# --generate-hashes is the whole point. A version pin says which release to
# fetch; a hash says which bytes, which is what makes a compromised index or a
# re-uploaded artifact a build failure instead of a supply-chain compromise.
#
# --strip-extras because pip refuses to mix hashed and unhashed requirements, and
# an extras marker in a hashed file is one of the shapes it will not take.
#
# --allow-unsafe pins setuptools and pip themselves. The name is historical: what
# was once "unsafe to pin" is now the opposite, since leaving a build backend
# floating is exactly the hole hashes are here to close.
set -eu

IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
PIP_TOOLS_VERSION="7.4.1"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "lock: resolving in ${IMAGE}"

docker run --rm \
    -v "${ROOT}:/work" \
    -w /work \
    "${IMAGE}" \
    sh -eu -c "
        pip install --quiet --no-cache-dir pip-tools==${PIP_TOOLS_VERSION}
        for source in requirements requirements-dev; do
            pip-compile \
                --generate-hashes \
                --strip-extras \
                --allow-unsafe \
                --no-header \
                --quiet \
                --output-file=\"\${source}.lock\" \
                \"\${source}.txt\"
        done
    "

echo "lock: wrote requirements.lock and requirements-dev.lock"
echo "lock: review the diff — a version that moved without you asking is the"
echo "      interesting part, not the hashes"
