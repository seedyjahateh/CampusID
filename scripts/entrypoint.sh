#!/usr/bin/env sh
# Container entrypoint.
#
#   serve     apply migrations, then run the broker (default)
#   migrate   apply migrations and exit
#   <other>   executed verbatim, for `docker compose run broker pytest ...`
set -eu

apply_migrations() {
    echo "entrypoint: applying migrations"
    # env.py takes a Postgres advisory lock, so concurrent replicas are safe
    # to start simultaneously (NFR-OPS-03).
    alembic upgrade head
    echo "entrypoint: migrations at head"
}

case "${1:-serve}" in
    serve)
        apply_migrations
        exec python -m campusid
        ;;
    migrate)
        apply_migrations
        ;;
    *)
        exec "$@"
        ;;
esac
