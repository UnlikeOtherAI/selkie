#!/bin/sh
# Reuse the project that owns Selkie's existing containers and persistent volumes.
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
project=
for container in selkie-server selkie-redis selkie-coturn; do
    if docker container inspect "$container" >/dev/null 2>&1; then
        owner=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container")
        case "$owner" in
            ''|'<no value>')
                echo "Cannot deploy: $container has no Compose project label." >&2
                exit 1
                ;;
        esac
        if [ -n "$project" ] && [ "$owner" != "$project" ]; then
            echo "Cannot deploy: Selkie containers belong to different Compose projects." >&2
            exit 1
        fi
        project=$owner
    fi
done

exec docker compose -p "${project:-selkie}" --env-file .env -f ops/docker-compose.prod.yml "$@"
