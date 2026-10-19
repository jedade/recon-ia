#!/bin/sh
# scripts/run-tests.sh — lance la suite pytest de l'API dans un conteneur
# jetable (image construite depuis api/Dockerfile.test), sans dépendre de la
# stack docker-compose ni d'un Python installé sur l'hôte.
#
#   ./scripts/run-tests.sh                      # toute la suite
#   ./scripts/run-tests.sh tests/test_auth.py   # arguments passés à pytest
#   REBUILD=1 ./scripts/run-tests.sh            # après un changement de requirements.txt
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="recon-ia-api-test"

if [ -n "$REBUILD" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f "$ROOT/api/Dockerfile.test" -t "$IMAGE" "$ROOT/api"
fi

# --network none : un test qui tenterait un vrai appel réseau échoue au lieu
# de dépendre d'Internet (les outils OSINT doivent être simulés).
# MSYS_NO_PATHCONV : évite la réécriture des chemins par Git Bash sous Windows.
MSYS_NO_PATHCONV=1 docker run --rm --network none \
    -v "$ROOT/api:/app" -w /app \
    "$IMAGE" python -m pytest -p no:cacheprovider "$@"
