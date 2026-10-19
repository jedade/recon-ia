#!/bin/sh
# scripts/e2e/run-result-page.sh — test de bout en bout de la page
# « Voir le résultat » dans Chrome headless.
#
#   ./scripts/e2e/run-result-page.sh [chemin de Chrome]
#
# Prérequis : Docker, Node ≥ 22, Chrome ou Chromium (chemin auto-détecté ou
# passé en argument / variable CHROME). Démarre deux conteneurs jetables :
#   - l'API (image de test recon-ia-api-test) avec un dossier scellé de
#     démonstration, sur 127.0.0.1:18080 ;
#   - un serveur statique pour web/result.* sur 127.0.0.1:18081.
# Les captures d'écran restent dans le dossier de travail affiché à la fin.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
# Git Bash (Windows) : Docker Desktop ne comprend pas les chemins /tmp/... ni
# /c/... — on lui passe la forme C:/... quand cygpath est disponible.
to_docker() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
WORK_D="$(to_docker "$WORK")"
ROOT_D="$(to_docker "$ROOT")"
CHROME="${1:-${CHROME:-}}"
if [ -z "$CHROME" ]; then
    for c in google-chrome chromium chromium-browser \
             "/c/Program Files/Google/Chrome/Application/chrome.exe" \
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
        if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CHROME="$c"; break; fi
    done
fi
[ -n "$CHROME" ] || { echo "Chrome introuvable : passez son chemin en argument."; exit 2; }

cleanup() { docker rm -f reconia-e2e-api reconia-e2e-web >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker image inspect recon-ia-api-test >/dev/null 2>&1 || \
    docker build -f "$ROOT_D/api/Dockerfile.test" -t recon-ia-api-test "$ROOT_D/api"

mkdir -p "$WORK/web"
cp "$ROOT/web/result.html" "$ROOT/web/result.css" "$ROOT/web/result.js" "$WORK/web/"
echo 'window.RECON_IA_CONFIG = { API_BASE: "http://localhost:18080", TURNSTILE_SITE_KEY: "" };' > "$WORK/web/config.js"
cp "$ROOT/scripts/e2e/demo_server.py" "$WORK/"

cleanup
MSYS_NO_PATHCONV=1 docker run -d --name reconia-e2e-api -p 127.0.0.1:18080:8080 \
    -v "$ROOT_D/api:/app" -v "$WORK_D:/demo" -w /app recon-ia-api-test python /demo/demo_server.py >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name reconia-e2e-web -p 127.0.0.1:18081:8000 \
    -v "$WORK_D/web:/srv:ro" -w /srv recon-ia-api-test python -m http.server 8000 >/dev/null

for _ in $(seq 1 60); do
    [ -f "$WORK/code.txt" ] && curl -s -o /dev/null http://localhost:18080/ && break
    sleep 1
done
[ -f "$WORK/code.txt" ] || { docker logs reconia-e2e-api; exit 1; }

node "$ROOT/scripts/e2e/result_page.mjs" "$WORK" "$CHROME"
echo "Captures : $WORK"
