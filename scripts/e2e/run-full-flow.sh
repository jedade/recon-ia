#!/bin/sh
# scripts/e2e/run-full-flow.sh — parcours COMPLET sur la stack réelle
# (formulaire + Turnstile → OTP → pipeline n8n → mail avec code → result.html).
#
#   ./scripts/e2e/run-full-flow.sh [chemin de Chrome]
#
# Prérequis :
#   - stack démarrée (./setup.sh), Node ≥ 22, Chrome ;
#   - .env racine : TURNSTILE_SITE_KEY=1x00000000000000000000AA et
#     TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA (clés de TEST
#     Cloudflare : validation toujours réussie, vrai appel siteverify) ;
#   - api/.env : SMTP_SERVER=mailpit, SMTP_PORT=1025, SMTP_USERNAME et
#     SMTP_PASSWORD quelconques (Mailpit accepte toute authentification).
#     Ce script démarre Mailpit sur le réseau de la stack (alias `mailpit`,
#     STARTTLS actif, interface sur http://localhost:8026).
#
# Variables : SITE (http://localhost:${CADDY_HTTP_PORT:-80}), API_ADMIN
# (http://localhost:8080), ADMIN_AUTH (« email:motdepasse » de l'admin),
# DOMAIN (example.com), PIPELINE_TIMEOUT_S (3600 — l'analyse via Ollama sur
# CPU prend ~20-30 min).
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHROME="${1:-${CHROME:-}}"
if [ -z "$CHROME" ]; then
    for c in google-chrome chromium chromium-browser \
             "/c/Program Files/Google/Chrome/Application/chrome.exe" \
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
        if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CHROME="$c"; break; fi
    done
fi
[ -n "$CHROME" ] || { echo "Chrome introuvable : passez son chemin en argument."; exit 2; }
[ -n "$ADMIN_AUTH" ] || { echo "Définissez ADMIN_AUTH=\"email:motdepasse\" (compte admin de l'API)."; exit 2; }

NETWORK="$(docker inspect api --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
if ! docker ps --format '{{.Names}}' | grep -q '^reconia-mailpit$'; then
    docker rm -f reconia-mailpit >/dev/null 2>&1 || true
    docker run -d --name reconia-mailpit --network "$NETWORK" --network-alias mailpit \
        -p 127.0.0.1:8026:8025 -e MP_SMTP_TLS_CERT=sans:mailpit -e MP_SMTP_TLS_KEY=sans:mailpit \
        -e MP_SMTP_AUTH_ACCEPT_ANY=1 axllent/mailpit:latest >/dev/null
    sleep 3
fi

PORT="$(grep -E '^CADDY_HTTP_PORT=' "$ROOT/.env" 2>/dev/null | cut -d= -f2)"
export SITE="${SITE:-http://localhost:${PORT:-80}}"
OUT="$(mktemp -d)"
node "$ROOT/scripts/e2e/full_flow.mjs" "$OUT" "$CHROME"
echo "Captures et journal : $OUT"
