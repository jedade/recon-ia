#!/bin/sh
# entrypoint.sh — Corrige le DNS, lance les migrations puis démarre l'API.

set -e

# ── Fix DNS ──────────────────────────────────────────────────────────────────
# Ordre nameservers :
#   1. 127.0.0.11 EN PREMIER — résolveur Docker interne, connaît les noms de
#      services (postgres, ollama, etc.) et renvoie SERVFAIL (pas NXDOMAIN)
#      pour les domaines externes → musl retry le suivant automatiquement.
#   2. 8.8.8.8 / 1.1.1.1 — fallback pour les domaines publics.
#
# ATTENTION : ne PAS mettre 8.8.8.8 en premier avec ndots:0.
# 8.8.8.8 retourne NXDOMAIN pour "postgres" → musl s'arrête et ne tente
# plus les autres nameservers (comportement musl sur NXDOMAIN = autoritative).
echo "=== [entrypoint] Correction DNS ==="
printf "nameserver 127.0.0.11\nnameserver 8.8.8.8\nnameserver 1.1.1.1\noptions ndots:1 timeout:3 attempts:3\n" > /etc/resolv.conf
echo "[entrypoint] resolv.conf :"
cat /etc/resolv.conf

# ── Migrations ───────────────────────────────────────────────────────────────
echo "=== [entrypoint] Lancement des migrations ==="
python migrate.py

# ── API ──────────────────────────────────────────────────────────────────────
# Serveur WSGI de production (gunicorn), et non le serveur de développement
# Flask qui est mono-processus et déconseillé hors développement.
#
# Choix de configuration :
#   --worker-class gthread : la charge est I/O-bound (attente réseau des outils
#       OSINT et des API IA). Des threads suffisent et consomment bien moins
#       de mémoire que des processus supplémentaires.
#   --timeout 300 : un scan passif peut durer jusqu'à SCAN_DEADLINE_SECONDS
#       (180 s par défaut) plus l'analyse. Un timeout inférieur ferait tuer le
#       worker par gunicorn en plein scan.
#   --workers : plusieurs processus → le rate limiter DOIT utiliser un stockage
#       partagé (REDIS_URL), sans quoi chaque worker compte séparément.
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"
GUNICORN_THREADS="${GUNICORN_THREADS:-4}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-300}"

echo "=== [entrypoint] Démarrage de l'API (gunicorn) ==="
echo "[entrypoint] workers=$GUNICORN_WORKERS threads=$GUNICORN_THREADS timeout=${GUNICORN_TIMEOUT}s"

exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers "$GUNICORN_WORKERS" \
    --threads "$GUNICORN_THREADS" \
    --worker-class gthread \
    --timeout "$GUNICORN_TIMEOUT" \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    "app:create_app()"
