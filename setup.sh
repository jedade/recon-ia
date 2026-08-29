#!/usr/bin/env bash
# setup.sh — Lancement complet de recon-ia en UNE seule commande.
#
#   ./setup.sh
#
# Ce script :
#   1. Vérifie que Docker + Docker Compose sont disponibles
#   2. Génère api/.env et .env (racine) avec des identifiants de DEV s'ils
#      n'existent pas déjà (jamais écrasés s'ils existent — voir §3)
#   3. Build + démarre tous les services (web/api/postgres/ollama/n8n/redis)
#   4. Attend que postgres et l'API soient prêts (migrations auto via
#      api/entrypoint.sh — rien à faire ici)
#   5. Télécharge le modèle Ollama local (qwen3:1.7b — seul filet de sécurité
#      d'analyse IA testé sur ce projet qui supporte le tool use ET tourne à
#      une vitesse raisonnable sans GPU, voir CLAUDE.md §5)
#   6. Affiche les URLs d'accès et les identifiants générés
#
# Idempotent : ré-exécutable sans danger. Les .env existants ne sont jamais
# écrasés (un message l'indique) ; docker compose up -d ne recrée que ce qui a
# changé.
#
# ⚠️  Les identifiants générés ici sont des identifiants de DÉVELOPPEMENT LOCAL
#     uniquement. Ne jamais les utiliser tels quels sur un déploiement exposé
#     publiquement — voir CLAUDE.md §7-8 pour le durcissement production.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Identifiants de dev fixes et documentés (déjà utilisés/vérifiés dans CLAUDE.md
# — reprendre les mêmes valeurs partout évite toute divergence entre les deux
# fichiers .env, un piège déjà rencontré sur ce projet).
DEV_ADMIN_EMAIL="admin@idachallenge.bj"
DEV_ADMIN_PASSWORD_PLAIN="ReconIA-Local-2026!"
# Hash scrypt correspondant EXACT à DEV_ADMIN_PASSWORD_PLAIN ci-dessus (généré
# une fois avec generate_password_hash.py). Le $ ne doit JAMAIS être doublé
# dans un fichier .env sur ce projet — voir CLAUDE.md §7 pour le piège vécu
# (docker-compose interpole les $, mais config.py relit le fichier brut via
# load_dotenv(override=True) et écrase toujours avec la valeur non interpolée).
DEV_ADMIN_PASSWORD_HASH='scrypt:32768:8:1$tXoMSEWqmpUfx9bC$51d5183a18db2143f1fb1f1c164d8409a72ab3b73ae86f8c5584625c66260a8b38acf7fcc625e43c5177a4bdf31dacddf24ce61498c7762ba22b8ca7a9f544cc'
DEV_POSTGRES_USER="reconuser"
DEV_POSTGRES_PASSWORD="ReconIA-Postgres-2026"
DEV_POSTGRES_DB="recondb"
OLLAMA_MODEL_DEFAULT="qwen3:1.7b"

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$1"; }

# ─────────────────────────────────────────────────────────────────────────
log "1/6 — Vérification des prérequis"
# ─────────────────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker n'est pas installé (ou pas dans PATH). Installez Docker Desktop : https://docs.docker.com/get-docker/"
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 introuvable (docker compose ...). Mettez à jour Docker Desktop."
    exit 1
fi
ok "docker + docker compose détectés"

# ─────────────────────────────────────────────────────────────────────────
log "2/6 — Génération des fichiers .env (dev local) si absents"
# ─────────────────────────────────────────────────────────────────────────
if [ -f api/.env ]; then
    ok "api/.env existe déjà — non modifié"
else
    cat > api/.env <<EOF
# Généré par setup.sh — identifiants de DEV LOCAL, à ne jamais exposer publiquement.
POSTGRES_DB=${DEV_POSTGRES_DB}
POSTGRES_USER=${DEV_POSTGRES_USER}
POSTGRES_PASSWORD=${DEV_POSTGRES_PASSWORD}
DATABASE_URL=postgresql://${DEV_POSTGRES_USER}:${DEV_POSTGRES_PASSWORD}@postgres:5432/${DEV_POSTGRES_DB}

REDIS_URL=redis://redis:6379/0

ADMIN_DOMAIN=initial.idachallenge.bj
ADMIN_EMAIL=${DEV_ADMIN_EMAIL}
ADMIN_PASSWORD=${DEV_ADMIN_PASSWORD_HASH}
ADMIN_PASSWORD_PLAIN=${DEV_ADMIN_PASSWORD_PLAIN}

SECRET_KEY=$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)

# --- SMTP (optionnel — sans ces valeurs, l'envoi d'OTP/PDF échoue proprement,
# le reste du pipeline fonctionne quand même) ---
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
EMAIL_FROM=noreply@example.com
ADMIN_NOTIFICATION_EMAIL=

# --- IA cloud (toutes optionnelles — clés gratuites, voir CLAUDE.md §7).
# Sans aucune clé, la cascade retombe automatiquement sur Ollama local. ---
GEMINI_API_KEY=
CEREBRAS_API_KEY=
GROQ_API_KEY=
ANALYSIS_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_KEY=
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free

# --- Ollama (filet de sécurité local — voir CLAUDE.md §5 pour le choix du modèle) ---
OLLAMA_MODEL=${OLLAMA_MODEL_DEFAULT}
OLLAMA_CHAT_TIMEOUT=360

ANALYSIS_LANG=fr
FLASK_ENV=development
FLASK_DEBUG=0
LOG_LEVEL=INFO
CORS_ORIGINS=*

# --- OSINT (toutes optionnelles) ---
GITHUB_TOKEN=
OTX_API_KEY=
ABUSEIPDB_API_KEY=
ABUSECH_AUTH_KEY=
URLSCAN_API_KEY=
TAVILY_API_KEY=
EOF
    ok "api/.env généré (identifiants de dev local)"
fi

if [ -f .env ]; then
    ok ".env (racine) existe déjà — non modifié"
else
    cat > .env <<EOF
# Généré par setup.sh — UNIQUEMENT pour l'interpolation \${VAR} de docker-compose.yml.
POSTGRES_USER=${DEV_POSTGRES_USER}
POSTGRES_PASSWORD=${DEV_POSTGRES_PASSWORD}
POSTGRES_DB=${DEV_POSTGRES_DB}
DOMAIN_URL_API=http://api:8080
ADMIN_EMAIL=${DEV_ADMIN_EMAIL}
ADMIN_PASSWORD_PLAIN=${DEV_ADMIN_PASSWORD_PLAIN}
DASHBOARD_API_BASE=http://localhost:8080
EOF
    ok ".env (racine) généré"
fi

# ─────────────────────────────────────────────────────────────────────────
log "3/6 — Build + démarrage des services (peut prendre plusieurs minutes au premier lancement)"
# ─────────────────────────────────────────────────────────────────────────
docker compose up -d --build

# ─────────────────────────────────────────────────────────────────────────
log "4/6 — Attente que postgres et l'API soient prêts"
# ─────────────────────────────────────────────────────────────────────────
printf "  postgres "
for i in $(seq 1 60); do
    status=$(docker inspect --format='{{.State.Health.Status}}' postgres 2>/dev/null || echo "starting")
    [ "$status" = "healthy" ] && break
    printf "."; sleep 2
done
echo
if [ "$status" = "healthy" ]; then ok "postgres prêt"; else warn "postgres pas encore healthy après 2 min — vérifiez 'docker compose logs postgres'"; fi

printf "  api "
api_ready=0
for i in $(seq 1 60); do
    if curl -sf http://localhost:8080/ >/dev/null 2>&1; then api_ready=1; break; fi
    printf "."; sleep 2
done
echo
if [ "$api_ready" = "1" ]; then ok "api prête (migrations exécutées automatiquement au démarrage)"; else warn "api ne répond pas encore après 2 min — vérifiez 'docker compose logs api'"; fi

# ─────────────────────────────────────────────────────────────────────────
log "5/6 — Téléchargement du modèle Ollama local (${OLLAMA_MODEL_DEFAULT}, ~1,4 Go)"
# ─────────────────────────────────────────────────────────────────────────
for i in $(seq 1 30); do
    docker exec ollama true >/dev/null 2>&1 && break
    sleep 2
done
if docker exec ollama ollama pull "${OLLAMA_MODEL_DEFAULT}"; then
    ok "modèle ${OLLAMA_MODEL_DEFAULT} téléchargé — fallback IA local opérationnel"
else
    warn "échec du téléchargement du modèle Ollama — relancez manuellement : docker exec ollama ollama pull ${OLLAMA_MODEL_DEFAULT}"
fi

# ─────────────────────────────────────────────────────────────────────────
log "6/6 — Terminé"
# ─────────────────────────────────────────────────────────────────────────
cat <<EOF

  Frontend public   http://localhost:5000/
  Dashboard admin   http://localhost:5000/dashboard.html
  API (Swagger)     http://localhost:8080/apidocs
  API (ReDoc)       http://localhost:8080/redoc
  n8n               http://localhost:5678/  (⚠ sans authentification, ne jamais exposer publiquement)

  Identifiants admin (dev local — à changer avant toute exposition publique) :
    email    : ${DEV_ADMIN_EMAIL}
    password : ${DEV_ADMIN_PASSWORD_PLAIN}

  Pour activer l'analyse IA via un backend cloud (plus rapide/qualitatif que le
  fallback Ollama local), ajoutez une clé gratuite dans api/.env puis relancez :
    GEMINI_API_KEY, CEREBRAS_API_KEY, GROQ_API_KEY ou OPENROUTER_API_KEY
    (voir api/.env pour les liens d'inscription) — puis : docker restart api

  Pour suivre les logs :  docker compose logs -f api
EOF
