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

# Secret aléatoire de 64 caractères hexadécimaux (256 bits)
gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Ajoute NOM=valeur au .env racine si NOM n'y figure pas encore (mise à niveau
# d'une installation existante sans jamais écraser une valeur déjà présente).
ensure_root_var() {
    if ! grep -q "^$1=" .env 2>/dev/null; then
        printf '%s=%s\n' "$1" "$2" >> .env
        ok "$1 ajoutée au .env racine"
    fi
}

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
# Généré par setup.sh — interpolation \${VAR} de docker-compose.yml, et SEULE
# source des secrets partagés entre l'API et n8n (voir CLAUDE.md §7).
POSTGRES_USER=${DEV_POSTGRES_USER}
POSTGRES_PASSWORD=${DEV_POSTGRES_PASSWORD}
POSTGRES_DB=${DEV_POSTGRES_DB}

# Adresses servies par Caddy (préfixe http:// = sans TLS, développement local).
# En production : SITE_ADDRESS=recon.mondomaine.tld, API_ADDRESS=api.mondomaine.tld
SITE_ADDRESS=http://localhost
API_ADDRESS=http://api.localhost
DASHBOARD_API_BASE=http://api.localhost
RESULTS_PAGE_URL=http://localhost/result.html

# Cloudflare Turnstile (vide = désactivé, développement uniquement)
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
EOF
    ok ".env (racine) généré"
fi

# Secrets générés aléatoirement, ajoutés aussi aux installations existantes.
ensure_root_var PIPELINE_SERVICE_TOKEN "$(gen_secret)"
ensure_root_var N8N_WEBHOOK_SECRET     "$(gen_secret)"
ensure_root_var RESULTS_ACCESS_SECRET  "$(gen_secret)"
ensure_root_var N8N_ENCRYPTION_KEY     "$(gen_secret)"
ensure_root_var APP_DB_PASSWORD        "$(gen_secret)"
ensure_root_var RAG_DB_PASSWORD        "$(gen_secret)"
ensure_root_var SITE_ADDRESS           "http://localhost"
ensure_root_var API_ADDRESS            "http://api.localhost"
ensure_root_var RESULTS_PAGE_URL       "http://localhost/result.html"
if grep -q "^ADMIN_PASSWORD_PLAIN=" .env api/.env 2>/dev/null; then
    warn "ADMIN_PASSWORD_PLAIN n'est plus utilisé (n8n a désormais son propre jeton de service) — vous pouvez le retirer de .env et api/.env"
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
# Modèle d'embeddings du RAG (ingestion n8n ET recherche dans utils/rag_retrieval.py) :
# sans lui, /api/embeddings répond 404 et l'analyse tourne sans extraits de référence.
if docker exec ollama ollama pull nomic-embed-text:v1.5; then
    ok "modèle d'embeddings nomic-embed-text:v1.5 téléchargé — RAG opérationnel"
else
    warn "échec du téléchargement de nomic-embed-text:v1.5 — relancez : docker exec ollama ollama pull nomic-embed-text:v1.5"
fi

# ─────────────────────────────────────────────────────────────────────────
log "6/6 — Terminé"
# ─────────────────────────────────────────────────────────────────────────
cat <<EOF

  Frontend public   http://localhost/              (via Caddy)
  Voir le résultat  http://localhost/result.html
  Dashboard admin   http://localhost/dashboard.html
  API               http://api.localhost/          (via Caddy)
  API (Swagger)     http://localhost:8080/apidocs  (boucle locale uniquement)
  n8n (éditeur)     http://localhost:5678/         (boucle locale uniquement — créez
                    tout de suite le compte propriétaire ; sur un serveur, passez
                    par un tunnel : ssh -L 5678:127.0.0.1:5678 serveur)

  Identifiants admin (dev local — à changer avant toute exposition publique) :
    email    : ${DEV_ADMIN_EMAIL}
    password : ${DEV_ADMIN_PASSWORD_PLAIN}

  Pour activer l'analyse IA via un backend cloud (plus rapide/qualitatif que le
  fallback Ollama local), ajoutez une clé gratuite dans api/.env puis relancez :
    GEMINI_API_KEY, CEREBRAS_API_KEY, GROQ_API_KEY ou OPENROUTER_API_KEY
    (voir api/.env pour les liens d'inscription) — puis : docker restart api

  Pour suivre les logs :  docker compose logs -f api
EOF
