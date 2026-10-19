# Recon-IA — Documentation API

API Flask de reconnaissance **passive** OSINT : 47 outils exécutés en
parallèle, analyse par une cascade de LLM avec traçabilité outil → conclusion,
génération et envoi de rapports PDF, et exports de données citables
(JSON + CSV avec empreinte SHA-256).

Servie par **gunicorn** en production (le serveur de développement Flask n'est
plus utilisé).

---

## Sommaire

1. [Architecture](#architecture)
2. [Installation](#installation)
3. [Variables d'environnement](#variables-denvironnement)
4. [Authentification](#authentification)
5. [Format de réponse](#format-de-réponse)
6. [Endpoints](#endpoints)
   - [Public](#public)
   - [Authentification](#endpoint-dauthentification)
   - [CRUD](#endpoints-crud)
   - [Audit / logs](#endpoints-audit--logs)
   - [OSINT passif](#endpoints-osint-passif)
   - [Analyse IA](#endpoints-analyse-ia)
   - [Rapports PDF](#endpoints-rapports-pdf)
   - [Exports et statistiques](#endpoints-exports-et-statistiques)
7. [Les 47 outils OSINT](#les-47-outils-osint)
8. [Traçabilité des findings](#traçabilité-des-findings)
9. [Rate limiting](#rate-limiting)
10. [Logging et audit](#logging-et-audit)
11. [Sécurité](#sécurité)
12. [Tests](#tests)
13. [Structure du projet](#structure-du-projet)

---

## Architecture

```
                      gunicorn (2 workers × 4 threads, timeout 300 s)
                                     │
                            app.py :: create_app()
                                     │
   ┌──────────────┬──────────────────┼──────────────────┬───────────────┐
   │              │                  │                  │               │
ProxyFix       CORS          Flask-Limiter        audit_log        blueprints
(X-Forwarded)  (CORS_ORIGINS) (Redis partagé)    (chaque requête)  (9 fichiers)
                                                                        │
        ┌───────────────────────────────┬───────────────────────────────┤
        ▼                               ▼                               ▼
  routes/recon.py                routes/analyze.py               routes/report.py
  47 outils passifs              cascade LLM                     PDF + exports
  2 vagues parallèles            Gemini → Cerebras → Groq        méthodologie,
  (utils/parallel.py)            → OpenRouter → Ollama           provenance, CSV
        │                               │                               │
        └───────────────► PostgreSQL 16 + pgvector ◄────────────────────┘
             recon · audit_log · pass_recon_cache · rag_documents
```

**Modules clés**

| Fichier | Rôle |
|---|---|
| `app.py` | Factory Flask : logging, ProxyFix, CORS, en-têtes de sécurité, audit DB, blueprints, handlers d'erreurs |
| `config.py` | Chargement `.env`, configuration Swagger, `SQLALCHEMY_DATABASE_URI`, identifiants admin, `MAX_CONTENT_LENGTH` (1 Mo) |
| `extensions.py` | Flask-Limiter — stockage Redis si `REDIS_URL`, repli `memory://` avec avertissement |
| `entrypoint.sh` | Correction DNS → `migrate.py` → `gunicorn` |
| `migrate.py` | Migrations SQL idempotentes (`… IF NOT EXISTS`) + extension `pgvector` + table `rag_documents` |
| `utils/parallel.py` | Exécution parallèle et résiliente des outils (`run_tools_parallel`) |
| `utils/pdf_generator.py` | PDF, dont la section « Méthodologie & Sources » |
| `utils/mitre_attack.py` | Corrélation déterministe outils exécutés → techniques ATT&CK |

**Tables**

| Table | Contenu |
|---|---|
| `recon` | Dossier utilisateur, `scan_results`, `analysis_result`, `final_report`, `pdf_report` (binaire), et **`security_score` / `security_grade` dénormalisés et indexés** |
| `audit_log` | Une ligne par requête HTTP métier (méthode, chemin, code, durée, IP, User-Agent) |
| `pass_recon_cache` | Cache des scans par `(domain, tools_key)`, TTL 30 jours par défaut |
| `rag_documents` | Corpus RAG `pgvector` (`vector(768)`), consommé par n8n |

Le champ `security_score` est dénormalisé volontairement : `GET /recon` et
`GET /recon/stats` peuvent ainsi trier et agréger en SQL sans rapatrier ni
parser les rapports IA (plusieurs dizaines de Ko chacun).

---

## Installation

### Avec Docker (recommandé)

```bash
# Depuis la racine du dépôt
cp api/.env.example api/.env      # puis compléter (voir ci-dessous)
docker compose up -d              # les migrations sont jouées par l'entrypoint
docker compose logs -f api

curl http://localhost:8080/       # catalogue public
open http://localhost:8080/apidocs
```

⚠️ Un **second `.env` à la racine du dépôt** est nécessaire : interpolation
`${VAR}` de `docker-compose.yml` (`POSTGRES_*`, adresses Caddy) **et** seule
source des secrets partagés avec n8n (`PIPELINE_SERVICE_TOKEN`,
`N8N_WEBHOOK_SECRET`), ainsi que `RESULTS_ACCESS_SECRET`,
`RESULTS_PAGE_URL` et `TURNSTILE_SECRET_KEY`. `setup.sh` le génère. Voir le
[README racine](../README.md#deux-fichiers-env--à-ne-pas-confondre).

### En local (développement / tests)

```bash
cd api
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Sans PostgreSQL : DATABASE_URL=sqlite:///local.db dans .env
python3 -m pytest
```

Les outils OSINT en ligne de commande (`subfinder`, `amass`, `gau`,
`dnstwist`, `sslscan`, `whois`, `dig`…) ne sont installés que dans l'image
Docker. Hors conteneur, les outils correspondants retournent
`status: not_installed` — le reste du scan continue normalement.

### Générer le hash du mot de passe admin

```bash
docker exec api python3 generate_password_hash.py
# ou
docker exec api python3 -c \
  "from werkzeug.security import generate_password_hash; print(generate_password_hash('MonMotDePasse'))"
```

Coller le résultat dans `api/.env` → `ADMIN_PASSWORD=pbkdf2:sha256:…`

⚠️ **Ne pas doubler les `$` du hash**, malgré l'avertissement « variable is not
set » émis par Docker Compose. L'application relit `api/.env` avec
`python-dotenv`, qui n'interpole pas les `$` et écrase la valeur injectée par
Docker : c'est donc toujours le contenu brut du fichier qui compte. Un `$$`
casse l'authentification silencieusement.

---

## Variables d'environnement

Toutes lues depuis `api/.env`.

### Base de données

| Variable | Défaut | Description |
|---|---|---|
| `DATABASE_URL` | — | URI complète, prioritaire sur les variables ci-dessous |
| `POSTGRES_USER` | — | **Obligatoire** si `DATABASE_URL` absent |
| `POSTGRES_PASSWORD` | — | Mot de passe PostgreSQL |
| `POSTGRES_DB` | — | **Obligatoire** si `DATABASE_URL` absent |

### Serveur et rate limiting

| Variable | Défaut | Description |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Stockage partagé du rate limiter. Absent ⇒ repli `memory://` (compteurs non partagés entre workers) |
| `GUNICORN_WORKERS` | `2` | Nombre de processus |
| `GUNICORN_THREADS` | `4` | Threads par processus (charge I/O-bound) |
| `GUNICORN_TIMEOUT` | `300` | Doit rester > `SCAN_DEADLINE_SECONDS` |
| `TRUSTED_PROXY_COUNT` | `1` | Nombre **exact** de proxys de confiance pour `ProxyFix`. `0` désactive la prise en compte de `X-Forwarded-For` |

### Administration

| Variable | Défaut | Description |
|---|---|---|
| `ADMIN_EMAIL` | — | **Obligatoire** — identifiant Basic Auth |
| `ADMIN_PASSWORD` | — | **Obligatoire** — hash werkzeug, jamais le mot de passe en clair |
| `SECRET_KEY` | aléatoire | ≥ 32 caractères, sinon avertissement au démarrage |
| `PIPELINE_SERVICE_TOKEN` | vide | *(.env racine)* jeton de service de n8n (`X-Service-Token`, ≥ 32 car.) — accepté seulement par les routes du pipeline. Vide ⇒ n8n ne peut pas appeler l'API |
| `N8N_WEBHOOK_SECRET` | vide | *(.env racine)* secret envoyé par l'API au webhook n8n (`X-Pipeline-Secret`, ≥ 32 car.) |
| `N8N_PIPELINE_WEBHOOK_URL` | `http://n8n:5678/webhook/recon-ia-pipeline` | webhook interne déclenché après validation de l'OTP |
| `TURNSTILE_SECRET_KEY` | vide | *(.env racine)* clé secrète Cloudflare Turnstile. Vide ⇒ captcha désactivé (développement uniquement) |

### Coffre des résultats et conservation

| Variable | Défaut | Description |
|---|---|---|
| `RESULTS_ACCESS_SECRET` | — | *(.env racine)* ≥ 32 caractères, **stable** : sert à l'empreinte de recherche des codes et aux sessions. Absent ⇒ aucun code émis. Le changer rend tous les codes émis introuvables |
| `RESULTS_PAGE_URL` | vide | *(.env racine)* lien vers `result.html` placé dans le mail |
| `RESULTS_ACCESS_TTL_DAYS` | `30` | validité du code d'accès |
| `RESULTS_SESSION_TTL_SECONDS` | `3600` | durée d'une session de consultation |
| `OTP_MAX_ATTEMPTS` | `5` | codes OTP faux tolérés par dossier avant annulation |
| `RETENTION_INTERVAL_S` | `3600` | fréquence de la purge |
| `RESULTS_PURGE_GRACE_DAYS` | `7` | délai après expiration/révocation avant effacement des résultats et anonymisation |
| `UNVERIFIED_RETENTION_DAYS` | `7` | suppression des demandes jamais vérifiées |
| `AUDIT_RETENTION_DAYS` | `90` | suppression du journal d'audit (adresses IP) |
| `CORS_ORIGINS` | vide | Liste d'origines séparées par des virgules. Vide en production ⇒ aucune requête cross-origin |
| `LOG_LEVEL` | `INFO` | `DEBUG` pour le détail |

### Email / SMTP

`SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM`,
`ADMIN_NOTIFICATION_EMAIL`, `OTP_TTL_SECONDS` (défaut `600`).
(`DOMAIN_URL_API` et `ADMIN_PASSWORD_PLAIN` ne sont plus utilisés : n8n
appelle `http://api:8080` avec son jeton de service.)

### Scan OSINT

| Variable | Défaut | Description |
|---|---|---|
| `SCAN_MAX_WORKERS` | `8` | Threads de la vague parallèle. Volontairement modeste : marteler les services tiers déclencherait du rate-limiting |
| `SCAN_DEADLINE_SECONDS` | `180` | **Délai global de la vague**, partagé entre tous les outils — pas un délai par outil |

### Analyse IA

Cascade séquentielle avec repli : **DeepSeek → Gemini → Cerebras → Groq →
OpenRouter → Ollama local**. Chaque backend qui échoue transmet sa
conversation (résultats d'outils déjà collectés) au suivant. DeepSeek (slot
0) est payant et désactivé par défaut : il ne s'active que si
`DEEPSEEK_API_KEY` **et** `DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true` sont tous
deux renseignés (double opt-in, voir `.env.example`) — sans ça, la cascade
démarre directement à Gemini.

| Groupe | Variables |
|---|---|
| Gemini (slot 1) | `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_MAX_TOOL_CALLS_PER_ROUND`, `GEMINI_MAX_TOOL_RESULT_CHARS`, `GEMINI_TPM_SLEEP` |
| Cerebras (slot 2) | `CEREBRAS_API_KEY`, `CEREBRAS_MODEL`, `CEREBRAS_MAX_TOOL_*`, `CEREBRAS_TPM_SLEEP` |
| Groq (slot 3) | `GROQ_API_KEY`, `ANALYSIS_MODEL`, `GROQ_FALLBACK_MODELS`, `GROQ_MAX_TOOL_*`, `GROQ_TPM_SLEEP` |
| OpenRouter (slot 4) | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `OPENROUTER_FALLBACK_MODELS`, `OPENROUTER_MAX_ROUNDS` (2 — quota 50 req/jour), `OPENROUTER_MAX_429_BEFORE_SWITCH`, `OPENROUTER_RATE_LIMIT_SLEEP` |
| Ollama (slot 5) | `OLLAMA_URL` (`http://ollama:11434`), `OLLAMA_CHAT_TIMEOUT`, `OLLAMA_MAP_ROUNDS`, `OLLAMA_MAX_SECTION_TOKENS` |
| Commun | `ANALYSIS_LANG` (`fr`), `ANALYSIS_MAX_SEARCH_ROUNDS` (`6`), `ANALYSIS_BACKEND_TIMEOUT` (`480`), `ANALYSIS_CACHE_TTL_HOURS` (`168`), `FINAL_REPORT_MAX_SCAN_CHARS`, `FINAL_REPORT_MAX_ANALYSIS_CHARS` |
| Recherche web | `TAVILY_API_KEY` (sinon DuckDuckGo via `ddgs`) |

### Clés d'API des outils OSINT (toutes optionnelles)

| Variable | Outil | Sans la clé |
|---|---|---|
| `GITHUB_TOKEN` | `github` | `skipped` — aucune requête |
| `OTX_API_KEY` | `otx_passive_dns` | accès anonyme tenté ; `limited` si OTX refuse (401/403) |
| `ABUSEIPDB_API_KEY` | `abuseipdb_check` | `skipped` |
| `ABUSECH_AUTH_KEY` | `abusech_check` | `skipped` |
| `URLSCAN_API_KEY` | `urlscan_search` | `skipped` |

`shodan_internetdb`, `rdap_info` et `xposedornot_breaches` **ne demandent
aucune clé**. `HIBP_API_KEY` n'est plus utilisée (voir
[Les 47 outils OSINT](#les-47-outils-osint)).

---

## Authentification

Quatre modes d'accès :

| Mode | Qui | Routes |
|---|---|---|
| public | demandeur, sans compte | `GET /`, `POST /auth/login`, `POST /recon`, `POST /verify_email`, `POST /results/access` |
| session | demandeur, après saisie de son code d'accès (`Authorization: Bearer <session_token>`) | `GET /results/*` |
| jeton de service | n8n (`X-Service-Token`) — **ou** admin | routes du pipeline |
| admin | HTTP Basic Auth | tout le reste |

Le jeton de service n'ouvre **aucune** route d'administration, et Caddy le
retire de toute requête venue d'Internet.

```bash
curl -u "admin@example.com:MonMotDePasse" http://localhost:8080/recon
# ou
curl -H "Authorization: Basic $(printf 'admin@example.com:MonMotDePasse' | base64)" \
     http://localhost:8080/recon
```

`POST /auth/login` **ne délivre aucun token** : il valide seulement les
identifiants (utilisé par `web/dashboard.html`, qui réutilise ensuite le Basic
Auth pour chaque appel). La comparaison de l'identifiant utilise
`hmac.compare_digest`, le mot de passe est vérifié contre le hash werkzeug.

---

## Format de réponse

```jsonc
// Succès — ressource unique
{ "success": true, "data": { ... }, "message": "..." }

// Succès — liste paginée
{ "success": true, "data": [ ... ], "total": 42, "page": 1, "per_page": 20, "pages": 3 }

// Erreur
{ "success": false, "error": "Message d'erreur en français" }
```

En-têtes de sécurité ajoutés à toutes les réponses : `X-Content-Type-Options`,
`X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`,
`Strict-Transport-Security`, `Content-Security-Policy: default-src 'none'`,
`Permissions-Policy`, et `Server: OSINT-API` (le serveur réel est masqué).

---

## Endpoints

**11 blueprints** enregistrés dans `routes/__init__.py`. Les routes du
pipeline (`/pass_recon`, `/analyze`, `/analyze/async`, `/analyze/wait`,
`generate_final_report`, `generate_report`) acceptent le **jeton de
service** de n8n (`X-Service-Token`) **ou** l'admin ; toutes les autres
routes protégées n'acceptent que l'admin. Les endpoints
`/crawl`, `/sublist3r`, `/crtsh`, `/sslscan`, `/holehe` et
`/netcraft_full_report` des versions antérieures **ont été supprimés** et
n'existent plus.

### Public

#### `GET /`

Catalogue des endpoints et métadonnées de l'API. Aucune authentification.

> Ce catalogue est actuellement incomplet côté code (il ne liste pas les
> endpoints `/analyze*`, `/recon/<id>/generate_*`, `report.pdf`, les exports ni
> `/recon/stats`). Se référer à `/apidocs` ou à ce document.

### Endpoint d'authentification

#### `POST /auth/login` — 10 requêtes/minute

```json
{ "email": "admin@example.com", "password": "MonMotDePasse" }
```

Retourne `200` si les identifiants sont valides, `401` sinon. Ne crée ni
session ni token.

### Endpoints CRUD

#### `POST /recon` — 20/heure, **public**

Crée un dossier et envoie un code OTP à 6 chiffres (valable
`OTP_TTL_SECONDS`, 600 s par défaut).

```json
{
  "domain": "example.com",
  "firstname": "Jean",
  "lastname": "Dupont",
  "email": "jean.dupont@example.com",
  "accord": true,
  "requested_info": "Analyse SSL et sous-domaines",
  "turnstile_token": "<jeton du widget Cloudflare Turnstile>"
}
```

`accord` (consentement) doit valoir **`true`** (400 sinon). `turnstile_token`
est vérifié auprès de Cloudflare quand `TURNSTILE_SECRET_KEY` est définie
(400 si absent ou refusé, aucun email envoyé). Un même email peut lancer
plusieurs analyses distinctes ; un nouveau code n'est envoyé que lorsque le
précédent a expiré (429 sinon).

#### `POST /verify_email` — 10/heure, **public**

```json
{ "email": "jean.dupont@example.com", "code": "123456" }
```

Positionne `verification = true`, horodate `start_report_date`, puis
**déclenche le pipeline n8n** sur le réseau interne : la réponse contient
`pipeline_started: true|false`. Le code est à usage unique, effacé après
validation, après expiration, ou après `OTP_MAX_ATTEMPTS` (5) essais faux
sur le même dossier.

#### `GET /recon` — liste paginée

Paramètres : `page` (1), `per_page` (20, max 100), `status`
(`pending|running|success|failed`), `domain` (sous-chaîne).

Les filtres sont appliqués **en SQL** : `total` et `pages` reflètent le nombre
d'enregistrements filtrés, pas la page courante. Un `status` inconnu retourne
`400` au lieu d'être ignoré silencieusement.

#### `GET /recon/<id>`

Vue publique de l'enregistrement. `scan_results`, `analysis_result` et
`final_report` ne sont **jamais** inclus — utiliser `GET /recon/<id>/report`.

#### `PUT /recon/<id>` · `DELETE /recon/<id>`

Mise à jour des champs d'identité / suppression définitive.

#### `PATCH /recon/<id>/result`

Réservé au workflow n8n. Reçoit `status` (obligatoire), `started_at`,
`completed_at`, `scan_results` (objet JSON), `final_report` (texte).
`end_report_date` et `execution_time` sont calculés automatiquement.

#### `GET /recon/<id>/report`

Rapport complet **avec** les données sensibles (`scan_results`,
`analysis_result`, `final_report`).

### Endpoints Audit — Logs

#### `GET /logs`

Historique paginé des requêtes HTTP. Filtres : `method`, `status_code`,
`status_class` (`2xx`/`4xx`/`5xx`), `endpoint` (sous-chaîne), `ip`, `from`,
`to` (dates ISO 8601), `page`, `per_page` (50, max 200).

```bash
curl -u "$ADMIN:$PASS" "http://localhost:8080/logs?status_class=5xx&per_page=100"
curl -u "$ADMIN:$PASS" "http://localhost:8080/logs?endpoint=/pass_recon&from=2026-07-01T00:00:00"
```

#### `GET /logs/stats`

Statistiques agrégées : répartition des codes HTTP, endpoints les plus
sollicités, top IP, taux d'erreur.

### Endpoints OSINT passif

#### `POST /pass_recon`

Lance le scan complet. Corps :

```json
{
  "recon_id": 42,
  "domain": "example.com",
  "email": "contact@example.com",
  "tools": ["crtsh", "subfinder", "ssl_info", "security_headers"],
  "force_refresh": false,
  "cache_ttl_days": 30
}
```

- `recon_id` **recommandé** : le domaine est lu en base et les résultats y sont
  écrits (`scan_results`) automatiquement.
- `tools` omis ⇒ **les 47 outils** sont lancés.
- `force_refresh` ignore le cache ; `cache_ttl_days` est borné entre 1 et 365
  (défaut 30).
- Le domaine est validé (`is_valid_domain`) puis contrôlé contre le SSRF
  (`is_safe_domain` : résolution DNS + refus de toute IP privée/réservée).

**Exécution parallèle en deux vagues** (`utils/parallel.py`) :

| Vague | Outils | Rôle |
|---|---|---|
| 1 | **9** — `whois`, `rdap_info`, `dns`, `crtsh`, `subfinder`, `assetfinder`, `github`, `amass`, `ip_info` | découverte ; les 5 outils de sous-domaines alimentent `all_subdomains`, `ip_info` fournit les IP réutilisées en vague 2 |
| 2 | **38** — tout le reste | `headers` et `subdomain_takeover` consomment les sous-domaines découverts ; les autres ne dépendent que du domaine |

Garanties :

- **Isolation** — l'exception d'un outil devient un résultat
  `status: "error"` ; elle ne fait plus échouer tout le scan.
- **Borne de temps** — `SCAN_DEADLINE_SECONDS` limite la vague entière ; les
  outils non terminés sont marqués `status: "timeout"` et le scan continue.
- **Déterminisme** — l'écriture des résultats suit l'ordre de déclaration des
  outils, pas l'ordre d'achèvement des threads. Le `dataset_sha256` des exports
  est donc stable.
- **Complétude** — chaque clé demandée est toujours présente dans la réponse,
  même en cas d'échec.

Chaque outil retourne :

```jsonc
{
  "status": "success",         // voir la liste des statuts ci-dessous
  "meta": {
    "tool": "Nom affiché",
    "category": "Catégorie",
    "description": "Ce que fait l'outil",
    "indicators": { "champ": "signification de l'indicateur" }
  },
  "data": { },                  // données structurées
  "raw_output": "sortie brute exacte (pour interprétation IA)"
}
```

Statuts possibles : `success`, `error`, `not_installed`, `timeout`,
`timeout_partial`, `not_found`, `unreachable`, `skipped` (clé d'API absente),
`no_data` (source interrogée, aucun résultat), `limited` (accès anonyme
restreint), `unavailable` (service inexistant pour la cible).

#### `POST /dns_info`

Collecte DNS/IP dédiée via `host`, `nslookup`, `dnsrecon` et `dig`.

```json
{ "domain": "example.com" }
```

### Endpoints Analyse IA

#### `POST /analyze` — 5/heure

```json
{ "recon_id": 42, "force_refresh": false, "model": "llama-3.3-70b-versatile", "max_search_rounds": 4 }
```

`recon_json` (sortie complète de `/pass_recon`) peut remplacer `recon_id`.
Réponse : `data` contient `domain`, `risk_score` (0-100), `risk_level`,
`security_score`, `security_grade` (A+ → F), `security_posture`,
`security_breakdown`, `executive_summary`, `findings`, `strengths`,
`immediate_actions`, `mitre_attack`, `_backend`, `_cache`.

Le résultat est mis en cache en base (`ANALYSIS_CACHE_TTL_HOURS`, 7 jours par
défaut) et le score est dénormalisé dans les colonnes `security_score` /
`security_grade`.

#### `POST /analyze/async` — 5/heure

Lance l'analyse dans un thread et retourne immédiatement `202` avec
`poll_url`. Retourne `200` + `status: "cached"` si le cache est valide, et
`status: "already_running"` si une analyse est déjà en cours pour ce
`recon_id` (pas de doublon de thread).

#### `GET|POST /analyze/wait/<recon_id>` — 60/minute

Long-polling : interroge la base toutes les 5 s jusqu'à ce que
`analysis_result` soit disponible. `?timeout=<secondes>` (10-600, défaut 600).
`408` si le délai expire — l'analyse continue en arrière-plan.

Configuration n8n recommandée : timeout de nœud 30 s pour `/analyze/async`,
660 s pour `/analyze/wait`.

#### `GET /analyze/status`

État de chaque backend (`configured`, `online`, `model`, `models`, `slot`) et
fournisseur de recherche web actif.

### Endpoints Rapports PDF

Ordre recommandé : `pass_recon` → `analyze` → `generate_final_report` →
`generate_report` → `report.pdf`.

#### `POST /recon/<id>/generate_final_report` — 20/heure

Condense `scan_results` + `analysis_result` en un rapport narratif structuré,
stocké dans `recon.final_report`. Corps optionnel :
`{ "force_regenerate": false }`. Prérequis : les deux champs doivent exister
en base.

#### `POST /recon/<id>/generate_report` — 10/heure

Génère le PDF et le stocke en base, puis **scelle le dossier** : les
résultats et le PDF sont chiffrés avec une clé dérivée d'un code d'accès
aléatoire, le clair est effacé, et le code est envoyé au demandeur par mail
(**sans pièce jointe**). Le scellement n'est validé qu'après l'envoi réussi
du mail ; en cas d'échec SMTP, rien n'est scellé et `email_error` le
signale. `send_email: false` laisse le dossier en clair. La réponse contient
`results_sealed`.

```json
{ "analysis": { }, "send_email": true }
```

`analysis` est optionnel — chargé depuis `recon.analysis_result` s'il est
absent. Si `final_report` existe, son résumé exécutif est intégré.

Le PDF contient notamment une section **« Méthodologie & Sources »** :
inventaire de chaque outil exécuté (clé `source_tool`, nom, catégorie, statut,
durée), contexte du scan (domaine, date, durée totale, résultat servi depuis le
cache ou non) et un bloc **« Limites de la collecte »** listant explicitement
les outils qui n'ont produit aucune donnée exploitable et pourquoi.

#### `GET /recon/<id>/report.pdf`

Télécharge le PDF stocké. `404` si aucun PDF n'a été généré, **`403`
(`results_sealed: true`) si le dossier est scellé** — même règle pour
`export.json`, `export.csv`, `generate_final_report` et `generate_report`.

#### `POST /recon/<id>/issue_access` — 10/heure (admin)

Rattrapage quand le mail de fin de pipeline a échoué : scelle le dossier et
envoie un code. `409` si le dossier est déjà scellé ou n'a pas de PDF,
`502` si l'envoi échoue (rien n'est scellé).

#### `POST /recon/<id>/revoke_access` (admin)

Révoque le code d'accès : les sessions ouvertes sont coupées à leur requête
suivante. Irréversible.

### Endpoints Cache des scans bruts (admin)

Le cache `pass_recon_cache` conserve en clair les résultats **bruts** de
chaque scan, par domaine (données publiques, sans analyse IA ni donnée du
demandeur). Il n'est jamais purgé : une entrée expirée n'est plus servie au
pipeline mais reste consultable. C'est le moyen pour l'admin de voir les
données collectées d'un dossier scellé.

- `GET /cache` — liste paginée (`page`, `per_page` ≤ 100, `domain`,
  `valid=true|false`), métadonnées seulement.
- `GET /cache/<id>` — entrée + résultat brut complet (`corrupted: true` si
  le JSON stocké est illisible).
- `GET /cache/<id>/export.json` — téléchargement.

### Endpoints Graphe, différentiel et surveillance (phase 7)

Détail et format du différentiel : `docs/phases/PHASE_7.md`. Données
techniques publiques uniquement, stockées en clair (lisibles même pour un
dossier scellé).

**Admin seul** (`require_auth`, le jeton de service est refusé) :
- `GET /graph/summary?domain=` — compteurs par type d'entité.
- `GET /graph/entities?domain=&type=&q=&page=` — entités paginées.
- `GET /graph/live_hosts?domain=&format=json|csv&max_age_days=90` — hôtes
  vivants, pour une phase active **autorisée** menée hors Recon-IA.
- `GET /graph/snapshots?domain=&significant=` · `GET /graph/snapshots/<id>` —
  historique des différentiels.
- `GET /recon/<id>/diff` — différentiel d'un dossier.
- `GET|POST /monitoring`, `PATCH|DELETE /monitoring/<id>` — domaines
  surveillés (ajout désactivé par défaut, refusé en 409 sans dossier vérifié
  et consenti).

**Jeton de service ou admin** (workflow n8n `recon-ia-rescan`, inactif par
défaut) :
- `GET /monitoring/due` — rescans dus (`MONITORING_MAX_PER_RUN`).
- `POST /monitoring/<id>/ingest` — graphe et différentiel depuis le dernier
  scan en cache ; alerte mail à l'admin si changement significatif.

### Endpoints Consultation des résultats (demandeur)

#### `POST /results/access` — 5/minute, 30/heure, **public**

```json
{ "code": "<code à 43 caractères reçu par mail>" }
```

Le code est lu dans le **corps** uniquement (jamais dans l'URL). Réponse :
`{ "session_token": "...", "expires_in": 3600, "recon": { domain, status,
security_score, security_grade, completed_at, access_expires_at } }`.
`401` code invalide (message identique quel que soit le motif), `403`
révoqué, `410` expiré, `503` serveur non configuré.

#### `GET /results/report` — 120/heure

`Authorization: Bearer <session_token>`. Rapport complet déchiffré :
`provenance` (dont `dataset_sha256`, identique à celui calculé avant
chiffrement), `scan_results`, `analysis_result`, `final_report`, `citation`.

#### `GET /results/report.pdf` · `export.json` · `export.csv` · `export.navigator.json` — 60/heure

Mêmes contenus que les exports admin, déchiffrés pour la session. Les deux
exports exigent toujours le consentement (`403` sinon). `export.navigator.json`
(phase 4) est un layer ATT&CK Navigator 4.5 : techniques colorées par
sévérité maximale des constats, recalculées par la table déterministe.

### Endpoints Exports et statistiques

#### `GET /recon/<id>/export.json`

Jeu de données complet destiné à un usage citable.

```jsonc
{
  "provenance": {
    "schema_version": "1.0",
    "generated_at": "2026-07-27T09:15:00Z",
    "recon_id": 42,
    "domain": "example.com",
    "tools_requested": ["amass", "asn_info", "..."],
    "tools_detail": [{ "key": "…", "name": "…", "category": "…", "status": "…" }],
    "scan_duration_s": 61.4,
    "ai_backend_used": "gemini-2.5-pro",
    "cache_hit": false,
    "dataset_sha256": "…",
    "data_integrity": { "scan_results_stored": true, "scan_results_parsed": true, "corrupted": false },
    "scan_started_at": "…", "scan_completed_at": "…", "analysis_generated_at": "…",
    "methodology": "Reconnaissance passive uniquement — aucune interaction intrusive…"
  },
  "scan_results":    { },
  "analysis_result": { },
  "final_report":    { },
  "citation": "Recon-IA, scan of example.com, 2026-07-27T…, 47 outils passifs (…), dataset SHA-256: …"
}
```

- `dataset_sha256` est calculé sur `scan_results` sérialisé en **JSON canonique**
  (clés triées, séparateurs compacts) : deux dumps sémantiquement identiques
  produisent le même hash, ce qui permet de vérifier qu'un jeu de données cité
  n'a pas été modifié.
- `data_integrity` distingue « donnée absente » de « donnée présente mais
  illisible » : un `scan_results` corrompu ne peut pas produire un export
  faussement valide.
- L'export **exige `accord = true`**, sinon `403`.

#### `GET /recon/<id>/export.csv`

Une ligne par finding. Colonnes stables et contractuelles :

```
finding_id, tool, tool_category, target, indicator, value,
severity, confidence, source_tool, source_url, collected_at
```

- Les colonnes absentes du schéma réel des findings (`confidence`) restent
  **vides** — aucune valeur n'est fabriquée.
- En-têtes toujours présents, même sans analyse.
- BOM UTF-8 pour l'ouverture dans Excel ; les cellules commençant par
  `=`, `+`, `-`, `@` sont préfixées d'une apostrophe pour neutraliser
  l'injection de formule (CWE-1236). **Le CSV est donc une vue ; le JSON reste
  la référence couverte par le SHA-256.**
- Exige également `accord = true`.

#### `GET /recon/stats`

KPI **agrégés en SQL sur l'ensemble de la table**, sans pagination.

```json
{
  "success": true,
  "data": {
    "total_recons": 128,
    "pdf_generated": 91,
    "analyses_completed": 104,
    "in_progress": 6,
    "by_status": { "pending": 4, "running": 2, "success": 118, "failed": 4 },
    "success_rate_pct": 92.2,
    "avg_security_score": 63.4,
    "scored_recons": 104,
    "unscored_analyses": 0,
    "avg_scan_duration_s": 41.7,
    "avg_flow_duration_s": 305.2,
    "computed_at": "2026-07-27T09:15:00Z"
  }
}
```

- `avg_security_score` est un `AVG` SQL sur la colonne dénormalisée ; les
  lignes sans score sont exclues de la moyenne et comptées séparément dans
  `unscored_analyses` (l'écart est exposé, pas masqué).
- `avg_scan_duration_s` = `completed_at − started_at` (durée du scan OSINT).
- `avg_flow_duration_s` = `end_report_date − start_report_date` (durée totale
  du flux, attente utilisateur comprise). Les deux ne doivent pas être
  confondues.
- Remplace le calcul côté client qui ne portait que sur la page courante et
  sous-estimait silencieusement les totaux.

---

## Les 47 outils OSINT

Comptés dans `TOOLS_REGISTRY` / `ALL_TOOLS` de `routes/recon.py` — les deux
ensembles sont identiques.

| Catégorie | Outils |
|---|---|
| **Domain Intelligence** (2) | `whois`, `rdap_info` |
| **Subdomain Discovery** (5) | `crtsh`, `subfinder`, `assetfinder`, `amass`, `github` |
| **DNS / Réseau** (6) | `dns`, `dns_records`, `dnssec`, `ip_info`, `ptr_records`, `asn_info` |
| **SSL / TLS** (4) | `ssl_info`, `tls_config`, `caa_check`, `dane_check` |
| **Email / Messagerie** (7) | `email_config`, `dkim_check`, `spf_analysis`, `dmarc_check`, `mta_sts_check`, `tlsrpt_check`, `bimi_check` |
| **Web / HTTP** (7) | `headers`, `security_headers`, `tech_stack`, `waf_detection`, `redirect_chain`, `favicon_hash`, `http_observatory` |
| **Web / OSINT** (4) | `robots_txt`, `sitemap`, `security_txt`, `js_endpoints` |
| **Infrastructure / Cloud** (1) | `reverse_ip` |
| **Vulnérabilités Passives** (2) | `subdomain_takeover`, `typosquatting` |
| **Réputation / Threat Intel** (5) | `dnsbl_check`, `shodan_internetdb`, `xposedornot_breaches`, `abuseipdb_check`, `abusech_check` |
| **OSINT Externe** (4) | `archive_history`, `otx_passive_dns`, `gau_urls`, `urlscan_search` |

### Les quatre outils ajoutés en dernier

| Outil | Source | Clé | Sans clé |
|---|---|---|---|
| `shodan_internetdb` | API InternetDB de Shodan | **aucune** | fonctionne toujours. Consulte les ports, CPE, CVE et hostnames **déjà observés** par Shodan sur les IP résolues — aucune sonde n'est envoyée à la cible. Les CVE sont enrichies (CVSS via CIRCL, score d'exploitabilité EPSS via FIRST). `no_data` si l'IP est inconnue de Shodan |
| `otx_passive_dns` | AlienVault OTX | `OTX_API_KEY` *(optionnelle)* | requête tentée en anonyme ; `limited` si OTX répond 401/403, `no_data` sur 404. Fournit l'historique des résolutions DNS dans le temps |
| `rdap_info` | `rdap.org` (RFC 9083) | **aucune** | données d'enregistrement **structurées** (registrar, IANA ID, contact abuse, statuts, dates). Complète `whois` sans le remplacer ; `unavailable` si le TLD n'a pas de service RDAP |
| `xposedornot_breaches` | XposedOrNot | **aucune** | fuites de données connues. Teste 5 adresses « rôle » (`admin@`, `contact@`, `info@`, `support@`, `webmaster@`), car l'API ne permet pas la recherche par domaine entier |

> **Have I Been Pwned n'est plus utilisé.** HIBP exige un abonnement payant
> **et** une vérification de propriété du domaine, ce qui produit un `403`
> systématique sur un domaine tiers — inutilisable pour cette plateforme.
> `xposedornot_breaches` le remplace (gratuit, sans clé), avec la couverture
> plus étroite décrite ci-dessus, explicitement signalée dans le champ `note`
> du résultat.

### Réseau sortant

Tous les appels HTTP des outils passent par une **`requests.Session` unique et
partagée** (`_build_http_session`) :

- **Connexions persistantes** — le pool keep-alive évite de refaire la poignée
  de main TLS à chaque appel, ce qui compte d'autant plus que les outils
  tournent en parallèle. Le pool est dimensionné sur `SCAN_MAX_WORKERS`.
- **Retries ciblés** — `total=2`, `backoff_factor=1` (1 s puis 2 s), sur
  `429, 502, 503, 504` uniquement, et uniquement pour les méthodes idempotentes
  (`GET`, `HEAD`, `OPTIONS`). Jamais de retry sur une `404`, qui est une
  réponse métier légitime.

---

## Traçabilité des findings

Chaque finding produit par l'analyse IA porte un champ **`source_tool`
obligatoire** : la clé technique de l'outil OSINT dont provient la preuve
(ex. `dns_records`, `ssl_info`, `shodan_internetdb`). Elle doit figurer parmi
les outils réellement exécutés. Un champ `source_tools` (pluriel) liste les
outils secondaires quand une conclusion croise plusieurs sources.

Cette clé est résolue en nom lisible et catégorie grâce au bloc
`meta.tool` / `meta.category` présent sur chaque entrée de `scan_results`.
Elle est ensuite propagée :

- dans le **PDF** — chaque finding affiche son « Outil source », et la section
  « Méthodologie & Sources » relie les clés à l'inventaire des outils ;
- dans **`export.csv`** — colonnes `source_tool`, `tool`, `tool_category` ;
- dans **`export.json`** — via `provenance.tools_detail`.

Le champ `mitre_attack` du rapport est, lui, calculé **de façon déterministe**
par `utils/mitre_attack.py` à partir des outils exécutés — il n'est pas inventé
par le LLM.

---

## Rate limiting

Limites globales par défaut : **5000/jour** et **1000/heure** par adresse IP.
Les requêtes porteuses du **jeton de service** valide (n8n) sont exemptées de
toutes les limites : elles partageaient l'IP du conteneur n8n, donc un
plafond commun à tous les utilisateurs.

| Endpoint | Limite |
|---|---|
| `POST /auth/login` | 10/minute |
| `POST /recon` | 20/heure |
| `POST /verify_email` | 10/heure |
| `POST /pass_recon` | 30/heure |
| `POST /analyze`, `POST /analyze/async` | 5/heure |
| `GET\|POST /analyze/wait/<id>` | 60/minute |
| `POST /recon/<id>/generate_final_report` | 20/heure |
| `POST /recon/<id>/generate_report` | 10/heure |
| `POST /recon/<id>/issue_access` | 10/heure |
| `POST /results/access` | 5/minute, 30/heure |
| `GET /results/report` | 120/heure |
| `GET /results/report.pdf`, `export.json`, `export.csv` | 60/heure |

Le stockage est **Redis** (`REDIS_URL`), partagé entre les workers gunicorn.
Sans Redis, le repli `memory://` donne un compteur **par processus** : une
limite de 20/heure autoriserait en réalité 20 × nombre de workers, et tous les
compteurs seraient perdus au redémarrage. Un avertissement est journalisé au
démarrage dans ce cas.

L'identification de l'IP dépend de `TRUSTED_PROXY_COUNT` : mal réglé, soit
toutes les requêtes tombent dans le même compartiment (un seul attaquant épuise
le quota commun), soit un client peut forger `X-Forwarded-For` et usurper une IP.

---

## Logging et audit

- **Console** — format `date [NIVEAU] module: message`, niveau réglable par
  `LOG_LEVEL`. Chaque requête produit une ligne `→` (entrée) et `←` (sortie
  avec code et durée). Les logs `werkzeug` et `urllib3` sont réduits à
  `WARNING`.
- **Base de données** — table `audit_log` : méthode, chemin, code HTTP, durée
  en ms, IP client, User-Agent tronqué à 200 caractères. Les chemins Swagger et
  la racine sont exclus pour éviter le bruit. Une erreur de persistance de
  l'audit n'interrompt **jamais** la réponse au client.
- **Préfixes de sous-système** dans les messages : `[parallel]`, `[export.json]`,
  `[export.csv]`, `[groq]`, `[entrypoint]`, `[provision]`.

```bash
docker compose logs api | grep '\[parallel\]'   # gain réel de la parallélisation
```

---

## Sécurité

- **Reconnaissance strictement passive** — aucun scan de ports, aucun payload,
  aucune tentative d'authentification, aucun fuzzing. Les données viennent de
  tiers (registres, Certificate Transparency, DNS public, archives, bases de
  réputation, observations Shodan préexistantes) ; les seules requêtes vers la
  cible sont des requêtes HTTP publiques banales (`/`, `robots.txt`,
  `sitemap.xml`, `.well-known/security.txt`, favicon) et des résolutions DNS.
  `amass` tourne en `-passive`.
- **Consentement** — `accord` est requis à la création, l'email est validé par
  OTP, et les exports sont refusés (`403`) sans consentement enregistré.
- **Anti-SSRF** — `is_safe_domain()` résout le domaine et refuse si **une
  seule** des adresses obtenues est privée ou réservée (y compris
  `169.254.169.254`), en plus des noms locaux et internes. Limite connue et
  documentée dans le code : le **DNS rebinding** reste possible, le nom étant
  re-résolu par chaque outil au moment de la connexion. Toutes les requêtes
  HTTP du scanner passent en plus par une session (`_SsrfGuardedSession`)
  qui revalide l'hôte de **chaque** requête et de chaque redirection : un
  sous-domaine découvert ou une redirection vers une adresse interne est
  refusé sans être contacté.
- **Résultats chiffrés** — AES-256-GCM, clé dérivée (HKDF) du code d'accès
  du demandeur, donnée associée liant chaque chiffré à son dossier et à son
  champ ; le serveur ne stocke que l'empreinte HMAC du code.
- **Exécution de commandes** — jamais `shell=True` ; `_run_subprocess` reçoit
  une liste d'arguments, avec timeout explicite.
- **Injection CSV** — les cellules d'export commençant par `=`, `+`, `-`, `@`
  sont neutralisées (CWE-1236). Les noms de fichiers `Content-Disposition` sont
  filtrés caractère par caractère.
- **Secrets** — `.env` est couvert par `.gitignore`, aucune clé n'est
  journalisée ni renvoyée par l'API. Le conteneur n8n ne reçoit que son
  jeton de service, le secret du webhook, sa clé de chiffrement et les
  variables `POSTGRES_*`, et l'accès à `$env` est bloqué dans ses nœuds.
- **n8n** — publié sur `127.0.0.1` uniquement (tunnel SSH pour l'éditeur) ;
  créer le compte propriétaire dès le premier démarrage.
- **Taille des requêtes** — `MAX_CONTENT_LENGTH` limité à 1 Mo.
- **CORS** — en production, `CORS_ORIGINS` vide refuse toute origine
  cross-domain (le mode « ouvert » n'existe qu'en `FLASK_ENV=development`).
- **HTTPS** — assuré par Caddy (`caddy/Caddyfile`), seul service publié.

---

## Tests

```bash
./scripts/run-tests.sh                      # recommandé : conteneur jetable, --network none
./scripts/run-tests.sh -m security          # tests de sécurité seuls
./scripts/run-tests.sh -m integration       # tests de bout en bout
docker exec -it api python3 -m pytest       # alternative dans le conteneur api
```

Suites présentes : `test_auth`, `test_crud`, `test_export_stats`,
`test_new_tools`, `test_otp`, `test_parallel`, `test_recon_results`,
`test_routes_scan`, `test_validators`, `test_verify_email`,
`test_grounding_check`, et depuis le plan d'action : `test_subdomain_selection`,
`test_attack_surface`, `test_security_ssrf`, `test_result_vault`,
`test_results_access`, `test_pipeline_flow`, `test_retention`,
`test_end_to_end_flow`.

`config.py` détecte l'exécution sous pytest et n'écrase alors pas les variables
posées par `tests/conftest.py` (notamment `DATABASE_URL=sqlite:///:memory:`).
L'exécution dans le conteneur reste la plus fiable, la suite étant encore
sensible aux variables déjà présentes dans le shell.

---

## Structure du projet

```
api/
├── app.py                  # Factory Flask (create_app)
├── config.py               # .env, Swagger, URI base de données, identifiants admin
├── database.py             # Instance SQLAlchemy partagée
├── extensions.py           # Flask-Limiter (Redis / memory://)
├── entrypoint.sh           # DNS → migrate.py → gunicorn
├── migrate.py              # Migrations SQL idempotentes + pgvector + rag_documents
├── generate_password_hash.py
├── test_smtp.py
├── requirements.txt
├── Dockerfile
├── .env.example
├── models/
│   ├── recon.py            # Dossier + scan/analyse/PDF + security_score dénormalisé
│   ├── audit_log.py
│   └── pass_recon_cache.py # Cache (domain, tools_key), TTL 30 j
├── routes/
│   ├── __init__.py         # register_routes() — 11 blueprints
│   ├── results.py          # POST /results/access, GET /results/* (consultation par code)
│   ├── cache.py            # GET /cache, /cache/<id>, export (scans bruts, admin)
│   ├── welcome.py          # GET /
│   ├── auth.py             # POST /auth/login
│   ├── crud.py             # /recon, /verify_email, /recon/<id>/result, /report
│   ├── logs.py             # /logs, /logs/stats
│   ├── recon.py            # POST /pass_recon — 47 outils, 2 vagues parallèles
│   ├── dns_info.py         # POST /dns_info
│   ├── analyze.py          # /analyze, /analyze/async, /analyze/wait, /analyze/status
│   ├── report.py           # generate_final_report, generate_report, report.pdf, exports
│   └── stats.py            # GET /recon/stats
├── utils/
│   ├── parallel.py         # run_tools_parallel — isolation + borne de temps
│   ├── validators.py       # is_valid_domain, is_safe_domain (anti-SSRF)
│   ├── auth.py             # @require_auth (Basic Auth), @require_service_or_auth (jeton n8n)
│   ├── result_vault.py     # code d'accès, chiffrement AES-GCM, sessions
│   ├── captcha.py          # vérification Cloudflare Turnstile
│   ├── pipeline_trigger.py # API → webhook n8n interne
│   ├── retention.py        # purge RGPD horaire
│   ├── gemini_client.py · cerebras_client.py · groq_client.py
│   ├── openrouter_client.py · ollama_client.py
│   ├── web_search.py       # DuckDuckGo (ddgs) ou Tavily
│   ├── analysis_merger.py  # compute_security_score
│   ├── final_report_generator.py
│   ├── pdf_generator.py    # dont la section « Méthodologie & Sources »
│   ├── mitre_attack.py     # Mapping déterministe outils → ATT&CK
│   ├── email_sender.py     # OTP + mail « rapport prêt » (code d'accès, sans pièce jointe)
│   └── command_runner.py   # (non importé actuellement)
├── errors/handlers.py      # 400/401/403/404/405/429/500 en JSON
├── templates/redoc.html
└── tests/
```
