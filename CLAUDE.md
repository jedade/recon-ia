# CLAUDE.md

Guide pour Claude Code sur le dépôt **recon-ia**. Ce fichier décrit ce qui est
réellement présent dans le code (vérifié fichier par fichier), pas ce qui est
seulement annoncé dans les README.

---

## 1. Vue d'ensemble

**Recon-IA** est une plateforme self-hosted de **reconnaissance passive OSINT
assistée par IA**. Un utilisateur remplit le formulaire (domaine + email) et
valide son email par OTP ; l'API déclenche alors le pipeline n8n, qui fait
exécuter **47 outils OSINT passifs en parallèle**, analyser la surface
d'attaque par des LLM (cloud ou local) avec traçabilité outil → conclusion,
puis générer un rapport PDF. En fin de pipeline, les résultats sont
**chiffrés** et le demandeur reçoit par mail un **code d'accès** (aucune
pièce jointe) qui lui permet de consulter le rapport et de le télécharger en
PDF, JSON ou CSV sur la page « Voir le résultat » (`web/result.html`). Les
exports portent une empreinte SHA-256 pour un usage citable.

Tout tourne via `docker-compose.yml` à la racine, derrière **Caddy** (seul
service publié sur Internet). Le déploiement de référence utilise le domaine
`idachallenge.bj`.

Langue du projet : **français** (docstrings, logs, commentaires, messages
d'erreur API, rapports IA par défaut `ANALYSIS_LANG=fr`).

**Feuille de route** : `docs/PLAN_ACTION.md` décrit les évolutions prévues
(flux cible, phases, décisions prises et ouvertes). Ce fichier-ci reste la
description de l'existant : reporter ici ce qui est livré.

---

## 2. Architecture

```
                Internet
                   │  80/443
            ┌──────▼───────┐
            │    Caddy     │  TLS auto, retire X-Service-Token, IP client réelle
            └──┬────────┬──┘
   SITE_ADDRESS│        │API_ADDRESS
         ┌─────▼──┐  ┌──▼───────────────────────┐
         │  web   │  │ API Flask (gunicorn)     │◄──── jeton de service ─────┐
         │ nginx  │  │ /recon /verify_email     │                            │
         └────────┘  │ /results/* (code d'accès)│── webhook interne ──► n8n (privé)
                     └──┬──────────┬──────────┬─┘   (X-Pipeline-Secret)    pipeline
                        ▼          ▼          ▼
       PostgreSQL 16 + pgvector   Redis      LLM en cascade + 47 outils OSINT
       (recon chiffré, audit_log, (rate      Gemini → Cerebras → Groq → OpenRouter
        pass_recon_cache,          limiter)  → Ollama local (11434)
        rag_documents)
```

Services déclarés dans `docker-compose.yml` (**7**) :

| Service    | Image / build            | Port | Rôle |
|------------|--------------------------|------|------|
| `caddy`    | `caddy:2.8.4-alpine`     | **80/443 publiés** — seul service exposé | reverse proxy TLS (`caddy/Caddyfile`) devant `web` et `api` |
| `web`      | `nginx:alpine`           | `expose 80` — non publié | sert `./web` en statique (via Caddy) |
| `api`      | build `./api`            | `127.0.0.1:8080` (boucle locale) | API Flask REST OSINT + IA + PDF (gunicorn) |
| `postgres` | `pgvector/pgvector:pg16` | `expose 5432` — non publié | base principale + RAG vectoriel (healthcheck `pg_isready`) |
| `ollama`   | `ollama/ollama`          | `expose 11434` — non publié | LLM local (dernier recours d'analyse) + embeddings RAG |
| `n8n`      | build `./n8n`            | `127.0.0.1:5678` (boucle locale) | orchestration — image custom, provisionne credentials/workflows au démarrage |
| `redis`    | `redis:alpine`           | `expose 6379` — non publié | stockage partagé du rate limiter Flask-Limiter (multi-workers gunicorn) |

Points à savoir :
- **Seul Caddy est joignable depuis Internet** (2026-10-19). `api` et `n8n`
  ne sont publiés que sur `127.0.0.1` (diagnostic local ; éditeur n8n par
  tunnel SSH `ssh -L 5678:127.0.0.1:5678 serveur`). Les anciens scripts
  `scripts/init-letsencrypt.sh` / `renew-certs.sh` et les dossiers
  `certbot/`, `nginx/`, `renew-certs.sh/` (cassés : ils visaient des
  services absents du compose) ont été supprimés. Caddy obtient et renouvelle
  seul les certificats quand `SITE_ADDRESS`/`API_ADDRESS` sont des noms de
  domaine (préfixe `http://` = sans TLS, développement).
- **Le navigateur ne parle qu'à l'API, jamais à n8n.** `POST /verify_email`
  (public) déclenche le webhook n8n sur le réseau interne
  (`utils/pipeline_trigger.py`, en-tête `X-Pipeline-Secret`) ; n8n rappelle
  les routes du pipeline avec un **jeton de service** (`X-Service-Token`,
  `utils/auth.py::require_service_or_auth`), plus avec le compte admin.
- `postgres`, `ollama` et `redis` n'exposent aucun port sur l'hôte. C'est
  délibéré (Ollama et Redis n'ont aucune authentification, Postgres contient
  des PII).
- `api` monte `./api:/app` en volume : le code est rechargé au redémarrage du
  conteneur, pas besoin de rebuild pour un changement Python (mais rebuild
  nécessaire si `requirements.txt` ou le `Dockerfile` change).
- **Qdrant/Pinecone ont été retirés du RAG.** Le corpus RAG (OWASP Cheat
  Sheets, ASVS, WSTG, OWASP Top 10:2021, MITRE ATT&CK Reconnaissance/Resource
  Development, RFC IETF derrière les enregistrements de confiance — 6 sources,
  cf. `data/script_*.py`) est stocké dans la table `rag_documents` de
  PostgreSQL (extension `pgvector`, voir `api/migrate.py` : colonnes
  `id/content/metadata/embedding`, embeddings `nomic-embed-text:v1.5` via
  Ollama, 768 dim).
  ⚠️ **Le RAG est interrogé par l'API (`utils/rag_retrieval.py`), pas par
  n8n** — corrigé après un audit qui a trouvé `rag_documents` alimentée mais
  **jamais lue nulle part** (voir §8, section RAG, pour l'historique complet
  de cette découverte et du correctif).
- Les deux workflows n8n (ingestion RAG + pipeline principal) sont **versionnés
  dans `n8n/workflows/*.json`** et **provisionnés + activés automatiquement** au
  démarrage du conteneur `n8n` par `n8n/provision-and-start.sh`. `docker compose up`
  seul suffit — sauf la création du compte propriétaire n8n, à faire
  immédiatement (tant qu'il n'existe pas, le premier visiteur de l'éditeur
  peut le créer).

---

## 3. Structure des dossiers

```
recon-ia/
├── setup.sh                 # Lancement complet en 1 commande (voir §6) — génère les .env de dev
│                            #   et les secrets, build+up, attend postgres/api, pull le modèle Ollama
├── caddy/Caddyfile          # Reverse proxy TLS, seul service publié (voir §2)
├── api/                     # Backend Flask (le cœur du projet)
├── web/                     # Frontend statique servi par nginx (derrière Caddy)
│   ├── index.html           # Formulaire public (+ widget Turnstile si configuré)
│   ├── result.html/.css/.js # « Voir le résultat » : consultation par code d'accès
│   ├── dashboard.html       # Console admin (métadonnées seulement pour un dossier scellé)
│   ├── config.js            # GÉNÉRÉ à chaque démarrage du conteneur `web` (envsubst) — gitignoré
│   └── templates/config.js.template  # Source : API_BASE + TURNSTILE_SITE_KEY (voir §7)
├── n8n/
│   ├── Dockerfile                 # Image custom : provisioning auto (voir §8)
│   ├── provision-and-start.sh     # Entrypoint : import credentials/workflows + exec n8n
│   ├── generate-credentials.js    # Génère le JSON credentials depuis l'environnement
│   └── workflows/                 # Workflows versionnés (source de vérité, pas la DB n8n)
│       ├── rag-ingestion.json     # Ingestion RAG : fichiers → Postgres PGVector Store
│       └── recon-ia-main.json     # Pipeline principal (webhook interne → … → PDF + code d'accès)
├── n8n_data/                # État runtime n8n (database.sqlite, logs, nodes) — gitignoré
├── n8n_ressource/           # Corpus RAG monté dans n8n (/tmp/n8n-source-docs)
├── caddy_data/, caddy_config/  # Certificats et état Caddy — gitignorés
├── ollama/                  # Volume modèles Ollama — gitignoré
├── postgres_data/           # Volume PostgreSQL (inclut rag_documents/pgvector) — gitignoré
├── scripts/run-tests.sh     # Suite pytest dans un conteneur jetable sans réseau (voir §6)
├── scripts/e2e/             # Tests navigateur : result.html (run-result-page.sh), parcours réel (run-full-flow.sh), dashboard (dashboard.mjs)
├── docs/PLAN_ACTION.md      # Feuille de route (phases, décisions D1–D9)
├── data/                    # Scripts d'agrégation de corpus RAG (6 sources — voir §8)
│   ├── github_md_aggregator.py   # Cœur commun réutilisé par script_asvs/wstg/owasp_top10/mitre_attack
│   ├── script.py                 # OWASP Cheat Sheet Series
│   ├── script_asvs.py            # OWASP ASVS 5.0
│   ├── script_wstg.py            # OWASP Web Security Testing Guide
│   ├── script_owasp_top10.py     # OWASP Top 10:2021
│   ├── script_mitre_attack.py    # MITRE ATT&CK — tactiques Reconnaissance + Resource Development
│   ├── script_rfc_trust_records.py  # 10 RFC IETF (SPF/DKIM/DMARC/DANE/MTA-STS/TLS-RPT/CAA/security.txt)
│   └── combined_*.md             # Sorties générées — copiées dans n8n_ressource/ pour l'ingestion
├── n8n-backup.tar.gz        # 87 octets — archive vide/tronquée (gitignorée)
├── docker-compose.yml
├── .env                     # Interpolation ${VAR} du compose + secrets partagés API/n8n (voir §7)
└── README.md
```

### `api/` (source de vérité fonctionnelle)

```
app.py                   # Factory Flask : logging, ProxyFix, CORS, headers sécurité,
                         #   audit DB de chaque requête, blueprints, handlers d'erreurs
config.py                # load_dotenv(.env, override sauf sous pytest), Swagger,
                         #   SQLALCHEMY_DATABASE_URI, ADMIN_*, MAX_CONTENT_LENGTH 1 Mo
database.py              # `db = SQLAlchemy()` partagé
extensions.py            # Flask-Limiter — storage Redis si REDIS_URL, repli memory:// signalé
migrate.py               # Migrations SQL idempotentes (CREATE/ALTER … IF NOT EXISTS) + pgvector
entrypoint.sh            # réécrit /etc/resolv.conf → migrate.py → gunicorn (PLUS `python app.py`)
generate_password_hash.py, test_smtp.py   # scripts utilitaires
models/     recon.py · audit_log.py · pass_recon_cache.py
routes/     __init__.py (register_routes) + 11 blueprints (dont results.py : consultation par code, cache.py : scans bruts admin)
utils/      auth (admin Basic + jeton de service) · validators · command_runner · parallel
            web_search · email_sender
            gemini_client · cerebras_client · groq_client · openrouter_client · ollama_client
            rag_retrieval (recherche pgvector — voir §5, §8)
            analysis_merger · final_report_generator · pdf_generator
            mitre_attack (corrélation outils exécutés → techniques ATT&CK, déterministe)
            result_vault (code d'accès, chiffrement AES-GCM, sessions — voir §5)
            captcha (Turnstile) · pipeline_trigger (API → webhook n8n interne)
            retention (purge RGPD horaire, lancée par stale_scan_watchdog)
errors/handlers.py       # 400/401/403/404/405/429/500 en JSON
templates/redoc.html
tests/                   # pytest : conftest + 19 fichiers de tests (marqueurs security/integration)
Dockerfile.test          # image légère pour lancer pytest sans la stack (scripts/run-tests.sh)
```

Il n'y a **plus** de `api/main.py`, `api/main.py.back`, `api/requirement`,
`api/services/`, ni `api/utils/netcraft_scraper*.py` — tous supprimés (vérifié).

### `web/`

- `index.html` — page publique : `POST /recon` (avec jeton Turnstile si
  `TURNSTILE_SITE_KEY` est configurée) puis `POST /verify_email`, tous deux
  sur l'API — plus aucun appel à n8n depuis le navigateur (CSS/JS inlinés).
- `result.html` + `result.css` + `result.js` — « Voir le résultat » (phase 2,
  design inspiré de web-check : fond `#141d2b`, accent `#9fef00`, PT Mono,
  cartes à ombre décalée, masonry, thème clair automatique ou bouton ◐) :
  saisie du code → `POST /results/access` → session en `sessionStorage`
  (jamais le code) → rendu de `GET /results/report` : jauge score/note,
  résumé, fiabilité (`grounding_check`/`coverage_check`), constats triés et
  filtrables par sévérité avec lien vers la carte de leur `source_tool`,
  points forts/actions, tableau ATT&CK, suivi des statuts d'outils, une carte
  par outil (recherche + filtre par catégorie, modale d'explication depuis
  `meta.description`/`meta.indicators`, sortie brute repliée),
  téléchargements PDF/JSON/CSV par `fetch` + Blob. JS/CSS **séparés** pour
  une CSP sans `unsafe-inline` ; rendu **uniquement** par
  `textContent`/`createElement` (données tierces et texte LLM) — ne jamais
  introduire `innerHTML` dans `result.js`. Testé dans Chrome par
  `scripts/e2e/run-result-page.sh` (voir §6).
- `dashboard.html` affiche pour un dossier scellé un cadenas (plus de bouton
  PDF) et une section « Coffre des résultats » avec bouton « Révoquer le
  code » (`POST /recon/<id>/revoke_access`).
- `dashboard.html` — console admin qui parle directement à l'API
  (`API_BASE_DEFAULT = 'https://api.idachallenge.bj'`, login via `POST /auth/login`).
- `docs.html` — documentation API en HTML statique.
- `vendor/chart.umd.min.js` — Chart.js embarqué pour le dashboard.

Les anciens `index-2.html`, `script.js`, `style.css` et les PDF de test
`report_*.pdf` ont été supprimés (`.gitignore` couvre désormais `web/*.pdf`).

---

## 4. Stack technique

**Backend** (`api/requirements.txt`) :
- **Flask 3** (pas FastAPI) + pattern *application factory* (`create_app()` dans `app.py`)
- **gunicorn** en production (`--worker-class gthread`, 2 workers × 4 threads,
  `--timeout 300`) — le serveur de développement Flask n'est plus utilisé
- **Flask-SQLAlchemy 3 / SQLAlchemy 2** — PostgreSQL 16 en prod (`psycopg2-binary`),
  SQLite prévu pour les tests
- **flasgger** (Swagger UI sur `/apidocs`, ReDoc sur `/redoc`) — chaque route est
  documentée via `@swag_from({...})`
- **flask-cors**, **flask-limiter** (+ client `redis`), **python-dotenv**
- **reportlab** pour les PDF
- Clients LLM : SDK `groq`, SDK `openai` réutilisé pour **OpenRouter, Cerebras et
  Gemini** (tous exposent une API OpenAI-compatible), Ollama via HTTP
- Recherche web : `ddgs` (DuckDuckGo) ou Tavily si `TAVILY_API_KEY`

**Outils CLI réellement invoqués par le code** :
`whois`, `nslookup`, `dig`, `host` (apt) · `sslscan` (apt, outil `tls_config`) ·
`dnsrecon` (pip, uniquement `POST /dns_info`) · `subfinder`, `assetfinder`,
`amass`, `github-subdomains`, `gau` (Go 1.22.5) · `dnstwist` (pip).

⚠️ `api/Dockerfile` et `requirements.txt` installent encore **du poids mort** :
`sublist3r`, `holehe`, `wafw00f`, `requests-html`, `selenium`/`chromium`/`xvfb`,
`creepyCrawler`. Aucun de ces paquets n'est importé ni exécuté par le code
Python actuel (vérifié par grep sur tout `api/`). Ils allongent le build sans
servir — candidats à la suppression sur demande explicite.

**Session HTTP sortante** : `routes/recon.py::_build_http_session()` construit
une `requests.Session` **unique et partagée** par tous les outils —
connexions keep-alive + `urllib3.Retry(total=2, backoff_factor=1,
status_forcelist=[429, 502, 503, 504])` limité aux méthodes idempotentes.
Le pool est dimensionné sur `SCAN_MAX_WORKERS` pour ne pas sérialiser les
threads de la vague parallèle.

**Garde anti-SSRF de cette session (2026-10-19)** : la session est une
`_SsrfGuardedSession`, dont `send()` passe l'hôte de **chaque** requête par
`is_safe_domain` — y compris chaque saut de redirection, que `requests`
envoie lui aussi via `send()`. Un hôte qui résout vers une adresse
interne/réservée lève `UnsafeTargetError` (sous-classe de
`RequestException`) sans qu'aucun octet ne parte. Ferme deux contournements
réels : les sous-domaines découverts n'étaient jamais validés (seul le
domaine saisi l'était, dans `pass_recon`), et les 5 appels
`allow_redirects=True` suivaient une redirection vers `10.x`/`169.254.x`
sans contrôle. Résultat mis en cache 30 s par hôte. Limite inchangée : DNS
rebinding (voir §8). Tout nouvel outil HTTP doit passer par `_http`, jamais
par `requests.get` directement, sous peine de perdre cette protection.

**Auth** : HTTP Basic Auth uniquement, un seul compte admin défini par
`ADMIN_EMAIL` + `ADMIN_PASSWORD` (hash werkzeug). Décorateur `@require_auth`
dans `utils/auth.py`, comparaison du login via `hmac.compare_digest`.
`POST /auth/login` ne délivre **aucun token** : il valide seulement les
identifiants (le dashboard réutilise ensuite le Basic Auth).

**Persistance** : 4 tables —
- `recon` : dossier utilisateur + `scan_results`, `analysis_result`,
  `final_report`, `pdf_report` (`LargeBinary`), et surtout
  **`security_score` / `security_grade` dénormalisés** (colonnes indexées,
  renseignées par `Recon.set_analysis_result()`) pour que `GET /recon` et
  `GET /recon/stats` n'aient plus à rapatrier et parser les rapports IA.
  Même principe pour les **métriques de conformité** (dashboard
  recherche/présentation) : `findings_total_count` / `findings_traceable_count`
  (traçabilité outil→finding), `mitre_technique_count` / `mitre_technique_ids`
  (couverture MITRE ATT&CK), `tools_status_summary` (fiabilité agrégée des
  47 outils) — renseignées par `Recon.set_compliance_metrics()` /
  `set_tools_status_summary()`, agrégées par `GET /recon/stats` (bloc
  `compliance`) sans jamais reparser `scan_results`/`analysis_result`. Détails
  au §5bis.
- `audit_log` : chaque requête HTTP métier (méthode, chemin, code, durée, IP, UA).
- `pass_recon_cache` : cache scan par `(domain, tools_key)`, TTL 30 j
  (`CACHE_DEFAULT_TTL_DAYS`). **Tous les outils restants sont passifs et
  cachables** — l'exclusion RGPD de `holehe` n'a plus d'objet, l'outil ayant
  été retiré.
- `rag_documents` : corpus RAG pgvector (`vector(768)`), interrogé par l'API
  (`utils/rag_retrieval.py`) au moment de l'analyse — voir §8 pour l'historique
  (longtemps alimentée mais jamais lue nulle part avant correctif).

---

## 5. Flux applicatif et endpoints

Pipeline nominal (seul `recon_id` circule à partir de l'étape 3) — refondu le
2026-10-19 (plan d'action, phase 1) :

1. `POST /recon` (public) → contrôle Turnstile (`utils/captcha.py`, si
   `TURNSTILE_SECRET_KEY`), consentement `accord` **obligatoirement `true`**
   (400 sinon — auparavant `false` était accepté et le scan tournait quand
   même), crée le dossier + envoie un OTP 6 chiffres (TTL `OTP_TTL_SECONDS`,
   600 s)
2. `POST /verify_email` (**public** — n8n ne l'appelle plus) → valide l'OTP,
   horodate `start_report_date`, puis **déclenche le webhook n8n en interne**
   (`utils/pipeline_trigger.py`) : `status='running'`, `current_step='queued'`,
   réponse `pipeline_started: true|false`. Après `OTP_MAX_ATTEMPTS` (5) codes
   faux sur un même dossier, le code est annulé (`otp_attempts`) — la seule
   limite par IP (10/h) laissait un attaquant réparti essayer les 10^6 codes.
3. n8n (jeton de service) : `POST /pass_recon` `{recon_id}` → scan OSINT,
   écrit `scan_results` en BD
4. `POST /analyze/async` + `/analyze/wait/<id>` → analyse IA, écrit
   `analysis_result` + `security_score`/`security_grade` + TTL cache
5. `POST /recon/<id>/generate_final_report` → rapport narratif IA (`final_report`)
6. `POST /recon/<id>/generate_report` → PDF stocké en BD, puis **scellement**
   du dossier et mail « rapport prêt » contenant **uniquement le code
   d'accès** (aucune pièce jointe, décision D1) — voir ci-dessous
7. Le demandeur ouvre `web/result.html`, saisit son code :
   `POST /results/access` → session, puis `GET /results/report`,
   `/results/report.pdf`, `/results/export.json`, `/results/export.csv`

Les routes admin `GET /recon/<id>/report.pdf`, `export.json`, `export.csv`
existent toujours, mais répondent **403** (`results_sealed: true`) une fois
le dossier scellé : le serveur ne peut plus en lire le contenu.

### Coffre des résultats et consultation par code (2026-10-19)

Décisions D1–D3 du plan d'action. Code : `utils/result_vault.py`,
`routes/results.py`, `routes/report.py::_seal_and_notify`.

- **Code d'accès** : `secrets.token_urlsafe(32)` (256 bits, 43 caractères),
  envoyé une seule fois par mail, **jamais stocké ni journalisé**. Valable
  `RESULTS_ACCESS_TTL_DAYS` (30 j), révocable (`POST /recon/<id>/revoke_access`,
  admin).
- **Recherche** : `access_token_hash = HMAC-SHA256(RESULTS_ACCESS_SECRET, code)`
  (unique, indexé). **Déchiffrement** : `clé = HKDF-SHA256(code, access_salt)`.
  Les deux usages sont séparés : l'empreinte ne permet pas de déchiffrer.
- **Chiffrement** : `scan_results` + `analysis_result` + `final_report`
  (compressés, dans `sealed_bundle`) et le PDF (`sealed_pdf`) en
  AES-256-GCM, avec une donnée associée `recon-ia:v1:<id>:<champ>` qui lie
  chaque chiffré à son dossier et à son champ (un chiffré recopié ailleurs
  ne se déchiffre pas). Les colonnes en clair sont ensuite **vidées**.
- **Ordre critique** : `seal_recon()` modifie le dossier sans commiter ; le
  commit n'a lieu qu'**après l'envoi réussi du mail**. Si l'envoi échoue,
  rollback : le dossier reste en clair, `email_error` est renvoyé, et l'admin
  peut réessayer avec `POST /recon/<id>/issue_access`. Sans cela, un code
  jamais reçu rendrait le rapport illisible à jamais. Un dossier déjà scellé
  ne peut pas recevoir de nouveau code (409).
- **`RESULTS_ACCESS_SECRET` absent** (< 32 caractères) : aucun code n'est
  émis (fail closed), `email_error` le signale ; `POST /results/access`
  répond 503. Ce secret est distinct de `SECRET_KEY`, qui retombe sur une
  valeur aléatoire **par worker** quand il manque — ce repli casserait la
  recherche d'un worker gunicorn à l'autre.
- **Sessions** : `POST /results/access` (code dans le CORPS, jamais dans
  l'URL ; 5/min et 30/h par IP) renvoie un jeton Fernet opaque de
  `RESULTS_SESSION_TTL_SECONDS` (1 h) contenant l'id du dossier et la clé
  dérivée. Chaque requête `GET /results/*` revalide l'état du dossier : une
  révocation ou une expiration coupe les sessions ouvertes (403/410). Code
  inconnu ou mal formé → toujours la même réponse 401 (pas d'oracle).
  Le contenu n'est déchiffré qu'en mémoire, jamais réécrit dans les colonnes
  du modèle (un commit ultérieur l'aurait remis en clair en base).
- **Consentement** : `export.json`/`export.csv` exigent toujours `accord`.
- **Admin** : `to_dict()` expose `results_sealed`, `access_state`
  (`none|active|expired|revoked`), `access_expires_at`, `access_count`,
  `last_access_at`, `results_purged_at` — jamais le code, l'empreinte ni le
  sel. Les colonnes dénormalisées (score, findings, MITRE, outils, tokens)
  restent en clair : le dashboard et `/recon/stats` fonctionnent sans le
  contenu.
- `send_report_email` (PDF en pièce jointe) a été **supprimée** :
  `send_results_ready_email` la remplace (`risk_level` restreint à une
  énumération avant d'entrer dans l'objet du mail).
- `send_email: false` sur `generate_report` laisse le dossier en clair
  (usage admin/tests : sans mail, personne ne détiendrait le code).

### Purge RGPD (`utils/retention.py`, 2026-10-19)

Lancée par la boucle du watchdog toutes les `RETENTION_INTERVAL_S` (1 h),
idempotente (plusieurs workers sans effet de bord) :
- code expiré/révoqué depuis `RESULTS_PURGE_GRACE_DAYS` (7 j) → contenu
  chiffré effacé, prénom/nom/email/`requested_info` anonymisés
  (`purged-<id>@anonymized.invalid`), `results_purged_at` horodaté ; domaine,
  score et métriques conservés pour les statistiques ;
- demandes jamais vérifiées de plus de `UNVERIFIED_RETENTION_DAYS` (7 j) →
  supprimées ;
- `audit_log` de plus de `AUDIT_RETENTION_DAYS` (90 j, adresses IP) →
  supprimé ;
- `pass_recon_cache` **n'est PAS purgé** (décision de l'utilisateur,
  2026-10-19) : il garde en clair les résultats **bruts** du scan par domaine
  (données publiques, sans analyse IA ni donnée du demandeur), hors du
  chiffrement D3, et l'admin doit pouvoir les consulter. Une entrée expirée
  (`expires_at` dépassé, 30 j) n'est plus servie au pipeline mais reste en
  base et consultable ; elle est réécrite au prochain scan du même domaine.

### Consultation admin du cache (`routes/cache.py`, 2026-10-19)

`GET /cache` (liste paginée, filtres `domain` et `valid=true|false`, sans le
résultat), `GET /cache/<id>` (résultat brut complet, `corrupted: true` si le
JSON stocké est illisible), `GET /cache/<id>/export.json`. **Admin seul**
(`require_auth`) — le jeton de service n'y donne pas accès (testé).
Dashboard : onglet **« Scans bruts (cache) »** (tableau, filtres, détail dans
la fenêtre habituelle avec les données brutes par outil, export JSON) et,
dans le détail d'un dossier scellé, bouton **« Voir le scan brut (cache) »**
qui ouvre l'entrée du même domaine : c'est le moyen pour l'admin de voir les
données collectées d'un dossier dont le rapport n'est lisible qu'avec le
code du demandeur. Tests : `tests/test_cache_admin.py`.

### Phases 3 à 8 (2026-10-19) — vue d'ensemble

Livrées en parallèle, une documentation détaillée par phase dans
`docs/phases/PHASE_<n>.md` (règles, formats, variables, limites). Ce qui
suit est ce qu'il faut savoir pour ne rien casser.

| Phase | Modules | À retenir |
|---|---|---|
| 3 Fiabilité | `utils/severity_rules.py`, `utils/kev.py`, `utils/finding_sanitizer.py` (réécrit), `utils/rag_retrieval.py` (réécrit), `analyze.py::_prepare_phase3` / `_postprocess_report` | **La sévérité est décidée par 43 règles sur les données brutes, pas par le LLM** (`severity_llm` garde sa proposition, `severity_rule` dit quelle règle a tranché). Constat positif → toujours INFO ; finding contredit par la donnée → retiré ; finding sans règle → plafonné à MEDIUM ; constat ≥ HIGH oublié → ajouté (`generated_by: "rule"`). `risk_score = 100 − security_score`. CVE citée mais non observée par Shodan → retirée (B6) ; CVE dans CISA KEV → CRITICAL. `references` est désormais `[{collection, source}]` (les lecteurs acceptent encore l'ancien format chaîne). RAG : une requête par constat, filtrée par `metadata->>'collection'`, repli sans filtre |
| 4 ATT&CK | `utils/attack_enablement.py`, `utils/mitre_attack.py`, `api/data/attack_reference.json` | Référentiel **v20.0** local, régénéré par `data/script_mitre_attack.py` (ajouter toute nouvelle technique à `REFERENCE_TECHNIQUES` puis régénérer — un test échoue sinon). `attack_enabled` / `mitigations` / `attack_rules` viennent **uniquement** de la table ; les ID du LLM sont écrasés. Chaîne d'attaque, layer Navigator (`GET /results/export.navigator.json`), section PDF |
| 5 Collecte | `utils/passive_sources/*.py`, `utils/signals_extra.py` | 9 outils ; ceux à clé passent en `skipped` sans clé. Tout ce qui touche la cible passe par `_http` (anti-SSRF) ; réponses tierces bornées (2 Mo). `github_dorks` ne conserve jamais la valeur d'un secret. Signaux pour l'IA : `signals["passive_extra"]`, répartis par section pour Ollama (`ollama_client._build_section_data`) |
| 6 Connaissance | `utils/rag_collections.py`, `utils/corpus_sanitizer.py`, `utils/explanations.py`, `utils/scan_stats.py`, `utils/takeover_fingerprints.py`, `data/script_*.py` | Collections `normes`, `attack`, `menaces`, `explications` (règle fichier → collection en 3 copies Python/n8n/SQL, testées identiques). Réindexation : redémarrer n8n, ou `data/sql/reindex_collections.sql` sous `rag_writer`. `comparative_context` : k-anonymat ≥ 10 domaines, jamais de nom de domaine, injecté comme **contexte, jamais comme preuve**. `subdomain_takeover` utilise can-i-take-over-xyz (suffixe DNS ; « Not vulnerable » ignoré, « Edge case » listé à part dans `edge_cases`) complété par `_CNAME_SUPPLEMENT` pour les services sans CNAME dans la source |
| 7 Graphe | `models/entity_graph.py`, `models/scan_monitoring.py`, `utils/entity_graph.py`, `utils/scan_diff.py`, `routes/graph.py`, `web/dashboard-graph.{js,css}`, `n8n/workflows/recon-ia-rescan.json` | Tables `entity`, `relation`, `scan_snapshot`, `watched_domain`. Graphe et différentiel calculés **avant le scellement** dans `generate_report`, stockés **en clair** (données techniques publiques uniquement, décision D10). Surveillance opt-in (désactivée par défaut), alertes à l'admin seulement. Routes `/graph/*`, `/monitoring*`, `/recon/<id>/diff` : admin ; `/monitoring/due` et `/monitoring/<id>/ingest` : jeton de service |
| 8 Agent | `utils/recon_agent.py`, `utils/agent_llm.py` | Étape finale de `/pass_recon`, **`AGENT_RECON_ENABLED=false` par défaut**. Refuse `qwen3:1.7b` (modèle ≥ 7B, Gemini ou DeepSeek requis — D9 ouverte). 7 outils passifs en liste blanche ; cible acceptée seulement si déjà observée dans le périmètre. Journal `scan_results["agent_pivots"]` → section Méthodologie du PDF, graphe (pivots rejoués) et `signals["agent_pivots"]` |

Raccords entre phases : `tests/test_phase_integration.py`. Exports CSV : 4
colonnes ajoutées (`observed_at`, `severity_rule`, `attack_enabled`,
`mitigations`, ces deux dernières recalculées par la table de la phase 4).

### Un email peut lancer plusieurs scans distincts (2026-07-30 — remplace l'ancienne « relance différée »)

`recon.email` n'a **plus** de contrainte UNIQUE, et `POST /recon` **crée
systématiquement un nouvel enregistrement** — y compris pour un email et/ou
un domaine déjà vus auparavant.

⚠️ **Changement de design demandé explicitement par l'utilisateur** : le
mécanisme précédent (contrainte UNIQUE(email) + colonnes `pending_*` +
« relance différée », voir historique ci-dessous) empêchait par construction
qu'un même email produise plusieurs rapports distincts et conservés — chaque
relance finissait par **réécrire** l'enregistrement existant après
vérification OTP. Or l'usage réel de la plateforme est **académique** :
relancer plusieurs fois le même domaine (test de reproductibilité,
comparaison de runs dans le temps) doit produire plusieurs rapports
**comparables et conservés séparément**, pas un seul rapport écrasé à chaque
tentative. Un historique qui s'auto-détruit à chaque nouvelle soumission est
inutilisable pour ce cas d'usage.

**Comportement actuel** (`models/recon.py`, `routes/crud.py::create_recon()`/
`verify_email()`) :
- `POST /recon` reste protégé contre le spam d'OTP : si un enregistrement
  **quelconque** pour cet email porte encore un `otp_code` non expiré
  (`OTP_TTL_SECONDS`), la requête est rejetée en `429` avec le délai
  d'attente restant — **aucun nouvel enregistrement n'est créé** tant qu'un
  code est en attente. Sinon, un nouvel enregistrement `Recon` est créé
  inconditionnellement (nouvel `id`, `status='pending'`, nouvel OTP), sans
  toucher à aucun enregistrement précédent pour cet email.
- `POST /verify_email` cherche l'enregistrement le plus récent
  (`ORDER BY id DESC`) portant `email` + `otp_code IS NOT NULL` — il n'y a
  plus besoin de distinguer « première vérification » et « relance », chaque
  enregistrement a son propre cycle de vie indépendant depuis sa création.
  Il n'y a plus de champs `pending_*` à appliquer : l'enregistrement validé
  **est** directement celui qui sera scanné, aucune étape de bascule.
- **Sécurité inchangée** : aucune perte de données n'est possible (aucun
  enregistrement existant n'est jamais modifié par une nouvelle soumission),
  et l'anti-spam empêche toujours qu'un tiers connaissant l'email d'autrui
  déclenche l'envoi répété d'OTP. La seule différence avec l'ancien design
  est qu'un email vérifié peut désormais accumuler plusieurs enregistrements
  au lieu d'un seul — ce qui est le but recherché, pas un risque.
- **Migration** (`api/migrate.py`) : `DROP CONSTRAINT recon_email_key` +
  `DROP COLUMN` sur les 5 colonnes `pending_*`, exécutée et vérifiée sur ce
  poste (`\d recon` confirme la contrainte et les colonnes absentes).
- **Testé de bout en bout après migration + restart complet** (`docker
  compose restart` de tous les services) : deux `POST /recon` successifs
  avec le **même email** (le premier suivi d'un `POST /verify_email` réussi
  pour vider son `otp_code`) produisent bien **deux lignes distinctes** en
  base (`id=3` et `id=4` dans le test), le premier enregistrement restant
  totalement intact (`verification=true`, `status='pending'`, aucun champ
  écrasé) après la création du second.

<details>
<summary>Historique — ancien design « relance différée » (obsolète, retiré 2026-07-30)</summary>

L'ancien design (`pending_domain`/`pending_firstname`/`pending_lastname`/
`pending_accord`/`pending_requested_info` + contrainte UNIQUE(email))
stageait la nouvelle demande sans toucher aux champs actifs, et n'appliquait
(en réinitialisant `scan_results`/`analysis_result`/`final_report`/
`pdf_report`/scores/métriques) qu'après confirmation du nouveau code OTP —
conçu à l'origine pour corriger un bug où `POST /recon` sur un email déjà
porteur de résultats répondait `HTTP 201` sans jamais envoyer d'OTP ni rien
créer. Ce design a lui-même été identifié comme problématique pour l'usage
réel (destruction de l'historique à chaque relance) et remplacé par le
comportement multi-enregistrements ci-dessus.

</details>

### Suivi d'étape en temps réel (`current_step`) — visibilité dashboard

⚠️ **Bug réel signalé (2026-07-29) — un code OTP incorrect était accepté
comme valide côté frontend, lançant le pipeline malgré tout — corrigé.**
Le formulaire public (`web/index.html::verifyCode()`) décidait du succès
avec `result?.valid === true || result?.success === true || response.status
=== 200` — or le webhook n8n (`respondWith: allIncomingItems`) répond
**toujours HTTP 200** tant que le workflow ne plante pas, **quel que soit**
le contenu réel de la réponse ; et le corps est un **tableau**
(`[{...}]`), jamais un objet nu, donc `result?.success` valait toujours
`undefined`. Le fallback `response.status === 200` faisait donc passer
n'importe quel code, correct ou non, pour une vérification réussie.
Aggravant : côté n8n, le nœud « Verify email for launch repporting »
**plantait réellement** sur un code incorrect (`verify_email` répond `400`,
et sans `neverError`, l'HTTP Request node lève une exception) — l'exécution
n8n s'arrêtait donc AVANT « Respond to Webhook », qui ne répondait jamais :
constaté en conditions réelles, la réponse au navigateur était `HTTP 200`
avec un **corps vide** (0 octet), confirmé par `execution_entity.status =
'error'` côté n8n. Corrigés ensemble :
- `n8n/workflows/recon-ia-main.json` — `options.response.response.neverError:
  true` ajouté au nœud « Verify email for launch repporting » : le nœud ne
  lève plus d'exception sur un `4xx`, son output devient le JSON réel de
  l'API (`{"success": false, "error": "Code incorrect"}` etc.), qui atteint
  enfin « Respond to Webhook ». Le nœud « Launch Passive Recon » reste
  branché en parallèle sur la même sortie mais lit `{{ $json.data.id }}` —
  absent sur un échec (`success: false` n'a pas de champ `data`) — donc son
  expression échoue et **aucun scan n'est lancé par erreur** sur un code
  invalide (vérifié : `verification` reste `false` après un mauvais code).
- `web/index.html::verifyCode()` — ne fait plus confiance à
  `response.status`, seulement au contenu réel (`result[0].success`, le
  webhook renvoyant toujours un tableau) ; le message d'erreur affiché à
  l'utilisateur est maintenant le vrai message de l'API (« Code incorrect »,
  « Code expiré »...) plutôt qu'un texte générique.
- Testé de bout en bout via le vrai webhook : mauvais code sur un
  enregistrement réel → `{"success":false,"error":"Code incorrect"}`,
  `verification` reste `false`, **aucun** `POST /pass_recon` déclenché ; bon
  code → `verification=true`, pipeline lancé normalement.

**Visibilité pendant l'exécution** — signalé conjointement : le dashboard
n'affichait qu'un statut binaire (`pending`/`running`/`success`/`failed`)
sans indiquer à quelle étape du pipeline (scan OSINT ? analyse IA ? PDF ?)
un enregistrement `running` se trouvait réellement, ni où un `failed` avait
échoué — critique pour justifier une analyse en cours devant un jury.
Nouvelle colonne `recon.current_step` (+ `current_step_updated_at`),
alimentée par `Recon.set_step()` à chaque transition :
`scanning_osint` (`routes/recon.py::pass_recon`, cache hit et scan complet)
→ `analyzing_ai` (`routes/analyze.py::analyze()` et `/analyze/async`) →
`generating_final_report` (`routes/report.py::generate_final_report_endpoint`)
→ `generating_pdf` (`routes/report.py::generate_report`) → `completed`.
**Jamais réinitialisée sur échec** : si `status` bascule à `failed`,
`current_step` reste sur la dernière étape entamée, donnant directement la
localisation de la panne sans relire les logs. Exposée dans `to_dict()`
(`GET /recon`), affichée sous le badge de statut par
`web/dashboard.html::reconStatusBadge()` (ex. « En cours — Analyse IA
(depuis 3 min) », « Échoué — bloqué à : Génération du PDF ») — rafraîchie
par le polling existant (30s), aucun mécanisme temps réel supplémentaire.
- **Gap comblé au passage** : l'échec de génération PDF
  (`routes/report.py::generate_report`) envoyait déjà un email d'erreur
  (`pdf_failed`) mais ne positionnait **jamais** `recon.status = 'failed'`
  — l'enregistrement restait affiché `running` indéfiniment malgré la
  notification déjà partie. Corrigé en miroir du correctif équivalent déjà
  appliqué à `generate_final_report_endpoint` (voir plus haut). Même
  correctif appliqué à l'échec de `_run_bg_analysis` (`/analyze/async`,
  `routes/analyze.py`) : cette voie n'avait **aucune** gestion d'échec — ni
  changement de statut, ni email (`analyze_failed`, déjà présent dans
  `_ERROR_LABELS` mais jamais appelé) — désormais alignée sur le même
  patron (`status='failed'` + `send_error_notification`, `current_step`
  laissé sur `analyzing_ai` pour indiquer où ça a échoué).
- Validé par appels directs à l'API (bypass du rate-limit partagé n8n, déjà
  documenté) : `scanning_osint` confirmé pendant un scan réel (216s sur
  `example.com`, 3106 sous-domaines), transition immédiate vers
  `analyzing_ai` dès l'acceptation de `/analyze/async` (avant même le
  premier appel LLM) — conforme à l'implémentation.

Blueprints (`routes/__init__.py`, **11 exactement**), accès et rate limits
déclarés. Accès : **public** = sans compte ; **admin** = Basic Auth
(`require_auth`) ; **service|admin** = jeton de service de n8n OU admin
(`require_service_or_auth`) ; **session** = jeton de session obtenu avec le
code d'accès.

| Route | Fichier | Accès | Limite |
|---|---|---|---|
| `GET /` (catalogue public) | `welcome.py` | public | — |
| `POST /auth/login` | `auth.py` | public | 10/min |
| `POST /recon` | `crud.py` | public (+ Turnstile) | 20/h |
| `POST /verify_email` | `crud.py` | public | 10/h |
| `GET /recon`, `GET/PUT/DELETE /recon/<id>`, `PATCH /recon/<id>/result`, `GET /recon/<id>/report` | `crud.py` | admin | — |
| `GET /logs`, `GET /logs/stats` | `logs.py` | admin | — |
| `POST /pass_recon` | `recon.py` | service\|admin | 30/h |
| `POST /analyze`, `POST /analyze/async` | `analyze.py` | service\|admin | 5/h |
| `GET /analyze/status` | `analyze.py` | admin | — |
| `GET\|POST /analyze/wait/<id>` | `analyze.py` | service\|admin | 60/min |
| `POST /recon/<id>/generate_final_report` | `report.py` | service\|admin | 20/h |
| `POST /recon/<id>/generate_report` | `report.py` | service\|admin | 10/h |
| `GET /recon/<id>/report.pdf`, `export.json`, `export.csv` | `report.py` | admin (403 si scellé) | — |
| `POST /recon/<id>/issue_access`, `POST /recon/<id>/revoke_access` | `report.py` | admin | 10/h (issue) |
| `POST /results/access` | `results.py` | public (code) | 5/min, 30/h |
| `GET /results/report` | `results.py` | session | 120/h |
| `GET /results/report.pdf`, `export.json`, `export.csv` | `results.py` | session | 60/h |
| `POST /dns_info` | `dns_info.py` | admin | — |
| `GET /cache`, `GET /cache/<id>`, `GET /cache/<id>/export.json` | `cache.py` | admin | — |
| `GET /recon/stats` | `stats.py` | admin | — |

Limites globales par défaut (`extensions.py`) : `5000/jour` + `1000/heure`
par IP. **Les requêtes porteuses du jeton de service valide sont exemptées
de toutes les limites** (`@limiter.request_filter`) : elles viennent toutes
de l'IP du conteneur n8n et épuisaient un plafond commun à tous les
utilisateurs (point S6 du plan). Le débit du pipeline reste borné en amont
par les limites de `POST /recon` et `POST /verify_email`. Le jeton de
service n'ouvre **aucune** route admin (testé).

⚠️ **Les endpoints `/crawl`, `/sublist3r`, `/crtsh`, `/sslscan`, `/holehe`,
`/netcraft_full_report` n'existent pas** (supprimés). Aucun fichier
`holehe.py` / `crawl.py` / etc. dans `routes/`. `GET /` (`welcome.py`) affiche
un catalogue **incomplet** : il ne liste ni `/analyze*`, ni `/recon/<id>/generate_*`,
ni `report.pdf`, ni les exports, ni `/recon/stats`. À corriger si on touche à
ce fichier — mais ce n'est pas la source de vérité, `routes/__init__.py` l'est.

### Pipeline OSINT — 56 outils (47 + 9 de la phase 5), entièrement parallélisé

`routes/recon.py` :
- `TOOLS_REGISTRY` contient **56 identifiants** depuis la phase 5 (47 historiques
  + `dns_mass`, `blocklists`, `threats_check`, `web_metadata`, `site_ranking`,
  `virustotal`, `dnsdumpster`, `grayhatwarfare`, `github_dorks` — voir
  `docs/phases/PHASE_5.md`), plus l'entrée `agent_pivots` (phase 8) quand la
  boucle agent tourne. Historique (47 outils) : `TOOLS_REGISTRY` et `ALL_TOOLS` contenaient **exactement 47 identifiants
  chacun, et les deux ensembles sont identiques** (compté par script, pas
  estimé). Répartis en 11 catégories : Domain Intelligence, Subdomain
  Discovery, DNS/Réseau, SSL/TLS, Email/Messagerie, Web/HTTP, Web/OSINT,
  Infrastructure/Cloud, Vulnérabilités Passives, Réputation/Threat Intel,
  OSINT Externe.
- Exécution en **deux vagues parallèles** via `utils/parallel.run_tools_parallel` :
  - **vague 1 (9 outils)** — `whois`, `rdap_info`, `dns`, `crtsh`, `subfinder`,
    `assetfinder`, `github`, `amass`, `ip_info`. Les 5 outils de découverte
    alimentent `all_subs` ; `ip_info` est ici car `shodan_internetdb` et
    `abuseipdb_check`/`abusech_check` réutilisent les IP qu'il résout.
  - **union `all_subdomains`** faite par le thread principal (aucune course).
  - **vague 2 (38 outils)** — tout le reste ; `headers` et
    `subdomain_takeover` consomment `all_subs`, les autres ne dépendent que
    du domaine. Ces deux outils ne prennent qu'un échantillon (10 et 50),
    choisi par `_prioritize_subdomains()` : les sous-domaines aux libellés
    sensibles d'abord (`_SENSITIVE_SUBDOMAIN_KEYWORDS` : admin, vpn, sso,
    jenkins, staging, dev, api…, reconnus comme libellé entier ou segment
    séparé par `-`, jamais comme sous-chaîne — `latest.` n'est pas `test`),
    puis ordre alphabétique. Sélection **déterministe** : avant le
    2026-10-19, `headers` prenait les 10 premiers par ordre alphabétique et
    `subdomain_takeover` `list(set)[:50]`, dont l'ordre change d'un processus
    à l'autre (deux scans identiques ne testaient pas les mêmes hôtes).
    `headers` marque `status: "blocked"` un sous-domaine refusé par la garde
    anti-SSRF.
  - 9 + 38 = 47.
- Réglages : `SCAN_MAX_WORKERS` (défaut `DEFAULT_MAX_WORKERS = 8`) et
  `SCAN_DEADLINE_SECONDS` (défaut 180 s).
- L'écriture dans `result` suit l'ordre des `_specs`, **pas** l'ordre
  d'achèvement des threads → sortie déterministe, donc `dataset_sha256` stable.
- Résilience : une exception d'un outil devient `status="error"` isolé (ne tue
  plus tout le scan) ; un outil bloqué devient `status="timeout"`.
- Paramètres de requête : `tools` (sous-ensemble), `force_refresh`,
  `cache_ttl_days` (borné 1-365), `recon_id`, `domain`, `email`.

Statuts possibles d'un outil : `success | error | not_installed | timeout |
timeout_partial | not_found | unreachable | skipped | no_data | limited | unavailable`.

**Les 4 outils ajoutés en dernier** (tous gratuits, dégradation propre) :

| Outil | Catégorie | Clé requise | Comportement sans clé |
|---|---|---|---|
| `shodan_internetdb` | Réputation / Threat Intel | **aucune** | fonctionne toujours (API InternetDB gratuite). Consulte les observations Shodan déjà collectées, n'envoie aucune sonde. CVE enrichies CVSS (CIRCL) + EPSS (FIRST) par `_enrich_cves`. `no_data` si l'IP est inconnue de Shodan. |
| `otx_passive_dns` | OSINT Externe | `OTX_API_KEY` **optionnelle** | requête tentée en anonyme ; `status: limited` si OTX répond 401/403, `no_data` sur 404 |
| `rdap_info` | Domain Intelligence | **aucune** | via `rdap.org` (RFC 9083) ; `status: unavailable` si le TLD n'a pas de service RDAP (404/400/501). Complète `whois`, ne le remplace pas. |
| `xposedornot_breaches` | Réputation / Threat Intel | **aucune** | remplace HIBP. ⚠️ **HIBP n'est plus utilisé du tout** : abonnement payant + vérification de propriété du domaine ⇒ 403 systématique sur un domaine tiers. XposedOrNot ne cherche pas par domaine : le code teste 5 adresses « rôle » (`admin@`, `contact@`, `info@`, `support@`, `webmaster@`). |

Autres clés optionnelles → `status: skipped` si absentes (aucune requête émise) :
`GITHUB_TOKEN` (`github`), `ABUSEIPDB_API_KEY` (`abuseipdb_check`),
`ABUSECH_AUTH_KEY` (`abusech_check`), `URLSCAN_API_KEY` (`urlscan_search`).

### Traçabilité outil → conclusion

- Le prompt d'analyse (`routes/analyze.py`) rend le champ **`source_tool`
  OBLIGATOIRE sur chaque finding** : il doit contenir la clé technique d'un
  outil présent dans `tools_executed`. `source_tools` (pluriel) liste les
  outils secondaires quand la conclusion croise plusieurs sources.
- Chaque entrée de `scan_results` porte un bloc `meta.tool` / `meta.category` /
  `meta.description` / `meta.indicators` issu de `TOOLS_REGISTRY` — c'est ce
  qui permet de résoudre `source_tool` → nom lisible + catégorie.
- Le PDF (`utils/pdf_generator.py::_build_methodology`) contient une section
  **« Méthodologie & Sources »** : inventaire des outils exécutés
  (clé `source_tool`, nom, catégorie, statut, durée), contexte du scan
  (domaine, date, cache hit, durée totale) et un bloc **« Limites de la
  collecte »** listant explicitement les outils dégradés. Chaque finding
  affiche son « Outil source ».

### Fiabilité de l'analyse — grounding_check + coverage_check

Deux contrôles PROGRAMMATIQUES (déterministes, aucun nouvel appel LLM),
additifs dans `report` sans jamais modifier un champ existant — répondent à
deux questions distinctes :

- **`grounding_check`** (`utils/grounding_check.py`, ajout externe antérieur)
  — les findings PRODUITS sont-ils ancrés dans des données réelles ? Vérifie
  par finding que `source_tool` désigne un outil réellement exécuté avec
  succès et que `evidence` chevauche (mots consécutifs) la donnée brute de
  cet outil. Ne prouve pas l'exactitude sémantique de l'interprétation,
  seulement que la preuve citée n'est pas fabriquée.
- **`coverage_check`** (`utils/coverage_check.py`, 2026-07-29) — question
  différente et complémentaire : est-ce que TOUTES les données collectées
  ont été EXAMINÉES, ou un outil avec des données exploitables a-t-il été
  silencieusement ignoré (aucun finding, aucune mention) ? Un score calculé
  uniquement à partir des findings produits est trompeur si des signaux
  réels n'ont jamais été transformés en finding — il paraît bon non pas
  parce que le domaine est sûr, mais parce qu'une partie des données n'a
  jamais été interprétée. Calcule :
  - `coverage_pct` : proportion des outils `status=success` + données non
    vides cités en `source_tool`/`source_tools` d'un finding, **ou** cités
    par leur clé entre parenthèses dans `strengths` (convention demandée au
    modèle, voir plus bas) — `tools_unreferenced` liste les angles morts.
    Un **plancher**, pas une mesure exacte (si le modèle ne suit pas la
    convention de citation dans `strengths`, un outil aux données propres
    compte à tort comme non référencé).
  - `rag_snippets_used` / `rag_snippets_available` : le prompt (instruction
    #7 de `_build_messages`) demande de **citer** la source RAG (ex: "cf.
    OWASP ASVS"), pas de la recopier — vérifié par présence du nom de la
    source dans au moins une `recommendation`, pas par chevauchement
    textuel sur le contenu (qui sous-détecterait un RAG reformulé).
  - `findings_citing_web_source` / `web_searches_performed` : proportion des
    findings citant au moins une URL (`web_sources`).
  - Wired dans `routes/analyze.py` (sync `analyze()` et async
    `_run_bg_analysis()`), juste après `grounding_check`.
- **Prompt renforcé en conséquence** (`_build_messages` instruction #2, et
  `_MAP_SYSTEM_PROMPT` d'Ollama instruction #3) : pour CHAQUE outil ayant
  retourné des données, le modèle DOIT produire soit un finding qui le cite,
  soit une entrée `strengths` citant sa clé entre parenthèses (ex: "SPF
  correctement configuré (spf_analysis)") si les données sont propres — ne
  plus jamais ignorer silencieusement un outil avec des données.
- ⚠️ **Gap comblé côté Ollama Map-Reduce** : le schéma JSON de la phase MAP
  (`_MAP_SYSTEM_PROMPT`) n'avait **aucun champ `strengths`** — seul
  `findings` existait, donc une section aux données propres (aucun
  problème) n'était **jamais mentionnée nulle part**, même pas comme bonne
  pratique. Corrigé : `strengths` ajouté au schéma MAP, `all_partial`
  (agrégat inter-sections) et la synthèse REDUCE le propagent désormais
  (`_REDUCE_SYSTEM_PROMPT` instruction #7 : « CONSOLIDER » les strengths
  déjà remontées par section, ne pas en inventer/perdre) ; le repli dégradé
  (`_reduce_degraded`, timeout de synthèse) les propage aussi. Une section
  peut désormais apparaître dans `all_partial` avec des `strengths` mais
  zéro `findings` (avant : ignorée silencieusement, condition sur
  `findings` uniquement). Testé par simulation isolée (section « email »
  sans finding mais avec une strength : confirmée présente jusque dans le
  rapport de repli dégradé).
- Affiché côté dashboard (`web/dashboard.html::renderCoverageCheck()`) dans
  la vue détail d'un rapport, juste après le résumé exécutif : pourcentage
  de couverture, extraits RAG cités, findings avec source web, et la liste
  des outils non référencés le cas échéant.

#### Bugs réels trouvés sur un rapport produit (`isoc.bj`, 2026-07-29) — corrigés

Un rapport réellement généré (fallback Ollama, `qwen3:1.7b`, `_reduce_degraded`)
a révélé plusieurs défauts de format, corrigés sans jamais réinterpréter le
contenu sémantique du LLM (voir plus bas pour ce qui RESTE une limite de
qualité du petit modèle, pas un bug) :

- ⚠️ **Durée d'analyse affichée ridiculement courte ("6.3s" pour un
  Map-Reduce qui prend réellement plusieurs minutes) — corrigé.** Cause :
  `now = datetime.utcnow()` capturé **avant** toute la cascade IA
  (potentiellement 20+ min avec le fallback Ollama), puis réutilisé tel quel
  comme `generated_at` lors de la sauvegarde — `analysis_generated_at`
  mesurait donc « début de la requête », pas « fin de l'analyse ».
  `_compute_timing()` (`routes/report.py`) en déduisait une durée quasi
  nulle. Corrigé dans `routes/analyze.py` (sync et async) : un horodatage
  **frais** (`finished_at = datetime.utcnow()`) est désormais capturé juste
  avant `set_analysis_result(...)`, séparément de `now` (conservé pour
  `analyzed_at`/`expires_at`, sans impact fonctionnel).
- ⚠️ **`category` des findings parfois égale à l'énumération ENTIÈRE du
  prompt** (ex: littéralement `"DNS|SSL|Email|Web|Infrastructure|Subdomain|
  Reputation|Cloud"` comme valeur, au lieu d'un seul choix) — fragmentait le
  tableau `security_breakdown` en fausses catégories garbage. Nouveau module
  `utils/finding_sanitizer.py::sanitize_findings()`, appelé juste avant
  `compute_security_score()` (sync et async) : si `category` n'est pas une
  valeur exacte de l'énumération, elle est **dérivée de la catégorie réelle
  de `source_tool` dans `TOOLS_REGISTRY`** (source de vérité déterministe),
  jamais du texte généré par le LLM.
- ⚠️ **`id` de finding dupliqué à l'identique** (`"DNS-001"` répété sur les 6
  findings d'un même rapport, y compris entre sections différentes) —
  renumérotés déterministiquement par le même module en cas de collision.
- ⚠️ **Références/sources gabarit non complétées présentées comme réelles**
  (`"CVE-2025-XXXX"`, `"CWE-2025"`, `"https://example.com/ssl-tls-let's-
  encrypt"`) — le modèle recopie le PATTERN d'exemple du prompt sans le
  remplacer. Détectées et retirées par le même module (marqueur `XXXX` ou
  `example.com`) plutôt que présentées comme des références vérifiables.
- ⚠️ **`strengths` dupliquées à l'identique** (5 occurrences de « SPF
  correctement configuré (spf_analysis) » dans un même rapport) — plusieurs
  sections MAP peuvent légitimement remarquer la même bonne pratique
  indépendamment, sans REDUCE pour dédupliquer. Corrigé par une déduplication
  (ordre préservé) dans `ollama_client.py`, repli `_reduce_degraded`.
- **Dashboard** : la durée totale du flux (`flow_duration_s`) n'était visible
  que dans la vue détail (modal), pas dans le tableau principal — il fallait
  ouvrir chaque ligne pour la voir. Colonne « Durée totale » ajoutée
  directement au tableau (`web/dashboard.html`).

**Limite de qualité NON corrigée, volontairement — à mesurer, pas à
patcher** : le même rapport contenait aussi des défauts purement
**sémantiques** que ce module ne corrige pas et ne devrait pas essayer de
corriger silencieusement : un finding au contenu entièrement positif
(« DNSBL propre et SPF correctement configuré ») classé en sévérité
`CRITICAL` (corrompt directement le score), une recommandation SPF qui se
contredit elle-même, du texte en anglais mélangé dans un rapport français,
un raisonnement HSTS conceptuellement confus. Ce sont des limites du petit
modèle local (`qwen3:1.7b`, choisi pour la vitesse — voir §5 « Cascade IA »)
sous forte contrainte de temps, pas des bugs de code : les corriger par
heuristique de mots-clés serait fragile et risquerait de masquer de vrais
findings. Le `grounding_check` de ce même rapport le confirme déjà de façon
déterministe : **0 finding sur 6 (0.0%) avec une preuve textuellement
vérifiée** — signal fort, déjà calculé et affiché (méthodologie du PDF,
section coverage du dashboard), qui pointe exactement vers ce que le
protocole de test de l'utilisateur (précision/rappel, taux d'hallucination
via `grounding_check`, notation par experts, reproductibilité) est conçu
pour quantifier. La suite logique n'est pas un correctif de code
supplémentaire ici, mais l'exécution de ce protocole pour caractériser
objectivement où qwen3:1.7b atteint ses limites face à un backend cloud.

#### Suite de l'audit — bugs déterministes confirmés par une analyse externe (2026-07-29)

Une relecture indépendante du rapport `isoc.bj` ci-dessus (et d'un second
run du même domaine) a confirmé et approfondi le diagnostic, en séparant
proprement ce qui relève du **code** (déterministe, à corriger) de ce qui
relève du **modèle** (qwen3:1.7b, à mesurer — voir plus haut). Tous les
points « code » ont été corrigés :

- ⚠️ **Contradiction « Headers présents » / « Headers manquants »
  affichant les MÊMES en-têtes dans les deux listes — corrigé.** Cause :
  `utils/pdf_generator.py` lisait `sec_headers['headers'].keys()` pour la
  liste des présents, mais cette clé contient une entrée pour les **9
  en-têtes analysés, présents ET absents** (chacun avec son propre champ
  `present` — voir `routes/recon.py::_security_headers`), pas seulement
  ceux réellement présents. Corrigé en filtrant sur `v.get('present')`
  avant de prendre les clés. **Précision importante** : les données
  transmises au LLM (`routes/analyze.py::_extract_signals`, `signals["web"]
  ["security_headers"]`) contenaient déjà la structure complète et correcte
  (chaque en-tête avec son `present`/`valid` réel) — ce bug n'affectait que
  l'AFFICHAGE PDF, pas ce que le LLM recevait. Le faux finding IA « HSTS
  non configuré » reste donc, lui, une hallucination du modèle sur une
  donnée d'entrée correcte, pas une conséquence de ce bug de rendu.
- ⚠️ **Compteurs de résumé à zéro (sous-domaines/technologies/services
  exposés) alors que les données existent — corrigé.** Le repli
  `_reduce_degraded` (`utils/ollama_client.py`) mettait `"attack_surface":
  {}` — vide — alors que REDUCE est l'étape censée le remplir. Nouvelle
  fonction `_build_attack_surface_from_signals()` : reconstruit ce champ
  directement depuis les signaux déterministes (nombre de sous-domaines,
  ports Shodan, stack techno, WAF/CDN détecté) au lieu du texte LLM —
  fonctionne même quand REDUCE échoue.
- ⚠️ **Durée totale du processus mathématiquement impossible (plus petite
  que la seule durée d'analyse IA) — corrigé, bug le plus profond de ce
  lot.** Cause à deux niveaux, tous deux dans `routes/recon.py::pass_recon`
  (les deux chemins, cache-hit et scan complet) :
  1. `execution_time` (censé représenter la durée TOTALE du flux) était
     positionné dès la fin du scan OSINT — sur un cache hit, quasi
     instantané (constaté : 0,5s). `routes/report.py`'s assignation finale
     est gardée par `if not recon.execution_time` : une fois cette valeur
     minuscule posée, la vraie durée totale n'était donc **plus jamais
     écrite**.
  2. Même défaut sur `end_report_date` (utilisé par `Recon.flow_duration_s()`,
     documenté comme "fin de TOUT le flux") — également positionné dès la
     fin du scan, alors que `completed_at` capture déjà cette information
     sans ambiguïté pour `scan_duration_s()`.
  Corrigé en arrêtant `pass_recon` de toucher ces deux champs : ils ne sont
  plus écrits qu'**une seule fois**, à la vraie fin du pipeline
  (`routes/report.py::generate_report`, juste après génération du PDF).
  `_compute_timing()` utilise désormais `completed_at` (prioritaire) plutôt
  que `end_report_date` pour délimiter la fin du scan dans le calcul de
  `analysis_duration_s`. Testé (scénario reproduisant exactement le bug
  signalé : cache-hit quasi instantané + analyse de 20min13s) : la durée
  totale dépasse maintenant bien la durée d'analyse, comme il se doit.
- Les corrections précédentes restent en place : catégories de finding
  dérivées de `source_tool` (jamais du texte LLM), IDs uniques, références/
  sources gabarit (`XXXX`, `example.com`) retirées, strengths dédupliquées,
  timeout REDUCE dédié plus court.
- **Non corrigé, à dessein, catégorisé « modèle » et non « code »** (confirmé
  par cette relecture indépendante) : sévérité `CRITICAL` sur un finding au
  contenu positif, texte anglais mélangé au français, explication SPF
  techniquement fausse (`~all` présenté comme laissant tout passer, alors
  que c'est un softfail — `+all` serait le mécanisme permissif, `-all` le
  durcissement réel), CVE plausibles mais non vérifiées (ex.
  `CVE-2023-12345`, sans marqueur `XXXX` donc non filtrées par le
  sanitizer actuel). Pour une évaluation d'article fiable, la recommandation
  externe est de monter au minimum à un modèle comme `qwen2.5:3b-instruct`
  pour les runs de mesure réels, et de garder `qwen3:1.7b` explicitement
  comme cas de « test de stress de fiabilité » documenté à part, plutôt que
  de corriger ces défauts sémantiques par heuristique de mots-clés (fragile,
  risquerait de masquer de vrais findings).

#### ⚠️ Découverte majeure (2026-07-29) — `source_tool` totalement absent du chemin Ollama, cause racine du 0% de grounding

En rejouant le rapport `isoc.bj` après les correctifs ci-dessus, la catégorie
de TOUS les findings restait `Infrastructure` (le repli par défaut), au lieu
d'être dérivée correctement via `source_tool`. Investigation sur les données
brutes réellement stockées (`analysis_result` en BD, pas seulement le PDF) :
**`source_tool` valait `None` pour les 6 findings, sans exception.**

Cause racine trouvée : **le schéma JSON des prompts MAP et REDUCE d'Ollama
(`_MAP_SYSTEM_PROMPT`/`_REDUCE_OUTPUT_SCHEMA`, `utils/ollama_client.py`)
NE DEMANDAIT JAMAIS le champ `source_tool`** — contrairement au prompt des
backends cloud (`_build_messages`, `routes/analyze.py`) qui le rend
explicitement obligatoire (instruction #5) avec le champ présent dans son
schéma. Le modèle ne recevait tout simplement jamais l'instruction de
produire ce champ sur le chemin Ollama : ce n'est pas un défaut du LLM, mais
un oubli dans le prompt qui l'encadre. Conséquences en cascade, toutes
dues à cette seule cause :
- `grounding_check` : 0% de findings vérifiables, puisque `source_tool`
  manquant → statut `no_source_cited` systématique.
- `finding_sanitizer.sanitize_findings()` : dérivation de catégorie
  impossible faute de clé d'outil à résoudre → repli sur `Infrastructure`
  pour 100% des findings, masquant le fait que le sanitizer fonctionne
  correctement dès qu'un `source_tool` (même approximatif) est fourni.

**Corrigé** :
- `_MAP_SYSTEM_PROMPT` : ajout de `source_tool` dans le schéma JSON
  d'exemple (avant : absent du template, donc jamais imité) + nouvelle
  instruction explicite (« un finding SANS `source_tool` est INVALIDE »).
- `_REDUCE_OUTPUT_SCHEMA` : ajout de `source_tool` (marqué OBLIGATOIRE,
  「repris du finding partiel correspondant」) + instruction #8 du prompt
  REDUCE : conserver ce champ tel quel lors de la fusion/déduplication,
  jamais le vider.
- `utils/finding_sanitizer.py` renforcé en profondeur (indépendamment du
  correctif ci-dessus, pour absorber les cas où le modèle citerait un nom
  plausible mais inexact) : `_resolve_tool_key()` tente d'abord une
  correspondance exacte contre `TOOLS_REGISTRY`, puis une correspondance par
  racine normalisée (suffixes `_check`/`_analysis`/`_info`/`_records`/
  `_lookup`/`_detection`/`_config` retirés avant comparaison) — récupère par
  exemple `dnsbl_analysis` → `dnsbl_check` (cas réellement observé : le
  modèle avait inventé « dnsbl_analysis », clé qui n'existe pas). Un
  `source_tool` totalement absent (`None`) reste, logiquement, impossible à
  récupérer par ce mécanisme — seul le correctif de prompt ci-dessus résout
  ce cas à la racine, pour les analyses futures.
- Testé : correspondance exacte, correspondance par racine normalisée
  (`dnsbl_analysis`→Reputation, `TLS_config`→SSL en dépit de la casse), et
  cas `None` (repli correct sur `Infrastructure`, aucune régression).

#### ⚠️ Bug réel signalé (2026-07-30) — score différent entre l'email et le PDF, corrigé

Constaté par l'utilisateur sur un scan réel : l'email de notification affichait
un score différent de celui du PDF pour le **même** scan. Confirmé en base sur
`recon.id=8` (isoc.bj) : `analysis_result.risk_score=72` mais
`analysis_result.security_score=60` (et `recon.security_score`, la colonne
dénormalisée, valait bien `60`). Le rapport JSON produit par le LLM contient
**deux champs de score distincts** :
- `risk_score` — brut, auto-évalué par le modèle lui-même, jamais recalculé après coup.
- `security_score` — recalculé **déterministiquement** par
  `compute_security_score()` (`utils/analysis_merger.py`), qui écrit
  `report["security_score"]` sans jamais toucher `report["risk_score"]`.

`utils/pdf_generator.py::_build_cover` et `models/recon.py::_extract_security`
(donc la colonne `recon.security_score`) préfèrent tous les deux
`security_score`, avec repli sur `risk_score` seulement si absent. Mais
`routes/report.py::generate_report` (l'appel à `send_report_email`) lisait
directement `analysis.get('risk_score', 0)` — l'inverse de cette convention,
et la seule occurrence du bug (vérifié par grep sur tout `routes/` : aucun
autre appel d'email n'utilise `risk_score`). Corrigé en appliquant le même
ordre de préférence que le PDF (`security_score` si présent, sinon
`risk_score`) juste avant l'appel à `send_report_email`. Vérifié sur le cas
réel `recon.id=8` : la nouvelle valeur calculée (`60`) correspond exactement
au PDF et à la colonne DB, alors que l'ancien code aurait envoyé `72`.

### Exports académiques (`routes/report.py`)

- `GET /recon/<id>/export.json` — bloc `provenance` (schema_version,
  `tools_requested`/`tools_detail` avec statut, durée du scan, backend IA
  utilisé, cache hit, horodatages, `data_integrity`, `methodology`), puis
  `scan_results`, `analysis_result`, `final_report`, et une chaîne `citation`
  prête à coller.
- `dataset_sha256` = SHA-256 de `scan_results` sérialisé en **JSON canonique**
  (`sort_keys=True`, séparateurs compacts) → vérifiable et reproductible.
- `data_integrity` distingue « absent » de « présent mais illisible » — un
  `scan_results` corrompu ne peut pas produire un export faussement valide.
- `GET /recon/<id>/export.csv` — une ligne par finding, colonnes **stables et
  contractuelles** : `finding_id, tool, tool_category, target, indicator,
  value, severity, confidence, source_tool, source_url, collected_at`.
  Les colonnes absentes du schéma réel (`confidence`) restent **vides** —
  aucune valeur n'est fabriquée. BOM UTF-8 pour Excel ; neutralisation de
  l'injection de formule (CWE-1236) par préfixe `'` — **le CSV est donc une
  vue, le JSON reste la référence citée par le hash**.
- **Les deux exports exigent `recon.accord`** (consentement) : sinon `403`.
- `GET /recon/stats` — KPI **agrégés en SQL sur toute la table**, sans
  pagination : `total_recons`, `pdf_generated`, `analyses_completed`,
  `in_progress`, `by_status`, `success_rate_pct`, `avg_security_score`
  (`AVG` sur la colonne dénormalisée), `scored_recons`, `unscored_analyses`,
  `avg_scan_duration_s` (`completed_at - started_at`), `avg_flow_duration_s`
  (`end_report_date - start_report_date`), `compliance` (voir ci-dessous),
  `computed_at`.
  Remplace le calcul client qui ne portait que sur la page courante.
  Note de routage : `/recon/stats` n'entre pas en conflit avec
  `/recon/<int:id>` (le convertisseur `int` ne matche pas « stats »).

### Bloc `compliance` de `GET /recon/stats` — dashboard recherche/présentation

Ajouté pour donner à l'utilisateur des métriques présentables (publication/
soutenance), au-delà des KPI opérationnels ci-dessus. Trois sous-blocs,
chacun agrégé en SQL/Python léger sur des colonnes dénormalisées dédiées
(`models/recon.py`) — **jamais** un reparsing de `scan_results`/
`analysis_result` (gros blobs `db.deferred`) :

- **`traceability`** — `routes/stats.py::_traceability_stats()`. Sur
  l'ensemble des analyses IA jamais produites, quelle proportion des findings
  cite un `source_tool` réellement présent dans `tools_executed` (le prompt
  d'analyse l'impose — ceci vérifie que c'est respecté en pratique, pas
  seulement demandé). Calculé une fois par analyse dans
  `Recon.set_compliance_metrics()` (appelé juste après `set_analysis_result()`
  dans les deux chemins sync et async de `routes/analyze.py`), stocké dans
  `findings_total_count`/`findings_traceable_count`. Le ratio global est
  `SUM(traceable)/SUM(total)` — **jamais** une moyenne de ratios par ligne
  (des analyses avec des tailles de findings très différentes fausseraient
  sinon la moyenne).
- **`mitre_coverage`** — `_mitre_coverage_stats()`. Nombre de techniques
  MITRE ATT&CK distinctes détectées sur l'ensemble des scans (`mitre_technique_ids`,
  JSON léger par ligne, pas le rapport complet), rapporté au nombre total de
  techniques connues de `utils/mitre_attack.TECHNIQUES`, plus une répartition
  par tactique (`by_tactic`) et une moyenne de techniques/scan
  (`mitre_technique_count`, colonne Integer).
- **`tools_reliability`** — `_tools_reliability_stats()`. Répartition agrégée
  des statuts (`success`/`error`/`timeout`/`skipped`/...) sur TOUTES les
  exécutions des 47 outils OSINT, tous scans confondus. Alimenté par
  `Recon.set_tools_status_summary()`, appelé dans `routes/recon.py::pass_recon`
  juste après la construction de `result` (les deux chemins : cache hit ET
  scan complet) — ne stocke qu'un résumé de quelques comptes par statut,
  jamais le blob `scan_results` complet (potentiellement des centaines de Ko
  avec le `raw_output` des 47 outils).
- **Backfill** : `migrate.py::backfill_compliance_metrics()` calcule ces
  colonnes pour les analyses produites AVANT leur ajout, en relisant
  `analysis_result`/`scan_results` une seule fois (lecture seule, aucun
  nouvel appel IA/OSINT) — idempotent, ne touche que les lignes où
  `findings_total_count` est encore `NULL`.
- **Dashboard** (`web/dashboard.html`) : nouvelle section « Conformité &
  Recherche » dans l'onglet Reconnaissances — 3 cartes KPI + 2 graphiques
  Chart.js (répartition des statuts d'outils en doughnut, techniques MITRE
  par tactique en barres). Alimentée par `renderComplianceStats()`, appelée
  depuis `loadReconStats()` (même appel réseau que les KPI existants, pas de
  requête supplémentaire).
- ⚠️ **`avg_scan_duration_s`/`avg_flow_duration_s` étaient déjà calculés par
  `/recon/stats` mais jamais affichés nulle part** (repérés en lisant
  `loadReconStats()` : la réponse était lue partiellement, ces deux champs
  silencieusement ignorés) — corrigé. Deux nouvelles cartes KPI dans le
  bandeau principal : **« Durée moy. scan OSINT »** (`completed_at -
  started_at`, collecte OSINT seule) et **« Durée moy. flux complet »**
  (`end_report_date - start_report_date`, du clic « vérifier l'email » au
  rapport terminé, attente IA incluse) — distinction déjà présente dans le
  calcul serveur (voir §5), simplement pas rendue visible côté dashboard.
  Réutilise `fmtDuration()` déjà existant (formatage `s`/`min s`).

### Accès au dashboard — URL API configurable (`DASHBOARD_API_BASE`)

`web/dashboard.html` a toujours eu un champ URL API éditable sur l'écran de
connexion (pré-rempli avec `API_BASE_DEFAULT`, codé en dur sur la prod), donc
l'accès local a toujours été possible en le retapant manuellement. Pour éviter
cette étape à chaque connexion : `DASHBOARD_API_BASE` (`.env` racine) est
injectée dans `web/config.js` (généré, jamais commité — `.gitignore`) par le
mécanisme `envsubst` intégré à l'image `nginx:alpine` officielle
(`docker-entrypoint.d/20-envsubst-on-templates.sh`), depuis le template
`web/templates/config.js.template`. Le service `web` de `docker-compose.yml`
monte ce template et fixe `NGINX_ENVSUBST_OUTPUT_DIR=/usr/share/nginx/html` ;
`config.js` est régénéré à **chaque démarrage** du conteneur (pas seulement le
premier). `dashboard.html` lit `window.RECON_IA_CONFIG.API_BASE`, avec repli
sur l'URL de prod codée en dur si `config.js` est absent ou vide (chaîne vide
→ falsy en JS). Valeur locale : `http://api.localhost` (via Caddy ; l'URL doit être
joignable par le **navigateur**, jamais un nom de service Docker comme
`http://api:8080` — piège symétrique à celui déjà documenté pour
`DOMAIN_URL_API` côté n8n).

### Cascade IA (important — la doc historique disait « parallèle », c'est faux)

`routes/analyze.py` exécute les backends **séquentiellement, en fallback** :

```
DeepSeek (slot 0) → Gemini (1) → Cerebras (2) → Groq (3) → OpenRouter (4) → Ollama local (5, map-reduce)
```

Chaque backend qui échoue transmet sa conversation (`prev_msgs`, tool results
déjà collectés) au suivant. OpenRouter est bridé à `OPENROUTER_MAX_ROUNDS`
(défaut 2) pour préserver son quota de 50 req/jour.

⚠️ **DeepSeek (slot 0) — ajouté 2026-07-30 à la demande explicite de
l'utilisateur, uniquement pour test.** Contrairement aux 4 autres backends
cloud (tous gratuits), DeepSeek est **payant à l'usage** (pas de quota
gratuit). Placé délibérément en **tête** de cascade (avant Gemini) plutôt
qu'en dernier recours cloud : Gemini réussit déjà presque systématiquement,
donc un ajout en fin de cascade ne serait quasiment jamais sollicité en
pratique — inutile pour un test. `utils/deepseek_client.py` (`DeepSeekClient`,
même interface interchangeable que `CerebrasClient`/`GroqClient`, SDK `openai`
réutilisé, `base_url=https://api.deepseek.com`). Un seul modèle dans la file
par défaut : **`deepseek-chat`** (DeepSeek-V3) — `deepseek-reasoner` (R1) est
volontairement exclu, il ne supporte pas le function calling (`tools`)
qu'exige l'architecture agentique (`web_search`) de ce projet. Actif
seulement si `DEEPSEEK_API_KEY` est renseignée (`api/.env`) — laissée vide
par défaut pour ne générer aucun coût ; retirer la clé fait retomber
immédiatement sur Gemini sans autre changement. Câblé aux mêmes endroits que
les autres backends : `analyze()` (sync), `_run_bg_analysis()` (async),
`GET /analyze/status` (slot 0), vérifications « au moins un backend
configuré » (`/analyze`, `/analyze/async`) et message d'erreur final.

⚠️ **Garde-fou double opt-in (`DEEPSEEK_CONFIRM_EXTERNAL_SHARING`)** — ajouté
à la demande explicite de l'utilisateur, préoccupé par le partage des
données OSINT du scan (domaine cible, sous-domaines, WHOIS, headers, stack
techno...) avec ce prestataire tiers **payant**, dans une juridiction
distincte des 4 autres backends cloud déjà en place. La seule présence de
`DEEPSEEK_API_KEY` dans `.env` **NE SUFFIT PAS** à activer le slot — il faut
**en plus** `DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true` (`routes/analyze.py` :
`_DEEPSEEK_ENABLED = bool(_DEEPSEEK_API_KEY) and _DEEPSEEK_CONFIRMED`, utilisé
partout à la place de la simple présence de la clé). Objectif : éviter
qu'une clé oubliée dans `.env` (après un test, ou recopiée par erreur) ne se
remette à envoyer silencieusement les données de chaque scan à ce
prestataire après un simple restart/rebuild, sans décision consciente à ce
moment précis. Si la clé est présente sans la confirmation :
- Un `logger.warning` explicite est émis **au démarrage du conteneur**
  (visible dans `docker logs api`), rappelant la variable manquante.
- `GET /analyze/status` renvoie `deepseek.configured=true` mais
  `deepseek.enabled=false` avec une note explicative — distinct du cas
  "clé absente" (`configured=false`).
- Un second avertissement est émis **à chaque scan réellement envoyé à
  DeepSeek** (`logger.warning`, sync et async), mentionnant explicitement le
  domaine et le prestataire — traçable dans les logs indépendamment de
  `used_backend`/`model_used` déjà persistés dans le rapport.
- Testé en conditions réelles (clé factice + restart complet) : avertissement
  au démarrage confirmé sans la confirmation, `enabled` bascule correctement
  `false`→`true` dès que `DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true` est ajoutée
  + redémarrage, sans autre changement de code.

⚠️ **RAG confirmé fonctionnel avec DeepSeek (backend externe payant),
vérifié en conditions réelles (2026-07-30).** Question posée : le RAG
(`utils/rag_retrieval.py`, corpus OWASP/ASVS/WSTG/MITRE/RFC dans
`rag_documents`) est-il bien utilisé aussi par ce nouveau backend, pas
seulement par les backends déjà testés auparavant ? Testé par un vrai appel
`POST /analyze` (`force_refresh=true`) sur un scan réel existant
(`recon.id=8`, isoc.bj), avec `DEEPSEEK_API_KEY` + `DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true`
renseignées — `report["_backend"] = "deepseek"` confirmé, et
`coverage_check.rag_snippets_used = 6` sur `rag_snippets_available = 6` : les
6 extraits RAG injectés dans le prompt ont bien été cités par le modèle dans
ses recommandations, comme pour les autres backends. Le câblage
(`signals["rag_context"]` → `_build_messages()` → prompt) est générique à
tous les backends OpenAI-compatibles (`_build_messages` ne distingue pas
DeepSeek des autres) — ce test confirme qu'aucune régression spécifique à
DeepSeek n'existe sur ce point.

### Tokens IA consommés — mesure de coût/usage (2026-07-30)

Chaque client (`utils/{gemini,cerebras,groq,openrouter,deepseek}_client.py`)
cumule désormais les tokens consommés sur tout l'échange (tous les tours
d'un `agentic_chat`, y compris les tentatives de reprise/réparation JSON qui
réutilisent le même client) dans `self.usage = {"prompt_tokens",
"completion_tokens", "total_tokens"}`, alimenté par `_accumulate_usage(resp)`
appelé après chaque `chat.completions.create(...)` (champ `resp.usage`,
standard OpenAI-compatible). `utils/ollama_client.py` fait de même mais lit
les compteurs natifs Ollama (`prompt_eval_count`/`eval_count`, pas de champ
`usage` façon OpenAI) directement dans `chat()` — capturés automatiquement
sur toute la phase Map-Reduce (MAP × 6 sections + REDUCE) puisque `self`
persiste sur tout l'appel.

`routes/analyze.py::_run_backend` attache `report["tokens_used"] =
dict(client.usage)` juste après avoir obtenu le rapport final (les deux
chemins : agentique normal et reprise directe) ; les slots Ollama (sync et
async) font de même avec `ol_client.usage`. Persisté par
`models/recon.py::set_analysis_result()` → `_extract_tokens()` dans trois
colonnes dénormalisées (`tokens_prompt`/`tokens_completion`/`tokens_total`,
même principe que `security_score` — éviter de reparser le blob
`analysis_result` pour un total). Migration : 3 `ADD COLUMN IF NOT EXISTS` +
backfill (les analyses antérieures à cette mesure n'ont pas `tokens_used`
dans leur JSON, donc restent `NULL` — pas de valeur inventée).

Exposé : `GET /recon`/`GET /recon/<id>` (`to_dict()`), `GET /recon/stats`
(nouveau bloc `tokens`: `total_tokens_all_time` (somme SQL), `avg_tokens_per_analysis`
(moyenne SQL, ignore les lignes `NULL`), `measured_analyses`).
Testé en conditions réelles (vrai appel DeepSeek) : `tokens_used:
{'completion_tokens': 5299, 'prompt_tokens': 28628, 'total_tokens': 33927}`
correctement propagé jusqu'aux 3 colonnes DB et jusqu'à `/recon/stats`.

⚠️ **Dashboard — allers-retours sur le niveau de détail (2026-07-30), design
final : agrégé (KPI) ET par scan (colonne de tableau).** Une première version
affichait un détail par rapport dans la modale (prompt/completion/total +
backend) ; retirée sur demande (la mesure devait rester globale, pas un
chiffre par scan) au profit d'une section KPI dédiée **« Utilisation IA
(tokens) »** (nouveau `.logs-card`, même style que « Conformité &
Recherche » juste en dessous) avec 3 cartes : **Tokens moy. / analyse**,
**Tokens cumulés (total)**, **Analyses mesurées** (rend explicite la taille
d'échantillon derrière la moyenne — sans elle, une moyenne calculée sur une
seule analyse paraîtrait aussi fiable qu'une calculée sur cent). Puis
l'utilisateur est revenu dessus : le tableau des reconnaissances (`GET
/recon`, déjà à 11 colonnes) affichait le score/durées par ligne mais pas
les tokens — nouvelle colonne **« Tokens »** ajoutée (12e colonne,
`r.tokens_total` déjà présent dans `to_dict()`, aucun appel réseau
supplémentaire par ligne ; tooltip au survol détaillant prompt/réponse ;
`—` pour les analyses antérieures à cette mesure). Les deux niveaux
coexistent donc : la colonne du tableau pour consulter un scan précis, la
section KPI pour la vue d'ensemble/coût cumulé.

⚠️ **Grille de cartes KPI — max 4 par ligne (demande explicite).**
`grid-template-columns: repeat(auto-fit, minmax(160px,1fr))` laissait la
dernière ligne s'étirer de façon inégale selon la largeur d'écran et le
nombre de cartes (particulièrement visible dès que le bandeau opérationnel
principal est passé à 8-10 cartes). Remplacé par un compte de colonnes
**fixe** : `repeat(4, 1fr)` (desktop), `repeat(2, 1fr)` sous 1100px de
large — la 5e carte et suivantes passent proprement à la ligne suivante,
quel que soit le nombre total de cartes d'une section, plutôt que de
s'étirer pour remplir l'espace restant. S'applique à tous les `.stats-grid`
de la page (bandeau KPI principal à 8 cartes → 2 lignes de 4 ; sections
« Utilisation IA (tokens) » et « Conformité & Recherche » à 3 cartes → 1
ligne de 3 + 1 emplacement vide, toujours ≤ 4 par ligne ; onglet Technique à
4 cartes → 1 ligne pleine).

### Bugs réels signalés sur un PDF produit (isoc.bj, runs 9/10, 2026-07-30) — corrigés

Rapport généré via DeepSeek (slot 0), remonté par l'utilisateur avec 3 défauts précis :

- ⚠️ **Tuiles Sous-domaines/Technologies/Services exposés/Points forts à 0
  malgré une narration citant "25 sous-domaines" et des technologies
  précises.** Cause : `report["attack_surface"]` totalement **absent**
  (`None`, pas même `{}`) du JSON produit par DeepSeek — confirmé sur les
  deux runs réels (`recon.id=9` et `10`). Même classe de bug que celui déjà
  corrigé pour le repli dégradé d'Ollama, mais jamais généralisé aux autres
  backends : rien ne garantissait que Gemini/Cerebras/Groq/OpenRouter/DeepSeek
  remplissent ce champ. Corrigé en le rendant **entièrement déterministe**
  pour tous les backends, jamais dépendant du LLM (nouveau
  `utils/attack_surface.py::build_attack_surface(signals)`, repris depuis
  l'ancien `ollama_client.py::_build_attack_surface_from_signals` — supprimé
  de `ollama_client.py`, importé depuis le module partagé) : câblé dans
  `routes/analyze.py` juste après `report["mitre_attack"]` (même principe
  déjà établi — ne jamais faire du LLM la source de vérité pour un champ
  entièrement dérivable des signaux déjà collectés), dans les deux chemins
  sync et async. `strengths` (None également sur les deux runs) normalisé à
  `[]` s'il est absent — un `None` explicite, pas une liste vide, aurait fait
  planter tout code downstream itérant dessus. Vérifié en conditions réelles
  (nouvel appel DeepSeek sur `recon.id=9`) : `attack_surface` correctement
  peuplé (`total_subdomains: 25`, `technologies: ['Apache','Ghost','WordPress','jQuery']`).
  ⚠️ **Mais `exposed_services` restait toujours vide — corrigé
  (2026-10-19).** `build_attack_surface` lisait `signals["shodan_internetdb"]`
  alors que `_extract_signals` range Shodan sous
  `signals["network"]["shodan_internetdb"]` : aucun port n'était jamais
  trouvé, sur aucun backend. Lecture corrigée (racine conservée en repli),
  testée sur la vraie chaîne scan brut → `_extract_signals` →
  `build_attack_surface` (`tests/test_attack_surface.py`, qui échoue sur
  l'ancien code).
- ⚠️ **"Durée totale" affichait "—" sur la couverture/cover du PDF malgré un
  `execution_time` correct en base (~1min37).** Cause : dans
  `routes/report.py::generate_report`, `timing = _compute_timing(recon,
  analysis)` était appelé **avant** que `end_report_date`/`execution_time` ne
  soient posés sur `recon` (ces champs n'étaient écrits qu'après la
  génération du PDF) — `_compute_timing()` lisait donc encore des valeurs
  `NULL`, et le "—" se retrouvait figé dans les octets du PDF déjà stocké
  (jamais régénéré après coup). Corrigé en posant `end_report_date`/
  `execution_time` **avant** l'appel à `_compute_timing()` — le temps de
  génération du PDF lui-même est négligeable devant la précision visée
  (secondes), le principe "figé, jamais recalculé après coup" reste
  respecté à l'identique. Vérifié par simulation isolée (reproduit exactement
  le bug signalé : `None` avant le correctif, `97.0s` après, sur les mêmes
  données) et confirmé visuellement sur un PDF régénéré (« Durée totale :
  1min 36s », « Scan OSINT : < 1s » au lieu de "—" — voir point suivant).
- ⚠️ **`_fmt_s(0.0)` affichait "—" au lieu de "0s"/"< 1s"** — `if not sec`
  confond `None` (aucune donnée) et `0.0` (une durée réellement mesurée et
  quasi instantanée, typiquement un cache hit sur `pass_recon`), `0.0` étant
  falsy en Python. Corrigé (`if sec is None` au lieu de `if not sec`) —
  affiche désormais `< 1s` pour un vrai zéro.
- ⚠️ **Valeurs affichées sous forme de repr Python brut** (`{'name':
  'TLS_AES_256_GCM_SHA384', 'protocol': 'TLS1.3', 'bits': 256}`,
  `{'selector': 'default', 'record': ...}`) au lieu d'un texte lisible —
  `str(dict)` appliqué sans formatage sur `tls_config.cipher` (Cipher suite),
  `dkim_check.found` (DKIM sélecteurs, liste de dicts) et
  `waf_detection.detected` (liste de dicts, bug latent non encore constaté en
  production mais du même type — repéré en auditant tous les
  `str(x)`/`join([str(x)...])` du fichier). Les trois corrigés pour extraire
  les champs pertinents (nom/protocole/bits pour le cipher, sélecteur +
  fournisseur + présence de clé pour DKIM, nom du WAF) plutôt que le dict
  entier. Les autres occurrences de ce pattern dans `pdf_generator.py` ont
  été vérifiées : toutes portent sur des listes de chaînes/entiers déjà
  simples (NS, SAN, CVE, IP...), pas de dict — pas de correctif nécessaire.
- ⚠️ **En-tête de section « Corrélation MITRE ATT&CK » affichait « MITRE
  ATT&CK; »** (point-virgule parasite). Cause : `_section()` passait `title`
  brut à `Paragraph()` — ReportLab traite le contenu comme du mini-XML, et un
  `&` non échappé (`ATT&CK`) est interprété comme le début d'une entité ;
  l'entité `CK` étant invalide, ReportLab l'affiche telle quelle avec le `;`
  qu'il a lui-même ajouté en tentant de la résoudre. Corrigé en passant
  `title` par `_safe()` (déjà utilisé partout ailleurs pour échapper
  `&`/`<`/`>`) — protège aussi contre tout futur titre contenant ces
  caractères, pas seulement ce cas précis.
- ⚠️ **Label "Recommandation" coupé au milieu du mot** (`Recomman` / `dation`
  sur deux lignes) dans les cartes de finding — la colonne de labels
  (`colWidths=[2.2*cm, None]`) était trop étroite pour ce mot en 7.5pt gras,
  et ReportLab n'a pas d'espace où couper proprement un mot sans espace.
  Élargie à 2.7cm.
- **Non corrigé, à dessein — variabilité de catégorie entre deux runs du
  même domaine (Email au run 9, Web au run 10) : ce n'est PAS un bug de
  catégorisation.** Vérifié sur les données brutes réelles : run 9 cite
  `dmarc_check`/`spf_check` (catégorisés `Email`, corrects), run 10 cite
  `security_headers`/un finding sans `source_tool` (catégorisés `Web`,
  corrects) — `finding_sanitizer.py` dérive déjà la catégorie de façon
  100% déterministe depuis `source_tool` → `TOOLS_REGISTRY`, aucune dérive
  constatée. La variabilité vient du fait que DeepSeek **choisit des
  problèmes différents à rapporter** d'un run à l'autre (2 findings sur un
  domaine qui en a objectivement bien plus), pas d'une mauvaise catégorisation
  du même problème. Rendre cette sélection elle-même déterministe (règles
  statiques pour certains contrôles bien identifiés — SPF/DMARC/headers —
  plutôt que laissée au LLM) serait un changement d'architecture plus large
  (remplacerait partiellement l'analyse "IA" par un moteur de règles pour ce
  sous-ensemble de contrôles) : décision à prendre explicitement avec
  l'utilisateur, pas un correctif silencieux.

`utils/analysis_merger.merge_analyses` est encore importé dans `analyze.py`
mais n'y est **plus appelé** (seul `compute_security_score` sert).

Après le calcul du score, `report["mitre_attack"]` est rempli **de façon
déterministe** (pas par le LLM) via `utils/mitre_attack.map_tools_to_techniques`,
à partir de `tools_executed`. Ce champ est aussi injecté dans `signals` avant
l'appel LLM et propagé jusqu'au rapport final et au PDF (`_build_mitre_attack`).

⚠️ **`ANALYSIS_MODEL` ne doit JAMAIS servir de nom de modèle Ollama** — corrigé
(`utils/ollama_client.py` lit désormais `OLLAMA_MODEL`, séparé). Bug vécu en
conditions réelles : les 4 backends cloud ont tous échoué le même run (Gemini
404 modèle introuvable, Cerebras 404 accès refusé au modèle pourtant listé
par sa propre API, Groq quota TPD épuisé sur 7 modèles, OpenRouter JSON final
non parsable/réparable) — et le slot 5 (Ollama local, dernier filet de
sécurité) n'a **même pas été tenté** : `ANALYSIS_MODEL=llama-3.3-70b-versatile`
(un nom de modèle Groq, cf. `api/.env`) était réutilisé tel quel comme nom de
modèle Ollama par `_DEFAULT_MODEL = os.getenv("ANALYSIS_MODEL", "qwen3:8b")`,
donc `model_loaded()` retournait toujours `False` pour un modèle qui n'existe
pas dans Ollama. Le chemin async (`_run_bg_analysis`) n'avait de surcroît
**aucun log** sur ce cas silencieux (contrairement au chemin sync qui logue
`"[ollama] Service non disponible ou modèle absent"`) — ajouté.

⚠️ **Modèles Ollama corrompus constatés sur ce poste** (`qwen3:8b`, `gemma2:2b`,
`deepseek-r1:8b` — tous avec la même signature `tensor "..." offset+size (...)
exceeds file size (...)`, tronqués à ~222-223 Mo peu importe la taille réelle
attendue) : même famille de symptôme que la base n8n tronquée trouvée plus tôt
(copie de l'environnement interrompue). Si un modèle Ollama existant se
comporte anormalement (500 sur `/api/chat` ou `/api/generate`), vérifier
`docker logs ollama` pour ce message de tenseur tronqué avant de suspecter
autre chose — `ollama rm <modèle> && ollama pull <modèle>` répare.

⚠️ **`phi3:mini` (re-téléchargé proprement, digest vérifié) N'EST PAS un
choix viable pour `OLLAMA_MODEL` malgré une réponse `/api/chat` fonctionnelle**
— deux problèmes distincts découverts en testant réellement le slot 5 de bout
en bout (pas seulement un ping) :
1. **Ne supporte pas `tools`** — Ollama renvoie `400 {"error":
   "registry.ollama.ai/library/phi3:mini does not support tools"}` sur
   *chaque* tour de la boucle agentique (`agentic_chat`), qui envoie
   systématiquement `WEB_SEARCH_TOOL`. La boucle « abandonne » proprement
   après 2 erreurs consécutives (pas de blocage), mais le fallback local perd
   alors toute capacité de recherche web.
2. **Débit de génération mesuré ≈ 2,4 tok/s** sur ce poste (CPU only, pas de
   GPU — `eval_count`/`eval_duration` de la réponse Ollama) : avec
   `num_predict` alors **figé à 4096 dans `chat()` quel que soit l'appelant**
   (bug distinct, corrigé — voir plus bas), un simple rapport de section
   dépassait largement `OLLAMA_CHAT_TIMEOUT` (300s) et échouait
   systématiquement en `Read timed out`. Avec ~15+ sections Map-Reduce
   touchées à ce rythme, une analyse complète n'aurait jamais abouti
   (plusieurs heures, findings quasi tous vides).
   → **`OLLAMA_MODEL=qwen3:1.7b`** (1,4 Go) : supporte réellement `tools`
   (vérifié par appel direct `/api/chat` avec un `tools` non vide → `200`,
   pas `400`) **et** génère à **≈20 tok/s** sur ce même poste (mesuré),
   soit ~8× plus rapide que phi3:mini — chargement à froid ~23s contre
   ~180s. Un modèle plus petit réduit aussi le risque de corruption au
   téléchargement (fenêtre d'exposition plus courte). `qwen3:8b` reste une
   meilleure option qualité si le poste cible est assez rapide.

⚠️ **`num_predict` figé à 4096 dans `OllamaClient.chat()` — corrigé.**
`OLLAMA_MAX_SECTION_TOKENS` ne bornait que les données en **entrée**
(troncature du contexte section), jamais la longueur de génération en
**sortie** : sur un modèle lent, un JSON de section qui dépasse quelques
centaines de tokens fait mécaniquement dépasser `OLLAMA_CHAT_TIMEOUT`, quel
que soit le modèle. `chat()` accepte maintenant un paramètre `num_predict`
explicite ; deux budgets dédiés — `OLLAMA_MAP_OUTPUT_TOKENS` (défaut 700,
findings d'une section) et `OLLAMA_REDUCE_OUTPUT_TOKENS` (défaut 1400,
synthèse finale) — remplacent la valeur figée. `OLLAMA_CHAT_TIMEOUT` relevé à
360s par prudence, mais la vraie correction est le plafond de sortie + le
choix d'un modèle assez rapide, pas seulement un timeout plus grand (cf. la
leçon déjà tirée sur le nœud n8n « Wait for Analysis »).

⚠️ **Bug réel signalé (2026-07-29) — un scan avec des problèmes de sécurité
réels obtenait quand même un score 100/A+ — corrigé.** Constaté sur le PDF
d'un scan réel (`idachallenge.bj`, tombé sur le fallback Ollama après
épuisement Gemini/Cerebras/Groq/OpenRouter) : `security_score=100`, `A+`,
`findings=0`, `risk_level=N/A`, alors que les données OSINT montraient
plusieurs problèmes réels (DNSSEC désactivé, DMARC/DKIM absents, grade
headers F). Cause : dans `map_reduce_agentic_chat()` (`utils/ollama_client.py`),
la phase MAP avait correctement produit 6 findings (un par section), mais
l'appel de synthèse REDUCE a expiré (`Read timed out`, cf. bug `num_predict`
ci-dessus, marge encore insuffisante pour ce modèle/cette machine) — et
l'ancien `except` de ce timeout retournait `content: "{}"`, **jetant les 6
findings déjà obtenus** sans recours. `compute_security_score()`
(`utils/analysis_merger.py`) traduit alors 0 finding en score 100 : un échec
technique de la dernière étape (pure mise en forme) devenait indiscernable
d'un scan réellement propre. Corrigé : ce `except` construit maintenant un
rapport de repli directement depuis les findings bruts de la phase MAP
(`all_partial`, non dédupliqués/non corrélés entre sections, sans
`executive_summary` narratif, avec `risk_level` dérivé de la sévérité max
présente et `_reduce_degraded: true` pour distinguer ce cas d'une synthèse
complète). Testé par simulation isolée (mock de `agentic_chat`/`chat`,
sans attendre un vrai cycle Map-Reduce de ~20 min sur ce poste) : les
findings de section survivent désormais au timeout de synthèse au lieu
d'être perdus.

⚠️ **Gemini et Cerebras : une erreur `404` (modèle renommé/déprécié/inaccessible
côté fournisseur) n'était PAS traitée comme un signal de switch de modèle —
corrigé.** `GeminiClient.chat()` et `CerebrasClient.chat()` ne routaient vers
`_switch_to_next_model()` que sur payload-trop-grand ou rate-limit/quota — un
404 générique tombait dans le `else: raise`, et `agentic_chat()` abandonnait
alors **tout le backend** après 2 erreurs consécutives sur le **même** modèle
en tête de file, sans jamais essayer les autres modèles pourtant valides de
la même liste de priorité. Constaté en conditions réelles : `_MODEL_PRIORITY`
de Gemini place `gemini-2.5-pro-preview-05-06` (déprécié par Google) en tête
même quand `GEMINI_MODEL=gemini-2.0-flash` (valide) est configuré — `
_build_model_queue()` ne place `preferred` en tête que s'il est **absent** de
`_MODEL_PRIORITY`, donc un modèle déjà présent ailleurs dans la liste ne
saute jamais devant. Résultat observé : Gemini et Cerebras étaient tous deux
neutralisés dès le premier modèle mort, forçant la cascade vers Groq/
OpenRouter/Ollama à chaque run. Ajout de `_is_model_unavailable()` (détecte
`404`/`not_found`/`does not exist`/`not supported for`) dans les deux clients
→ un modèle indisponible fait maintenant avancer la file au lieu de tuer le
backend. Le biais de `_build_model_queue()` (modèle préféré ignoré s'il est
déjà dans `_MODEL_PRIORITY`) reste présent mais est maintenant sans
conséquence pratique puisque la file entière est de toute façon parcourue.

**Test d'intégration bout en bout validé** (2026-07-28, après ces deux
correctifs) : `POST /recon` → `verify_email` → `pass_recon` (cache hit) →
`analyze/async` + `analyze/wait` (succès via OpenRouter après switch propre
Gemini→Cerebras→Groq→OpenRouter, `security_score=85`/`B+`, `mitre_attack`
peuplé) → `generate_final_report` → `generate_report` (PDF 12 pages, email
envoyé) → `GET report.pdf` → `export.json`/`export.csv` (provenance et
`data_integrity` corrects, citation générée). Chaîne complète fonctionnelle.

### Workflows n8n (`n8n/workflows/`)

- **`recon-ia-main.json`** (V3, 2026-10-19) — `Webhook` path
  `recon-ia-pipeline`, appelé **uniquement par l'API** sur le réseau interne
  (`http://n8n:5678/webhook/recon-ia-pipeline`, corps `{recon_id}`),
  authentifié par la credential *Header Auth* `X-Pipeline-Secret`
  (`N8N_WEBHOOK_SECRET`), réponse immédiate `202` (`responseMode:
  onReceived`). Puis `pass_recon` → `analyze/async` → `analyze/wait` →
  `generate_final_report` → `generate_report` (PDF + scellement + mail avec
  code, côté API). Chaque nœud lit `recon_id` dans le corps du webhook
  (`Number($('Webhook').first().json.body.recon_id)`) et appelle l'API à son
  adresse interne fixe `http://api:8080` avec la credential *Header Auth*
  `X-Service-Token` (`PIPELINE_SERVICE_TOKEN`). Plus d'étape
  `verify_email`, plus de `Respond to Webhook`, plus aucun `$env` — d'où
  `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`. L'ancien workflow (V2) recevait
  l'OTP du navigateur via un webhook public et appelait l'API avec le
  compte admin.
  Credentials provisionnées : `reconiaApiServiceTokenAutoV1`,
  `reconiaWebhookSecretAutoV1` (changer l'ID si la valeur change — voir §8,
  `import:credentials` n'est pas idempotent).
- **`rag-ingestion.json`** — `Local File Trigger` (dossier
  `/tmp/n8n-source-docs`, `usePolling: true`, `ignoreInitial: false`) →
  `Switch` (.md/.txt) → `Extract from File` → `Postgres PGVector Store`
  (table `rag_documents`) avec `Embeddings Ollama` (`nomic-embed-text:v1.5`)
  + `Recursive Character Text Splitter`. Remplace l'ancien nœud Pinecone.

---

## 6. Commandes courantes

### Lancement en une seule commande (recommandé pour un poste neuf)

```bash
./setup.sh
```

Génère `api/.env` **et** le `.env` racine avec des identifiants de DEV LOCAL
s'ils n'existent pas déjà (jamais écrasés sinon), `docker compose up -d
--build`, attend que postgres/l'API soient prêts, télécharge le modèle
Ollama local (`qwen3:1.7b`), puis affiche les URLs d'accès et les
identifiants générés. Idempotent — ré-exécutable sans danger (ne recrée que
ce qui a changé). **Ne jamais réutiliser les identifiants générés par ce
script sur un déploiement exposé publiquement** — voir §7-8 pour le
durcissement production (`ADMIN_PASSWORD`, `SECRET_KEY`, clés IA réelles...).

### Docker (mode manuel — si `.env` déjà présents ou besoin de contrôle fin)

```bash
cp api/.env.example api/.env      # puis compléter (voir §7)
# créer aussi le .env RACINE (interpolation ${VAR} du compose) — voir §7
docker compose up -d
docker compose ps
docker compose logs -f api

docker exec api python migrate.py            # migrations (aussi jouées par entrypoint.sh)
docker compose up -d --build api             # rebuild après changement de requirements/Dockerfile
docker restart api                           # suffit après un simple changement de code (volume monté)
```

### Hash du mot de passe admin

```bash
echo "MonMotDePasse" | docker exec -i api python3 generate_password_hash.py
# ou
docker exec api python3 -c \
  "from werkzeug.security import generate_password_hash; print(generate_password_hash('MonMotDePasse'))"
```

### Tests

```bash
./scripts/run-tests.sh                       # RECOMMANDÉ : conteneur jetable, sans réseau, sans la stack
./scripts/run-tests.sh -m security           # tests de sécurité seuls (SSRF, accès…)
./scripts/run-tests.sh -m integration        # tests de bout en bout sur les routes Flask
REBUILD=1 ./scripts/run-tests.sh             # après un changement de requirements.txt
./scripts/e2e/run-result-page.sh             # page « Voir le résultat » dans Chrome headless (27 vérifications)
# Sur la stack démarrée (./setup.sh) — voir l'en-tête de chaque script pour les prérequis
ADMIN_AUTH='email:motdepasse' ./scripts/e2e/run-full-flow.sh   # parcours complet réel (15 vérifications, ~15 min avec Ollama)
SITE=http://localhost API_PUBLIC=http://api.localhost ADMIN_EMAIL=… ADMIN_PASSWORD=…   node scripts/e2e/dashboard.mjs <dossier> <chrome>               # dashboard admin (15 vérifications)
docker exec -it api python3 -m pytest        # alternative dans le conteneur api
cd api && python3 -m pytest                  # pytest.ini : testpaths=tests, -v --tb=short
python3 -m pytest tests/test_export_stats.py
python3 -m pytest --cov=. --cov-report=term-missing
```

`scripts/run-tests.sh` construit au besoin l'image `recon-ia-api-test`
(`api/Dockerfile.test`, dépendances seules, code monté en volume) et lance
pytest avec `--network none` : un test qui oublierait de simuler le réseau
échoue au lieu de dépendre d'Internet. Marqueurs déclarés dans `pytest.ini` :
`security` et `integration` (un test non marqué est un test unitaire). État
au 2026-10-19 (après les phases 3 à 8) : **946 tests pytest verts, 11 ignorés**
(305 `security`, 113 `integration`), et 27
vérifications navigateur vertes (`scripts/e2e/run-result-page.sh` : API réelle
avec un dossier scellé contenant du HTML piégé, Chrome headless piloté par le
protocole DevTools, sans dépendance npm — Node ≥ 22). Ce test a trouvé des
défauts invisibles à pytest : le relancer après toute modification de
`web/result.*`.
Deux tests navigateur supplémentaires tournent sur la **stack réelle** :
`scripts/e2e/run-full-flow.sh` (`full_flow.mjs` : formulaire + Turnstile → OTP
lu dans Mailpit → pipeline n8n → mail avec code → `result.html` → PDF ;
démarre Mailpit sur le réseau de la stack, nécessite `SMTP_SERVER=mailpit` /
`SMTP_PORT=1025` dans `api/.env` et les clés de test Turnstile) et
`scripts/e2e/dashboard.mjs` (connexion admin, cadenas, coffre, scan brut,
onglet cache, aucune durée négative). Ils ont révélé 6 défauts au premier
déploiement réel (voir §8).

`config.py` détecte pytest (`sys.modules`, `PYTEST_CURRENT_TEST`, `TESTING`) et
passe alors `load_dotenv(override=False)` : les valeurs posées par
`tests/conftest.py` (notamment `DATABASE_URL=sqlite:///:memory:`) ne sont plus
écrasées par `api/.env`. La suite tourne donc hors Docker — mais elle reste
sensible aux variables déjà présentes dans le shell, l'exécution dans le
conteneur est la plus sûre.

### Diagnostic

```bash
docker exec api python test_smtp.py destinataire@example.com   # test SMTP
curl -u "$ADMIN_EMAIL:$PASS" http://localhost:8080/analyze/status
curl -u "$ADMIN_EMAIL:$PASS" http://localhost:8080/recon/stats
curl http://localhost:8080/                                    # catalogue public
open http://localhost:8080/apidocs                             # Swagger
docker compose logs api | grep '\[parallel\]'                  # gain de la parallélisation
```

### n8n (workflows versionnés, provisioning automatique)

```bash
docker compose up -d --build n8n        # rebuild après modif de n8n/Dockerfile ou provision-and-start.sh
docker exec -u node n8n n8n list:workflow
docker exec -u node n8n n8n import:workflow --input=/workflows/recon-ia-main.json
docker exec -u node n8n n8n update:workflow --id=<id> --active=true   # restart du conteneur requis pour effet
docker logs n8n | grep -i provision     # logs du provisioning au dernier démarrage
```

Modifier `n8n/workflows/*.json` à la main = édition directe du JSON exporté
(pas d'UI) : redémarrer le conteneur `n8n` pour que `provision-and-start.sh`
réimporte automatiquement la version modifiée.

### TLS / certificats (Caddy, automatique)

Dans le `.env` racine : `SITE_ADDRESS=recon.mondomaine.tld`,
`API_ADDRESS=api.mondomaine.tld`, `ACME_EMAIL=...`, `DASHBOARD_API_BASE=https://api.mondomaine.tld`,
`RESULTS_PAGE_URL=https://recon.mondomaine.tld/result.html`, et
`CORS_ORIGINS=https://recon.mondomaine.tld` dans `api/.env`. Les deux noms
doivent pointer vers le serveur (ports 80/443 ouverts) : Caddy obtient et
renouvelle les certificats seul.

```bash
docker compose up -d caddy           # (re)charge caddy/Caddyfile
docker compose logs -f caddy         # émission / renouvellement des certificats
ssh -L 5678:127.0.0.1:5678 serveur   # éditeur n8n, puis http://localhost:5678
```

---

## 7. Variables d'environnement

⚠️ **Deux fichiers `.env` distincts, à ne pas confondre :**

| Fichier | Rôle | Atteint les conteneurs ? |
|---|---|---|
| `api/.env` | réglages propres à l'API. `env_file:` des services **`api` et `postgres`**, et relu en Python par `config.py`/`migrate.py` | **oui** |
| `.env` (racine) | interpolation `${VAR}` de `docker-compose.yml` **et** seule source des secrets partagés API ↔ n8n, que le compose injecte explicitement dans chaque service | **oui, via `environment:`** |

**Secrets partagés (2026-10-19) — uniquement dans le `.env` racine**, générés
par `setup.sh` (`ensure_root_var` les ajoute aussi à une installation
existante) : `PIPELINE_SERVICE_TOKEN` (API + n8n), `N8N_WEBHOOK_SECRET`
(API + n8n), `RESULTS_ACCESS_SECRET` (API), `N8N_ENCRYPTION_KEY` (n8n),
`APP_DB_PASSWORD` (API) et `RAG_DB_PASSWORD` (API pour `migrate.py` + n8n). Ne
jamais les recopier dans `api/.env` : `config.py` (`load_dotenv(override=True)`)
donnerait priorité à cette seconde copie, qui finirait par diverger de celle
que reçoit n8n. `ADMIN_PASSWORD_PLAIN` et `DOMAIN_URL_API` ne servent plus
(n8n a son jeton et appelle `http://api:8080`) ; `setup.sh` le signale s'ils
traînent encore.

Le `.env` racine doit aussi contenir `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`POSTGRES_DB` (healthcheck et credential Postgres du workflow RAG) — sinon
Compose substitue une chaîne vide et émet « variable is not set ».

Le service **`n8n` n'a pas `env_file: ./api/.env`** : seules les variables
réellement utilisées lui sont injectées (`PIPELINE_SERVICE_TOKEN`,
`N8N_WEBHOOK_SECRET`, `N8N_ENCRYPTION_KEY`, `POSTGRES_*`, `NODES_EXCLUDE`, …),
et `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` empêche tout Code node de les lire.

**Obligatoires** (l'API refuse de démarrer sinon — `config.py` lève `ValueError`) :
`ADMIN_EMAIL`, `ADMIN_PASSWORD` (hash werkzeug), et `POSTGRES_USER` + `POSTGRES_DB`
si `DATABASE_URL` n'est pas fourni. **Requis en pratique** pour le flux
utilisateur : `RESULTS_ACCESS_SECRET` (sans lui, aucun code d'accès n'est
émis), `PIPELINE_SERVICE_TOKEN` + `N8N_WEBHOOK_SECRET` (sans eux, la
vérification de l'email ne lance rien), SMTP.

⚠️ **`ADMIN_PASSWORD` (et toute valeur contenant un `$` littéral, ex. hash
werkzeug `pbkdf2:sha256:…$xxx$yyy` / `scrypt:…$xxx$yyy`) : NE JAMAIS doubler
le `$` en `$$` dans `api/.env`, malgré ce que suggère le warning Compose.**
Piège à deux étages :
1. `docker-compose.yml` charge `api/.env` via `env_file:`, qui interpole les
   `$` comme des références de variable — `docker exec api printenv
   ADMIN_PASSWORD` montre alors un hash tronqué et Compose émet un warning.
2. **Mais `config.py` appelle `load_dotenv(..., override=True)` à l'import**,
   qui RELIT le même fichier en Python (`python-dotenv`, qui n'interpole PAS
   les `$`) et **écrase** la valeur injectée par Docker. C'est donc TOUJOURS
   le contenu brut du fichier qui finit dans `os.environ`.

Avec `$` simple : la valeur Docker est tronquée (inoffensif, écrasée juste
après) et la valeur finale est correcte. Avec `$$` : `load_dotenv` recopie deux
`$` littéraux, le hash ne correspond plus à rien, **authentification cassée
silencieusement** (`printenv` ne le révèle pas). **Garder les `$` non doublés.**

| Groupe | Variables |
|---|---|
| DB | `DATABASE_URL`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` (compte propriétaire : migrations) ; `APP_DB_PASSWORD` (.env racine, rôle d'exécution `recon_app`, prioritaire à l'exécution), `RAG_DB_PASSWORD` (.env racine, rôle `rag_writer` de n8n) |
| Rate limiting | `REDIS_URL` (déf. `redis://redis:6379/0`) — stockage partagé Flask-Limiter ; absent ⇒ repli `memory://` avec avertissement au démarrage |
| Serveur | `GUNICORN_WORKERS` (2), `GUNICORN_THREADS` (4), `GUNICORN_TIMEOUT` (300), `TRUSTED_PROXY_COUNT` (forcé à 1 par le compose : Caddy — nombre EXACT de proxys de confiance ; le surévaluer permet d'usurper une IP via `X-Forwarded-For`) |
| Admin / Flask | `ADMIN_EMAIL`, `ADMIN_PASSWORD` (hash, `$` **non** doublés), `SECRET_KEY` (≥32 car.), `CORS_ORIGINS` (en production : l'origine exacte de `SITE_ADDRESS`), `FLASK_ENV`, `FLASK_DEBUG`, `FLASK_HOST`, `FLASK_PORT`, `LOG_LEVEL` |
| SMTP / OTP | `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM`, `ADMIN_NOTIFICATION_EMAIL`, `OTP_TTL_SECONDS` (600), `OTP_MAX_ATTEMPTS` (5) |
| Flux & sécurité (`.env` racine) | `PIPELINE_SERVICE_TOKEN`, `N8N_WEBHOOK_SECRET`, `N8N_PIPELINE_WEBHOOK_URL` (déf. `http://n8n:5678/webhook/recon-ia-pipeline`), `N8N_ENCRYPTION_KEY`, `TURNSTILE_SITE_KEY` (publique, page web), `TURNSTILE_SECRET_KEY` (API ; vide = captcha désactivé, dev uniquement) |
| Coffre des résultats | `RESULTS_ACCESS_SECRET` (`.env` racine, ≥32 car., stable), `RESULTS_PAGE_URL` (`.env` racine, lien du mail), `RESULTS_ACCESS_TTL_DAYS` (30), `RESULTS_SESSION_TTL_SECONDS` (3600) |
| Conservation (purge RGPD) | `RETENTION_INTERVAL_S` (3600), `RESULTS_PURGE_GRACE_DAYS` (7), `UNVERIFIED_RETENTION_DAYS` (7), `AUDIT_RETENTION_DAYS` (90) |
| Proxy et images (`.env` racine) | `SITE_ADDRESS` (déf. `http://localhost`), `API_ADDRESS` (déf. `http://api.localhost`), `ACME_EMAIL`, `CADDY_HTTP_PORT` (80), `CADDY_HTTPS_PORT` (443), `N8N_IMAGE` (déf. `docker.n8n.io/n8nio/n8n` ; `n8nio/n8n` si le registre officiel répond 429) |
| Scan OSINT | `SCAN_MAX_WORKERS` (8), `SCAN_DEADLINE_SECONDS` (180) |
| IA — DeepSeek | `DEEPSEEK_API_KEY` (payant, vide par défaut — slot 0, test uniquement), `DEEPSEEK_MODEL` (déf. `deepseek-chat`), `DEEPSEEK_MAX_TOOL_RESULT_CHARS`, `DEEPSEEK_MAX_TOOL_CALLS_PER_ROUND`, `DEEPSEEK_TPM_SLEEP` |
| IA — Gemini | `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_MAX_TOOL_CALLS_PER_ROUND`, `GEMINI_MAX_TOOL_RESULT_CHARS`, `GEMINI_TPM_SLEEP` |
| IA — Cerebras | `CEREBRAS_API_KEY`, `CEREBRAS_MODEL`, `CEREBRAS_MAX_TOOL_*`, `CEREBRAS_TPM_SLEEP` |
| IA — Groq | `GROQ_API_KEY`, `ANALYSIS_MODEL`, `GROQ_FALLBACK_MODELS`, `GROQ_MAX_TOOL_*`, `GROQ_TPM_SLEEP` |
| IA — OpenRouter | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `OPENROUTER_FALLBACK_MODELS`, `OPENROUTER_MAX_ROUNDS` (2), `OPENROUTER_MAX_429_BEFORE_SWITCH`, `OPENROUTER_RATE_LIMIT_SLEEP`, `OPENROUTER_MAX_TOOL_RESULT_CHARS` |
| IA — Ollama | `OLLAMA_URL` (déf. `http://ollama:11434`), `OLLAMA_MODEL` (déf. **`qwen3:1.7b`** — **jamais** `ANALYSIS_MODEL`, qui est un nom de modèle Groq ; voir §5 « Cascade IA » pour pourquoi `phi3:mini` a été écarté), `OLLAMA_CHAT_TIMEOUT` (déf. 360), `OLLAMA_MAP_ROUNDS`, `OLLAMA_MAX_SECTION_TOKENS` (entrée), `OLLAMA_MAP_OUTPUT_TOKENS` (déf. 700, sortie section MAP), `OLLAMA_REDUCE_OUTPUT_TOKENS` (déf. 1400, sortie synthèse REDUCE) |
| Analyse (commun) | `ANALYSIS_LANG` (`fr`), `ANALYSIS_MAX_SEARCH_ROUNDS` (6), `ANALYSIS_BACKEND_TIMEOUT` (480), `ANALYSIS_CACHE_TTL_HOURS` (168), `FINAL_REPORT_MAX_SCAN_CHARS`, `FINAL_REPORT_MAX_ANALYSIS_CHARS` |
| RAG (retrieval, `utils/rag_retrieval.py`) | `RAG_TOP_K` (déf. 6, nombre d'extraits injectés dans le prompt d'analyse), `RAG_EMBED_TIMEOUT` (déf. 30s) |
| Pages web (`.env` racine) | `DASHBOARD_API_BASE` — URL API que le **navigateur** utilise depuis `index.html`, `result.html` et `dashboard.html` (injectée dans `web/config.js` au démarrage du conteneur `web`) ; jamais un nom de service Docker |
| OSINT (toutes optionnelles) | `GITHUB_TOKEN`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSECH_AUTH_KEY`, `URLSCAN_API_KEY`, `TAVILY_API_KEY` |

`.env` (donc `api/.env` **et** le `.env` racine) est couvert par `.gitignore`
(règle `.env`, sans ancrage → tous niveaux).

---

## 8. Points d'attention / dette technique

À signaler ou traiter **sur demande explicite** — ne rien supprimer d'office.

### Audit des 47 outils OSINT (2026-07-29) — clés manquantes, outils cassés, couverture

Question posée : les outils requérant une clé API et ceux qui ne fonctionnent
plus sont-ils correctement identifiés, et le champ d'une reconnaissance
passive complète est-il couvert ?

**5 outils gated par une clé API — toutes les 5 actuellement non configurées**
(`api/.env` : valeurs vides) :
- `github` (`GITHUB_TOKEN`) — `status: skipped` sans clé, aucune donnée
- `abuseipdb_check` (`ABUSEIPDB_API_KEY`) — idem
- `abusech_check` (`ABUSECH_AUTH_KEY`) — idem
- `urlscan_search` (`URLSCAN_API_KEY`) — idem
- `otx_passive_dns` (`OTX_API_KEY`, optionnelle) — fonctionne en anonyme mais
  déjà constaté `status: error` (HTTP 429) même sans charge particulière —
  quasi inutilisable sans clé en pratique.

Toutes gratuites à obtenir (comptes développeur gratuits) — aucune n'a été
enregistrée sur ce poste, à faire sur demande explicite si souhaité.

**Outils cassés indépendamment de toute clé, constatés en conditions
réelles** (voir aussi §« Budget de temps partagé du scan » plus bas pour
`typosquatting`/`gau_urls`, déjà documentés) :
- ⚠️ **`asn_info` — CORRIGÉ (2026-07-29).** `api.bgpview.io` ne répondait
  plus (`NameResolutionError`). Recherché et confirmé : **bgpview.io a fermé
  définitivement le 26 novembre 2025** (la page d'accueil du site pointe
  désormais vers bgp.tools comme alternative) — panne permanente, pas
  transitoire. Remplacé par **RIPEstat** (API officielle du RIPE NCC,
  `stat.ripe.net`) : **aucune clé requise**, pas de limite de débit pour un
  usage ponctuel (RIPE demande juste un paramètre `sourceapp` identifiant
  l'appelant). Trois appels REST simples (`prefix-overview` pour IP→ASN,
  `announced-prefixes` pour les préfixes CIDR) remplacent les deux anciens
  appels bgpview — testé en conditions réelles sur `cloudflare.com` :
  `status: success`, ASN + 5287 préfixes détectés (plafonnés à 100 dans la
  sortie, `prefix_list_truncated: true`).
- `crtsh` — 404/timeout fréquents (service communautaire notoirement
  instable) ; `subfinder`/`assetfinder`/`amass` interrogent aussi CT logs en
  interne, donc la découverte de sous-domaines reste résiliente même quand
  `crtsh` échoue seul.
- `archive_history` — 503/timeout intermittents côté Wayback Machine (hors
  de notre contrôle).
- `otx_passive_dns` — voir ci-dessus (clé optionnelle mais quasi requise en
  pratique).

**Couverture face à une reconnaissance passive complète** — recherche
externe menée (sources vérifiées à jour, pas de mémoire figée) pour
identifier des lacunes réelles et des alternatives actuellement actives :

| Piste | Statut vérifié (2026-07-29) | Décision |
|---|---|---|
| **VirusTotal** (réputation domaine/IP + passive DNS) | Vivant, clé gratuite, ~4 req/min | **À ajouter** — complète Shodan InternetDB/AbuseIPDB, aucun équivalent actuel |
| **GrayHatWarfare** (buckets cloud exposés — S3/Azure/GCS) | Vivant, clé gratuite (limitée) | À ajouter, priorité basse — lacune réelle (aucun outil actuel ne couvre les buckets cloud), approche passive (index déjà crawlé, pas de brute-force actif) |
| **DNSDumpster** (sous-domaines, API officielle) | Vivant, clé gratuite (50 enregistrements/domaine) | À ajouter — complément léger à crt.sh/subfinder/assetfinder/amass |
| **GitHub secret/credential dorks** | Levier existant (`GITHUB_TOKEN` déjà prévu, jamais utilisé pour ça) | À ajouter en extension de l'outil `github` existant (mêmes clé/quota — Search API 30 req/min), pas un nouvel outil séparé |
| Censys (recherche filtrée gratuite) | **Dégradé en 2026** — plan gratuit réduit à des lookups unitaires, plus de recherche filtrée | Ne pas ajouter — n'apporte plus rien au-delà de Shodan InternetDB déjà en place |
| SecurityTrails (passive DNS gratuit) | Vivant mais 50 requêtes/**mois** seulement | Ne pas ajouter — inutilisable pour un scan automatisé (quota épuisé en 1-2 scans) |
| RapidDNS | Vivant mais **aucune API officielle** (scraping HTML uniquement) | Ne pas ajouter — incohérent avec la convention du projet (pas de scraping HTML, seulement API/CLI officiels) |
| ThreatCrowd | **Mort** (certificat expiré janvier 2025, jamais renouvelé) | Ne pas ajouter |
| Project Sonar / omnisint / Crobat | Dataset brut (dumps gzip de centaines de Go) toujours publié, mais le **wrapper de requête en direct est mort** (Rapid7 a coupé l'accès qui l'alimentait) | Ne pas ajouter — inutilisable comme outil temps réel sans miner soi-même le dataset complet |

**Conclusion couverture** : la couverture actuelle (WHOIS/RDAP, DNS complet
+ DNSSEC, 5 sources de découverte de sous-domaines, SSL/TLS + CAA/DANE, 7
vérifications email, headers/WAF/tech stack, réputation/threat intel,
historique d'archives, détection de takeover) est **déjà large et conforme
aux pratiques standard de reconnaissance passive** ; les lacunes réelles
identifiées (buckets cloud, VirusTotal, secrets GitHub) sont des ajouts
ciblés, pas des trous béants — implémentation non faite ici (nécessite
l'obtention de nouvelles clés gratuites par l'utilisateur), à faire sur
demande explicite.

### Documentation ↔ code
- ✅ **`api/.env.example` a été resynchronisé depuis** (vérifié 2026-08-29,
  audit complet du fichier) : il contient désormais **45 variables**, y
  compris toutes les clés IA (`DEEPSEEK_API_KEY`, `GEMINI_API_KEY`,
  `CEREBRAS_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`), `DATABASE_URL`,
  `LOG_LEVEL`, `FLASK_ENV`, `ADMIN_DOMAIN`, `ADMIN_NOTIFICATION_EMAIL`,
  `ANALYSIS_MODEL`, `ANALYSIS_MAX_SEARCH_ROUNDS`, `ANALYSIS_CACHE_TTL_HOURS`,
  `GROQ_FALLBACK_MODELS`, `GROQ_TPM_SLEEP`, `OPENROUTER_MODEL`,
  `OPENROUTER_FALLBACK_MODELS`, `OPENROUTER_MAX_ROUNDS`,
  `OPENROUTER_RATE_LIMIT_SLEEP`, `TAVILY_API_KEY`. L'ancien constat (25 vs 44
  variables) ne reflète plus l'état du fichier — ne pas s'y fier.
  ✅ **Complété le 2026-10-19** avec les 11 variables qui manquaient encore
  (`SCAN_MAX_WORKERS`, `SCAN_DEADLINE_SECONDS`, `TRUSTED_PROXY_COUNT`,
  `GUNICORN_WORKERS`/`_THREADS`/`_TIMEOUT`, `OTP_TTL_SECONDS`, `RAG_TOP_K`,
  `RAG_EMBED_TIMEOUT`, `OPENROUTER_MAX_429_BEFORE_SWITCH`,
  `OPENROUTER_MAX_TOOL_RESULT_CHARS`), valeurs par défaut identiques au
  code. `DASHBOARD_API_BASE` reste absente, à juste titre : elle appartient
  au `.env` **racine** (`WEBHOOK_BASE_URL` a disparu avec la phase 1).
- ✅ **La référence morte `HIBP_API_KEY` dans `config.py` a été retirée**
  (vérifié 2026-08-29 : absente de `config.py`, ne subsiste plus qu'en note
  explicative dans `api/.env.example` ligne 147 expliquant pourquoi HIBP a
  été abandonné au profit de `xposedornot_breaches` — c'est un commentaire
  documentaire, pas une variable lue par le code).
- `routes/welcome.py` (`GET /`) annonce un catalogue d'endpoints incomplet
  (voir §5).
- Le docstring de module de `routes/recon.py` annonce « 35 outils agrégés »
  alors que le registre en contient **47** (le Swagger de `/pass_recon`, lui,
  dit bien 47). Le `enum` `tools` du Swagger ne liste que 31 des 47 clés.
- `utils/parallel.py` mentionne « 35 outils » dans sa docstring.

### Tests
- `tests/conftest.py` injecte `ADMIN_DOMAIN` alors que `config.py` lit
  `ADMIN_EMAIL`. Depuis la détection pytest de `config.py`
  (`override=False`), la suite est moins fragile qu'avant, mais reste
  perméable aux variables déjà présentes dans le shell.
- Pas de CI, pas de linter/formatter configuré (ni `ruff`, ni `black`, ni
  pre-commit) ; `pytest.ini` est le seul fichier de configuration outillage.

### Infra / sécurité

✅ **Résolus le 2026-10-19 (plan d'action, phase 1)** — conservés ici pour
l'historique :
- ~~TLS non assuré (scripts nginx/certbot visant des services absents)~~ →
  Caddy, seul service publié, TLS automatique ; scripts et dossiers morts
  supprimés.
- ~~UI n8n publiée sur 5678 sans authentification, `$env` ouvert,
  `ADMIN_PASSWORD_PLAIN` lisible depuis un Code node~~ → n8n publié sur
  `127.0.0.1` seulement, `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`, plus aucun mot
  de passe admin confié à n8n (jeton de service à droits limités),
  `N8N_ENCRYPTION_KEY` fixe. **Reste à faire à chaque déploiement neuf :
  créer le compte propriétaire n8n immédiatement.**
- ~~Webhook n8n public appelé par le navigateur~~ → appelé seulement par
  l'API sur le réseau interne, protégé par `X-Pipeline-Secret`.
- ~~Limites de débit du pipeline partagées par tous les utilisateurs (IP du
  conteneur n8n)~~ → appels porteurs du jeton de service exemptés.
- ~~`OLLAMA_HOST` sur le port 11435, fautes de frappe
  `N8N_EXPRESS_TRUCT_PROXY` / doublons `N8N_RUNNERS_ENABLED`,
  `extra_hosts: host.docker.internal` inutile sur n8n~~ → nettoyés.
- ~~Brute-force OTP réparti sur plusieurs IP~~ → 5 essais par dossier.

Toujours d'actualité :
- ✅ **Rôles PostgreSQL à droits minimaux (2026-10-19, vérifiés sur la vraie
  base).** `api/migrate.py::ensure_roles()` (après les migrations, compte
  propriétaire) crée ou resynchronise à chaque démarrage :
  - `recon_app` (`APP_DB_PASSWORD`) — rôle d'exécution de l'API
    (`config.py` le préfère à `DATABASE_URL`) : DML sur `recon`, `audit_log`,
    `pass_recon_cache`, lecture seule de `rag_documents`, aucun DDL.
    Vérifié : `CREATE TABLE` → *permission denied for schema public*,
    écriture dans `rag_documents` refusée, l'API tourne bien avec ce rôle
    (`pg_stat_activity`).
  - `rag_writer` (`RAG_DB_PASSWORD`) — credential Postgres du workflow RAG
    de n8n (`reconiaPostgresRagWriterV2`) : `rag_documents` uniquement
    (+ USAGE/CREATE sur le schéma). Vérifié : lecture de `recon`,
    `audit_log`, `pass_recon_cache` refusée ; `CREATE EXTENSION IF NOT
    EXISTS vector` et `CREATE TABLE IF NOT EXISTS rag_documents` passent
    (ce que le nœud PGVector exécute) ; INSERT/TRUNCATE passent. Le droit
    CREATE sur le schéma est **indispensable** : sans lui, `CREATE TABLE IF
    NOT EXISTS` est refusé même quand la table existe (testé). n8n ne reçoit
    plus du tout le mot de passe propriétaire (`POSTGRES_PASSWORD` retiré de
    son environnement).
  Sans ces mots de passe (`.env` racine, générés par `setup.sh`), tout
  retombe sur le compte propriétaire comme avant.
- **Ne jamais monter `/var/run/docker.sock` dans le conteneur n8n** (le
  compose le documente explicitement) : cela donne un contrôle root sur l'hôte.
- `.gitignore` couvre `caddy_data/`, `caddy_config/`, `n8n_data/`, `ollama/`,
  `postgres_data/`, `n8n-backup.tar.gz`, `web/*.pdf`, `web/config.js` et `.env`.
  Vérifier malgré tout avant tout `git add -A`.
- `web/dashboard.html` transmet les identifiants admin en Basic Auth depuis le
  navigateur vers `api.idachallenge.bj` — pas de session, pas de token.
- `is_safe_domain` (anti-SSRF) résout le domaine et refuse toute IP interne,
  mais **reste vulnérable au DNS rebinding** (documenté dans le code : le nom
  est re-résolu par chaque outil au moment de la connexion). S'en prémunir
  imposerait d'épingler la connexion sur l'IP validée.

#### Audit de sécurité (2026-07-28) — nouveaux constats

En complément des points déjà listés ci-dessus (tous reconfirmés exacts lors
de cet audit) :

- ⚠️ **(Medium) Les limites de débit sur les endpoints appelés par n8n
  protègent la plateforme entière, pas un attaquant précis.**
  `extensions.py` clé Flask-Limiter sur `get_remote_address` — mais
  `/verify_email`, `/pass_recon`, `/analyze`, `/analyze/async`,
  `/generate_final_report`, `/generate_report` sont tous appelés **depuis le
  conteneur n8n** (nœuds HTTP Request de `recon-ia-main.json`), qui ne
  transmet pas l'IP du visiteur d'origine. Chaque appel n8n arrive donc avec
  la **même** IP (celle du conteneur n8n), quel que soit l'utilisateur réel à
  l'origine du scan — les limites (`/verify_email` 10/h, `/analyze` 5/h...)
  deviennent des **plafonds globaux partagés par toute la plateforme**
  plutôt que des protections par client. Quelques scans légitimes simultanés
  suffisent à bloquer (429) des utilisateurs sans rapport entre eux. Non
  corrigé (nécessiterait une clé par `recon_id`/email, changement plus
  invasif) — mais fortement atténué par le relèvement du défaut global
  ci-dessous, qui était la cause dominante en pratique.
- ⚠️ **(Medium) `POST /pass_recon` n'avait AUCUNE limite de débit dédiée —
  corrigé (2026-07-29).** Bug réel signalé : un `429 Limite de requêtes
  atteinte` apparaissait sur `pass_recon` en usage normal, sans aucun abus.
  Cause racine, plus large que `pass_recon` seul : **`GET /recon` et
  `GET /recon/stats` n'avaient eux non plus aucune limite dédiée**, et sont
  tous deux interrogés par le polling du dashboard toutes les 30s
  (`web/dashboard.html::refreshAll()`) — à eux seuls **~240 requêtes/heure**,
  déjà largement au-dessus de l'ancien défaut global (`60 per hour`). Ce
  défaut, partagé par toute route sans limite explicite, était donc épuisé
  par le trafic de routine du dashboard avant même qu'un scan ne soit lancé
  — `pass_recon` n'était qu'une victime parmi d'autres du même défaut
  sous-dimensionné pour un usage self-hosted. Confirmé en conditions
  réelles : clé Redis `LIMITS:LIMITER/<ip>/pass_recon.run_recon/60/1/hour`
  quasi épuisée sans usage anormal. Corrigé sur deux plans :
  1. `extensions.py::default_limits` relevé de `["200 per day", "60 per
     hour"]` à `["5000 per day", "1000 per hour"]` — dimensionné pour un
     usage self-hosted mono-tenant (un seul compte admin), pas pour un
     SaaS public multi-tenant. `POST /recon` (anonyme, le plus sensible)
     garde son propre plafond dédié bien plus bas (20/h), inchangé.
  2. `POST /pass_recon` reçoit désormais son propre `@limiter.limit("30 per
     hour")` (`routes/recon.py`) — indépendant du défaut global, pour que le
     trafic de routine (dashboard, listing) ne puisse plus jamais épuiser le
     budget de l'endpoint le plus coûteux de l'API (jusqu'à 47 outils en deux
     vagues, déjà mesuré à 250s+ en conditions réelles). Le verrou de
     concurrence sur le nombre de scans simultanés (limite `--workers 2
     --threads 4` gunicorn) reste un point ouvert, non traité ici.
- **(Low/Medium) `POST /dns_info` n'applique pas `is_safe_domain`** (SSRF),
  contrairement aux outils équivalents de `routes/recon.py` — seul
  `is_valid_domain` est vérifié. Impact limité (`host`/`nslookup`/`dig`/
  `dnsrecon` n'émettent que des requêtes DNS, pas de récupération de contenu
  sur l'IP résolue) mais incohérent avec le reste du code. Ajouter
  `is_safe_domain()` ici aussi par cohérence/défense en profondeur.
- **(Low) `requirements.txt` n'a aucune borne supérieure ni lockfile** — tout
  est en `>=`, donc un rebuild peut silencieusement récupérer une version
  transitively plus récente (ou retirée/compromise) sans garantie de
  reproductibilité. Envisager un lockfile (`pip-compile`/`uv pip compile`).
- **Confirmé sans nouveau problème** (vérifié explicitement, pas seulement
  supposé) : pas de bypass SSRF par encodage IP décimal/octal/IPv6 ou
  domaines type `nip.io` (`is_valid_domain` exige un TLD alphabétique, rejette
  les IP nues avant même `is_safe_domain`) ; aucun `shell=True` nulle part
  dans `api/` (hors `.venv` tiers), tous les appels `subprocess` utilisent des
  listes, `DOMAIN_REGEX` bloque tout domaine commençant par `-` (injection de
  flag) ; CSV export (neutralisation formule + consentement) et JSON export
  (hash sur JSON canonique) fonctionnent comme documenté ; pas de CORS
  wildcard + credentials (Basic Auth par en-tête, pas de cookies) ; en-têtes
  de sécurité (HSTS, CSP `default-src 'none'`, X-Frame-Options DENY,
  nosniff) tous présents et non permissifs ; pas de secret en dur dans le
  code Python, OTP généré via `secrets.choice` (CSPRNG), comparaisons via
  `hmac.compare_digest`, logs sans identifiants/OTP ; `web/dashboard.html`
  échappe systématiquement (`escHtml`) tout champ contrôlé par un outil/LLM,
  y compris le `raw_output` brut — pas de XSS stocké trouvé.
- ⚠️ **(High) SSRF par sous-domaine ou redirection — corrigé
  (2026-10-19).** Constat de l'audit du plan d'action : seul le domaine
  saisi passait par `is_safe_domain`. Un attaquant scannant son propre
  domaine pouvait publier un sous-domaine résolvant vers `169.254.169.254`
  ou une IP du réseau Docker (`_http_headers_tool` l'interrogeait en `HEAD`
  et recopiait les en-têtes dans le rapport), ou faire répondre son domaine
  par une redirection vers une adresse interne (suivie par les 5 appels
  `allow_redirects=True`). Corrigé à la source par la garde
  `_SsrfGuardedSession` (voir §4). Couvert par
  `tests/test_security_ssrf.py` (20 tests : IP littérales sensibles, noms
  Docker internes, nom public → IP interne, redirections, intégration
  `POST /pass_recon` avec sous-domaine piégé).

### Premier déploiement réel après les phases 0–2 (2026-10-19) — 3 blocages corrigés

Stack complète démarrée par `setup.sh` sur un poste Windows (Docker
Desktop), pour valider ce que les tests ne couvraient pas. Trois défauts ont
empêché le démarrage, tous corrigés à la source :

- ⚠️ **Registre `docker.n8n.io` → HTTP 429** (limite de débit) : le build de
  l'image n8n échouait. `n8n/Dockerfile` prend maintenant l'image de base en
  argument (`N8N_IMAGE`, défaut `docker.n8n.io/n8nio/n8n`) ;
  `N8N_IMAGE=n8nio/n8n` (Docker Hub, même image) dans le `.env` racine
  contourne le problème.
- ⚠️ **L'API ne démarrait pas sous Windows : `entrypoint.sh` en CRLF**
  (« set: Illegal option - »). Avec `core.autocrlf=true`, le checkout
  convertit les fins de ligne, et `api/` est monté tel quel dans le conteneur
  Linux. Nouveau **`.gitattributes`** : LF imposé pour `*.sh`, `*.py`, `*.js`,
  `*.mjs`, `*.json`, `*.yml`, `Dockerfile*`, `Caddyfile`, `*.template`. Le
  dépôt stockait déjà du LF : la conversion de la copie de travail ne crée
  aucun diff de contenu.
- ⚠️ **SQLAlchemy 2.1 installé au rebuild → « No module named 'psycopg' »**.
  `requirements.txt` n'a pas de borne haute ; SQLAlchemy 2.1 a changé le
  pilote par défaut de `postgresql://` (psycopg2 → psycopg 3), absent de
  l'image. Nouveau `api/db_url.py::with_psycopg2()` appliqué par `config.py`
  et `migrate.py` : pilote `postgresql+psycopg2://` forcé quelle que soit
  l'origine de l'URL. Testé (`tests/test_validators.py::TestDbUrl`).
  ⚠️ Rappel : sans lockfile, tout rebuild peut encore apporter une version
  incompatible (point déjà signalé plus bas).
- ⚠️ **Sans clé cloud, l'analyse IA était refusée (503) au lieu de passer à
  Ollama** — bug antérieur au plan, révélé par le premier parcours réel :
  `/analyze` et `/analyze/async` exigeaient au moins une clé cloud, alors que
  `setup.sh` et le README promettent le repli local. Le pipeline n8n
  s'arrêtait juste après le scan. Nouveau `routes/analyze.py
  ::_any_backend_available()` : une clé cloud OU Ollama joignable avec son
  modèle. Testé (`tests/test_pipeline_flow.py
  ::TestAnalysisBackendAvailability`) et vérifié en réel (`202`, Map-Reduce
  Ollama lancé).

Vérifié ensuite sur cette stack réelle : ports exposés depuis l'IP du poste
(seuls 8088/8444 de Caddy répondent ; 8080, 5678, 5432, 6379, 11434
fermés) ; provisioning n8n (4 credentials, workflow V3 actif, webhook qui
refuse toute requête sans `X-Pipeline-Secret` valide → 403) ; en-têtes
anti-iframe posés par Caddy ; SMTP réel avec STARTTLS + authentification
(Mailpit) ; widget Turnstile réel avec les clés de test Cloudflare ; rôles
PostgreSQL (voir « Infra / sécurité »). Parcours complet : voir
`scripts/e2e/full_flow.mjs` (§6).

### Stack réelle après les phases 3 à 8 (2026-10-19) — 3 défauts corrigés

Parcours complet 15/15 et dashboard 15/15 sur la stack reconstruite, puis
relecture des données produites. Trois défauts invisibles aux tests
unitaires, corrigés et couverts par `tests/test_phase_integration.py` :

- **Graphe rempli par les seuls sous-domaines** : example.com remonte ~5 000
  noms énumérés, qui épuisaient le plafond `MAX_ENTITIES_PER_SCAN` avant les
  IP, ASN et ports. Plafond séparé `MAX_ENUMERATED_SUBDOMAINS = 3000`.
- **`ssl_info` en échec « Network is unreachable »** : si la résolution A
  échouait ponctuellement, l'outil se connectait à la première IPv6
  (injoignable depuis Docker) et abandonnait. Il essaie désormais chaque
  adresse, IPv4 d'abord ; une erreur TLS n'est pas réessayée.
- **RAG toujours vide en local** : le modèle d'embeddings
  `nomic-embed-text:v1.5` n'était jamais téléchargé (`/api/embeddings` en
  404). `setup.sh` le télécharge maintenant à l'étape 5.

Constat à garder en tête : sans clé cloud (`GEMINI_API_KEY`, `GROQ_API_KEY`…
vides), toute l'analyse tombe sur `qwen3:1.7b` en CPU (~7 tokens/s, ~19 min de
pipeline, synthèse REDUCE qui dépasse `OLLAMA_REDUCE_TIMEOUT_S`). La qualité
mesurée en phase 3 suppose un backend cloud.

### Incidents réels constatés et corrigés (2026-07-28)

Deux bugs trouvés en conditions réelles (pas en audit théorique) pendant
qu'un vrai scan utilisateur restait bloqué sans aucune notification :

- ⚠️ **`POST /recon/<id>/generate_final_report` n'envoyait jamais d'email
  d'échec ni ne marquait `recon.status='failed'` — corrigé.** Constaté sur
  un scan réel (`recon_id=1`, domaine `idachallenge.bj`) : `pass_recon` et
  `analyze` avaient réussi (`security_score=60`/`D+` en base), mais
  `final_report`/`pdf_report` étaient restés `NULL` indéfiniment, `status`
  bloqué à `running`, et **aucun email** n'était jamais parti — ni succès, ni
  échec. Cause : le bloc `except Exception` de
  `generate_final_report_endpoint` (`routes/report.py`) journalisait
  l'erreur et retournait un 500, mais ne faisait **rien d'autre** — contrairement
  au bloc équivalent de `generate_report` (génération PDF, plus bas dans le
  même fichier) qui appelle bien `send_error_notification(error_type=
  "pdf_failed", ...)`. Corrigé en miroir : le bloc `except` de
  `generate_final_report_endpoint` positionne maintenant `recon.status =
  'failed'` (commit dédié, avec rollback si l'update lui-même échoue) et
  appelle `send_error_notification(error_type="final_report_failed", ...)`.
  Nouvelle entrée ajoutée à `_ERROR_LABELS` dans `utils/email_sender.py`
  (jusque-là, un `error_type` inconnu retombait silencieusement sur le
  message générique `workflow_failed` — `.get(error_type,
  _ERROR_LABELS["workflow_failed"])`).
  Note : `routes/recon.py::pass_recon` n'a **aucun** appel à
  `send_error_notification` non plus, mais ce n'est pas un oubli du même
  type — la vague parallèle (`utils/parallel.py`) isole déjà chaque échec
  d'outil en `status: "error"` par outil, si bien que l'endpoint ne lève
  quasiment jamais d'exception fatale jusqu'en haut (`scan_failed` dans
  `_ERROR_LABELS` n'est d'ailleurs appelé nulle part dans le code — vérifié
  par grep). Pas de correctif appliqué ici, le design évite déjà la panne
  catastrophique par un autre mécanisme.
  **Les deux scans réels bloqués par ce bug ont été rattrapés manuellement**
  après correctif (`POST .../generate_final_report` puis
  `.../generate_report` rejoués pour `recon_id=1` et `2`) — email envoyé,
  `status='success'` dans les deux cas.
- ⚠️ **CSP de `web/dashboard.html` bloquait la connexion à une API locale en
  HTTP — corrigé.** La balise `<meta http-equiv="Content-Security-Policy">`
  avait `connect-src 'self' https:` — n'autorisant que le même-origine ou
  du HTTPS. Avec `DASHBOARD_API_BASE=http://localhost:8080` (dev local, HTTP
  simple), le navigateur bloquait tout `fetch()` vers l'API avec l'erreur
  *"Refused to connect because it violates the Content Security Policy"*
  (observée sur `handleLogin`, mais s'appliquait à tous les appels API du
  dashboard). Corrigé en changeant `connect-src` en `'self' http: https:`.
  Vérifié : CSP servie par le conteneur `web` reflète bien le changement
  (pas de couche de cache faisant obstacle), et le flux CORS+Basic Auth vers
  l'API fonctionne indépendamment (`Access-Control-Allow-Origin` reflète
  bien l'origine `http://localhost:5000`).
- ⚠️ **`web/index.html` (formulaire public) n'avait jamais reçu le traitement
  `config.js` appliqué à `dashboard.html`, et sa propre CSP bloquait tout
  appel API** — corrigé. Constaté en creusant « je lance un scan depuis le
  frontend et rien ne se passe » : `RECON_API_URL`/`VERIFY_API_URL` étaient
  codées en dur sur les URLs de production (`api.idachallenge.bj`,
  `n8n.idachallenge.bj`), injoignables en local, et `connect-src` ne les
  autorisait de toute façon que ces deux hôtes. Corrigé en miroir du
  dashboard : URLs dérivées de `window.RECON_IA_CONFIG` (nouveau champ
  `WEBHOOK_BASE` dans `config.js.template`/`WEBHOOK_BASE_URL` en `.env`
  racine), `connect-src` élargi à `'self' http: https:`.
- ⚠️ **Bug n8n critique — `jsonBody` non quoté sur le code OTP, échoue sur
  ~10% des codes (ceux commençant par 0) — corrigé.** Repéré en simulant le
  vrai flux webhook (pas un appel direct à l'API) : `POST /recon` → OTP
  reçu (ex. `"099424"`) → `POST` vers le webhook n8n réel → `HTTP 200` mais
  `recon.verification` restait `false`. Investigation dans
  `execution_entity`/`execution_data` (SQLite n8n) : le nœud « Verify email
  for launch repporting » de `recon-ia-main.json` échouait avec
  `NodeOperationError: The value in the "JSON Body" field is not valid JSON`
  (`Unexpected number in JSON at position 13`). Cause :
  `"code": {{ $json.body.code }}` (interpolation **sans guillemets**) — pour
  un OTP commençant par `0`, produit un JSON invalide (`code: 099424` n'est
  pas un nombre JSON valide). Corrigé en quotant : `"code": "{{ $json.body.code }}"`.
  Bug présent depuis l'origine du projet, jamais détecté car les tests
  précédents utilisaient des appels directs à l'API (contournant n8n) plutôt
  que le vrai webhook. **Déploiement d'un correctif `n8n/workflows/*.json`
  nécessite un rebuild complet de l'image** (`docker compose up -d --build
  n8n`) — `provision-and-start.sh` et les workflows sont copiés à la
  construction de l'image, pas montés en volume.
- ⚠️ **Relance d'un scan sur un email déjà porteur de résultats : aucun OTP
  envoyé, aucune erreur visible — corrigé.** Voir §5 « Relance d'un scan sur
  un email déjà utilisé » pour le détail complet du correctif (colonnes
  `pending_*`, application différée à `POST /verify_email`). Testé de bout
  en bout via le vrai webhook n8n, pipeline complet rejoué avec succès.
- ⚠️ **Piège opérationnel à ne pas reproduire : une boucle `curl` de
  diagnostic laissée active entre deux tours de session a fini par
  auto-provoquer un déni de service partiel de la plateforme.** Une boucle
  `until curl ... ; do sleep 20; done` lancée pour surveiller la fraîcheur
  d'une analyse (`recon_id=3`) est restée active en arrière-plan largement
  après que sa condition de sortie a été atteinte. Comme Docker Desktop NAT
  tout le trafic venant de l'hôte derrière la **même IP interne**
  (`192.168.65.1`), cette boucle partageait le même compteur Flask-Limiter
  (`extensions.py`, 60/heure par IP par défaut) que le vrai trafic navigateur
  de l'utilisateur — épuisant le quota et provoquant des `429 Too Many
  Requests` sur les tentatives réelles de l'utilisateur au même moment.
  Recoupe le point déjà documenté plus haut sur les limites de débit
  partagées (trafic n8n → même IP pour tous les utilisateurs) : ici la cause
  était un script de diagnostic oublié, pas n8n, mais l'effet est identique.
  **Réflexe pour toute session future : toute boucle de polling `curl`/`sleep`
  lancée en arrière-plan pour un diagnostic ponctuel doit être tuée dès que
  sa condition de sortie est atteinte, jamais laissée tourner « au cas où ».**

### Scans en parallèle et fallback Ollama (`utils/ollama_lock.py`)

Question posée (2026-07-29) : peut-on lancer plusieurs scans en parallèle en
garantissant un résultat sous 30 min **chacun**, en s'appuyant sur le LLM
local (Ollama) plutôt que sur les APIs cloud ? Mesures réelles en conditions
de charge (quotas gratuits Gemini/Cerebras/Groq déjà épuisés par les tests du
jour — 2 des 3 dernières analyses tombées jusqu'au fallback Ollama) :
- Phase MAP (6 sections, `qwen3:1.7b`, CPU seul) : ~12-13 min mesurées.
- Phase REDUCE : jusqu'à `OLLAMA_CHAT_TIMEOUT` (360s) avant repli dégradé
  (voir bug `_reduce_degraded` déjà documenté plus haut).
- Total pour **une seule** analyse Ollama : ~20-25 min — déjà proche du
  plafond de 30 min à elle seule, en comptant `pass_recon` (3-5 min) +
  rapport final + PDF/email.

⚠️ **Optimisation appliquée (2026-07-29) — timeout REDUCE dédié, plus court.**
Le repli `_reduce_degraded` préserve déjà intégralement les findings/
strengths de la phase MAP (voir plus haut) — attendre les 360s complètes
de `OLLAMA_CHAT_TIMEOUT` avant d'y tomber n'apportait donc rien de plus
qu'y tomber plus tôt. Nouvelle constante `OLLAMA_REDUCE_TIMEOUT_S` (déf.
150s), passée explicitement à `self.chat(..., timeout=_REDUCE_TIMEOUT_S)`
pour l'appel REDUCE **uniquement** — les appels MAP et les autres usages de
`chat()` gardent `_CHAT_TIMEOUT` (360s) inchangé, ils ont besoin de leur
propre marge. Gain direct : ~3-4 min économisées sur le budget total d'une
analyse Ollama dégradée, sans aucune perte de contenu (mêmes findings/
strengths qu'avant, juste atteints plus vite). Vérifié par test isolé
(mock de l'appel HTTP, capture du paramètre `timeout` effectivement transmis :
150s pour REDUCE, 360s inchangé pour un appel `chat()` par défaut).

**Ollama est une instance unique, CPU seul, partagée par tout le projet**
(analyse IA slot 5 ET embeddings RAG). Sur ce matériel, deux analyses
Map-Reduce simultanées ne s'exécutent PAS réellement en parallèle : elles se
partagent le même CPU et se ralentissent mutuellement (déjà constaté par
ailleurs : un worker gunicorn OOM-killé pendant un usage concurrent
RAG+analyse — voir plus haut). Lancer plusieurs scans en parallèle qui
tombent tous sur Ollama ne les fait donc pas terminer chacun sous 30 min :
ils se mettent en file d'attente et se dégradent silencieusement les uns
les autres — le 2e scan attend le CPU du 1er, le 3e attend les deux
premiers, etc., sans qu'aucun mécanisme n'en informe l'utilisateur.

**Corrigé par un verrou distribué** plutôt que par une parallélisation
matérielle impossible sur ce poste (CPU seul, pas de GPU) : `utils/
ollama_lock.py` sérialise explicitement l'accès à Ollama pour l'analyse IA
via un verrou Redis (`redis.lock.Lock`, pas un `threading.Lock` — gunicorn
tourne en **2 processus workers séparés**, un verrou en mémoire de l'un ne
protégerait pas contre un appel concurrent de l'autre). Un scan qui doit
attendre son tour est désormais **visible comme tel** plutôt que de ramer
silencieusement : `current_step='analyzing_ai_queued'` (nouveau, affiché
dans le dashboard comme « En file d'attente (Ollama occupé) »), remis à
`analyzing_ai` dès que le verrou est effectivement acquis
(`routes/analyze.py::_run_bg_analysis`, wrapping de l'appel à
`map_reduce_agentic_chat`). TTL de sécurité du verrou (45 min, largement
au-dessus des ~25 min mesurés) pour éviter un deadlock si le processus qui
le détient meurt sans le relâcher ; délai d'attente max (60 min) au-delà
duquel une `TimeoutError` est levée et traitée comme un échec normal
(`status='failed'` + email `analyze_failed`) — couvert en plus par
`stale_scan_watchdog.py` (seuil `analyzing_ai_queued` à 70 min, filet
redondant). Dégradation : sans `REDIS_URL`, le verrou est un no-op
(cohérent avec le repli déjà en place pour le rate limiter).
- **Gap comblé au passage** : si les 5 backends IA échouaient tous
  (Gemini/Cerebras/Groq/OpenRouter/Ollama, y compris un verrou Ollama saturé
  après le délai max), `_run_bg_analysis` faisait un simple `return` sans
  jamais marquer `status='failed'` ni notifier — l'enregistrement restait
  affiché `running` indéfiniment. Corrigé en miroir des autres échecs déjà
  traités (email `analyze_failed`, `current_step` conservé tel quel).
- Testé par acquisition/attente/libération simulées (deux threads, verrou
  réel via Redis) : le second appelant attend bien la libération du premier
  avant d'acquérir à son tour, et le callback de mise en file d'attente se
  déclenche correctement.

**Réponse à la question initiale** : non, pas de façon fiable en s'appuyant
sur Ollama seul pour plusieurs scans strictement simultanés — le verrou
rend le comportement prévisible et visible (plus de dégradation silencieuse
partagée), mais ne fait pas disparaître la limite matérielle : un scan mis
en file d'attente derrière un autre dépassera mécaniquement les 30 min
depuis son propre lancement. Pour plusieurs scans **réellement** garantis
sous 30 min chacun en parallèle, il faudrait soit une clé cloud avec un
quota fiable (contourne la contention CPU locale), soit accélérer
significativement l'analyse Ollama elle-même (modèle plus rapide, réduction
du nombre de sections/tours, ou GPU) — pistes non mises en œuvre ici, une
option cloud restant la voie la plus simple si la vitesse prime sur la
confidentialité des données envoyées à un tiers.

### Filet de sécurité contre les scans silencieusement bloqués (`utils/stale_scan_watchdog.py`)

⚠️ **Bug réel signalé (2026-07-29) — un scan restait bloqué indéfiniment
(`status='running'`), sans email d'échec, sans que le dashboard ne le
signale jamais — corrigé par un filet de sécurité, pas par l'élimination de
la cause exacte (non identifiée avec certitude).** Constaté deux fois de
suite sur le même domaine (`isoc.bj`) : un `POST /pass_recon` bloqué plus
d'une heure dès la « vague 1 » (log `pass_recon — vague 1 : 9 outils…`
présent, aucune ligne suivante, alors que `SCAN_DEADLINE_SECONDS=180`
aurait dû forcer une sortie), puis — après une relance manuelle ayant cette
fois abouti (306,7s) — un `POST /analyze/async` bloqué à son tour plus de 50
minutes sans **aucune** ligne de log (pas même l'échec rapide habituel de
Gemini/Cerebras par épuisement de quota). Dans les deux cas : aucun process
`whois`/subprocess orphelin trouvé (`/proc` vérifié), d'autres requêtes sur
le même worker gunicorn continuaient de répondre normalement (`GET
/recon/<id>/report` a répondu pendant le blocage) — cohérent avec un thread
`gthread` unique bloqué sur un appel réseau dont le timeout configuré n'a
pas été respecté par la bibliothèque sous-jacente (suspecté : résolution
DNS bas niveau, non couverte par le paramètre `timeout` de `requests` dans
certains cas). **Cause exacte non confirmée** — le code de
`utils/parallel.py::run_tools_parallel` a été relu et semble correct
(`concurrent.futures.wait(timeout=...)` avec sortie de boucle si le délai
global est dépassé) ; le blocage doit donc se produire dans un appel encore
plus bas niveau, hors de la portée de ce mécanisme. À ré-investiguer avec de
meilleurs outils (`py-spy` non installé dans l'image actuelle) si le
phénomène se reproduit.

**Filet de sécurité ajouté** plutôt que d'attendre une élimination certaine
de la cause : `utils/stale_scan_watchdog.py`, thread daemon démarré par
`app.py::create_app()` (un par worker gunicorn — sans effet de bord, voir
plus bas), qui balaie `recon` toutes les 60s (`WATCHDOG_CHECK_INTERVAL_S`) et
marque `status='failed'` tout enregistrement `running` dont `current_step`
n'a pas progressé au-delà d'un seuil généreux et propre à chaque étape
(variables d'env, valeurs par défaut) :
- `scanning_osint` → 1200s (20 min ; mesuré en usage normal : 216-307s)
- `analyzing_ai` → 2400s (40 min ; fallback Ollama mesuré jusqu'à ~25 min)
- `generating_final_report` / `generating_pdf` → 600s (10 min) chacun
- `current_step` encore `NULL` alors que `status='running'` → 900s (15 min)

Dès qu'un enregistrement est marqué, un email d'échec est envoyé
(`send_error_notification`, même `_ERROR_LABELS` que les échecs explicites
— `scan_failed`/`analyze_failed`/`final_report_failed`/`pdf_failed` selon
l'étape) et `current_step` **n'est jamais réinitialisé**, donc reste visible
dans le dashboard comme point de blocage exact. Sûr en multi-worker : le
`UPDATE ... WHERE status='running' ... RETURNING` est atomique, un
enregistrement n'est donc jamais marqué/notifié deux fois même si les
copies du watchdog de chaque worker l'examinent au même instant. Désactivé
sous pytest (même détection que `config.py`).

Testé par insertion directe d'un enregistrement `running`/`generating_pdf`
avec `current_step_updated_at` artificiellement vieux de 20 min : capté au
sweep suivant (dans la minute), marqué `failed`, email `pdf_failed` envoyé —
confirmé par les logs (`docker compose logs api | grep watchdog`).

### Budget de temps partagé du scan (`SCAN_DEADLINE_SECONDS`)
`utils/parallel.py::run_tools_parallel` applique **un seul délai global**
(déf. 180 s) à **tout le lot parallèle** — pas un délai par outil. Un outil qui
dépasse largement son propre timeout grille donc le budget de tous les autres
outils encore en cours, qui remontent `status: timeout` par effet de bord.
Constaté en conditions réelles :
- `dnstwist` (`typosquatting`) sur github.com : **260 s+** avec la commande de
  base. Timeout interne réduit à **60 s** (`--threads 30`, fuzzer `dictionary`
  exclu). ⚠️ **Constaté aussi sur `idachallenge.bj`** (domaine de référence, pas
  un cas extrême) : timeout systématique, et réduire à 5 fuzzers + 50 threads
  n'a rien amélioré (230 s). Le goulot est probablement la résolution DNS dans
  cet environnement (résolveur Docker interne 127.0.0.11 en premier, cf.
  `entrypoint.sh`) — non diagnostiqué plus finement. **En l'état,
  `typosquatting` renvoie quasi toujours `status: timeout`.** À ré-évaluer sur
  le serveur de production.
- `gau` (`gau_urls`) : même symptôme — **660 s+** sur github.com, au plafond de
  **45 s** sur `idachallenge.bj`. `_run_subprocess` capture normalement les
  lignes déjà produites (`status: timeout_partial`), mais `gau` ne produit
  aucune sortie incrémentale avant d'avoir interrogé toutes ses sources.
- `_enrich_cves` (CVSS/EPSS sur les CVE de `shodan_internetdb`) : un premier
  jet avec `with ThreadPoolExecutor(...) as pool:` a mesuré **328 s** au lieu
  des ~6 s voulus — `__exit__` appelle `shutdown(wait=True)`, qui attend TOUS
  les threads malgré un `wait(timeout=6)` explicite. Corrigé :
  `shutdown(wait=False)` dans un `finally`, jamais de context manager (même
  pattern que `run_tools_parallel`). **Piège à ne pas reproduire.**
- CIRCL (`vulnerability.circl.lu`) limite à **20 requêtes/minute** — au-delà,
  403/429 silencieux, dégradation propre vers EPSS seul.
- Réflexe pour tout futur outil CLI/API ajouté à `_parallel_specs` :
  **toujours mesurer le pire cas réel** (domaine très indexé) avant de fixer un
  timeout, et rester nettement sous `SCAN_DEADLINE_SECONDS` (viser <60 s,
  idéalement <30 s).
- **Test d'intégration validé** : les 14 derniers outils ajoutés, exécutés
  ensemble via `run_tools_parallel` sur `idachallenge.bj`, terminent en
  **60,1 s au total** (borné par `typosquatting`, seul outil à plafonner) — les
  12 autres terminent tous en **moins de 5 s**.

### RAG / n8n — provisioning automatique (validé en local, un point ouvert)
- Pipeline complet (pgvector + workflows versionnés + provisioning auto)
  **testé de bout en bout en local** (2026-07-28, avant la phase 1) : build,
  migrations, import des credentials, import + activation des deux
  workflows. Depuis le 2026-10-19, les credentials du pipeline sont deux
  *Header Auth* (`X-Service-Token`, `X-Pipeline-Secret`), provisionnées
  seulement si `PIPELINE_SERVICE_TOKEN` / `N8N_WEBHOOK_SECRET` font ≥ 32
  caractères — ⚠️ ce nouveau provisioning est validé par script
  (`generate-credentials.js` exécuté hors conteneur) mais **pas encore
  rejoué sur une stack démarrée**.
- **Image `n8n/Dockerfile`** : l'image officielle `docker.n8n.io/n8nio/n8n`
  n'embarque **plus aucun gestionnaire de paquets** (image durcie). L'ancien
  `apt-get install bash whois` ne fonctionnait déjà pas et a été retiré —
  `provision-and-start.sh` n'a besoin que de `/bin/sh`. Si `whois` redevient
  nécessaire, prévoir un binaire statique copié depuis une image builder.
- `provision-and-start.sh` est **best-effort** : un échec de provisioning
  n'empêche jamais n8n de démarrer. Le fichier de credentials temporaire
  (mots de passe en clair) est supprimé après import.
- ⚠️ **`n8n import:credentials` N'EST PAS idempotent pour la VALEUR d'une
  credential existante.** Ré-importer un ID déjà présent affiche "Successfully
  imported" (aucune erreur) mais **ne met pas à jour** la valeur déchiffrée
  utilisée à l'exécution — constaté en changeant `ADMIN_PASSWORD_PLAIN` :
  l'ancien mot de passe continuait d'être envoyé, 401 côté API, **même après
  un restart complet de n8n**. Contournement dans `generate-credentials.js` :
  si une valeur de credential change, **changer aussi son ID** (ex.
  `reconiaApiBasicAuthAuto` → `...AutoV2`) pour forcer une insertion neuve.
  Seuls les WORKFLOWS (`import:workflow`) sont réellement idempotents par ID.
- *(Historique, obsolète depuis le 2026-10-19)* `DOMAIN_URL_API` devait
  pointer vers le réseau interne Docker (`http://api:8080`) : `localhost`
  depuis le conteneur n8n désignait n8n lui-même (symptôme trompeur : un
  simple 401). Les workflows utilisent désormais directement
  `http://api:8080`, la variable n'existe plus.
- **`NODES_EXCLUDE=[]` est requis** : le nœud *Local File Trigger* est
  désactivé par défaut depuis n8n 2.0 ; sans cette variable, l'activation du
  workflow RAG échoue en boucle (`Unrecognized node type`).
- `N8N_BLOCK_ENV_ACCESS_IN_NODE` vaut désormais **`true`** : plus aucun
  workflow n'utilise `$env` (vérifié par grep sur `n8n/workflows/*.json`).
  Ne pas réintroduire `$env` dans un nœud — passer par une credential.
- ✅ **CORRIGÉ (2026-07-28) — `Local File Trigger` remplacé, ingestion
  désormais automatique.** Confirmé cassé sur ce poste : sur Docker Desktop
  macOS (bind mount), ce nœud s'activait sans erreur mais ne déclenchait
  aucune exécution, ni au premier démarrage (`ignoreInitial: false`) ni sur
  ajout manuel — problème documenté de l'écosystème n8n avec les bind mounts
  Docker Desktop (issue n8n-io/n8n#17893). `usePolling: true` était déjà
  activé, sans effet observé.

  **Nouveau design de `rag-ingestion.json`** (nœuds concernés) :
  - `Local File Trigger` **supprimé**, remplacé par **`Démarrage n8n
    (auto-ingestion)`** (`n8n-nodes-base.n8nTrigger`, typeVersion 1,
    `events: ["init", "activate"]`) — déclenche une exécution à chaque
    démarrage de l'instance n8n **et** à chaque (ré)activation du workflow
    (donc à chaque redémarrage du conteneur, `provision-and-start.sh`
    réactivant systématiquement les deux workflows). Ne dépend d'aucun
    événement fichier — fonctionne sur n'importe quel système de fichiers.
  - Nouveau nœud **`Vider rag_documents`** (`n8n-nodes-base.postgres`,
    typeVersion 2.6, `resource: database` / `operation: executeQuery`,
    `TRUNCATE TABLE rag_documents;`) inséré juste après le trigger, avant la
    lecture des fichiers.
  - **`Read/Write Files from Disk`** reconfiguré : `fileSelector` n'est plus
    `{{ $json.path }}` (dépendait du payload par-fichier du trigger cassé)
    mais un glob direct **`/tmp/n8n-source-docs/**/*.md`** (le nœud utilise
    `fast-glob`/picomatch en interne — vérifié dans le code source du nœud
    installé, pas supposé) : relit et réembarque **tout** le dossier à
    chaque exécution.
  - Le reste de la chaîne (`Switch` → `Extract from File` → `Embeddings
    Ollama` + `Default Data Loader` + `Recursive Character Text Splitter` →
    `Postgres PGVector Store`) est inchangé.
  - **Compromis assumé** : un rechargement complet re-embarque l'intégralité
    du corpus à chaque (re)démarrage de n8n (pas d'incrémental par hash/mtime
    de fichier) — plusieurs dizaines de minutes sur ce poste sans GPU vu la
    taille du corpus combiné (~5 Mo). Choix délibéré : une déduplication
    incrémentale aurait ajouté une logique conditionnelle complexe dans un
    format JSON édité à l'aveugle (sans UI n8n interactive pour la tester) —
    le risque d'un bug subtil non détectable sans exécution réelle a été jugé
    supérieur au coût d'un ré-embarquement complet, qui ne se produit de
    toute façon qu'au (re)démarrage du conteneur, pas en continu.
  - **Test de validation réel effectué** (pas seulement un import sans
    erreur) : `docker restart n8n` → le trigger s'est déclenché
    automatiquement, `rag_documents` a été vidée puis réalimentée en
    conditions réelles (observé : passage de plusieurs milliers de lignes à
    0 puis re-remontée progressive), sans aucune intervention manuelle.
    Confirme que « automatique à l'initialisation » et « fonctionne si on
    ajoute du contenu » (déposer un fichier + `docker compose restart n8n`)
    sont tous deux vérifiés, pas seulement supposés corrects sur la lecture
    du JSON.
  - Le script Python ponctuel (`ingest_rag.py`, voir plus haut) qui avait
    servi à peupler `rag_documents` pendant que ce correctif était en cours
    de conception est désormais **obsolète** — n8n réingère automatiquement
    tout le corpus à chaque redémarrage, sans intervention.
- La dimension `vector(768)` suppose l'embedding **Ollama
  `nomic-embed-text:v1.5`**. Changer de modèle impose de modifier la dimension
  **et** de tout ré-embarquer (aucune migration automatique).
- `n8n_data/database.sqlite` a été vu corrompu/tronqué une fois sur ce poste
  (copie interrompue pendant une écriture WAL) — à surveiller si le conteneur
  est arrêté brutalement. `EXECUTIONS_DATA_PRUNE` limite déjà l'historique à 3 j.

#### ⚠️ Découverte majeure (2026-07-28) : le RAG était alimenté mais JAMAIS interrogé

Un audit de bout en bout a révélé que **`rag_documents` n'était lue par
aucun code, nulle part** : ni par le workflow n8n principal
(`recon-ia-main.json` — vérifié nœud par nœud, une simple chaîne d'appels
HTTP sans nœud vector store), ni par `routes/analyze.py` (le prompt d'analyse
ne s'appuyait que sur les signaux OSINT + l'outil `web_search` en temps réel).
Le RAG était donc un entrepôt mort : peupler `rag_documents` n'avait **aucun
effet** sur les rapports produits, quel que soit son contenu. Trois causes
cumulatives ont été identifiées et corrigées :

1. **Le trigger d'ingestion ne s'est jamais déclenché** sur ce poste (point
   déjà documenté ci-dessus — bind mount Docker Desktop). `rag_documents`
   était donc vide (0 ligne) avant correctif, confirmé par requête directe.
2. **Le modèle d'embedding `nomic-embed-text:v1.5` était lui-même corrompu**
   — même signature que `qwen3:8b`/`gemma2:2b`/`deepseek-r1:8b` (`tensor
   "blk.7.ffn_up.weight" offset+size (...) exceeds file size (...)`, même
   classe de symptôme qu'un téléchargement interrompu). `/api/embeddings`
   renvoyait `500` sur **tout** appel, même en supposant le trigger
   fonctionnel. Réparé par `ollama rm nomic-embed-text:v1.5 && ollama pull
   nomic-embed-text:v1.5` (274 Mo, rapide) — vérifié fonctionnel après
   (réponse `200` avec un vecteur 768-dim cohérent).
3. **Aucun code ne consommait le résultat même en supposant les deux points
   ci-dessus réglés** — c'est le point le plus important : corriger
   l'ingestion seule n'aurait servi à rien.

**Correctifs appliqués** :
- **Contournement de l'ingestion** (le trigger n8n restant cassé sur ce
  poste) : script Python ponctuel reproduisant exactement le pipeline de
  `rag-ingestion.json` (découpage 500 caractères / 50 de chevauchement,
  embeddings `nomic-embed-text:v1.5`, insertion dans `rag_documents` avec les
  mêmes colonnes `content`/`metadata`/`embedding`) — exécuté manuellement pour
  peupler la table dès maintenant. **Ce contournement ne remplace pas le
  vrai correctif** (le Local File Trigger reste cassé sur ce poste) ; sur le
  serveur de production (Linux), vérifier d'abord si le trigger fonctionne
  nativement avant de reproduire ce contournement.
- **`utils/rag_retrieval.py`** (nouveau) : `retrieve_relevant_docs(query_text,
  top_k=6)` — embed la requête (même modèle qu'à l'ingestion, cohérence
  obligatoire pour une similarité cosinus valide), recherche pgvector
  (opérateur `<=>`, index HNSW déjà créé par `migrate.py`), dégrade
  silencieusement vers `[]` si Ollama/Postgres/rag_documents indisponible —
  l'analyse IA doit pouvoir continuer sans ce contexte.
- **Câblage dans `routes/analyze.py`** : requête construite à partir des
  mêmes signaux que `search_hints` (technologies, TLS, SPF...) mais orientée
  « guidance de sécurité » ; résultat stocké dans `signals["rag_context"]`
  (même principe que `signals["mitre_attack"]`), aux **deux** points d'entrée
  (`analyze()` sync et `_run_bg_analysis()` async). Instruction dédiée dans
  `_build_messages()` : citer la source RAG dans `recommendation` quand un
  extrait s'applique, plutôt que reformuler une bonne pratique générique de
  mémoire. Câblé aussi dans le fallback Ollama Map-Reduce
  (`utils/ollama_client.py::_build_global_context()`) — mais limité aux 2
  premiers extraits tronqués à 200 caractères, car ce contexte se répète dans
  **chaque** prompt de section MAP (6×), contrairement au prompt unique des
  autres backends qui peut se permettre les 6 extraits complets.
- **Corpus RAG étendu à 6 sources** (`data/script_*.py`, tous suivent le
  même patron `github_md_aggregator.py` sauf le dernier) :
  - `combined_owasp_cheatsheets.md` (OWASP Cheat Sheet Series)
  - `combined_owasp_asvs.md` (OWASP ASVS 5.0)
  - `combined_owasp_wstg.md` (OWASP WSTG)
  - `combined_owasp_top10.md` (OWASP Top 10:2021, `script_owasp_top10.py`) —
    classification stable des **catégories** de vulnérabilité (chaque
    catégorie liste ses CWE constitutifs), complément naturel des CVE déjà
    enrichies en LIVE et par cible précise via `routes/recon.py::_enrich_cves`
    (CVSS + résumé CIRCL, exploitabilité EPSS) : la CVE live donne le « quoi,
    précisément, sur cette cible » (change chaque jour, ne se prête pas à un
    corpus statique), le Top 10 (RAG) donne le « dans quelle famille de
    risque, avec quelle remédiation générale reconnue ». Ferme aussi l'écart
    CWE/CAPEC documenté plus haut (une version précédente de ce fichier notait
    ces deux sources reportées « faute d'URLs vérifiées ») sans avoir à
    parser le XML CWE complet de MITRE (~900 entrées, hors périmètre).
  - `combined_mitre_attack_recon.md` (`script_mitre_attack.py`) — techniques
    MITRE ATT&CK Enterprise des tactiques **Reconnaissance (TA0043)** et
    **Resource Development (TA0042)** uniquement (pas les 14 tactiques de la
    matrice), extraites du bundle STIX officiel (`github.com/mitre/cti`) :
    seules ces deux tactiques sont pertinentes pour un outil de recon
    passive, et ce sont précisément celles déjà corrélées
    déterministiquement par `utils/mitre_attack.py` — ce corpus complète
    cette corrélation avec la description/détection officielle de chaque
    technique plutôt que la seule liste id→nom déjà en dur dans le code.
  - `combined_rfc_trust_records.md` (`script_rfc_trust_records.py`) — texte
    intégral des 10 RFC IETF derrière les enregistrements DNS de confiance
    déjà vérifiés passivement par ce projet : SPF (7208), DKIM (6376), DMARC
    (7489), DANE/TLSA (6698, 7671), MTA-STS (8461), TLS-RPT (8460), CAA
    (6844, 8659), security.txt (9116). Chacun correspond à un outil déjà
    implémenté (`spf_analysis`, `dkim_check`, `dmarc_check`, `dane_check`,
    `mta_sts_check`, `tlsrpt_check`, `caa_check`, `security_txt`) — permet à
    l'IA de citer la norme exacte (« RFC 7208 §3.1 ») plutôt que de
    reformuler une bonne pratique de mémoire.
  - Les fichiers `.md` générés vivent dans `n8n_ressource/` (source pour le
    workflow n8n, si son trigger venait à fonctionner) et `data/` (traçabilité
    de la génération). Un doublon périmé (`combined_owasp_cheatsheets2.md`,
    même contenu à quelques octets près, résidu d'une double exécution
    passée) a été supprimé.
- **Régénération systématique depuis `ref="master"`** sur les dépôts GitHub
  officiels (pas de tag figé) : relancer un script `data/script_*.py`
  récupère toujours la version actuelle, jamais un instantané figé — c'est ce
  qui a permis de vérifier que le corpus cheat sheets était bien à jour
  (120 fichiers au lieu de la version de la veille) en le régénérant.

### Artefacts résiduels
- `n8n-backup.tar.gz` (87 octets — archive vide/tronquée).
- `renew-certs.sh/`, `nginx/`, `certbot/` et la règle `qdrant_data/` du
  `.gitignore` : supprimés le 2026-10-19.

---

## 9. Conventions de code observées

À respecter pour rester cohérent avec l'existant :

- **Français partout** : docstrings de module détaillées en tête de fichier
  (rôle, cycle de vie, sécurité), commentaires, messages d'erreur, logs.
  Les docstrings expliquent souvent **pourquoi** un choix a été fait et ce que
  faisait la version précédente — conserver ce style, il porte l'essentiel de
  la mémoire du projet.
- **Séparateurs visuels** dans les gros fichiers :
  `# ----------------------------------------------------------------------`
  ou `# ═════` pour les sections majeures, en-têtes `# nom_du_fichier.py`
  en première ligne.
- **Format de réponse API systématique** :
  succès `{"success": true, "data": …}` (+ `total/page/per_page/pages` si liste),
  erreur `{"success": false, "error": "message en français"}`.
- **Un blueprint par fichier** dans `routes/`, nommé `<sujet>_bp`, enregistré
  dans `routes/__init__.py::register_routes()` avec un commentaire d'ordre.
- **Swagger obligatoire** : chaque endpoint porte un `@swag_from({...})`.
- **Ordre des décorateurs** : `@bp.route(...)` → `@require_auth` →
  `@limiter.limit(...)` → `@swag_from(...)` (l'ordre exact varie un peu selon
  les fichiers ; s'aligner sur le fichier qu'on modifie).
- **Contrat de résultat d'un outil OSINT** : tout nouvel outil DOIT retourner
  `{"status", "data", "raw_output"}` (+ `"error"` si dégradé), avec une entrée
  correspondante dans `TOOLS_REGISTRY` (`tool`, `category`, `description`,
  `indicators`) — sinon il n'apparaît ni dans l'inventaire des exports, ni
  dans la section « Méthodologie & Sources » du PDF, et `source_tool` ne peut
  pas être résolu.
- **Imports lourds différés** : les clients LLM, modèles et `models.audit_log`
  sont importés **à l'intérieur des fonctions** pour éviter les cycles et le
  coût au démarrage. Conserver ce pattern.
- **Logging** via `logger = logging.getLogger(__name__)` et interpolation `%s`
  (jamais de f-string dans les appels de log). Préfixes `[groq]`, `[parallel]`,
  `[export.json]`, `[provision]`, `[entrypoint]` pour tracer le sous-système.
- **Sécurité** : jamais `shell=True` — `routes/recon.py::_run_subprocess` prend
  une liste (`utils/command_runner.py` existe mais n'est importé nulle part,
  code mort). Validation systématique via `utils/validators.py`
  (`is_valid_domain`, `is_safe_domain` anti-SSRF), aucune donnée sensible dans
  les logs.
- **Modèles** : `to_dict()` public / `to_dict_full()` pour les données
  sensibles (`scan_results`, `final_report`, `analysis_result`) réservées aux
  endpoints `/report` et exports.
- **Migrations** : pas d'Alembic. Toute nouvelle colonne s'ajoute dans
  `api/migrate.py` sous forme d'`ALTER TABLE … ADD COLUMN IF NOT EXISTS`
  idempotent, en plus de la déclaration SQLAlchemy dans `models/`.
- **Type hints** utilisés sur les utilitaires (`-> dict`, `Optional[Dict]`),
  pas systématiques sur les vues Flask.

---

## 10. Réflexes pour une session Claude Code

1. Le point d'entrée est `api/app.py` (`create_app()`), servi par **gunicorn**
   depuis `entrypoint.sh`.
2. Ajouter un endpoint = nouveau blueprint dans `routes/` + enregistrement dans
   `routes/__init__.py` + `@swag_from` + `@require_auth` + format
   `{"success": …}`.
3. Ajouter un outil OSINT = fonction `_mon_outil(domain)` respectant le contrat
   `status/data/raw_output` + entrée dans `TOOLS_REGISTRY` + clé dans
   `ALL_TOOLS` + entrée dans `_wave1_specs` **ou** `_parallel_specs` + timeout
   mesuré sur un domaine réel (voir §8).
4. Ajouter une colonne = `models/*.py` **et** `migrate.py`.
5. Ajouter une dépendance = `api/requirements.txt` uniquement, puis rebuild de
   l'image `api`.
6. Toucher à l'analyse IA = lire d'abord la cascade de `routes/analyze.py`
   avant `utils/*_client.py`. Le champ `source_tool` est obligatoire sur chaque
   finding — ne pas relâcher cette contrainte, exports et PDF en dépendent.
7. Ne rien committer sans vérifier que `caddy_data/`, `n8n_data/`,
   `postgres_data/` et les deux `.env` restent hors du diff.
11. Lire un résultat d'un dossier scellé = **jamais** en réécrivant les
    colonnes du modèle (`recon.scan_results = ...`) : un commit ultérieur
    remettrait le clair en base. Déchiffrer en mémoire
    (`result_vault.unlock`) et passer les valeurs aux builders
    (`build_export_json(recon, raw)`).
12. Toute nouvelle route appelée par n8n = `@require_service_or_auth` (jamais
    `@require_auth` seul, n8n n'a plus le compte admin) ; toute route
    d'administration = `@require_auth` seul (le jeton de service ne doit pas
    l'ouvrir).
13. Lancer les tests : `./scripts/run-tests.sh` (voir §6).
8. Modifier un workflow n8n = éditer `n8n/workflows/*.json` (source de vérité
   versionnée), **pas** l'éditeur n8n en prod — la modification serait perdue
   au prochain redémarrage du conteneur.
9. Toute valeur avec un `$` littéral dans `api/.env` (hash werkzeug) doit garder
   un `$` **simple**, jamais doublé (voir §7).
10. Modifier `docker-compose.yml` = penser au `.env` **racine** si on introduit
    une nouvelle interpolation `${VAR}`, et à `api/.env` pour la valeur runtime.
