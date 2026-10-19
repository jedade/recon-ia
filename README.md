# Recon-IA

Plateforme self-hosted de **reconnaissance passive OSINT assistée par IA**.
Un utilisateur soumet un domaine et son adresse email ; la plateforme collecte
des informations exclusivement à partir de sources publiques, les fait analyser
par un LLM, produit un rapport PDF traçable et expose les données brutes dans un
format exportable et citable.

Stack : **Flask + gunicorn**, **n8n**, **PostgreSQL/pgvector**, **Redis**,
**Ollama**, et une cascade de fournisseurs LLM (DeepSeek en test optionnel,
Gemini, Cerebras, Groq, OpenRouter, Ollama local).

---

## Ce que fait Recon-IA

- **Collecte passive** — 56 outils OSINT (WHOIS, RDAP, DNS, DNSSEC,
  certificats, sous-domaines et leur résolution, en-têtes HTTP, cookies,
  configuration email, réputation d'IP, listes de blocage DNS, classement
  Tranco, Safe Browsing/PhishTank, archives web, secrets GitHub…), exécutés
  **en parallèle** en deux vagues. Les outils à clé API sont ignorés sans clé.
- **Analyse IA encadrée** — un LLM interprète les résultats, mais **la
  sévérité est fixée par 43 règles déterministes** appliquées aux données
  brutes : un constat positif n'est jamais critique, une CVE non observée est
  retirée, une CVE du catalogue CISA KEV passe en critique. Chaque finding
  cite **l'outil qui a produit la preuve** (`source_tool`), un niveau de
  confiance et sa date d'observation.
- **MITRE ATT&CK v20** — techniques de reconnaissance utilisées et, pour
  chaque constat, **techniques rendues possibles** et mitigations (table
  déterministe), chaîne d'attaque plausible, export layer ATT&CK Navigator.
- **Graphe et différentiel** — entités (domaine, sous-domaines, IP, ASN,
  certificats, technologies, CVE) et changements depuis le scan précédent ;
  surveillance planifiée optionnelle avec alerte à l'administrateur.
- **Boucle agent (optionnelle)** — un LLM capable (Gemini, DeepSeek, modèle
  local ≥ 7B) choisit des pivots passifs supplémentaires, dans une liste
  blanche et un périmètre stricts ; désactivée par défaut.
- **Rapport PDF** — avec une section « Méthodologie & Sources » qui
  inventorie chaque outil exécuté, son statut, sa durée, et les limites de la
  collecte.
- **Résultats chiffrés, consultés par code** — en fin d'analyse, le rapport
  et les données sont chiffrés (AES-256-GCM) et le demandeur reçoit par mail
  un **code d'accès** de 256 bits, sans pièce jointe. Il le saisit sur la page
  « Voir le résultat » (`web/result.html`) pour consulter le rapport et le
  télécharger en PDF, JSON ou CSV. Le serveur ne conserve pas ce code : sans
  lui, même l'administrateur ne peut pas relire le contenu. Code valable
  30 jours, révocable ; purge automatique des données périmées (RGPD).
- **Exports exploitables** — JSON complet avec bloc de provenance et empreinte
  SHA-256 du jeu de données, CSV tabulaire des findings, KPI agrégés.
- **Cache** — les scans sont réutilisés 30 jours par défaut (puis conservés en
  base, consultables par l'admin) et les analyses IA 7 jours ; ils sont
  mis en cache en base pour éviter les recollectes et les coûts inutiles.
- **RAG (retrieval-augmented generation)** — avant l'appel au LLM, une
  recherche par similarité (pgvector) va chercher les extraits les plus
  pertinents dans un corpus de référence (OWASP Cheat Sheets, ASVS, WSTG,
  Top 10:2021, techniques et mitigations MITRE ATT&CK v20, guides ANSSI,
  recommandations TLS Mozilla, CWE/CAPEC, avis CISA, fiches explicatives,
  RFC IETF des enregistrements DNS de confiance) et les injecte comme
  contexte que le rapport doit citer — les recommandations s'ancrent dans une
  norme reconnue plutôt qu'une reformulation générique.
- **Dashboard** — console admin (`web/dashboard.html`) avec KPI opérationnels
  et une section « Conformité & Recherche » (traçabilité outil→finding,
  couverture MITRE ATT&CK, fiabilité agrégée des outils), un onglet « Graphe &
  surveillance » et l'accès aux scans bruts en cache ; pensée pour une
  présentation/publication.

### Reconnaissance strictement passive

Concrètement, dans ce projet, « passif » signifie :

- Aucun scan de ports, aucun envoi de payload, aucune tentative
  d'authentification, aucun fuzzing sur la cible.
- Les informations proviennent de **tiers** (registres WHOIS/RDAP, journaux de
  Certificate Transparency, DNS public, archives Wayback/Common Crawl, bases de
  réputation, observations Shodan **déjà collectées** via l'API InternetDB).
- Les seules requêtes atteignant directement le domaine sont des requêtes HTTP
  banales et publiques (page d'accueil, `robots.txt`, `sitemap.xml`,
  `.well-known/security.txt`, favicon) et des résolutions DNS — équivalentes à
  une visite de navigateur.
- `amass` est lancé en mode `-passive` ; `dnstwist` n'interroge que les domaines
  de typosquatting candidats, jamais la cible.
- Un consentement (`accord`) et une validation d'email par code OTP sont requis
  avant toute exécution, et les exports sont refusés (HTTP 403) sans
  consentement enregistré.

---

## Services (`docker-compose.yml`)

| Service    | Image / build            | Port                          | Rôle |
|------------|--------------------------|-------------------------------|------|
| `caddy`    | `caddy:2.8.4-alpine`     | **80 / 443** — seul exposé    | reverse proxy, HTTPS automatique (`caddy/Caddyfile`) |
| `web`      | `nginx:alpine`           | interne (via Caddy)           | frontend statique (`./web`) |
| `api`      | build `./api`            | interne (via Caddy) + `127.0.0.1:8080` | API Flask REST OSINT + IA + PDF (gunicorn) |
| `n8n`      | build `./n8n`            | `127.0.0.1:5678` uniquement   | orchestration du pipeline (image custom, provisioning auto) |
| `postgres` | `pgvector/pgvector:pg16` | interne (non publié)          | base principale + RAG vectoriel (`pgvector`) |
| `ollama`   | `ollama/ollama`          | interne (non publié)          | LLM local (dernier recours) + embeddings RAG |
| `redis`    | `redis:alpine`           | interne (non publié)          | stockage partagé du rate limiter |

**Seul Caddy est joignable depuis Internet.** Le navigateur ne parle qu'à
l'API ; c'est l'API qui déclenche n8n sur le réseau interne, et n8n la
rappelle avec un jeton de service dédié (il n'a plus le mot de passe admin).
L'éditeur n8n s'ouvre par un tunnel SSH :
`ssh -L 5678:127.0.0.1:5678 serveur`, puis `http://localhost:5678`.

Il n'y a **pas** de service Qdrant : le RAG est stocké dans la table
`rag_documents` de PostgreSQL via l'extension `pgvector`.

---

## Démarrage rapide

### Prérequis

- Docker 20+ et Docker Compose 2+
- Au moins une clé LLM gratuite (sinon, repli sur Ollama local) :
  [Gemini](https://aistudio.google.com/apikey) ·
  [Cerebras](https://cloud.cerebras.ai) ·
  [Groq](https://console.groq.com/keys) ·
  [OpenRouter](https://openrouter.ai/keys)
- Un compte SMTP pour l'envoi des codes OTP et des codes d'accès
- En production : deux noms de domaine pointant vers le serveur (site + API)
  et une clé [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile)
  (gratuite) pour l'anti-robot du formulaire

### Installation — en une commande (recommandé)

```bash
git clone https://github.com/your-user/recon-ia.git
cd recon-ia
./setup.sh
```

Génère des `.env` de développement local (identifiants clairement marqués
« dev », à ne jamais réutiliser sur un déploiement exposé publiquement) **et
des secrets aléatoires** (jeton de service, secret du webhook, secret du
coffre des résultats, clé de chiffrement n8n), build + démarre tous les
services, attend qu'ils soient prêts, télécharge le modèle Ollama local, puis
affiche les URLs d'accès. Idempotent : ré-exécutable sans danger ; sur une
installation existante, il ajoute seulement les secrets manquants.

En local, le site est servi sur `http://localhost` et l'API sur
`http://api.localhost` (sans TLS).

### Installation — manuelle (configuration complète/production)

```bash
# 1. Cloner le dépôt
git clone https://github.com/your-user/recon-ia.git
cd recon-ia

# 2. Configurer l'API
cp api/.env.example api/.env
# Éditer api/.env — au minimum : POSTGRES_*, SMTP_*, ADMIN_EMAIL,
# ADMIN_PASSWORD (hash), SECRET_KEY, une clé LLM, et
# CORS_ORIGINS=https://recon.votredomaine.com

# 3. Générer le hash du mot de passe admin
docker run --rm python:3.11-slim sh -c \
  "pip install -q werkzeug && python3 -c \
   \"from werkzeug.security import generate_password_hash; print(generate_password_hash('VotreMotDePasse'))\""
# Coller le résultat dans api/.env → ADMIN_PASSWORD=pbkdf2:sha256:...
# ⚠️ NE PAS doubler les « $ » du hash (voir « Deux fichiers .env » ci-dessous)

# 4. Créer le .env RACINE (adresses publiques + secrets partagés API/n8n)
cat > .env <<EOF
POSTGRES_USER=reconuser
POSTGRES_PASSWORD=...
POSTGRES_DB=recondb
SITE_ADDRESS=recon.votredomaine.com
API_ADDRESS=api.votredomaine.com
ACME_EMAIL=admin@votredomaine.com
DASHBOARD_API_BASE=https://api.votredomaine.com
RESULTS_PAGE_URL=https://recon.votredomaine.com/result.html
TURNSTILE_SITE_KEY=...
TURNSTILE_SECRET_KEY=...
PIPELINE_SERVICE_TOKEN=$(openssl rand -hex 32)
N8N_WEBHOOK_SECRET=$(openssl rand -hex 32)
RESULTS_ACCESS_SECRET=$(openssl rand -hex 32)
N8N_ENCRYPTION_KEY=$(openssl rand -hex 32)
APP_DB_PASSWORD=$(openssl rand -hex 32)
RAG_DB_PASSWORD=$(openssl rand -hex 32)
# Si docker.n8n.io répond 429 au build : même image sur Docker Hub
# N8N_IMAGE=n8nio/n8n
EOF

# 5. Lancer tous les services (Caddy obtient les certificats automatiquement)
docker compose up -d

# 6. Créer IMMÉDIATEMENT le compte propriétaire n8n (tunnel SSH, puis
#    http://localhost:5678) : tant qu'il n'existe pas, le premier visiteur
#    de l'éditeur peut le créer.

# 7. Vérifier
docker compose ps
docker compose logs -f api caddy
```

### Deux fichiers `.env` — à ne pas confondre

| Fichier | Rôle |
|---|---|
| `api/.env` | réglages propres à l'API (base, SMTP, clés LLM, durées…). Chargé par `env_file:` pour `api` et `postgres`, et relu directement en Python par l'application |
| `.env` (racine) | interpolation `${VAR}` de `docker-compose.yml` **et seule source des secrets partagés** entre l'API et n8n, injectés explicitement dans chaque service |

Les secrets partagés (`PIPELINE_SERVICE_TOKEN`, `N8N_WEBHOOK_SECRET`) et
`RESULTS_ACCESS_SECRET` vivent **uniquement** dans le `.env` racine : une
seconde copie dans `api/.env` aurait priorité côté API et finirait par
diverger de celle de n8n. Ne jamais changer `RESULTS_ACCESS_SECRET` sur une
installation en service : tous les codes d'accès déjà envoyés deviendraient
introuvables.

⚠️ Dans `api/.env`, les valeurs contenant un `$` littéral (typiquement le hash
werkzeug) doivent garder un **`$` simple**, jamais doublé — même si Docker
Compose émet un avertissement « variable is not set ». L'application relit le
fichier brut et écrase la valeur interpolée par Docker ; doubler le `$` casse
l'authentification silencieusement.

### Vérification

```bash
# Catalogue public (via Caddy, ou en direct sur la boucle locale)
curl http://api.localhost/
curl http://localhost:8080/

# Swagger UI interactif
open http://localhost:8080/apidocs

# Statut des backends IA
curl -u admin@example.com:VotreMotDePasse http://localhost:8080/analyze/status

# KPI agrégés
curl -u admin@example.com:VotreMotDePasse http://localhost:8080/recon/stats

# Frontend, page de résultat, éditeur n8n
open http://localhost
open http://localhost/result.html
open http://localhost:5678

# Tests (conteneur jetable, sans réseau)
./scripts/run-tests.sh
./scripts/e2e/run-result-page.sh   # page de résultat dans Chrome headless
# Sur la stack démarrée : parcours complet réel (formulaire → mail → rapport)
ADMIN_AUTH='admin@example.com:VotreMotDePasse' ./scripts/e2e/run-full-flow.sh
```

---

## Workflow complet

```
Utilisateur (web/index.html)
    │
POST /recon  (domaine + identité + email + accord + jeton Turnstile)
    │ → consentement obligatoire, contrôle anti-robot, code OTP envoyé par email
    ▼
POST /verify_email  (code à 6 chiffres — 5 essais max par code)
    │ → dossier activé, l'API déclenche le webhook n8n en interne
    ▼
n8n (réseau interne, jeton de service) ──────────────────────────────┐
POST /pass_recon  {recon_id}                                         │
    │ 47 outils OSINT passifs, 2 vagues parallèles                   │
    │   vague 1 (9)  : whois, rdap, dns, crt.sh, subfinder,          │
    │                  assetfinder, github, amass, ip_info           │
    │   → union des sous-domaines découverts                         │
    │   vague 2 (38) : tout le reste (DNS, SSL/TLS, email, HTTP,     │
    │                  réputation, archives, takeover…)              │
    │ borné par SCAN_DEADLINE_SECONDS, SCAN_MAX_WORKERS threads      │
    ▼                                                                │
POST /analyze/async + GET /analyze/wait/<id>                         │
    │ cascade IA : DeepSeek (test) → Gemini → Cerebras → Groq        │
    │              → OpenRouter → Ollama local                       │
    │ chaque finding porte un `source_tool` obligatoire              │
    │ score de sécurité + grade dénormalisés en base                 │
    │ mapping MITRE ATT&CK déterministe (pas inventé par le LLM)     │
    ▼                                                                │
POST /recon/<id>/generate_final_report   → rapport narratif IA       │
POST /recon/<id>/generate_report         → PDF, chiffrement des      │
    │                                      résultats, mail avec code ┘
    ▼
Utilisateur (web/result.html) saisit son code d'accès
POST /results/access                     → session de consultation (1 h)
GET  /results/report                     → rapport complet
GET  /results/report.pdf | export.json | export.csv | export.navigator.json  → téléchargements
```

L'administrateur garde le dashboard (`web/dashboard.html`) et les KPI
(`GET /recon/stats`) : statut, score, durées, compteurs. Il ne peut plus lire
le contenu d'un dossier chiffré.

---

## Documentation API

La documentation complète (endpoints, authentification, variables
d'environnement, outils OSINT, sécurité) est dans **[api/README.md](api/README.md)**.

Documentation interactive :

- Swagger UI : `http://localhost:8080/apidocs`
- ReDoc : `http://localhost:8080/redoc`
- Page statique : `http://localhost/docs.html`

---

## Structure du projet

```
recon-ia/
├── api/                        # API Flask REST OSINT — voir api/README.md
│   ├── app.py                  # Factory Flask (create_app)
│   ├── config.py               # Chargement .env, Swagger, URI base de données
│   ├── extensions.py           # Flask-Limiter (Redis, repli mémoire)
│   ├── entrypoint.sh           # DNS → migrations → gunicorn
│   ├── migrate.py              # Migrations SQL idempotentes + extension pgvector
│   ├── models/                 # recon · audit_log · pass_recon_cache
│   ├── routes/                 # 10 blueprints (dont results.py : consultation par code)
│   ├── utils/                  # parallel, clients LLM, PDF, email, coffre des résultats…
│   ├── errors/                 # Handlers d'erreurs JSON
│   ├── tests/                  # pytest (unitaires, sécurité, intégration)
│   ├── requirements.txt
│   ├── .env.example            # Modèle de configuration
│   ├── Dockerfile
│   └── Dockerfile.test         # Image légère pour les tests
├── caddy/Caddyfile             # Reverse proxy HTTPS (seul service exposé)
├── n8n/
│   ├── Dockerfile              # Image custom avec provisioning automatique
│   ├── provision-and-start.sh  # Import credentials + workflows, puis démarre n8n
│   ├── generate-credentials.js # Génère les credentials depuis l'environnement
│   └── workflows/              # recon-ia-main.json · rag-ingestion.json
├── web/                        # Frontend statique (nginx, derrière Caddy)
│   ├── index.html              # Formulaire public
│   ├── result.html             # « Voir le résultat » (consultation par code)
│   ├── dashboard.html          # Console admin (Basic Auth vers l'API)
│   ├── docs.html               # Documentation API statique
│   └── vendor/chart.umd.min.js
├── data/                       # Scripts d'agrégation du corpus RAG (OWASP, ASVS, WSTG…)
├── n8n_ressource/              # Corpus RAG monté dans n8n
├── scripts/run-tests.sh        # Lance la suite pytest dans un conteneur
├── scripts/e2e/                # Test de la page de résultat dans Chrome headless
├── docs/PLAN_ACTION.md         # Feuille de route
├── docker-compose.yml
├── .env                        # Adresses publiques + secrets partagés API/n8n
└── README.md
```

Volumes de données locaux (gitignorés, créés à l'exécution) : `postgres_data/`,
`n8n_data/`, `ollama/`, `caddy_data/`, `caddy_config/`.

---

## n8n — provisioning automatique

Le service `n8n` utilise une image custom (`n8n/Dockerfile`). À chaque
démarrage, `n8n/provision-and-start.sh` :

1. génère les credentials à partir des variables d'environnement
   (`n8n/generate-credentials.js`) : PostgreSQL, Ollama, le **jeton de
   service** de l'API (`X-Service-Token`) et le **secret du webhook**
   (`X-Pipeline-Secret`) — ces deux derniers seulement s'ils font au moins
   32 caractères ;
2. les importe (`n8n import:credentials`, stockage chiffré par
   `N8N_ENCRYPTION_KEY`), puis supprime le fichier temporaire qui contient
   les secrets en clair ;
3. importe et active les deux workflows versionnés de `n8n/workflows/`.

L'opération est **idempotente** (identifiants fixes) et **best-effort** : un
échec de provisioning n'empêche jamais n8n de démarrer, il est seulement
journalisé (`docker logs n8n | grep -i provision`).

Les workflows sont versionnés dans `n8n/workflows/*.json` : c'est la source de
vérité. Une modification faite dans l'éditeur n8n sera perdue au prochain
redémarrage du conteneur.

---

## RAG — corpus de référence et ingestion automatique

Avant l'appel au LLM, `routes/analyze.py` interroge par similarité
(`utils/rag_retrieval.py`, pgvector) un corpus de référence stocké dans
`rag_documents` et injecte les extraits les plus pertinents comme contexte
que le rapport doit citer. Le corpus couvre aujourd'hui 6 sources officielles :
OWASP Cheat Sheets, ASVS, WSTG, Top 10:2021, les techniques MITRE ATT&CK des
tactiques Reconnaissance/Resource Development, et les RFC IETF derrière les
enregistrements DNS de confiance vérifiés passivement (SPF, DKIM, DMARC,
DANE, MTA-STS, TLS-RPT, CAA, security.txt).

### Ingestion — entièrement automatique

Le workflow `n8n/workflows/rag-ingestion.json` s'exécute **automatiquement à
chaque démarrage/redémarrage de n8n** (nœud `n8n Trigger`, événements
`init`/`activate` — aucune étape manuelle) :

1. Vide `rag_documents` (`TRUNCATE`) ;
2. Relit **tous** les fichiers `.md` de `n8n_ressource/` (`Read/Write Files
   from Disk`, sélecteur `/tmp/n8n-source-docs/**/*.md`) ;
3. Découpe (500 caractères / 50 de chevauchement), calcule les embeddings
   (`nomic-embed-text:v1.5` via Ollama) et réinsère tout dans `rag_documents`.

Un rechargement complet re-embarque l'intégralité du corpus (quelques
dizaines de minutes sur un poste sans GPU, le corpus combiné pesant plusieurs
Mo) — c'est volontaire : plus simple et plus fiable qu'une logique
incrémentale, et ça ne se produit qu'au (re)démarrage de n8n, pas en continu.

⚠️ Ce mécanisme remplace le nœud *Local File Trigger* d'origine, qui ne se
déclenche **jamais** sur un bind mount Docker Desktop (problème connu de
l'écosystème n8n, issue n8n-io/n8n#17893) — voir `CLAUDE.md` §8 pour
l'historique complet de cette découverte.

### Ajouter du contenu au corpus RAG

1. **Régénérer ou ajouter un fichier markdown** dans `n8n_ressource/` :
   - Pour rafraîchir une source existante, relancer le script
     correspondant dans `data/` (toujours à jour, interroge la branche
     `master` du dépôt GitHub officiel) :
     ```bash
     cd data
     python3 script_asvs.py            # ou script.py, script_wstg.py,
                                        # script_owasp_top10.py,
                                        # script_mitre_attack.py,
                                        # script_rfc_trust_records.py
     cp combined_*.md ../n8n_ressource/
     ```
     (ces scripts nécessitent `requests`, installé dans l'image `api` — à
     défaut d'un environnement Python local, les exécuter via
     `docker cp data api:/tmp/data && docker exec -w /tmp/data api python3 script_xxx.py`
     puis `docker cp` le résultat vers `n8n_ressource/`.)
   - Pour une **nouvelle source**, déposer directement un fichier `.md`
     dans `n8n_ressource/` (pas besoin d'écrire un script si le contenu
     existe déjà sous cette forme).
2. **Redémarrer n8n** pour déclencher la réingestion automatique :
   ```bash
   docker compose restart n8n
   ```
   Le workflow videra `rag_documents` et réembarquera **tout** le contenu de
   `n8n_ressource/` (fichiers existants + nouveaux), sans étape manuelle
   supplémentaire.
3. **Vérifier** que l'ingestion a bien eu lieu :
   ```bash
   docker exec postgres psql -U reconuser -d recondb \
     -c "SELECT metadata->>'source', count(*) FROM rag_documents GROUP BY 1;"
   ```
   (`metadata->>'source'` correspond au nom de fichier — un nouveau fichier
   doit apparaître comme une nouvelle valeur distincte.)

Pas de reconnaissance active dans les sources ajoutées : ce corpus documente
des méthodologies/normes de référence, jamais d'outils ou techniques actives
(scan de ports, exploitation...) — cohérent avec la portée strictement
passive du projet (voir plus haut).

---

## Sécurité

À lire avant tout déploiement :

- **Reconnaissance passive uniquement** — voir la définition concrète en haut de
  ce fichier. Ne pas ajouter d'outil actif sans revoir le cadre légal et le
  texte de consentement présenté à l'utilisateur.
- **Surface exposée** — seul Caddy (80/443) est publié. L'API et n8n ne sont
  publiés que sur `127.0.0.1`, Postgres, Redis et Ollama nulle part.
- **n8n** — jamais exposé sur Internet ; accès aux variables d'environnement
  bloqué dans les nœuds ; aucun mot de passe admin confié (jeton de service
  limité aux routes du pipeline, retiré par Caddy de toute requête externe) ;
  webhook appelé seulement par l'API, avec un secret d'en-tête. **Créer le
  compte propriétaire n8n dès le premier démarrage.**
- **Ne jamais monter `/var/run/docker.sock` dans le conteneur n8n** : cela
  donne un contrôle root complet sur l'hôte. Aucun workflow du projet n'en a
  besoin.
- **Résultats** — chiffrés en AES-256-GCM avec une clé dérivée du code
  d'accès du demandeur ; le serveur ne stocke que l'empreinte HMAC du code.
  Le code transite dans le corps d'un POST, jamais dans une URL. Tentatives
  limitées par IP, sessions courtes revalidées à chaque requête (révocation
  immédiate).
- **Formulaire** — consentement obligatoire, anti-robot Cloudflare Turnstile
  (définir `TURNSTILE_SITE_KEY` et `TURNSTILE_SECRET_KEY` en production),
  5 essais maximum par code OTP.
- **Scanner** — chaque requête HTTP sortante, redirections comprises, est
  refusée si l'hôte résout vers une adresse interne (protection SSRF).
- **Conservation** — purge horaire : résultats et identité effacés 7 jours
  après l'expiration du code, demandes non vérifiées après 7 jours, journal
  d'audit après 90 jours.
- **Secrets** — `.env` (aux deux emplacements), `n8n_data/`, `caddy_data/`,
  `postgres_data/` et `ollama/` sont couverts par `.gitignore`. Vérifier le
  diff avant tout `git add -A`.
- **Mot de passe admin** — toujours un **hash werkzeug** dans `ADMIN_PASSWORD`.
- **HTTPS** — assuré par Caddy dès que `SITE_ADDRESS`/`API_ADDRESS` sont des
  noms de domaine. `TRUSTED_PROXY_COUNT` est fixé à 1 (Caddy) : ne pas
  l'augmenter sans ajouter réellement un proxy de confiance devant.
- **CORS** — restreindre `CORS_ORIGINS` au domaine réel du frontend. En
  production, une valeur vide refuse toute requête cross-origin.
- **Clés d'API LLM** — sensibles ; elles ne sont jamais renvoyées par l'API ni
  journalisées, et ne sont plus transmises au conteneur n8n.

Détail complet : [api/README.md § Sécurité](api/README.md#sécurité).
