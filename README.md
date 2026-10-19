<p align="center">
  <img src="web/assets/brand/reconia-logo-600.png" alt="ReconIA — De la donnée à la décision" width="260">
</p>

# ReconIA

> **De la donnée à la décision** — Veille | Analyse | Intelligence

Plateforme self-hosted de **reconnaissance passive OSINT analysée par IA**.
Un utilisateur soumet un domaine et son adresse email. La plateforme collecte ce
que n'importe qui peut savoir de ce domaine à partir de sources publiques, fixe
la gravité de chaque constat par des règles vérifiables, fait interpréter et
rédiger le tout par un LLM, puis remet un rapport **chiffré**, consultable
uniquement avec un code d'accès personnel envoyé par email.

Stack : **Flask + gunicorn**, **n8n**, **PostgreSQL/pgvector**, **Redis**,
**Caddy**, **Ollama**, et une cascade de fournisseurs LLM (Gemini, Groq,
Cerebras, OpenRouter, DeepSeek en test optionnel, Ollama local en dernier
recours).

---

## Ce qu'est ReconIA, et ce qu'il n'est pas

| | |
|---|---|
| **La collecte** | 56 outils fixes, exécutés en parallèle. Ce n'est pas l'IA qui choisit quoi collecter |
| **La gravité** | 43 règles déterministes appliquées aux données brutes. L'IA propose, la règle tranche : un constat positif n'est jamais critique, une CVE non observée est retirée, une CVE du catalogue CISA KEV passe en critique |
| **L'IA** | Interprète les données, relie les constats, rédige le rapport, donne **un avis sur chaque outil** et des recommandations. C'est un **analyste**, pas un enquêteur autonome |
| **ATT&CK, score, graphe, différentiel** | Calculés par du code déterministe, jamais inventés par le LLM |
| **La boucle agent** | Une IA qui choisit elle-même des pistes supplémentaires (IP → hébergeur, certificat → sous-domaines…) est codée et testée, mais **désactivée par défaut** (`AGENT_RECON_ENABLED=false`). Elle exige un modèle capable de la piloter (Gemini, DeepSeek ou un modèle local ≥ 7B) |

Ce partage est volontaire : un LLM, surtout petit, invente des CVE et note
« critique » des bonnes pratiques. Les règles rendent les rapports défendables.

### « Passif » : ce que fait exactement le projet

**Aucun test intrusif** : pas de scan de ports, pas d'envoi de charge d'attaque,
pas de tentative d'authentification, pas de fuzzing, pas de force brute.

La majorité des outils n'interrogent **que des tiers** : registres WHOIS/RDAP,
DNS public, journaux Certificate Transparency (crt.sh), subfinder, assetfinder
et `amass enum -passive`, archives du web, Shodan InternetDB (observations déjà
collectées), OTX, urlscan, listes de blocage DNS, VirusTotal, Tranco, bases de
fuites, GitHub. `dnstwist` n'interroge que les domaines de typosquatting
candidats, jamais la cible.

**Certains outils contactent directement la cible**, comme un visiteur. Ces
requêtes apparaissent dans ses journaux :

| Contact direct | Volume approximatif |
|---|---|
| Page d'accueil (technologies, WAF déduit des en-têtes, redirections, en-têtes de sécurité, cookies, JavaScript) | une dizaine de requêtes HTTP |
| `robots.txt`, `sitemap.xml`, `.well-known/security.txt`, favicons, fichiers JavaScript | une dizaine de requêtes |
| Sous-domaines prioritaires (requête HEAD, HTTP et HTTPS) | jusqu'à 20 requêtes |
| `ssl_info` : une négociation TLS | 1 connexion |
| **`sslscan`** : énumération des protocoles et suites de chiffrement | **des dizaines de connexions TLS**, repérables par un IDS |

Au sens strict du métier (zéro interaction avec la cible), ReconIA est donc
« **passif + léger actif non intrusif** ». `sslscan` est conservé par choix
(décision D7 de `docs/PLAN_ACTION.md`) ; un mode strictement passif, qui
désactiverait ces contacts directs, n'existe pas encore.

Un consentement (`accord`) et une validation d'email par code OTP sont requis
avant toute exécution, et les exports sont refusés (HTTP 403) sans consentement
enregistré.

---

## Fonctionnalités

- **Collecte** — 56 outils OSINT : WHOIS, RDAP, DNS, DNSSEC, certificats,
  sous-domaines et leur résolution massive, en-têtes HTTP, cookies,
  configuration email (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI), réputation
  d'IP, listes de blocage DNS, classement Tranco, Safe Browsing/PhishTank,
  archives web, fuites, secrets GitHub… Les outils à clé API sont ignorés sans
  clé, sans bloquer le scan.
- **Analyse encadrée** — chaque constat cite **l'outil qui l'a prouvé**
  (`source_tool`), un niveau de confiance et sa date d'observation ; sa preuve
  est confrontée à la donnée brute (contrôle d'ancrage).
- **Couverture mesurée** — un outil compte comme examiné s'il est cité par un
  constat, s'il a reçu un avis de l'IA (`tool_reviews` : rien à signaler,
  constat ou information) ou si une règle a lu ses données. Mesuré à 100 % sur
  un scan réel d'example.com avec Gemini.
- **MITRE ATT&CK v20** — techniques de reconnaissance utilisées et, pour chaque
  constat, techniques rendues possibles et mitigations, chaîne d'attaque
  plausible, export layer ATT&CK Navigator.
- **Page « Voir le résultat »** — vue d'ensemble avec graphiques (sévérités,
  catégories, couverture), **globe** de localisation des serveurs façon
  web-check, **cartographie** de l'infrastructure (domaine → IP et hébergeur →
  sous-domaines), constats filtrables, une carte par outil avec l'avis de
  l'IA, thème clair ou sombre.
- **Rapport PDF professionnel** — couverture sobre (sans score), sommaire,
  périmètre et méthode, échelle de sévérité, synthèse avec jauge et
  graphiques, carte du monde des serveurs, cartographie, constats détaillés,
  ATT&CK, plan d'action, méthodologie (outils exécutés, limites).
- **Résultats chiffrés, consultés par code** — rapport et données chiffrés en
  AES-256-GCM ; le demandeur reçoit par email un **code d'accès** de 256 bits,
  **sans pièce jointe**. Le serveur ne conserve pas ce code : sans lui, même
  l'administrateur ne peut pas relire le contenu. Code valable 30 jours,
  révocable ; purge automatique des données périmées (RGPD).
- **Exports** — PDF, JSON complet (provenance, empreinte SHA-256 du jeu de
  données, éditeur), CSV des constats, layer ATT&CK Navigator.
- **Graphe et différentiel** — entités (domaine, sous-domaines, IP, ASN,
  certificats, technologies, CVE) et changements depuis le scan précédent ;
  surveillance planifiée optionnelle avec alerte à l'administrateur.
- **Cache** — scans réutilisés 30 jours (puis conservés en base, consultables
  par l'admin), analyses IA 7 jours.
- **RAG** — avant l'appel au LLM, une requête par constat dans un corpus de
  référence (OWASP, ASVS, WSTG, Top 10, MITRE ATT&CK, ANSSI, Mozilla TLS,
  CWE/CAPEC, avis CISA, RFC des enregistrements DNS de confiance), filtrée par
  collection — voir l'état réel de l'ingestion plus bas.
- **Dashboard admin** — KPI, conformité et recherche (traçabilité
  outil→constat, couverture ATT&CK, fiabilité des outils), scans bruts en
  cache, graphe et surveillance, coffre des résultats (révocation).
- **Charte ReconIA** — logo, favicons, couleurs et polices sur toutes les
  pages, le PDF et les emails (logo intégré, jamais chargé à distance) ; thème
  clair/sombre partagé entre les pages ; responsive de 320 à 1440 px.

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
l'API ; c'est l'API qui déclenche n8n sur le réseau interne, et n8n la rappelle
avec un jeton de service dédié. L'éditeur n8n s'ouvre par un tunnel SSH :
`ssh -L 5678:127.0.0.1:5678 serveur`, puis `http://localhost:5678`.

---

## Démarrage rapide

### Prérequis

- Docker 20+ et Docker Compose 2+
- **Au moins une clé LLM gratuite** — sans elle, toute l'analyse tombe sur
  `qwen3:1.7b` en local (10 à 15 min par analyse, qualité faible) :
  [Gemini](https://aistudio.google.com/apikey) (recommandé) ·
  [Groq](https://console.groq.com/keys) ·
  [Cerebras](https://cloud.cerebras.ai) ·
  [OpenRouter](https://openrouter.ai/keys)
- Un compte SMTP pour les codes OTP et les codes d'accès
- En production : deux noms de domaine pointant vers le serveur (site + API) et
  une clé [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile)
  (gratuite) pour l'anti-robot du formulaire

Les modèles Gemini ne sont pas codés en dur : le client lit au démarrage la
liste des modèles que la clé propose réellement (Google retire régulièrement
des versions), commence par l'alias `gemini-flash-latest`, passe au modèle
suivant en cas de quota épuisé ou de saturation, et écarte temporairement les
modèles refusés. Groq construit sa file de la même façon.

### Installation — en une commande (recommandé)

```bash
git clone https://github.com/your-user/recon-ia.git
cd recon-ia
./setup.sh
```

Génère des `.env` de développement local (identifiants marqués « dev », **à ne
jamais réutiliser sur un déploiement exposé** : le mot de passe admin de
développement est écrit en clair dans `setup.sh`) et des secrets aléatoires
(jeton de service, secret du webhook, secret du coffre des résultats, clé de
chiffrement n8n, mots de passe des rôles PostgreSQL). Il construit et démarre
les services, télécharge le modèle Ollama et le modèle d'embeddings
`nomic-embed-text:v1.5`, puis affiche les URLs d'accès. Idempotent.

En local, le site est servi sur `http://localhost` et l'API sur
`http://api.localhost` (sans TLS). Si les ports 80/443 sont pris, définir
`CADDY_HTTP_PORT` / `CADDY_HTTPS_PORT` dans le `.env` racine.

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

# 6. Télécharger les modèles locaux (repli LLM + embeddings du RAG)
docker exec ollama ollama pull qwen3:1.7b
docker exec ollama ollama pull nomic-embed-text:v1.5

# 7. Créer IMMÉDIATEMENT le compte propriétaire n8n (tunnel SSH, puis
#    http://localhost:5678) : tant qu'il n'existe pas, le premier visiteur
#    de l'éditeur peut le créer.

# 8. Vérifier
docker compose ps
docker compose logs -f api caddy
```

### Deux fichiers `.env` — à ne pas confondre

| Fichier | Rôle |
|---|---|
| `api/.env` | réglages propres à l'API (base, SMTP, clés LLM et OSINT, durées…). Chargé par `env_file:` pour `api` et `postgres`, et relu directement en Python par l'application |
| `.env` (racine) | interpolation `${VAR}` de `docker-compose.yml` **et seule source des secrets partagés** entre l'API et n8n, injectés explicitement dans chaque service |

Les secrets partagés (`PIPELINE_SERVICE_TOKEN`, `N8N_WEBHOOK_SECRET`) et
`RESULTS_ACCESS_SECRET` vivent **uniquement** dans le `.env` racine. Ne jamais
changer `RESULTS_ACCESS_SECRET` sur une installation en service : tous les
codes d'accès déjà envoyés deviendraient inutilisables.

⚠️ Dans `api/.env`, les valeurs contenant un `$` littéral (typiquement le hash
werkzeug) doivent garder un **`$` simple**, jamais doublé.

Toutes les variables sont décrites et commentées dans `api/.env.example`
(clés OSINT optionnelles, KEV, sévérité, RAG, boucle agent, surveillance,
plafonds de sortie des LLM…).

### Vérification

```bash
# Catalogue public
curl http://api.localhost/

# Swagger UI interactif
open http://localhost:8080/apidocs

# Statut des backends IA (modèles réellement disponibles)
curl -u admin@example.com:VotreMotDePasse http://localhost:8080/analyze/status

# Frontend, page de résultat, dashboard, éditeur n8n
open http://localhost
open http://localhost/result.html
open http://localhost/dashboard.html
open http://localhost:5678
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
n8n (réseau interne, jeton de service ; chaque appel réessayé 5 fois) ──┐
POST /pass_recon  {recon_id}                                             │
    │ 56 outils OSINT, 2 vagues parallèles                               │
    │   vague 1 : WHOIS, RDAP, DNS, crt.sh, subfinder, assetfinder,      │
    │             GitHub, amass, ip_info, DNSDumpster                    │
    │   → union des sous-domaines découverts                             │
    │   vague 2 : tout le reste (résolution massive, SSL/TLS, email,     │
    │             HTTP, réputation, archives, takeover, fuites…)         │
    │ borné par SCAN_DEADLINE_SECONDS ; boucle agent si activée          │
    ▼                                                                    │
POST /analyze/async + GET /analyze/wait/<id>                             │
    │ règles de sévérité (43) + CISA KEV + RAG par constat               │
    │ cascade IA : DeepSeek (test) → Gemini → Cerebras → Groq            │
    │              → OpenRouter → Ollama local (map-reduce)              │
    │ constats + avis par outil, validés et bornés côté serveur          │
    │ ATT&CK, score, contrôles d'ancrage et de couverture                │
    ▼                                                                    │
POST /recon/<id>/generate_final_report   → rapport narratif IA           │
POST /recon/<id>/generate_report         → graphe + différentiel, PDF,  │
    │                                      chiffrement, mail avec code ──┘
    ▼
Utilisateur (web/result.html) saisit son code d'accès
POST /results/access                     → session de consultation (1 h)
GET  /results/report                     → rapport complet
GET  /results/report.pdf | export.json | export.csv | export.navigator.json
```

En pratique, avec une clé Gemini : 3 à 5 minutes de scan, moins d'une minute
d'analyse. L'administrateur garde le dashboard et les KPI (statut, score,
durées, compteurs) mais ne peut pas lire le contenu d'un dossier chiffré.

---

## Documentation

- **[api/README.md](api/README.md)** — endpoints, authentification, variables
  d'environnement, outils OSINT, sécurité.
- **[docs/PLAN_ACTION.md](docs/PLAN_ACTION.md)** — feuille de route et décisions
  (D1–D11).
- **[docs/phases/](docs/phases/)** — détail de chaque phase (fiabilité,
  ATT&CK, collecte, base de connaissance, graphe, boucle agent).
- **[CLAUDE.md](CLAUDE.md)** — notes techniques détaillées (architecture,
  incidents constatés, conventions).
- Swagger UI : `http://localhost:8080/apidocs` · ReDoc :
  `http://localhost:8080/redoc` · page statique : `http://localhost/docs.html`.

---

## Structure du projet

```
recon-ia/
├── api/                        # API Flask REST OSINT — voir api/README.md
│   ├── app.py                  # Factory Flask (create_app)
│   ├── config.py               # Chargement .env, Swagger, URI base de données
│   ├── migrate.py              # Migrations SQL idempotentes, rôles PostgreSQL
│   ├── models/                 # recon, audit_log, pass_recon_cache, graphe, surveillance
│   ├── routes/                 # 12 blueprints (recon, analyze, report, results, cache, graph…)
│   ├── utils/                  # clients LLM, règles de sévérité, KEV, ATT&CK, PDF et
│   │                           # graphiques, coffre, graphe, différentiel, agent, sources passives
│   ├── data/                   # référentiel ATT&CK, explications, empreintes de takeover
│   ├── static/                 # logo du PDF et des emails, contours des terres
│   ├── tests/                  # pytest (unitaires, sécurité, intégration)
│   ├── .env.example            # Modèle de configuration commenté
│   ├── Dockerfile
│   └── Dockerfile.test         # Image légère pour les tests
├── caddy/Caddyfile             # Reverse proxy HTTPS (seul service exposé)
├── n8n/
│   ├── provision-and-start.sh  # Import credentials + workflows, puis démarre n8n
│   ├── generate-credentials.js # Génère les credentials depuis l'environnement
│   └── workflows/              # recon-ia-main · rag-ingestion · recon-ia-rescan
├── web/                        # Frontend statique (nginx, derrière Caddy)
│   ├── index.html · landing.css · landing.js       # Page publique (CSP stricte)
│   ├── result.html · result.css · result.js        # « Voir le résultat »
│   ├── result-visuals.js       # Graphiques, globe, cartographie
│   ├── dashboard.html · dashboard-graph.*          # Console admin
│   ├── docs.html               # Documentation API statique
│   ├── theme.js                # Thème clair/sombre commun
│   └── assets/                 # Logo, favicons, contours des terres
├── data/                       # Scripts du corpus RAG (OWASP, ATT&CK, ANSSI, CWE…)
├── n8n_ressource/              # Corpus RAG monté dans n8n
├── scripts/run-tests.sh        # Suite pytest dans un conteneur sans réseau
├── scripts/e2e/                # Tests navigateur (Chrome headless)
├── docs/                       # Plan d'action, phases, charte (docs/brand)
├── docker-compose.yml
├── setup.sh                    # Installation locale en une commande
└── README.md
```

Volumes de données locaux (gitignorés) : `postgres_data/`, `n8n_data/`,
`ollama/`, `caddy_data/`, `caddy_config/`.

---

## Tests

```bash
./scripts/run-tests.sh                    # 1 011 tests pytest, conteneur jetable sans réseau
./scripts/run-tests.sh -m security        # tests de sécurité seuls
./scripts/run-tests.sh -m integration     # tests d'intégration seuls
./scripts/e2e/run-result-page.sh          # page de résultat dans Chrome headless (THEME=light|dark)
# Sur la stack démarrée :
ADMIN_AUTH='admin@example.com:MotDePasse' ./scripts/e2e/run-full-flow.sh   # parcours réel complet (SMTP vers Mailpit)
node scripts/e2e/dashboard.mjs <dossier> <chrome>                         # dashboard (WIDTH=375, THEME=light)
node scripts/e2e/page_check.mjs <url> <dossier> <chrome>                  # 6 largeurs, 2 thèmes, CSP, débordement
```

Le parcours complet lit les emails dans Mailpit : il suppose `SMTP_SERVER=mailpit`
dans `api/.env`. Avec un vrai serveur SMTP, tester en soumettant le formulaire
avec sa propre adresse.

---

## n8n — provisioning automatique

Le service `n8n` utilise une image custom (`n8n/Dockerfile`). À chaque
démarrage, `n8n/provision-and-start.sh` :

1. génère les credentials à partir des variables d'environnement : PostgreSQL
   (rôle `rag_writer`, limité au RAG), Ollama, le **jeton de service** de l'API
   (`X-Service-Token`) et le **secret du webhook** (`X-Pipeline-Secret`) ;
2. les importe (stockage chiffré par `N8N_ENCRYPTION_KEY`), puis supprime le
   fichier temporaire qui contient les secrets en clair ;
3. importe les trois workflows versionnés de `n8n/workflows/` :
   `recon-ia-main` (pipeline, **actif**), `rag-ingestion` et `recon-ia-rescan`
   (surveillance planifiée) **inactifs** par défaut.

Tous les appels HTTP du pipeline sont réessayés 5 fois à 5 s d'intervalle :
un redémarrage de l'API pendant un scan ne fait plus échouer le dossier.
**Éviter malgré tout de reconstruire `api` pendant un pipeline** : le scan en
cours repart de zéro.

Les workflows versionnés sont la source de vérité : une modification faite dans
l'éditeur n8n est perdue au prochain redémarrage du conteneur.

---

## RAG — corpus de référence

Avant l'appel au LLM, `routes/analyze.py` interroge par similarité
(`utils/rag_retrieval.py`, pgvector) un corpus stocké dans `rag_documents` :
**une requête par constat**, filtrée par collection (`normes`, `attack`,
`menaces`, `explications`). Les extraits sont injectés comme contexte que les
recommandations doivent citer.

Sources (fichiers `n8n_ressource/combined_*.md`, produits par `data/script_*.py`,
licences documentées dans `docs/phases/PHASE_6.md`) : OWASP Cheat Sheets,
ASVS, WSTG, Top 10, MITRE ATT&CK v20, synthèse des guides ANSSI, Mozilla TLS,
CWE/CAPEC, avis CISA, fiches explicatives, RFC des enregistrements DNS de
confiance.

### État de l'ingestion

Le workflow `n8n/workflows/rag-ingestion.json` vide `rag_documents`, relit tous
les `.md` de `n8n_ressource/`, les découpe, calcule les embeddings
(`nomic-embed-text:v1.5` via Ollama) et les réinsère avec leur collection.

⚠️ Il est **importé mais désactivé** au démarrage : sur Docker Desktop
(Windows), son exécution bloquait n8n (problème d'entrées/sorties du bind
mount, voir `CLAUDE.md` §8). Tant qu'il n'est pas lancé, **la base de
connaissance est vide** et les rapports ne citent aucune norme (« Références
citées : 0 / 0 » dans la fiabilité). L'analyse fonctionne quand même : le RAG
n'est jamais bloquant.

Pour l'alimenter (sur un serveur Linux, en priorité) :

```bash
docker exec ollama ollama pull nomic-embed-text:v1.5      # si absent
docker exec n8n n8n update:workflow --id=8481rbwSG3V1qzCT --active=true
docker compose restart n8n                                  # déclenche l'ingestion
docker exec postgres psql -U reconuser -d recondb \
  -c "SELECT metadata->>'collection', count(*) FROM rag_documents GROUP BY 1;"
```

Pour ajouter une source : régénérer ou déposer un `.md` dans `n8n_ressource/`
(voir `data/script_*.py`), puis relancer l'ingestion. Une base déjà ingérée
sans collection se met à jour sans recalcul des embeddings avec
`data/sql/reindex_collections.sql`.

---

## Sécurité

À lire avant tout déploiement :

- **Passif, non intrusif** — voir la définition précise en haut de ce fichier,
  y compris les contacts directs avec la cible. Ne pas ajouter d'outil actif
  sans revoir le cadre légal et le texte de consentement.
- **Surface exposée** — seul Caddy (80/443) est publié. L'API et n8n ne sont
  publiés que sur `127.0.0.1` ; Postgres, Redis et Ollama nulle part.
- **n8n** — jamais exposé sur Internet ; accès aux variables d'environnement
  bloqué dans les nœuds ; aucun mot de passe admin confié (jeton de service
  limité aux routes du pipeline, retiré par Caddy de toute requête externe) ;
  webhook appelé seulement par l'API, avec un secret d'en-tête. **Créer le
  compte propriétaire n8n dès le premier démarrage.** Ne jamais monter
  `/var/run/docker.sock` dans le conteneur n8n.
- **Base de données** — l'API tourne avec un rôle limité à ses tables
  (`recon_app`) et n8n avec un rôle limité au RAG (`rag_writer`).
- **Résultats** — chiffrés en AES-256-GCM avec une clé dérivée du code d'accès
  du demandeur ; le serveur ne stocke que l'empreinte HMAC du code. Le code
  transite dans le corps d'un POST, jamais dans une URL. Tentatives limitées
  par IP, sessions courtes revalidées à chaque requête.
- **Emails** — aucun rapport en pièce jointe ; le logo est intégré au message
  (pas d'image distante, donc pas de pixel de suivi).
- **Formulaire** — consentement obligatoire, anti-robot Cloudflare Turnstile,
  5 essais maximum par code OTP.
- **Scanner** — chaque requête HTTP sortante, redirections comprises, est
  refusée si l'hôte résout vers une adresse interne (protection SSRF). Les
  réponses des sources tierces sont bornées en taille ; les secrets trouvés
  sur GitHub ne sont jamais conservés en clair.
- **IA** — tout ce que renvoie le LLM est validé (liste blanche de champs,
  énumérations fermées, longueurs bornées) ; la page de résultat n'affiche
  rien autrement qu'en texte (`textContent`) sous une CSP stricte.
- **Conservation** — purge horaire : résultats et identité effacés 7 jours
  après l'expiration du code, demandes non vérifiées après 7 jours, journal
  d'audit après 90 jours.
- **Secrets** — `.env` (aux deux emplacements), `n8n_data/`, `caddy_data/`,
  `postgres_data/` et `ollama/` sont couverts par `.gitignore`. Vérifier le
  diff avant tout `git add -A`.
- **Mot de passe admin** — toujours un **hash werkzeug** dans `ADMIN_PASSWORD`,
  jamais le mot de passe de développement de `setup.sh`.
- **HTTPS** — assuré par Caddy dès que `SITE_ADDRESS`/`API_ADDRESS` sont des
  noms de domaine. `TRUSTED_PROXY_COUNT` est fixé à 1 (Caddy).
- **CORS** — restreindre `CORS_ORIGINS` au domaine réel du frontend.
- **Clés d'API** — jamais renvoyées par l'API ni journalisées, et non
  transmises au conteneur n8n.

Détail complet : [api/README.md § Sécurité](api/README.md#sécurité).
