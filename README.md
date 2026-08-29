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

- **Collecte passive** — 47 outils OSINT (WHOIS, RDAP, DNS, DNSSEC,
  certificats, sous-domaines, en-têtes HTTP, configuration email, réputation
  d'IP, archives web…), exécutés **en parallèle** en deux vagues.
- **Analyse IA** — un LLM interprète les résultats, produit des findings avec
  sévérité, un score de sécurité 0-100 et des recommandations. Chaque finding
  cite obligatoirement **l'outil qui a produit la preuve** (`source_tool`).
- **Rapport PDF** — généré et envoyé par email, avec une section
  « Méthodologie & Sources » qui inventorie chaque outil exécuté, son statut,
  sa durée, et les limites de la collecte.
- **Exports exploitables** — JSON complet avec bloc de provenance et empreinte
  SHA-256 du jeu de données, CSV tabulaire des findings, KPI agrégés.
- **Cache** — les scans (30 jours par défaut) et les analyses IA (7 jours) sont
  mis en cache en base pour éviter les recollectes et les coûts inutiles.
- **RAG (retrieval-augmented generation)** — avant l'appel au LLM, une
  recherche par similarité (pgvector) va chercher les extraits les plus
  pertinents dans un corpus de référence (OWASP Cheat Sheets, ASVS, WSTG,
  Top 10:2021, techniques MITRE ATT&CK Reconnaissance/Resource Development,
  RFC IETF des enregistrements DNS de confiance) et les injecte comme
  contexte que le rapport doit citer — les recommandations s'ancrent dans une
  norme reconnue plutôt qu'une reformulation générique.
- **Dashboard** — console admin (`web/dashboard.html`) avec KPI opérationnels
  et une section « Conformité & Recherche » (traçabilité outil→finding,
  couverture MITRE ATT&CK, fiabilité agrégée des 47 outils) pensée pour une
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

| Service    | Image / build            | Port                   | Rôle |
|------------|--------------------------|------------------------|------|
| `web`      | `nginx:alpine`           | **5000** → 80          | frontend statique (`./web`) |
| `api`      | build `./api`            | **8080**               | API Flask REST OSINT + IA + PDF (gunicorn) |
| `n8n`      | build `./n8n`            | **5678**               | orchestration des workflows (image custom, provisioning auto) |
| `postgres` | `pgvector/pgvector:pg16` | interne (non publié)   | base principale + RAG vectoriel (`pgvector`) |
| `ollama`   | `ollama/ollama`          | interne (non publié)   | LLM local (dernier recours) + embeddings RAG |
| `redis`    | `redis:alpine`           | interne (non publié)   | stockage partagé du rate limiter |

Il n'y a **pas** de service Qdrant : le RAG est stocké dans la table
`rag_documents` de PostgreSQL via l'extension `pgvector`. Il n'y a pas non plus
de service `nginx` reverse-proxy ni `certbot` — le TLS doit être assuré par un
proxy externe.

`postgres`, `ollama` et `redis` ne publient aucun port sur l'hôte : ils ne sont
joignables que sur le réseau interne Docker (Ollama et Redis n'ont aucune
authentification, PostgreSQL contient des données personnelles).

---

## Démarrage rapide

### Prérequis

- Docker 20+ et Docker Compose 2+
- Au moins une clé LLM gratuite (sinon, repli sur Ollama local) :
  [Gemini](https://aistudio.google.com/apikey) ·
  [Cerebras](https://cloud.cerebras.ai) ·
  [Groq](https://console.groq.com/keys) ·
  [OpenRouter](https://openrouter.ai/keys)
- Un compte SMTP pour l'envoi des codes OTP et des rapports

### Installation — en une commande (recommandé)

```bash
git clone https://github.com/your-user/recon-ia.git
cd recon-ia
./setup.sh
```

Génère des `.env` de développement local (identifiants clairement marqués
« dev », à ne jamais réutiliser sur un déploiement exposé publiquement),
build + démarre tous les services, attend qu'ils soient prêts, télécharge le
modèle Ollama local, puis affiche les URLs d'accès et les identifiants
générés. Idempotent : ré-exécutable sans danger. Pour une configuration
manuelle complète (clés LLM réelles, SMTP, domaine de production...), voir
l'installation détaillée ci-dessous.

### Installation — manuelle (configuration complète/production)

```bash
# 1. Cloner le dépôt
git clone https://github.com/your-user/recon-ia.git
cd recon-ia

# 2. Configurer l'API (variables runtime des conteneurs)
cp api/.env.example api/.env
# Éditer api/.env — au minimum : POSTGRES_*, SMTP_*, ADMIN_EMAIL,
# ADMIN_PASSWORD (hash), SECRET_KEY, DOMAIN_URL_API, et une clé LLM

# 3. Générer le hash du mot de passe admin
docker run --rm python:3.11-slim sh -c \
  "pip install -q werkzeug && python3 -c \
   \"from werkzeug.security import generate_password_hash; print(generate_password_hash('VotreMotDePasse'))\""
# Coller le résultat dans api/.env → ADMIN_PASSWORD=pbkdf2:sha256:...
# ⚠️ NE PAS doubler les « $ » du hash (voir « Deux fichiers .env » ci-dessous)

# 4. Créer le .env RACINE (interpolation ${VAR} de docker-compose.yml)
cat > .env <<'EOF'
POSTGRES_USER=reconuser
POSTGRES_PASSWORD=...
POSTGRES_DB=recondb
DOMAIN_URL_API=https://api.votredomaine.com
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD_PLAIN=VotreMotDePasse
EOF

# 5. Lancer tous les services
docker compose up -d

# 6. Les migrations DB sont jouées automatiquement par l'entrypoint.
#    Pour les relancer manuellement :
docker exec api python migrate.py

# 7. Vérifier
docker compose ps
docker compose logs -f api
```

### Deux fichiers `.env` — à ne pas confondre

| Fichier | Rôle | Atteint les conteneurs ? |
|---|---|---|
| `api/.env` | **source de vérité runtime**. Chargé par `env_file:` pour les services `api` et `postgres`, et relu directement en Python par l'application | **oui** |
| `.env` (racine) | **uniquement** l'interpolation `${VAR}` dans le texte de `docker-compose.yml` | **non** |

Le `.env` racine doit contenir `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`POSTGRES_DB`, `DOMAIN_URL_API`, **`ADMIN_EMAIL`** et **`ADMIN_PASSWORD_PLAIN`**.
Sans eux, Docker Compose substitue une chaîne vide, avec deux conséquences
concrètes :

- `DOMAIN_URL_API` vide casse silencieusement `{{ $env.DOMAIN_URL_API }}` dans
  le workflow n8n principal ;
- `ADMIN_EMAIL` / `ADMIN_PASSWORD_PLAIN` vides empêchent le provisioning de la
  **credential Basic Auth** du workflow n8n principal — tous ses appels vers
  l'API échouent alors en boucle.

`ADMIN_PASSWORD_PLAIN` est le mot de passe **en clair** correspondant au hash
`ADMIN_PASSWORD`. Il doit être renseigné **à la fois dans `api/.env` et dans le
`.env` racine**, et gardé synchronisé manuellement.

⚠️ Dans `api/.env`, les valeurs contenant un `$` littéral (typiquement le hash
werkzeug) doivent garder un **`$` simple**, jamais doublé — même si Docker
Compose émet un avertissement « variable is not set ». L'application relit le
fichier brut et écrase la valeur interpolée par Docker ; doubler le `$` casse
l'authentification silencieusement.

### Vérification

```bash
# Catalogue public
curl http://localhost:8080/

# Swagger UI interactif
open http://localhost:8080/apidocs

# Statut des backends IA
curl -u admin@example.com:VotreMotDePasse http://localhost:8080/analyze/status

# KPI agrégés
curl -u admin@example.com:VotreMotDePasse http://localhost:8080/recon/stats

# Frontend et n8n
open http://localhost:5000
open http://localhost:5678
```

---

## Workflow complet

```
Utilisateur (web/index.html)
    │ webhook n8n
    ▼
POST /recon  (domaine + identité + email + accord)
    │ → code OTP envoyé par email
    ▼
POST /verify_email  (code à 6 chiffres)
    │ → dossier activé
    ▼
POST /pass_recon  {recon_id}
    │ 47 outils OSINT passifs, 2 vagues parallèles
    │   vague 1 (9)  : whois, rdap, dns, crt.sh, subfinder,
    │                  assetfinder, github, amass, ip_info
    │   → union des sous-domaines découverts
    │   vague 2 (38) : tout le reste (DNS, SSL/TLS, email, HTTP,
    │                  réputation, archives, takeover…)
    │ borné par SCAN_DEADLINE_SECONDS, SCAN_MAX_WORKERS threads
    ▼
POST /analyze/async + GET /analyze/wait/<id>
    │ cascade IA : DeepSeek (test) → Gemini → Cerebras → Groq → OpenRouter → Ollama local
    │ recherches web ciblées (CVE, OWASP, standards)
    │ chaque finding porte un `source_tool` obligatoire
    │ score de sécurité + grade dénormalisés en base
    │ mapping MITRE ATT&CK déterministe (pas inventé par le LLM)
    ▼
POST /recon/<id>/generate_final_report      → rapport narratif IA
POST /recon/<id>/generate_report            → PDF + envoi email
    ▼
GET /recon/<id>/report.pdf     → téléchargement du PDF
GET /recon/<id>/export.json    → dataset + provenance + SHA-256
GET /recon/<id>/export.csv     → findings tabulaires
GET /recon/stats               → KPI agrégés sur toute la base
```

---

## Documentation API

La documentation complète (endpoints, authentification, variables
d'environnement, outils OSINT, sécurité) est dans **[api/README.md](api/README.md)**.

Documentation interactive :

- Swagger UI : `http://localhost:8080/apidocs`
- ReDoc : `http://localhost:8080/redoc`
- Page statique : `http://localhost:5000/docs.html`

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
│   ├── routes/                 # 9 blueprints (voir api/README.md)
│   ├── utils/                  # parallel, clients LLM, PDF, email, validators…
│   ├── errors/                 # Handlers d'erreurs JSON
│   ├── tests/                  # pytest
│   ├── requirements.txt
│   ├── .env.example            # Modèle de configuration
│   └── Dockerfile
├── n8n/
│   ├── Dockerfile              # Image custom avec provisioning automatique
│   ├── provision-and-start.sh  # Import credentials + workflows, puis démarre n8n
│   ├── generate-credentials.js # Génère les credentials depuis l'environnement
│   └── workflows/              # recon-ia-main.json · rag-ingestion.json
├── web/                        # Frontend statique (nginx)
│   ├── index.html              # Page publique (poste sur le webhook n8n)
│   ├── dashboard.html          # Console admin (Basic Auth vers l'API)
│   ├── docs.html               # Documentation API statique
│   └── vendor/chart.umd.min.js
├── data/                       # Scripts d'agrégation du corpus RAG (OWASP, ASVS, WSTG)
├── n8n_ressource/              # Corpus RAG monté dans n8n
├── scripts/                    # init-letsencrypt.sh · renew-certs.sh
├── docker-compose.yml
├── .env                        # Interpolation ${VAR} du compose uniquement
└── README.md
```

Volumes de données locaux (gitignorés, créés à l'exécution) : `postgres_data/`,
`n8n_data/`, `ollama/`, `n8n_certs/`, `certbot/conf/`.

---

## n8n — provisioning automatique

Le service `n8n` utilise une image custom (`n8n/Dockerfile`). À chaque
démarrage, `n8n/provision-and-start.sh` :

1. génère les credentials à partir des variables d'environnement
   (`n8n/generate-credentials.js`) : PostgreSQL, Ollama, et la credential
   **Basic Auth** de l'API — cette dernière **uniquement si `ADMIN_EMAIL` et
   `ADMIN_PASSWORD_PLAIN` sont renseignés** ;
2. les importe (`n8n import:credentials`), puis supprime le fichier temporaire
   qui contient les mots de passe en clair ;
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
- **L'UI n8n (port 5678) n'a aucune authentification** : `N8N_BASIC_AUTH_*`
  n'est pas configuré, et l'accès aux variables d'environnement dans les nœuds
  est activé (nécessaire au workflow principal). Quiconque atteint ce port peut
  lire `ADMIN_PASSWORD_PLAIN` et `POSTGRES_PASSWORD` en clair via un Code node.
  **Ne jamais exposer 5678 publiquement sans authentification devant** (reverse
  proxy avec auth, VPN, ou restriction réseau).
- **Ne jamais monter `/var/run/docker.sock` dans le conteneur n8n** : cela
  donne un contrôle root complet sur l'hôte. Aucun workflow du projet n'en a
  besoin.
- **Secrets** — `.env` (aux deux emplacements), `n8n_data/`, `n8n_certs/`,
  `certbot/conf/`, `postgres_data/` et `ollama/` sont couverts par
  `.gitignore`. Vérifier le diff avant tout `git add -A`.
- **Mot de passe admin** — toujours un **hash werkzeug** dans `ADMIN_PASSWORD`.
  `ADMIN_PASSWORD_PLAIN` n'existe que pour provisionner la credential n8n ;
  sur un déploiement réel, considérer ce mot de passe comme exposé au réseau
  qui peut atteindre n8n.
- **HTTPS** — le compose ne contient pas de reverse proxy. Placer nginx,
  Traefik ou Caddy devant, et ajuster `TRUSTED_PROXY_COUNT` au nombre **exact**
  de proxys de confiance (le surévaluer permet d'usurper une IP via
  `X-Forwarded-For` et de contourner le rate limiting).
- **CORS** — restreindre `CORS_ORIGINS` au domaine réel du frontend. En
  production, une valeur vide refuse toute requête cross-origin.
- **Clés d'API LLM** — sensibles ; elles ne sont jamais renvoyées par l'API ni
  journalisées, et ne sont plus transmises au conteneur n8n.

Détail complet : [api/README.md § Sécurité](api/README.md#sécurité).
