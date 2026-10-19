# Phase 6 — Base de connaissance

Livrée le 2026-10-19 (code, corpus et tests ; intégration dans `analyze.py`
et réindexation de la base de production à faire — voir « À intégrer »).

Objectif (docs/PLAN_ACTION.md §5) : un corpus organisé en collections,
interrogé finding par finding, plus un contexte comparatif anonymisé tiré
des scans passés.

---

## 1. Collections du RAG

| Collection | Fichiers (`n8n_ressource/`) | Mode |
|---|---|---|
| `normes` | `combined_owasp_*.md`, `combined_rfc_trust_records.md`, **`combined_anssi_guides.md`**, **`combined_mozilla_tls.md`**, **`combined_cwe_capec.md`** | RAG |
| `attack` | `combined_mitre_attack_recon.md` (phase 4) | RAG |
| `menaces` | **`combined_cisa_advisories.md`** | RAG |
| `explications` | **`combined_explications.md`** (généré depuis `api/data/explanations/*.json`) | RAG + modales |
| *(hors RAG)* | **`api/data/takeover_fingerprints.json`** (can-i-take-over-xyz) | consultation directe |

KEV (phase 3) et Tranco (phase 5) ne sont pas refaits ici.

### Règle « fichier → collection »

Fondée sur le nom de fichier, pour qu'une nouvelle source `combined_<x>.md`
soit classée sans toucher au workflow (première règle qui correspond) :

| Le nom contient | Collection |
|---|---|
| `mitre_attack` | `attack` |
| `combined_cisa` | `menaces` |
| `combined_explications` | `explications` |
| *(sinon)* | `normes` |

Elle existe en trois exemplaires, vérifiés identiques par
`tests/test_phase6_collections.py` :
`api/utils/rag_collections.py` (référence Python), l'expression du nœud n8n,
et le `CASE` de `data/sql/reindex_collections.sql`.

### Workflow `n8n/workflows/rag-ingestion.json`

- **Nouveau nœud** « Métadonnées RAG (collection) » (Set 3.4) entre
  *Extract from File* et *Postgres PGVector Store*. Il produit
  `{data, source, collection}` : `source` = nom du fichier lu par
  *Read/Write Files from Disk* (`json.fileName`, repli `binary.data.fileName`),
  `collection` = règle ci-dessus.
- **Default Data Loader** : `jsonMode: expressionData`,
  `jsonData: {{ $json.data }}` et métadonnées `source` + `collection`.
  Auparavant (`allInputData`) le chargeur indexait l'objet JSON entier et
  `metadata.source` valait la valeur par défaut de LangChain (`blob`), si bien
  que `rag_retrieval.py` affichait une source sans intérêt. Désormais
  `metadata->>'source'` = `combined_owasp_asvs.md` etc. et
  `metadata->>'collection'` est renseigné à chaque extrait.
- Ni le compose ni le n8n en cours n'ont été touchés : le workflow sera
  réimporté au prochain démarrage du conteneur `n8n`
  (`provision-and-start.sh`).

---

## 2. Réindexation de l'existant

État constaté sur le banc local le 2026-10-19 : `rag_documents` **vide**
(0 ligne) — rien à rattraper, la prochaine ingestion posera la collection.

Deux procédures, au choix :

**A. Ré-ingestion complète (recommandée)** — le workflow commence par
`TRUNCATE rag_documents` puis réindexe tout `n8n_ressource/`.

1. `n8n_ressource/` contient déjà les 5 nouveaux fichiers (copiés le
   2026-10-19). Après une régénération : `cp data/combined_*.md n8n_ressource/`.
2. Redémarrer le conteneur `n8n` (le déclencheur `init`/`activate` relance
   l'ingestion) — **à faire par l'exploitant**, pas pendant les tests en cours.
3. Contrôle :
   `docker exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT metadata->>'collection', metadata->>'source', count(*) FROM rag_documents GROUP BY 1,2 ORDER BY 1,2"`

**B. Rattrapage en place, sans recalcul des embeddings** —
`data/sql/reindex_collections.sql` :

```sh
docker exec -i postgres psql -U rag_writer -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 \
    < data/sql/reindex_collections.sql
```

- Une transaction ; `UPDATE rag_documents SET metadata = metadata || {"collection": …}`
  uniquement sur les lignes **sans** clé `collection` (idempotent).
- Droits : n'utilise que `SELECT`/`UPDATE` sur `rag_documents`, compatibles
  avec `ROLE_GRANTS['rag_writer']` (`api/migrate.py`) ; aucun DDL, aucune
  autre table (vérifié par un test de sécurité).
- Si `metadata.source` ne contient pas de nom de fichier (anciennes lignes
  `blob` ou script de contournement), repli heuristique sur le contenu :
  identifiant de technique `T1xxx` + mention « ATT&CK » → `attack`, sinon
  `normes`. En cas de doute, préférer la procédure A.

Aucune migration de schéma n'est nécessaire (la colonne `metadata JSONB` et
son index GIN `ix_rag_documents_metadata` existent déjà) : rien à ajouter à
`migrate.py`. Pour accélérer le filtre de la phase 3, un index d'expression
optionnel peut être ajouté par le propriétaire de `migrate.py` :
`CREATE INDEX IF NOT EXISTS ix_rag_documents_collection ON rag_documents ((metadata->>'collection'))`.

---

## 3. Sources et licences

| Fichier | Script | Source | Licence | Contenu repris |
|---|---|---|---|---|
| `combined_anssi_guides.md` | `data/script_anssi_guides.py` | ANSSI : *Recommandations de sécurité relatives à TLS* (PA-035), *Mise en œuvre d'un site web : standards de sécurité côté navigateur* (PA-009), *Sécurisation des sites web* (NT-009), *Bonnes pratiques pour l'acquisition et l'exploitation de noms de domaine* | Licence Ouverte / Etalab 2.0 (sauf mention contraire du PDF) — attribution « ANSSI », date, lien | **Synthèse rédigée pour Recon-IA** (`data/sources/anssi_guides_resume.md`), qui cite chaque guide. cyber.gouv.fr renvoie un défi anti-robot (Incapsula) aux téléchargements automatisés : les URL n'ont pas pu être vérifiées en ligne. Option : `script_anssi_guides.py <dossier_pdf>` ajoute le texte intégral des PDF téléchargés à la main (`pip install pypdf`). La section « messagerie » est une synthèse RFC + principes ANSSI, explicitement **non** attribuée à un guide ANSSI (aucun guide dédié vérifié). |
| `combined_mozilla_tls.md` | `data/script_mozilla_tls.py` | `ssl-config.mozilla.org/guidelines/latest.json` (v6.0) | MPL 2.0 | Données structurées des profils modern/intermediate/old ; textes explicatifs originaux (le wiki *Server Side TLS*, CC BY-SA, n'est pas repris). |
| `combined_cwe_capec.md` | `data/script_cwe_capec.py` | MITRE CWE (`cwec_latest.xml.zip`) et CAPEC (`capec_latest.xml`) | CWE™/CAPEC™ Terms of Use : reproduction libre avec mention « © The MITRE Corporation » (présente dans le fichier) | 29 CWE + 19 CAPEC correspondant aux constats d'une recon passive (pas les catalogues entiers). |
| `combined_cisa_advisories.md` | `data/script_cisa_advisories.py` | Flux RSS CISA *Cybersecurity Advisories* (avis conjoints `AAyy-nnnX` seulement) | Domaine public (œuvre du gouvernement fédéral US, 17 U.S.C. §105) ; ne pas laisser entendre un soutien de CISA | 10 avis (ceux présents dans le flux au 2026-10-19), texte nettoyé, ≤ 12 000 caractères chacun. Le CDN de cisa.gov répond 403 au client `requests` mais pas à curl : `curl -o cisa.xml <flux>` puis `script_cisa_advisories.py cisa.xml`. |
| `combined_explications.md` | `data/script_explications.py` | `api/data/explanations/*.json` (19 contrôles) | Textes originaux Recon-IA ; structure inspirée de la page « About » de **web-check** (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check), citée dans chaque fichier | — |
| `api/data/takeover_fingerprints.json` | `data/script_takeover_fingerprints.py` | `EdOverflow/can-i-take-over-xyz` `fingerprints.json` | CC BY 4.0 (attribution dans le fichier) | 76 empreintes (service, suffixes CNAME, statut, NXDOMAIN). |

Tous les scripts se lancent **à la main** (réseau requis sauf
`script_explications.py`), par exemple sans Python sur l'hôte :

```sh
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/repo" -w /repo recon-ia-api-test \
    python -I data/script_cwe_capec.py
```

### Contenus tiers = données non fiables

`api/utils/corpus_sanitizer.py` (utilisé par tous les nouveaux scripts) :
HTML → texte (suppression `script/style/iframe/svg/form…` et des commentaires),
retrait des caractères de contrôle et invisibles (zero-width, bidi),
neutralisation des motifs d'injection de prompt (« ignore previous
instructions », `<|im_start|>`, `[INST]`, « system prompt », faux tours
`system:`…) remplacés par `[contenu neutralisé]`, neutralisation des liens
`javascript:`/`data:`, suppression des faux titres markdown, troncature.
XML (CISA, CWE, CAPEC) analysé par lxml **sans résolution d'entités ni
réseau** (protection XXE, testée).

---

## 4. Collection `explications` (fichiers JSON)

`api/data/explanations/<id>.json`, un par contrôle : dmarc, spf, dkim,
mta_sts, hsts, csp, en_tetes_securite, cookies, tls, certificat, dnssec, caa,
takeover, ports_exposes, fuites_donnees, listes_blocage, tranco,
security_txt, typosquatting.

```json
{
  "id": "dmarc", "titre": "…", "categorie": "Messagerie",
  "outils": ["dmarc_check", "email_config"],
  "pourquoi": "…", "risque": "…",
  "comment_corriger": ["…", "…"],
  "exemple": "…",                       // optionnel, texte brut
  "references": [{"titre": "RFC 7489 — DMARC", "url": "https://…"}],
  "credits": "Structure inspirée de … web-check … licence MIT …"
}
```

`api/utils/explanations.py` : `load_all()`, `get(id)`, `for_tool(tool_key)`,
`validate(entry)`, `render_markdown(entry)`, `render_corpus()`. Texte brut
uniquement (aucun `<`/`>`, aucune entité HTML, URL en `https://`) : pour les
modales du dashboard, insérer avec `textContent`. Un fichier invalide fait
échouer `load_all()` (et le script de génération).

> `tranco.json` cite l'outil `tranco_rank` : nom supposé de l'outil de la
> phase 5, à corriger si celle-ci en choisit un autre.

---

## 5. Statistiques comparatives — `api/utils/scan_stats.py`

```python
from utils.scan_stats import comparative_context, tld_of

comparative_context(tld: str, signals: dict) -> list[str]
```

- `tld` : « bj » ou « .bj » (`tld_of(domain)` le calcule ; invalide → seules
  les stats tous TLD sont utilisées) ;
- `signals` : la sortie de `routes/analyze.py::_extract_signals` ; la clé
  `domain` sert **uniquement** à exclure le domaine courant de l'échantillon ;
- retour : au plus 6 phrases (`SCAN_STATS_MAX_SENTENCES`), faiblesses
  d'abord, par exemple
  « Comme ce domaine, 65 % des domaines .bj déjà analysés par Recon-IA
  (échantillon : 12) n'ont pas d'enregistrement DMARC. » ;
  ou, pour un point fort notable (≥ 50 % du périmètre en défaut),
  « Ce domaine fait mieux que la moyenne : … » ;
- **ne lève jamais** (liste vide si base indisponible, échantillon trop
  petit, signaux vides).

Autres fonctions : `compute_stats(tld=None, exclude_domain=None)` (dict
agrégé pour un futur affichage dashboard), `features_from_scan(result)`,
`features_from_signals(signals)`, `reset_cache()`.

17 contrôles : DMARC absent / p=none, SPF absent / permissif (+all, ?all),
DKIM absent, MTA-STS absent, DNSSEC absent, CAA absent, HSTS absent, CSP
absente, TLS 1.0/1.1/SSL accepté, certificat expiré ou proche, security.txt
absent, ports d'administration exposés (Shodan), candidat takeover, IP en
DNSBL, fuites de données. Un outil en erreur/timeout → contrôle non évaluable
(exclu du dénominateur).

**Source** : `pass_recon_cache` uniquement (les résultats de `recon` sont
chiffrés — D3). Scan le plus récent par domaine, fenêtre
`SCAN_STATS_WINDOW_DAYS` (365 j), au plus `SCAN_STATS_MAX_ROWS` (500)
domaines. Cache mémoire incrémental par (id, updated_at) : seuls les
`result_json` nouveaux ou rescannés sont relus. Requêtes ORM (paramétrées).

**Anonymat** :
- k-anonymat : une statistique exige ≥ `SCAN_STATS_MIN_SAMPLE` (10) domaines
  évaluables **pour ce contrôle** ; plancher absolu 5 même si la variable est
  plus basse ;
- TLD sous le seuil → repli sur « tous TLD confondus » (jamais un petit TLD) ;
- domaine courant exclu ; domaines manipulés en mémoire sous forme
  d'empreinte SHA-256 ; phrases construites sur gabarits fixes + TLD validé
  par regex ; aucun texte de scan dans la sortie ;
- pourcentages arrondis au multiple de 5 (limite les attaques par
  différence).

Pas d'indexation vectorielle des scans bruts.

---

## 6. Empreintes de takeover — `api/utils/takeover_fingerprints.py`

`match_cname(cname) -> dict | None` : correspondance par **suffixe DNS**
(le plus long gagne) sur `api/data/takeover_fingerprints.json`, avec
`service`, `status` (Vulnerable / Not vulnerable / Edge case), `vulnerable`,
`nxdomain`, `fingerprint`.

Constat utile pour la phase 5 : `routes/recon.py::_subdomain_takeover`
teste `service_domain in cname_target` (sous-chaîne : `evilfastly.com`
correspondrait) et signale des services que can-i-take-over-xyz classe
« Edge case » ou « Not vulnerable » au 2026-10-19 : Fastly et Zendesk (Not
vulnerable), GitHub Pages (Edge case, sans CNAME de référence), Shopify,
Heroku, Netlify (Edge case) — source de faux positifs.

---

## 7. Fichiers

Créés :
- `api/utils/rag_collections.py`, `api/utils/corpus_sanitizer.py`,
  `api/utils/explanations.py`, `api/utils/scan_stats.py`,
  `api/utils/takeover_fingerprints.py`
- `api/data/explanations/*.json` (19), `api/data/takeover_fingerprints.json`
- `data/script_anssi_guides.py`, `data/script_mozilla_tls.py`,
  `data/script_cwe_capec.py`, `data/script_cisa_advisories.py`,
  `data/script_explications.py`, `data/script_takeover_fingerprints.py`
- `data/sources/anssi_guides_resume.md`, `data/sql/reindex_collections.sql`
- `data/combined_{anssi_guides,mozilla_tls,cwe_capec,cisa_advisories,explications}.md`
  (+ copies dans `n8n_ressource/`)
- `api/tests/test_phase6_{collections,explanations,sanitizer,scan_stats,takeover}.py`

Modifié : `n8n/workflows/rag-ingestion.json`.

---

## 8. Tests

`api/tests/test_phase6_*.py` — 113 tests (dont 46 `security`, 11
`integration`), tous verts ; suite complète : 755 verts, 11 ignorés.

```sh
# depuis la racine (le glob doit être développé dans api/)
./scripts/run-tests.sh $(cd api && ls tests/test_phase6_*.py)
# → 102 passés, 11 ignorés : les tests du workflow n8n, du SQL et des
#   scripts data/ ont besoin de fichiers hors api/. Pour les inclure :
R="$(pwd -W)"; MSYS_NO_PATHCONV=1 docker run --rm --network none \
  -v "$R/api:/app" -v "$R/n8n:/n8n:ro" -v "$R/data:/data:ro" -w /app \
  recon-ia-api-test python -m pytest -p no:cacheprovider $(cd api && ls tests/test_phase6_*.py)
# → 113 passés
```

- **unitaires** : règle de collection, extraction des 17 caractéristiques
  (scan brut, signaux compacts, accord entre les deux), arrondi, TLD,
  rendu markdown, correspondance de suffixe takeover, rendu CWE ;
- **sécurité** : k-anonymat global et par contrôle, plancher, exclusion du
  domaine courant, aucun nom de domaine en sortie, TLD hostile, aucune
  exception ; JSON d'explications UTF-8 strict, sans HTML, URL https,
  validateur qui rejette HTML/`javascript:`/entités/clé inconnue ;
  sanitizer (script/style/iframe/commentaires, injections FR/EN, caractères
  invisibles, liens dangereux) ; flux CISA piégé (XXE, faux domaine, script,
  injection) ; SQL limité aux droits `rag_writer` ;
- **intégration** : SQLite de test (fixture `app`) peuplée de lignes
  `pass_recon_cache` → `compute_stats` (TLD, global, dédoublonnage, fenêtre,
  JSON corrompu, cache incrémental) et `comparative_context` (TLD, repli
  tous TLD, base trop petite).

---

## 9. À intégrer (autres propriétaires)

1. **`routes/analyze.py` (phase 3)** — aux deux points d'entrée, après
   `_extract_signals` :
   ```python
   from utils.scan_stats import comparative_context, tld_of
   signals["comparative_context"] = comparative_context(tld_of(domain), signals)
   ```
   et une consigne dans `_build_messages` : contexte statistique agrégé, à
   utiliser pour situer le domaine (« comme 65 % des domaines .bj… »), jamais
   comme une preuve de finding.
2. **`utils/rag_retrieval.py` (phase 3)** — filtre
   `metadata->>'collection' = :c` : les valeurs sont `normes`, `attack`,
   `menaces`, `explications` (`utils.rag_collections.COLLECTIONS`).
   `metadata->>'source'` contient désormais le nom de fichier.
3. **Réindexation** — procédure A ou B (§2) sur la base de production.
4. **`migrate.py` (phase 7)** — optionnel : index
   `((metadata->>'collection'))` (§2).
5. **`routes/recon.py` (phase 5)** — optionnel : remplacer
   `TAKEOVER_SERVICES` par `utils.takeover_fingerprints.match_cname` (§6) ;
   confirmer le nom de l'outil Tranco cité par `tranco.json`.
6. **Dashboard (phase 7)** — modales : `utils.explanations.get(id)` /
   `for_tool(tool_key)` via une route à créer, affichage en `textContent`.
7. **CLAUDE.md / PLAN_ACTION.md** — reporter cette phase (non modifiés ici,
   par consigne).
