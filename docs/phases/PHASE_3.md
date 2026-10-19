# Phase 3 — Fiabilité de l'analyse (2026-10-19)

Objectif du plan : *un score et des findings qu'on peut défendre*. Le LLM
propose ; des contrôles déterministes, appliqués aux **données brutes du
scan**, tranchent. Aucun nouvel appel LLM.

## Ce qui a été fait

| Point du plan | Où | Résumé |
|---|---|---|
| CISA KEV | `api/utils/kev.py` (nouveau), appel dans `stale_scan_watchdog.py` | JSON officiel téléchargé au plus une fois par `KEV_REFRESH_HOURS` (24 h), cache disque (écriture atomique) + mémoire, échec non bloquant et journalisé, pas de nouvelle tentative avant `KEV_RETRY_MINUTES` après un échec. Une CVE observée présente dans KEV → règle `cve_kev` → **CRITICAL**. |
| B6 | `api/utils/finding_sanitizer.py` | Toute CVE citée (titre, description, evidence, recommandation, références, URL) doit être dans les CVE observées (Shodan `vulns` / `vulns_enriched` / `ips[].vulns`, outil en `success`). Sinon retirée ; finding retiré s'il ne repose que sur elle (titre centré sur la CVE sans autre CVE vérifiée, ou evidence vide une fois la CVE ôtée). Échec fermé : aucune liste → aucune CVE acceptée. |
| B5 | `api/utils/severity_rules.py` (nouveau) | Table de 43 règles (email, DNS, TLS, en-têtes, takeover, ports, CVE/KEV/EPSS/CVSS, réputation, fuites, typosquatting, fichiers sensibles, secrets). Voir « Sévérité déterministe ». |
| `confidence`, `observed_at` | sanitizer, `severity_rules.finalize_confidence`, `_OUTPUT_SCHEMA`, prompts cloud et Ollama | Voir « Nouveaux champs ». |
| B7 | `api/utils/rag_retrieval.py` (réécrit), `routes/analyze.py`, `utils/ollama_client.py` | Une requête par constat (avant le LLM) puis par finding sans constat (après), 2 extraits chacune, filtrées par `metadata->>'collection'`, repli sans filtre si aucune ligne n'a de collection. `references` `[{collection, source}]` sur chaque finding. |
| Mesure avant/après | `api/tools/measure_phase3.py` + `api/tests/fixtures/phase3/` | Hors ligne, voir « Mesure ». |
| Accroche phase 4 | `routes/analyze.py::_annotate_attack` | `from utils.attack_enablement import annotate_findings` protégé (ImportError → no-op ; exception ou retour non-liste → findings inchangés). |

### Restructuration de `routes/analyze.py`

Le post-traitement était dupliqué entre `analyze()` (sync) et
`_run_bg_analysis()` (async). Il est désormais factorisé :

- `_prepare_phase3(recon_json, signals, fallback_query)` — **avant** le LLM :
  CVE observées, KEV, `detect_observations()`, ajout de
  `signals["deterministic_findings"]` (constats déjà établis, montrés au
  modèle), `signals["network"]["shodan_internetdb"]["kev_cves"]` et
  `signals["rag_context"]` (RAG par constat).
- `_postprocess_report(report, signals, ctx, backend)` — **après** le LLM,
  dans cet ordre : liste blanche des champs de premier niveau du LLM →
  `sanitize_findings` (+ B6) → `apply_severity_rules` (B5) → bornage
  `strengths` / `executive_summary` / `immediate_actions` →
  `attach_references` (B7) → `_annotate_attack` (phase 4) →
  `compute_security_score` → `risk_score`/`risk_level` déterministes →
  `attack_surface` → `grounding_check` → `finalize_confidence` →
  `coverage_check` → `severity_check`.

## Sévérité déterministe (B5)

1. `detect_observations(scan, kev)` donne pour chaque règle un état
   `observed` / `absent` / `unknown`, lu **uniquement** dans les données
   brutes des outils (jamais dans le texte du LLM).
2. Chaque finding est rattaché à des règles par son titre puis son
   evidence (mots-clés ; les règles « absence » exigent un marqueur
   d'absence à ≤ 3 mots du sujet). Puis :

| Situation | Sévérité finale | `severity_rule` |
|---|---|---|
| Règle `observed` (la plus grave si plusieurs) | celle de la règle | id de la règle (`dmarc_missing`, `cve_kev`…) |
| CVE citée (vérifiée par B6) | KEV → CRITICAL, EPSS ≥ seuil → HIGH, CVSS ≥ 9 → HIGH, 7–8,9 → MEDIUM, sinon LOW | `cve_kev`, `cve_epss_high`, `cve_cvss_critical`, `cve_cvss_high`, `cve_cvss_low` |
| Contenu positif, aucun défaut prouvé | INFO | `positive_observation` |
| Seules des règles `absent` (la donnée dit le contraire), rattachement net par le titre | **finding retiré** (tracé dans `severity_check.dropped`) | — |
| Idem, rattachement fragile (evidence, tournure « mais… ») | INFO | `contradicted_by_data` |
| Règles `unknown` seulement (outil absent/en échec) | min(LLM, MEDIUM) | `unverified` |
| Aucune règle | min(LLM, `SEVERITY_UNMATCHED_CAP`) | `llm_capped` / `llm_proposed` |
| Doublon d'une règle sans sujet multiple (ex. deux « HSTS absent ») | fusionné dans le premier (`source_tools` unis) | — |

3. Les constats `observed` de sévérité ≥ `SEVERITY_INJECT_MIN` (HIGH par
   défaut) qu'aucun finding ne couvre sont **ajoutés** (`generated_by:
   "rule"`, titre/recommandation de la table, evidence tirée de la donnée).
   Ils sont exclus de `coverage_check` (qui mesure le modèle).

Choix de calibrage notables : CVE Shodan = version déduite, jamais
confirmée → CVSS ≥ 9 est HIGH, seul KEV donne CRITICAL. Takeover passif
non confirmé → HIGH (comme `routes/recon.py`). DKIM introuvable → LOW,
confiance `low` (sélecteurs devinés). X-XSS-Protection absent → INFO
(en-tête obsolète). MTA-STS/TLS-RPT absents sans MX → non applicables.

**Score** : `security_score` reste `compute_security_score()` (inchangé),
mais calculé sur les sévérités **finales**. `risk_score` = `100 −
security_score` (l'auto-évaluation du modèle est conservée dans
`risk_score_llm`) ; `risk_level` = sévérité finale la plus haute (LOW si
rien au-dessus de LOW).

## Nouveaux champs

Par finding :

| Champ | Format | Origine |
|---|---|---|
| `severity` | `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` | **finale**, tranchée par la règle |
| `severity_llm` | même énumération, ou `null` (finding ajouté par règle) | proposition du modèle, pour la traçabilité/mesure |
| `severity_rule` | chaîne : id de règle (`dmarc_missing`, `hsts_missing`, `cve_kev`, `port_database_exposed`…) ou `positive_observation`, `contradicted_by_data`, `unverified`, `llm_capped`, `llm_proposed` | serveur |
| `confidence` | `high\|medium\|low` | règle (ou `medium` si evidence vérifiée par grounding, `low` sinon) ; le modèle peut l'abaisser, jamais l'élever ; une règle `high` sans evidence vérifiée descend à `medium` |
| `observed_at` | ISO 8601 UTC `2026-10-19T10:42:00Z` | horodatage du scan (`cache.cached_at` des résultats), à défaut l'heure de l'analyse ; jamais la valeur du modèle |
| `references` | **liste d'objets** `[{"collection": str, "source": str}]` | `collection` ∈ `normes`, `attack`, `menaces`, `explications` (RAG), `corpus` (RAG sans collection, repli), `llm` (référence textuelle du modèle validée par motif : CVE observée, CWE, CAPEC, RFC, T/TA/M ATT&CK, OWASP, ASVS, WSTG, NIST, ANSSI, CIS, ISO…) |
| `generated_by` | `"rule"` (absent sinon) | finding ajouté par une règle |
| `attack_enabled`, `mitigations` | définis par la phase 4 | via `annotate_findings` |

⚠️ **Changement de type** : `references` était une liste de chaînes, c'est
maintenant une liste d'objets. Les anciens rapports en cache restent en
chaînes : les consommateurs doivent accepter les deux.

Par rapport :

- `risk_score` déterministe, `risk_score_llm` (int 0–100 ou `null`).
- `severity_check` : `rule_applied`, `positive_capped`, `llm_capped`,
  `llm_proposed`, `unverified`, `contradicted_dropped`, `contradicted_info`,
  `duplicates_dropped`, `injected` (ids de règles), `dropped` (≤ 50 :
  `{id, title, reason, rule}`), `rules_observed`, `kev_cves`,
  `epss_threshold`, `unmatched_cap`, `dropped_invalid`,
  `dropped_unverified_cve`, `cves_removed`, `kev` (`{enabled, loaded,
  count, fetched_at}`), `observed_at`, `method`.
- `coverage_check` gagne `rag_queries`, `rag_filtered_by_collection`
  (`true`/`false`/`null`), `findings_with_rag_references`.
- Les champs de premier niveau acceptés depuis le LLM sont en liste
  blanche (`domain`, `risk_score`, `risk_level`, `executive_summary`,
  `findings`, `strengths`, `immediate_actions`, `searches_performed`,
  `model_used`, `analyzed_at`, `tokens_used`, `_partial`, `_resumed`,
  `_reduce_degraded`) ; tout le reste est recalculé ou ignoré.

## RAG (B7)

- Collections : `normes`, `attack`, `menaces`, `explications`. Catégorie →
  collections : Email/DNS/SSL/Web → `normes` + `explications` ;
  Subdomain/Infrastructure/Reputation → `menaces` + `explications` ; Cloud
  → `menaces` + `normes`. Chaque requête renvoie 1 extrait de ces
  collections + 1 extrait `attack`, l'un complétant l'autre si vide.
- Avant le LLM : une requête par constat observé (requête fixe de la
  table, ex. « DMARC record missing email spoofing phishing RFC 7489 »),
  triées par sévérité, plafonnées à `RAG_MAX_QUERIES`. Si aucun constat :
  l'ancienne requête globale en repli. Chaque extrait porte `topic` (id de
  règle), `collection`, `category`.
- Après le LLM : un finding rattaché à une règle déjà interrogée reprend
  ses extraits (aucune requête) ; les autres déclenchent une requête
  (titre + catégorie), plafonnée à `RAG_MAX_FINDING_QUERIES`.
- Repli : si aucune ligne de `rag_documents` n'a `metadata.collection`
  (test mis en cache 10 min), requêtes sans filtre.
- Ollama : les extraits ne sont plus répétés dans le contexte global des 6
  sections MAP ; chaque section reçoit ses 2 extraits et ses constats
  déterministes (catégories de la section).
- SQL entièrement paramétré (`:qvec`, `:cols`, `:k`), collections en liste
  blanche, `k` borné à 20, embedding revalidé (nombres finis).
- **Dépendance phase 6** : le filtrage n'agit qu'une fois le corpus
  réindexé avec `metadata.collection` ∈ {`normes`, `attack`, `menaces`,
  `explications`}. `metadata.source` doit être un nom lisible (« RFC
  7489 », « MITRE ATT&CK T1566 ») : c'est lui qui apparaît dans
  `references` et que `rag_snippets_used` cherche dans les
  recommandations.

## Variables d'environnement ajoutées

| Variable | Défaut | Rôle |
|---|---|---|
| `KEV_ENABLED` | `true` | Désactive entièrement KEV si `false` |
| `KEV_URL` | flux officiel CISA | https obligatoire |
| `KEV_CACHE_PATH` | `<tmp>/recon-ia-kev.json` | Cache disque partagé par les workers |
| `KEV_REFRESH_HOURS` | `24` | Âge maximal du cache |
| `KEV_RETRY_MINUTES` | `60` | Délai avant nouvelle tentative après échec |
| `KEV_TIMEOUT_S` | `20` | Timeout du téléchargement |
| `KEV_CHECK_INTERVAL_S` | `3600` | Fréquence de l'appel `refresh()` par le watchdog |
| `EPSS_HIGH_THRESHOLD` | `0.1` | EPSS ≥ seuil → HIGH |
| `SEVERITY_UNMATCHED_CAP` | `MEDIUM` | Plafond d'un finding sans règle |
| `SEVERITY_INJECT_MIN` | `HIGH` | Sévérité minimale des constats ajoutés (`NONE` = désactivé) |
| `RAG_SNIPPETS_PER_QUERY` | `2` | Extraits par requête (1–5) |
| `RAG_MAX_QUERIES` | `8` | Requêtes « constat » avant le LLM |
| `RAG_MAX_FINDING_QUERIES` | `10` | Requêtes « finding » après le LLM |

`RAG_TOP_K` (6) ne sert plus qu'à `retrieve_relevant_docs()`, conservée
pour compatibilité.

## Mesure avant / après (hors ligne)

```sh
MSYS_NO_PATHCONV=1 docker run --rm --network none -v "$PWD/api:/app" -w /app \
    recon-ia-api-test python tools/measure_phase3.py      # --json pour la sortie brute
```

Jeu fixe : `api/tests/fixtures/phase3/` — `scan_example_com.json` (domaine
sain) et `scan_vuln_target.json` (KEV, MySQL, takeover, DMARC absent…),
avec des sorties LLM brutes reconstituées à partir des défauts réellement
constatés (`llm_*.json`). « Avant » = nettoyage de format seul, sévérité
du modèle, RAG en une requête globale de 6 extraits sans filtre. « Après »
= `_prepare_phase3` + `_postprocess_report`. KEV depuis
`kev_catalog.json`, RAG simulé par recouvrement lexical sur
`rag_corpus.json` (16 documents) : les chiffres RAG mesurent la
mécanique (requêtes, filtrage, rattachement), pas des embeddings réels.

| Métrique | example.com avant | après | vuln-target avant | après |
|---|---|---|---|---|
| Findings | 6 | 4 | 7 | 7 |
| dont CRITICAL + HIGH | 6 | 0 | 3 | 4 |
| `security_score` | **0** | **93** | 33 | 11 |
| `risk_score` | 100 (modèle) | 7 | 40 (modèle) | 89 |
| `grounding_check.verified_pct` | 66,7 | 100,0 | 71,4 | 85,7 |
| `coverage_check.coverage_pct` | 58,3 | 41,7 | 42,9 | 42,9 |
| `rag_snippets_used` / disponibles | 0 / 5 | 1 / 4 | 0 / 5 | 1 / 11 |
| Requêtes RAG | 1 | 8 | 1 | 10 |
| Findings avec références RAG | 0 | 4 | 0 | 6 |
| CVE non observées restantes | 1 | 0 | 1 | 0 |

Lecture :
- example.com passe de 0/100 à 93/100 : les deux constats positifs notés
  CRITICAL deviennent INFO, HSTS/CSP reprennent MEDIUM/LOW, le « DNSSEC
  absent » contredit par la donnée et la CVE inventée sont retirés.
- vuln-target se dégrade (33 → 11), et c'est voulu : Log4Shell (KEV)
  passe de MEDIUM à CRITICAL, MySQL exposé de LOW à HIGH, DMARC absent de
  MEDIUM à HIGH, le takeover ignoré par le modèle est ajouté.
- `coverage_pct` baisse sur example.com parce que les findings retirés
  (faux) citaient `dnssec` et `shodan_internetdb` : une couverture par un
  constat faux n'en est pas une. C'est un plancher honnête.
- `rag_snippets_used` reste faible : il dépend du texte des
  recommandations du modèle (figé dans les fixtures). Le gain réel se lit
  dans `findings_with_rag_references`, qui ne dépend plus du modèle.
- **À refaire sur la stack réelle** (pgvector réindexé par la phase 6,
  vrais backends) pour des chiffres publiables.

## Tests

- `api/tests/test_phase3_unit.py` — 53 tests (KEV, sanitizer/B6, règles,
  RAG, prompts, accroche phase 4, merger, final_report_generator).
- `api/tests/test_phase3_security.py` — 21 tests `security` (champs forgés
  par le LLM ignorés, injection de prompt sans effet sur la sévérité,
  bornes, URL, clés d'outils, CVE en échec fermé, SQL paramétré et
  collections en liste blanche, embedding non fini, flux KEV http/trop
  gros/cache corrompu).
- `api/tests/test_phase3_integration.py` — 6 tests `integration` (route
  `POST /analyze` réelle avec repli Ollama simulé, chemin async persistant
  en base, accroche phase 4 dans la route, RAG indisponible, script de
  mesure).

```sh
./scripts/run-tests.sh tests/test_phase3_unit.py tests/test_phase3_security.py tests/test_phase3_integration.py
```

(Lancé depuis la racine du dépôt, `tests/test_phase3_*.py` n'est pas
développé par le shell de l'hôte — il n'y a pas de `tests/` à la racine —
et pytest reçoit le motif littéral : nommer les fichiers.)

## Limites connues

- Le rattachement finding → règle reste une heuristique par mots-clés
  (français/anglais). Il ne fait que choisir la règle candidate ; la
  décision vient de la donnée brute, et un rattachement fragile ne retire
  jamais un finding (il le met en INFO `contradicted_by_data`).
- Un finding sur un sous-domaine précis est rapproché des en-têtes
  observés sur la racine **et** sur les sous-domaines joignables (outil
  `headers`), pas d'un sous-domaine particulier.
- Les règles `secrets_exposed` lisent tout outil dont `data` expose
  `secrets_found`/`secrets` (format attendu de l'extension GitHub de la
  phase 5) : à confirmer quand la phase 5 sera livrée.
- L'`executive_summary` du modèle n'est pas réécrit : il peut encore
  évoquer une sévérité que la règle a corrigée.
