# Phase 8 — Boucle agent (l'IA pilote les pivots de recon)

Statut : **livrée (code + tests)** le 2026-10-19. Désactivée par défaut
(`AGENT_RECON_ENABLED=false`).

## 1. Fichiers

**Créés**
- `api/utils/agent_llm.py` — adaptateur function-calling minimal (format OpenAI
  `/chat/completions` + `tools`, via `requests`) pour Gemini, DeepSeek et Ollama
  ≥ 7B ; parsing tolérant des tool calls ; sélection du backend.
- `api/utils/recon_agent.py` — boucle agent : résumé borné du graphe, liste
  blanche, périmètre, budget, nettoyage des sorties, journal des décisions.
- `api/tests/phase8_fixtures.py`, `test_phase8_unit.py`,
  `test_phase8_security.py`, `test_phase8_integration.py`.
- `docs/phases/PHASE_8.md` (ce fichier).

**Modifiés (avec parcimonie)**
- `api/routes/recon.py` :
  - `_reverse_ip(domain, ip=None)` et `_asn_info(domain, ip=None)` : paramètre
    optionnel pour interroger directement une IP observée (comportement
    inchangé sans `ip`) ;
  - fin de `run_recon` (après la vague 2, avant cache et persistance) : étape
    optionnelle qui ajoute `result["agent_pivots"]`.
- `api/.env.example` : bloc « BOUCLE AGENT » (§7).

Non modifiés : clients LLM existants (`utils/*_client.py`), `analyze.py`,
`entity_graph.py`, `pdf_generator.py`, `routes/__init__.py` (aucune nouvelle
route), `CLAUDE.md`, `README.md`, `PLAN_ACTION.md`.

## 2. Choix d'intégration : étape finale de `POST /pass_recon`

Retenu plutôt qu'un endpoint dédié, pour quatre raisons :
1. **Aucun changement du workflow n8n** : un endpoint séparé ne serait jamais
   appelé sans modifier `recon-ia-main.json`, qui n'est pas dans mon périmètre.
2. **Les résultats des pivots suivent le chemin des autres outils** : mis en
   cache (`pass_recon_cache`), persistés dans `recon.scan_results`, donc vus
   par l'analyse, le différentiel, l'export JSON et le scellement, sans code
   en plus.
3. **Même protection** : `require_service_or_auth` + rate limit 30/h déjà
   en place sur `/pass_recon`.
4. **Les données nécessaires sont déjà en mémoire** (`result`) : pas de
   relecture BD.

Règles :
- `AGENT_RECON_ENABLED=false` → l'étape n'existe pas : la clé `agent_pivots`
  est absente et le résultat reste identique à celui d'avant la phase 8.
- Activée sans backend capable → `agent_pivots.status = "skipped"`
  (`stop_reason: "no_backend"`, raison dans `error`) ; le flux continue.
- Le corps peut seulement **désactiver** l'étape (`"agent_recon": false`, p. ex.
  pour les rescans de surveillance), jamais l'activer contre la configuration.
- Sur un cache hit, la boucle ne relance pas : le cache contient déjà
  `agent_pivots` si elle était active lors du scan.
- La boucle ne lève jamais. Une exception résiduelle est en plus capturée dans
  `run_recon` : `agent_pivots.status = "error"`, et le scan répond 200.

⚠️ Durée : la boucle ajoute au plus `AGENT_DEADLINE_SECONDS` (défaut
`min(SCAN_DEADLINE_SECONDS, 120)`), plus éventuellement l'appel LLM ou l'outil en
cours. Garder `GUNICORN_TIMEOUT` et le timeout HTTP du nœud n8n au-dessus de la
somme des deux vagues et de cette échéance.

## 3. Outils exposés (liste blanche stricte)

| Tool call | Argument | Fonction de `recon.py` | Clé `TOOLS_REGISTRY` | Pivot |
|---|---|---|---|---|
| `resolve_host` | `hostname` | `_dns_records(host)` (DNS seul) | `dns_records` | sous-domaine → IP (deviennent pivotables) |
| `reverse_ip` | `ip` | `_reverse_ip(root, ip=ip)` (HackerTarget) | `reverse_ip` | IP → noms co-hébergés |
| `internetdb` | `ip` | `_shodan_internetdb(root, ips=[ip])` | `shodan_internetdb` | IP → ports / CPE / CVE / noms |
| `asn_lookup` | `ip` | `_asn_info(root, ip=ip)` (RIPEstat) | `asn_info` | IP → ASN / opérateur |
| `crtsh_subdomains` | `hostname` | `_crtsh_tool(host)` | `crtsh` | certificat → SAN (journaux CT) |
| `http_headers` | `hostname` | `_http_headers_tool([host])` (session anti-SSRF) | `headers` | sous-domaine sensible → en-têtes |
| `takeover_check` | `hostname` | `_subdomain_takeover({host}, root)` (DNS CNAME) | `subdomain_takeover` | sous-domaine → takeover |

Schéma de chaque outil : `{<argument>: string, reason: string}`, les deux
requis, `additionalProperties: false`. Le nom doit correspondre exactement (pas
de casse ni d'espace tolérés). Les runners sont résolus à l'appel
(`routes.recon.<fonction>`) : ils restent patchables par les tests.

## 4. Garde-fous

**Périmètre** (`Scope`, vérifié avant chaque exécution) :
- nom d'hôte : syntaxe valide, égal au domaine racine ou sous lui, **et déjà
  observé** (graphe du scan ou résultat d'un pivot précédent). Le LLM ne peut
  pas faire deviner des noms : pas de brute force déguisé. C'est plus strict
  que « tout sous-domaine du racine », et c'est voulu ;
- IP : syntaxe valide, `is_global`, IPv4 (les trois outils IP ne couvrent que
  l'IPv4), et observée dans ce scan (graphe, ou résolution d'un nom du
  périmètre par `resolve_host`) ;
- `utils.validators.is_safe_domain` sur chaque argument (un nom observé qui
  résout vers 10.x ou 169.254.169.254 est refusé), en plus de
  `_SsrfGuardedSession` pour les outils HTTP ;
- les noms hors périmètre renvoyés par un outil (reverse IP, CNAME, crt.sh)
  sont montrés au LLM à titre d'information, mais ne deviennent jamais
  pivotables.

**Budget dur** : `AGENT_MAX_PIVOTS` pivots exécutés ; échéance globale
`AGENT_DEADLINE_SECONDS`, transmise comme timeout de l'appel LLM et bornant
chaque outil (exécuté via `run_tools_parallel`, `min(AGENT_TOOL_TIMEOUT_SECONDS,
reste)`) ; profondeur `AGENT_MAX_DEPTH` (graphe = 0, une découverte faite par un
pivot de profondeur n est à n+1, un pivot est refusé si l'argument est à une
profondeur ≥ max) ; `AGENT_MAX_ROUNDS` tours de LLM ;
`AGENT_MAX_CALLS_PER_ROUND` ; arrêt après `AGENT_MAX_REFUSALS` refus cumulés
(anti-boucle) ; un même pivot (outil + cible) n'est exécuté qu'une fois.

**Données non fiables** (défense contre l'injection de prompt) :
- le LLM ne reçoit jamais `raw_output` ni le JSON brut ; le résumé du graphe et
  chaque sortie d'outil sont réduits à des champs typés et validés (IP, noms
  d'hôte, ports, CVE, entiers) et à de courts libellés nettoyés par
  `safe_text` : caractères de contrôle et invisibles retirés, ponctuation
  réduite, longueur bornée. Un libellé qui ressemble à une consigne
  (« ignore… », « system », « call »…) devient `[filtré]` ;
- les messages d'outil sont du JSON `{"tool", "target", "status",
  "untrusted_data", "budget_remaining"}`, bornés à `AGENT_TOOL_OUTPUT_CHARS` ;
- le prompt système déclare non fiable tout contenu d'outil ;
- le contrôle reste dans le code : même si une injection passait, elle ne
  pourrait déclencher qu'un outil de la liste blanche, sur une cible du
  périmètre, dans le budget.

**Backends** : DeepSeek exige, comme l'analyse,
`DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true`. Ollama n'est accepté que si
`AGENT_OLLAMA_MODEL` est défini et que la taille lue dans son tag est
≥ `AGENT_OLLAMA_MIN_PARAMS_B` (7). `qwen3:1.7b` et les tags illisibles
(`:latest`) sont refusés. Les clés n'apparaissent jamais dans le journal ni dans
les erreurs (`_scrub`). Les redirections HTTP vers le backend ne sont pas
suivies.

Codes de refus (stables) : `not_whitelisted`, `malformed_arguments`,
`out_of_scope`, `not_observed`, `unsafe_target`, `max_depth`, `duplicate`,
`too_many_calls`, `max_pivots`, `deadline`, `max_refusals`. Chaque refus est
aussi journalisé (`logger.warning "[agent] pivot refusé …"`).

## 5. Résumé du graphe envoyé au LLM

`summarize_graph(domain, raw_results, max_chars)` s'appuie sur
`entity_graph.extract_graph` et produit :

```json
{
  "root_domain": "example.com",
  "counts": {"entities": {"domain": 1, "subdomain": 3, "ip": 1, ...},
             "relations": {"has_subdomain": 3, "has_port": 2, ...}},
  "notable": {
    "ips": [{"ip": "93.184.216.34", "ports": [80, 443], "asn": "AS15133", "cves": 1, "hosts": 2}],
    "sensitive_subdomains": ["admin.example.com", "dev.example.com"],
    "other_subdomains_sample": ["www.example.com"],
    "certificates": [{"subject_cn": "...", "issuer": "...", "not_after": "...", "san_count": 2}],
    "asns": [{"asn": "AS15133", "name": "Edgecast Inc"}],
    "vulnerabilities": [{"id": "CVE-2023-44487", "cvss": 7.5}],
    "technologies": ["nginx"],
    "takeover_candidates": [{"subdomain": "dev.example.com", "service": "GitHub Pages"}]
  }
}
```

Plafonds : 20 IP, 25 sous-domaines sensibles, 15 autres, 3 certificats,
10 ASN, 10 CVE, 15 technologies, 10 candidats. Si la sérialisation dépasse
`AGENT_SUMMARY_MAX_CHARS`, la plus longue liste est réduite de moitié, et ainsi
de suite. Les compteurs restent exacts.

## 6. Journal des décisions — `scan_results["agent_pivots"]` (schema_version 1)

L'entrée a la forme d'un résultat d'outil, `{status, meta, data, raw_output,
error?}`, ce qui permet au code qui parcourt `scan_results` de la traiter sans
cas particulier. `status` : `success` | `skipped` | `error`. Le journal est
dans `data` :

```json
{
  "schema_version": 1,
  "domain": "example.com",
  "status": "success",
  "stop_reason": "llm_finished",
  "backend": {"name": "gemini", "model": "gemini-2.0-flash"},
  "started_at": "2026-10-19T10:00:00Z",
  "finished_at": "2026-10-19T10:00:41Z",
  "duration_s": 41.2,
  "budget": {"max_pivots": 15, "max_depth": 2, "deadline_s": 120.0, "max_rounds": 8,
             "max_calls_per_round": 4, "max_refusals": 10, "tool_timeout_s": 30.0,
             "tool_output_chars": 1500, "summary_max_chars": 6000},
  "usage": {"llm_rounds": 3, "tool_calls": 6, "pivots_executed": 5, "pivots_refused": 1},
  "graph_summary": {"counts": {"entities": {...}, "relations": {...}}},
  "scope": {"root_domain": "example.com", "seed_hosts": 4, "seed_ips": 1,
            "discovered_hosts": 2, "discovered_ips": 1},
  "decisions": [{
    "seq": 1, "round": 1, "timestamp": "2026-10-19T10:00:03Z",
    "tool": "internetdb", "arguments": {"ip": "93.184.216.34"},
    "reason": "IP exposée avec une CVE",
    "depth": 0, "outcome": "executed", "refusal": null,
    "result_status": "success",
    "result_summary": {"ports": [22, 443], "vuln_count": 1, "vulns": ["CVE-2021-44228"], ...},
    "discovered": {"hosts": 1, "ips": 0}, "duration_s": 0.84
  }, {
    "seq": 6, "round": 3, "timestamp": "...", "tool": "http_headers",
    "arguments": {"hostname": "attacker.tld"}, "reason": "...",
    "depth": null, "outcome": "refused",
    "refusal": {"code": "out_of_scope", "detail": "hors du périmètre example.com"},
    "result_status": null, "result_summary": null, "discovered": null, "duration_s": null
  }],
  "results": [{"seq": 1, "tool": "internetdb", "registry_key": "shodan_internetdb",
               "target": "93.184.216.34",
               "result": {"meta": {...}, "status": "success", "data": {...}, "raw_output": "≤ 4000 car."}}],
  "final_message": "Synthèse du LLM, ≤ 500 car."
}
```

`stop_reason` : `llm_finished`, `max_pivots`, `deadline`, `max_rounds`,
`max_refusals`, `llm_error`, `no_backend`, `invalid_domain`, `internal_error`.
`status = "error"` si le LLM échoue avant tout pivot exécuté, ou si le domaine
est invalide. Sinon `success`, même quand la boucle s'arrête sur une erreur LLM
après des pivots utiles.

Garanties pour l'affichage : `reason`, `final_message` et les arguments sont
débarrassés des caractères de contrôle et des chevrons `<` `>`, et sont bornés.
Pour un appel refusé, `arguments` contient ce que le LLM a proposé (tronqué à
120 caractères), ou `{"_raw": …}` si le JSON était invalide. Pour un appel
exécuté, `arguments` contient la valeur normalisée. Échapper tout de même `&`
avant de passer ces textes à un `Paragraph` ReportLab.

## 7. Variables d'environnement (`api/.env.example`)

| Variable | Défaut | Rôle |
|---|---|---|
| `AGENT_RECON_ENABLED` | `false` | active l'étape |
| `AGENT_BACKEND` | `auto` | `auto` (gemini → deepseek → ollama) ou un nom |
| `AGENT_GEMINI_MODEL` / `AGENT_DEEPSEEK_MODEL` | `GEMINI_MODEL` / `DEEPSEEK_MODEL` | modèle de la boucle |
| `AGENT_OLLAMA_MODEL` | vide | modèle local dédié (≥ 7B), ex. `qwen2.5:7b` |
| `AGENT_OLLAMA_MIN_PARAMS_B` | `7` | taille minimale lue dans le tag |
| `AGENT_LLM_TIMEOUT_SECONDS` / `AGENT_OLLAMA_TIMEOUT_SECONDS` | `60` / `180` | délai d'un appel LLM |
| `AGENT_MAX_PIVOTS` | `15` | pivots exécutés |
| `AGENT_MAX_DEPTH` | `2` | profondeur |
| `AGENT_DEADLINE_SECONDS` | `min(SCAN_DEADLINE_SECONDS, 120)` | échéance globale |
| `AGENT_MAX_ROUNDS` | `8` | tours de LLM |
| `AGENT_MAX_CALLS_PER_ROUND` | `4` | appels par tour |
| `AGENT_MAX_REFUSALS` | `10` | refus avant arrêt |
| `AGENT_TOOL_TIMEOUT_SECONDS` | `30` | délai d'un outil |
| `AGENT_SUMMARY_MAX_CHARS` / `AGENT_TOOL_OUTPUT_CHARS` | `6000` / `1500` | bornes du contexte envoyé au LLM |

Réutilisées sans modification : `GEMINI_API_KEY`, `GEMINI_MODEL`,
`DEEPSEEK_API_KEY`, `DEEPSEEK_CONFIRM_EXTERNAL_SHARING`, `DEEPSEEK_MODEL`,
`OLLAMA_URL`, `SCAN_DEADLINE_SECONDS`. Elles sont lues à l'exécution, pas à
l'import.

## 8. Tests

Lancés par `scripts/run-tests.sh` (`--network none`), avec un LLM scripté et
des outils simulés.
- `test_phase8_unit.py` : parsing des tool calls (JSON invalide, non objet,
  trop long, plafond du nombre d'appels), budget (pivots, appels par tour,
  échéance avec horloge simulée, tours), profondeur (propagation, refus,
  IP découverte pivotable), résumé du graphe borné et compteurs exacts,
  schémas, format stable du journal, sélection du backend (tailles Ollama,
  confirmation DeepSeek, forçage), adaptateur HTTP (forme de la requête, clé
  masquée), paramètre `ip` de `_reverse_ip` / `_asn_info`.
- `test_phase8_security.py` (`security`) : hors périmètre, nom non observé,
  IP non observée, IP privée / loopback / métadonnées / CGNAT / IPv6 locale,
  nom observé qui résout en interne, outil hors liste blanche (y compris
  variantes de casse et d'espaces), arguments malformés, injection dans des
  en-têtes HTTP et dans les libellés du graphe (jamais transmise au LLM, aucun
  outil non autorisé déclenché), boucle de doublons et d'outils interdits
  coupée, clé d'API absente du journal, raison et arguments hostiles
  nettoyés.
- `test_phase8_integration.py` (`integration`) : boucle complète dans
  `POST /pass_recon` (8 pivots, 1 refus, fonctions de `recon.py` appelées
  avec les cibles validées), mise en cache, désactivée par défaut, désactivable
  par le corps, `skipped` sans backend capable, panne LLM et crash contenus,
  authentification requise.

Résultat : **124 tests phase 8 verts**. Suite demandée (phase 8 + SSRF +
routes_scan + phase 5) : **202 verts**. Suite complète : **929 verts,
11 ignorés**.

## 9. À intégrer par le mainteneur

1. **PDF, section Méthodologie** (`pdf_generator.py`) : lire
   `scan_results.get("agent_pivots")`. Si la clé est absente, ne rien
   afficher. Si `status == "skipped"`, une ligne « Boucle agent non exécutée :
   <error> ». Sinon, un en-tête (backend, `stop_reason`, `usage`, `budget`),
   puis un tableau par décision (`seq`, `tool`, `arguments`, `reason`,
   `outcome`, `refusal.code`, `result_status`, `timestamp`).
2. **Graphe (phase 7)** : `extract_graph` ne lit pas encore
   `agent_pivots.data.results[*].result`. Chaque entrée a le format standard
   d'un outil et porte `registry_key` (même structure de `data` que l'outil
   d'origine). On peut les rejouer avec la logique existante.
3. **Analyse (phase 3)** : faute de lecture, les pivots n'entrent pas dans
   les signaux. Proposition : un signal compact à partir de
   `decisions[*].result_summary` (déjà nettoyé et borné).
4. **Décision D9** (backend de référence) : Gemini est proposé par défaut
   (`AGENT_BACKEND=auto`).
5. Avant d'activer en production : vérifier `GUNICORN_TIMEOUT` et le timeout
   du nœud n8n qui appelle `/pass_recon` (§2).
