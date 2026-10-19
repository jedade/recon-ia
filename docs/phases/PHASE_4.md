# Phase 4 — MITRE ATT&CK étendu (livrée le 2026-10-19)

Objectif du plan : passer de « ce que notre méthode collecte » à « ce que
cette exposition permet à un attaquant ».

## 1. Référentiel ATT&CK local (Enterprise v20.0)

- `data/script_mitre_attack.py` lit le bundle STIX officiel `mitre/cti`
  (`enterprise-attack.json`). Il produit deux fichiers :
  - `api/data/attack_reference.json` (versionné, ~10 Ko) : 21 techniques
    (celles de `utils/mitre_attack.py` et de la table B8), avec pour chacune
    son nom complet, ses tactiques, ses mitigations (relations `mitigates`)
    et le nombre de groupes connus qui l'utilisent (relations `uses`, avec 5
    noms au plus). Le fichier contient aussi 25 mitigations, les tactiques
    utiles, la version et l'URL source ;
  - `data/combined_mitre_attack_recon.md` (corpus RAG, collection `attack`) :
    104 techniques (Reconnaissance + Resource Development + techniques de la
    table), chacune avec ses mitigations, puis les 25 mitigations décrites.
- Le bundle de `mitre/cti` ne contient aucun objet `x-mitre-collection`. La
  version vient donc de la release GitHub : sans `--bundle`, le script
  télécharge la dernière release au tag `ATT&CK-vX.Y`. Avec un bundle local,
  il faut passer `--version`.
- Régénération (Python dans un conteneur) :
  `docker run --rm -v "$PWD/data:/repo/data" -v "$PWD/api/data:/repo/api/data" -v <dossier du bundle>:/bundle:ro recon-ia-api-test python -I /repo/data/script_mitre_attack.py --bundle /bundle/enterprise-attack.json --version 20.0`
- Le runtime ne lit que le fichier JSON, jamais le réseau
  (`utils/mitre_attack.py::load_reference()`, avec un cache mémoire). Au
  chargement, chaque ID est revalidé par regex et chaque texte est borné. Si
  le fichier manque ou est corrompu, le référentiel est vide : aucune
  technique n'est émise (fail closed).
- `attack_version()` remplace la mention codée en dur « Enterprise v15 ».
- À noter : dans la v20, la tactique TA0005 s'appelle **« Stealth »**
  (anciennement Defense Evasion).
- Correctif : `TOOL_TECHNIQUES["typosquatting"]` vaut désormais
  **T1583.001** (Acquire Infrastructure: Domains) et non plus T1584.001. Un
  domaine imitant la marque est enregistré par un tiers, pas compromis.

## 2. Table constat → techniques rendues possibles (B8)

Module `api/utils/attack_enablement.py`.

| Règle (`attack_rules`) | Constat reconnu | Techniques | Mitigations |
|---|---|---|---|
| `dmarc_weak` | DMARC absent / p=none / faible | T1566 | M1054, M1017 |
| `typosquatting` | domaines imitant la marque | T1583.001 (+ T1566 si MX) | M1056 (+ M1017) |
| `cve_kev` | CVE présente dans CISA KEV | T1190 | M1051, M1050 |
| `remote_service_exposed` | VPN, RDP, Citrix, SSH, panneau d'admin | T1133 | M1032, M1035 |
| `breached_accounts` | adresses du domaine dans des fuites | T1110.004, T1078 | M1032, M1027 |
| `subdomain_takeover` | sous-domaine vulnérable | T1584.001 | M1056 (+ nettoyage des CNAME) |
| `archived_sensitive_files` | `.env`, `.git`, config dans les archives | T1552.001 | M1022 |
| `github_secrets` | secrets dans un dépôt public | T1593.003 → T1552 | M1013, M1047, M1027 |

Comment un constat est reconnu :
- à partir de `severity_rule` (phase 3), de `source_tool(s)`, de `category`
  et des mots-clés du **titre** ;
- le texte est normalisé (sans accents, en minuscules), et les sigles courts
  (`rdp`, `vpn`, `kev`, `mx`) ne sont reconnus que comme mots entiers ;
- la description, texte libre du LLM, n'est **pas** utilisée ;
- un constat de sévérité INFO ne rend aucune technique possible.

Les `signals` servent uniquement à confirmer ou infirmer un constat :
- 0 sous-domaine vulnérable → pas de takeover ;
- DMARC `reject`/`quarantine` à 100 % → pas de T1566 ;
- `breach_count` = 0 → pas de fuite ;
- `mx_configured_count` > 0 → T1566 ajoutée au typosquatting ;
- un drapeau `kev`/`in_kev`/`known_exploited` dans `vulns_enriched`, ou le
  cache disque de `utils/kev.py` (`allow_fetch=False`, donc sans réseau),
  confirme une CVE KEV.

Pour les mitigations, on garde celles que préfère le plan **si** le bundle
les relie (relation `mitigates`) à une technique de la règle. Sinon, on
prend les mitigations officielles de ces techniques.

Garanties :
- seule la table fait foi : tout `attack_enabled`/`mitigations` fourni par le
  LLM est écrasé ;
- un ID absent du référentiel n'est jamais émis ;
- les noms viennent du référentiel, jamais du constat ;
- l'annotation est idempotente et ne modifie pas l'entrée.

### API publique

```python
annotate_findings(findings: list[dict], signals: dict | None = None) -> list[dict]
build_attack_chain(findings: list[dict]) -> list[dict]
build_navigator_layer(findings: list[dict], mitre_attack: list[dict] | None = None, domain: str = "") -> dict
attack_csv_fields(finding: dict) -> {"attack_enabled": str, "mitigations": str}
technique_context(technique_ids) -> {tid: {"groups_count": int, "groups_sample": [str]}}
# utils/mitre_attack.py
load_reference(path=None) -> dict ; attack_version() -> str
```

Champs ajoutés à chaque constat :
- `attack_enabled` [{id, name}] ;
- `mitigations` [{id, name}] ;
- `attack_rules` [str] ;
- `mitigation_advice` (str, mesure concrète en français, vide si aucune règle).

## 3. Chaîne d'attaque plausible

`build_attack_chain(findings annotés)` renvoie des étapes non vides, dans cet
ordre :
1. Reconnaissance : techniques des outils sources des constats retenus ;
2. Préparation de l'infrastructure (TA0042) ;
3. Obtention d'identifiants (TA0006) ;
4. Accès initial (TA0001).

Les identifiants obtenus alimentent l'accès initial (T1078, T1133), d'où
l'ordre. Chaque étape a la forme `{order, stage, label, tactic_id, tactic,
max_severity, finding_ids, techniques: [{id, name, finding_ids,
max_severity}]}`. Les ID sont revalidés et ne sont jamais repris tels quels
du constat. Les ID de constats mal formés sont remplacés par `F-NNN`. La
fonction renvoie `[]` si aucun constat ne rend de technique possible. Le
récit éventuel est rédigé par le LLM ailleurs, à partir de cette structure.

## 4. Export ATT&CK Navigator

`GET /results/export.navigator.json` (`routes/results.py`) a les mêmes
protections que les autres exports :
- Bearer de session revalidé à chaque requête (révocation 403, expiration
  410) ;
- consentement `accord` (403) ;
- `Content-Disposition: attachment` et `nosniff` ;
- 60 requêtes par heure.

Contenu du layer :
- format 4.5, domaine `enterprise-attack`, `versions.attack` = version
  majeure du référentiel ;
- chaque technique rendue possible a la couleur et le score (1 à 4) de la
  **sévérité maximale** des constats qui la rendent possible. Son
  commentaire contient les ID et titres de ces constats ;
- les techniques de reconnaissance (`analysis.mitre_attack`) apparaissent en
  gris avec un score de 0.

Contre l'injection, le JSON est sérialisé par `json.dumps`, les couleurs
sont fixes, les ID et noms d'outils sont filtrés par regex. Dans le texte,
les caractères de contrôle et U+2028/2029 sont retirés, `<`/`>` neutralisés,
et la longueur est bornée.

## 5. Page de résultat et PDF

`GET /results/report` renvoie maintenant `data.attack = {attack_version,
chain, context}`. Les constats de `analysis_result` y sont ré-annotés **en
mémoire**. L'export JSON, lui, reste le jeu de données brut (même
`dataset_sha256`).

La page de résultat (`web/result.*`) affiche :
- pour chaque constat : la confiance (badge), la date d'observation, les
  références (chaînes ou `{collection, source}`), « Rend possible »,
  « Mitigations » (liens attack.mitre.org construits seulement depuis des ID
  valides) et « Mesure » ;
- une section « Chaîne d'attaque plausible » : cartes numérotées avec
  flèches, empilées sur mobile, où chaque constat cité est un lien vers la
  carte correspondante. Les relations `uses` y apparaissent comme
  **contexte** (« technique employée par N groupes connus… — information
  générale, pas une menace avérée ») ;
- un bouton « Layer ATT&CK Navigator ».

Le rendu passe exclusivement par `textContent`/`createElement`, sans aucun
style inline.

Le PDF (`utils/pdf_generator.py`) réannote les constats par la table, comme
la page. Il contient :
- dans chaque constat, une ligne « Fiabilité » (confiance + date
  d'observation), puis « Rend possible » et « Mitigations » (avec la mesure
  concrète) ;
- les références structurées ;
- une nouvelle section « Chaîne d'Attaque Plausible » (tableau Étape /
  Tactique / Techniques / Constats).

Si l'annotation échoue, le PDF est quand même généré.

## 6. Tests

Il y a 90 tests en tout, dont 22 de sécurité et 16 d'intégration :
- `tests/test_phase4_attack_reference.py` : couverture du référentiel,
  noms officiels, relations `mitigates`, chargeur fail closed et rejet des ID
  mal formés ;
- `tests/test_phase4_attack_enablement.py` : chaque ligne de la table,
  reconnaissance (accents, mots entiers, négations, infirmation par les
  signaux), idempotence, défiance envers le LLM, chaîne, layer (format,
  sévérité max, injection), CSV ;
- `tests/test_phase4_results_attack.py` : endpoint Navigator (session,
  consentement, révocation, expiration, en-têtes), vue ATT&CK du rapport,
  export JSON inchangé, sections PDF.

La suite complète est verte (755 réussis, 11 ignorés). Le test e2e Chrome
(`scripts/e2e/run-result-page.sh`) passe 27 vérifications sur 27, dont 11
nouvelles : chaîne, techniques, mitigations, liens valides, T9999 écarté,
confiance, références, layer téléchargeable et refusé sans session. Aucune
violation CSP et aucun débordement à 390 px.

## 7. Reste à intégrer (autres phases)

- **Phase 3** (`routes/analyze.py`) : appeler
  `annotate_findings(report["findings"], signals)` après la sanitisation et
  le calcul de `severity_rule`. Le reste se fait déjà à la lecture, mais
  annoter dès l'analyse permet aux signaux de confirmer ou infirmer les
  constats et rend les champs disponibles dans l'export JSON.
- **Phase 7** (`routes/report.py::_CSV_COLUMNS` / `_finding_rows`) : ajouter
  les colonnes `confidence`, `observed_at`, `attack_enabled`, `mitigations`
  à partir de `attack_csv_fields(annotate_findings([f], {})[0])`.
- **Phase 6** : le corpus `combined_mitre_attack_recon.md` a été régénéré ; il
  reste à le recopier dans `n8n_ressource/` pour l'ingestion.
- Les nouveaux outils de la phase 5 doivent être ajoutés à
  `TOOL_TECHNIQUES`. Si un outil introduit une nouvelle technique, il faut
  aussi l'ajouter à `REFERENCE_TECHNIQUES` du script puis régénérer le
  référentiel (un test échoue sinon).
