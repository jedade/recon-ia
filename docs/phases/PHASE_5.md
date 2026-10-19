# Phase 5 — Collecte passive enrichie

Statut : **livrée (code + tests)** le 2026-10-19.

Objectif : combler les vraies lacunes de couverture sans contredire le passif
strict. Tous les outils ajoutés sont passifs (sources tierces publiques ou
requêtes DNS / un unique GET de la page d'accueil, déjà pratiqués par le
projet). Aucun scan actif intrusif n'est émis vers la cible.

## 1. Fichiers créés / modifiés

**Créés**
- `api/utils/passive_sources/__init__.py` — helpers partagés : lecture bornée
  des réponses tierces (`read_bounded`, `read_json`, `ResponseTooLarge`,
  `InvalidResponse`), masquage de secrets (`scrub`), `skipped()`.
- `api/utils/passive_sources/dns_mass.py` — B4, résolution DNS massive + ASN
  (Team Cymru) + détection CDN.
- `api/utils/passive_sources/blocklists.py` — résolveurs DNS filtrants.
- `api/utils/passive_sources/threats.py` — Safe Browsing + PhishTank.
- `api/utils/passive_sources/ranking.py` — Tranco + HSTS preload.
- `api/utils/passive_sources/reputation.py` — VirusTotal v3.
- `api/utils/passive_sources/discovery.py` — DNSDumpster + GrayHatWarfare.
- `api/utils/passive_sources/github_dorks.py` — GitHub secret dorks.
- `api/utils/passive_sources/webpage.py` — cookies / social-tags / linked-pages
  (sur une seule réponse).
- `api/utils/signals_extra.py` — `extract_extra_signals(raw_results) -> dict`.
- `api/tests/test_phase5_unit.py`, `test_phase5_security.py`,
  `test_phase5_integration.py`.
- `docs/phases/PHASE_5.md` (ce fichier).

**Modifiés**
- `api/routes/recon.py` — registre des 9 nouveaux outils, wrappers, câblage
  dans les vagues 1/2, `ALL_TOOLS`, `_SUBDOMAIN_TOOLS`, légende, enum Swagger.
- `api/.env.example` — nouvelles variables d'environnement (voir §5).

Non modifiés volontairement (possédés par d'autres agents) : `analyze.py`,
`mitre_attack.py`, `pdf_generator.py`, `CLAUDE.md`, `README.md`,
`PLAN_ACTION.md`.

## 2. Outils ajoutés

| Clé outil | Source | Clé requise | Statut sans clé | Vague |
|---|---|---|---|---|
| `dns_mass` | Résolveurs DNS publics + Team Cymru (DNS TXT) | aucune | n/a | 2 (consomme `all_subs`) |
| `blocklists` | 17 résolveurs DNS filtrants (Quad9, AdGuard, CleanBrowsing, OpenDNS…) | aucune | n/a | 2 |
| `threats_check` | Google Safe Browsing + PhishTank | `GOOGLE_SAFE_BROWSING_API_KEY` (SB) ; PhishTank sans clé | SB `skipped`, PhishTank actif | 2 |
| `web_metadata` | Page d'accueil (1 GET) : cookies B11, OG/Twitter, domaines liés | aucune | n/a | 2 |
| `site_ranking` | Tranco API + hstspreload.org | aucune | n/a | 2 |
| `virustotal` | VirusTotal v3 (réputation + passive DNS) | `VIRUSTOTAL_API_KEY` | `skipped` | 2 (réutilise IP d'`ip_info`) |
| `dnsdumpster` | DNSDumpster API officielle | `DNSDUMPSTER_API_KEY` | `skipped` | 1 (alimente `all_subs`) |
| `grayhatwarfare` | GrayHatWarfare API (buckets exposés) | `GRAYHATWARFARE_API_KEY` | `skipped` | 2 |
| `github_dorks` | GitHub code search | `GITHUB_TOKEN` (réutilisé) | `skipped` | 2 |

Intégration conforme aux outils existants : même format de résultat
(`status`/`meta`/`data`/`raw_output`), métadonnées dans `TOOLS_REGISTRY`,
exécution dans les vagues parallèles bornées par `SCAN_DEADLINE_SECONDS`, échec
isolé non bloquant. Tout appel HTTP touchant la cible passe par la session
anti-SSRF partagée `_http` (`_SsrfGuardedSession`). Les appels aux API tierces
fixes ont des timeouts et une taille de réponse bornée (`read_bounded`,
défaut 2 Mo).

## 3. Sécurité

- **Anti-SSRF** : les wrappers HTTP transmettent `recon._http` (gardé). `dns_mass`
  et `blocklists` n'émettent que des requêtes DNS vers des résolveurs publics,
  jamais une connexion à la cible. Les IP privées publiées dans un DNS public
  sont signalées (`internal_ip_hosts`) mais jamais contactées.
- **Masquage de secrets** : `github_dorks` ne stocke JAMAIS la valeur d'un
  secret — seuls l'emplacement (dépôt + chemin), le type et un fragment masqué
  (`AKIA…XZ`) sont conservés. Les clés d'API sont retirées (`scrub`) de tout
  message d'erreur ; aucune clé n'apparaît dans les résultats.
- **Réponses bornées / malformées** : `read_bounded` rejette un flux infini ou
  un `Content-Length` excessif (`ResponseTooLarge`) ; un JSON invalide donne un
  statut `error`, jamais une exception.
- **Échec non bloquant** : chaque outil renvoie un statut au lieu de lever ;
  l'exécuteur parallèle isole toute exception résiduelle.

## 4. `extract_extra_signals(raw_results: dict) -> dict`

Fonction défensive (ne lève jamais) qui condense les résultats bruts des outils
de la phase 5 en signaux compacts pour l'analyse LLM. **À intégrer dans
`routes/analyze.py::_extract_signals`** (p. ex. `signals["extra"] =
extract_extra_signals(scan_results)`). Structure (toutes les clés toujours
présentes) :

```python
{
  "dns_mass": {
      "alive_count": int, "dead_count": int, "unique_ip_count": int,
      "cdn_distribution": {str: int},
      "asns": [{"asn": int, "as_name": str|None, "ip_count": int}],  # ≤ 10
      "internal_ip_hosts": [str],   # ≤ 20 (fuite d'adressage interne)
      "top_live_hosts": [str],      # ≤ 30
  },
  "blocklists": {"is_blocked": bool, "blocked_count": int, "blocked_by": [str]},
  "threats": {"flagged": bool, "safe_browsing_types": [str], "phishtank_listed": bool},
  "virustotal": {"available": bool, "malicious_total": int,
                 "risk_level": "clean|medium|high", "categories": [str]},
  "cookies": {"count": int, "all_secure": bool, "insecure": [str]},
  "social_tags_present": bool,
  "linked_domains": [str],          # ≤ 30
  "ranking": {"tranco_rank": int|None, "hsts_preloaded": bool},
  "dnsdumpster_subdomains": int,
  "grayhatwarfare": {"available": bool, "file_count": int},
  "github_dorks": {"available": bool, "match_count": int,
                   "confirmed_secret_count": int,
                   "secret_types": [str], "locations": [str]},  # locations ≤ 15
}
```

`raw_results` est le dict complet de `run_recon` : `{clé_outil: {status, data,
meta, raw_output}}`. Tout champ manquant ou mal typé est ignoré silencieusement.

## 5. Variables d'environnement (ajoutées à `api/.env.example`)

Toutes optionnelles, dégradation propre en `skipped` si absentes :

- `VIRUSTOTAL_API_KEY` — outil `virustotal` (gratuit, 4 req/min).
- `GOOGLE_SAFE_BROWSING_API_KEY` — volet Safe Browsing de `threats_check`.
- `PHISHTANK_API_KEY` — bonus de quota PhishTank (fonctionne sans).
- `DNSDUMPSTER_API_KEY` — outil `dnsdumpster`.
- `GRAYHATWARFARE_API_KEY` — outil `grayhatwarfare` (priorité basse).
- `GITHUB_TOKEN` — réutilisé par `github_dorks` (déjà présent pour `github`).

Bornes de `dns_mass` : `DNS_MASS_MAX_SUBDOMAINS` (300), `DNS_MASS_WORKERS` (10),
`DNS_MASS_BUDGET_SECONDS` (60), `SHODAN_IDB_MAX_IPS` (50, plafond d'IP uniques
dont l'ASN est résolu).

## 6. NEW_TOOL_TECHNIQUES — correspondance outil → ATT&CK

À intégrer dans `api/utils/mitre_attack.py` (NE PAS modifié par cet agent).
Tactiques Reconnaissance (TA0043) et Resource Development (TA0042).

```python
NEW_TOOL_TECHNIQUES = {
    # B4 : résolution massive → cartographie IP/ASN/sous-domaines
    "dns_mass": ["T1590.002", "T1590.005", "T1596.001", "T1590.001"],
    #   T1590.002 Gather Victim Network Information: DNS
    #   T1590.005 IP Addresses
    #   T1596.001 Search Open Technical Databases: DNS/Passive DNS
    #   T1590.001 Domain Properties

    # block-lists : réputation DNS (renseignement sur la cible)
    "blocklists": ["T1596.001"],

    # Safe Browsing + PhishTank : réputation/menaces
    "threats_check": ["T1596", "T1593"],
    #   T1596 Search Open Technical Databases
    #   T1593 Search Open Websites/Domains

    # cookies / social-tags / linked-pages : infos exposées sur le site
    "web_metadata": ["T1593.001", "T1592.002"],
    #   T1593.001 Search Open Websites/Domains: Social Media (balises sociales)
    #   T1592.002 Gather Victim Host Information: Software (cookies/en-têtes)

    # Tranco + HSTS preload : propriétés du domaine / bases techniques
    "site_ranking": ["T1590.001", "T1596"],

    # VirusTotal : bases techniques + passive DNS
    "virustotal": ["T1596.001", "T1596.005", "T1590.005"],
    #   T1596.005 Search Open Technical Databases: Scan Databases

    # DNSDumpster : DNS + sous-domaines
    "dnsdumpster": ["T1590.002", "T1596.001", "T1590.005"],

    # GrayHatWarfare : stockage cloud exposé
    "grayhatwarfare": ["T1596", "T1593.003"],
    #   T1593.003 Search Open Websites/Domains: Code Repositories (proche) /
    #   données exposées publiquement

    # GitHub secret dorks : fuite dans des dépôts de code publics
    "github_dorks": ["T1593.003", "T1552.001"],
    #   T1593.003 Search Open Websites/Domains: Code Repositories
    #   T1552.001 Unsecured Credentials: Credentials In Files (secret exposé)
}
```

## 7. Tests

Lancés dans le conteneur jetable `scripts/run-tests.sh` (`--network none`).

- `tests/test_phase5_unit.py` — unitaires (helpers bornés, chaque outil avec
  réponses simulées, `signals_extra`).
- `tests/test_phase5_security.py` — marqueur `security` (SSRF via session
  partagée, masquage des secrets, réponses géantes/malformées).
- `tests/test_phase5_integration.py` — marqueur `integration` (outils dans le
  flux `/pass_recon` : meta préservée, `skipped` sans clé, `dnsdumpster` →
  `all_subdomains`, `dns_mass` consomme les sous-domaines, échec non bloquant).

Résultat : **55 tests phase 5 verts**. Suite demandée complète (phase 5 + SSRF +
new_tools + routes_scan + parallel + subdomain_selection) : **151 tests verts**.

## 8. À intégrer par le mainteneur

1. `routes/analyze.py::_extract_signals` → appeler `extract_extra_signals`.
2. `utils/mitre_attack.py` → fusionner `NEW_TOOL_TECHNIQUES` (§6).
3. Renseigner les clés gratuites souhaitées dans `api/.env` (§5).
