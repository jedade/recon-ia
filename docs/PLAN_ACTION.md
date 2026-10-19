# Plan d'action — Recon-IA, IA de reconnaissance passive

> Statut : **intégration en cours** — phases 0, 1 et 2 livrées le 2026-10-19, décisions
> du §6 tranchées le même jour. Ce document rassemble trois
> analyses successives : audit du projet, comparaison avec `web-check-free`,
> évaluation d'une recommandation externe sur la base de connaissance et
> MITRE ATT&CK.
>
> Il complète `CLAUDE.md` (état réel du code) : `CLAUDE.md` décrit ce qui
> **existe**, ce fichier décrit ce qu'on **va faire** et pourquoi. Cocher les
> cases au fil de l'intégration et reporter dans `CLAUDE.md` ce qui est livré.

---

## Sommaire

1. [Objectif](#1-objectif)
2. [Diagnostic de l'existant](#2-diagnostic-de-lexistant)
3. [Principes directeurs](#3-principes-directeurs)
4. [Flux actuel et flux cible](#4-flux-actuel-et-flux-cible)
5. [Plan par phases](#5-plan-par-phases)
6. [Décisions à prendre avant de coder](#6-décisions-à-prendre-avant-de-coder)
7. [Écarté, et pourquoi](#7-écarté-et-pourquoi)
8. [Risques](#8-risques)
9. [Annexes](#9-annexes)

---

## 1. Objectif

Faire de Recon-IA une **IA qui automatise la reconnaissance passive** :

- l'utilisateur remplit un formulaire, la demande est stockée en base et le
  système se lance ;
- la collecte reste **strictement passive** (aucune interaction intrusive avec
  la cible) ;
- l'IA **oriente** la collecte et **explique** les résultats, appuyée par une
  base de connaissance (normes, ATT&CK, vulnérabilités exploitées) ;
- à la fin, l'utilisateur reçoit un **email avec un code d'accès long et
  sécurisé**. Sur l'onglet « Voir le résultat », il saisit ce code pour
  consulter un dashboard (inspiré de web-check) et télécharger le rapport en
  JSON, CSV ou PDF ;
- la sécurité est renforcée sur **toutes les couches** (frontend, API, n8n,
  base, réseau).

---

## 2. Diagnostic de l'existant

### 2.1 Points forts à conserver

- 47 outils OSINT passifs, en 2 vagues parallèles, sortie déterministe
  (`dataset_sha256` stable).
- Traçabilité outil → finding (`source_tool` obligatoire), contrôles
  `grounding_check` et `coverage_check`, `finding_sanitizer`.
- Correspondance ATT&CK déterministe (`utils/mitre_attack.py`), jamais
  laissée au LLM.
- RAG pgvector (OWASP, ASVS, WSTG, Top 10, MITRE recon, RFC).
- Cascade LLM avec repli local Ollama, cache scan et analyse, exports JSON/CSV
  avec bloc de provenance.

### 2.2 Problème de fond

**Recon-IA est aujourd'hui un pipeline fixe suivi d'un LLM analyste, pas une
IA de reconnaissance.**

- Les 47 outils sont lancés à l'aveugle, toujours dans le même ordre. Le LLM
  n'a qu'un outil (`web_search`) : il ne peut ni relancer un outil, ni creuser
  une piste, ni pivoter.
- La cible est **un domaine**, pas une organisation : aucun pivot (IP → reverse
  IP, certificat → SAN, registrant → autres domaines).
- `_extract_signals` (`routes/analyze.py`) tronque fortement les données
  (40 sous-domaines sur parfois 3000, 20 endpoints JS) : l'IA analyse un
  échantillon sans savoir ce qui a été écarté.

### 2.3 Bugs et limites constatés dans le code

| # | Problème | Emplacement | Effet |
|---|---|---|---|
| B1 | `build_attack_surface` lit `signals["shodan_internetdb"]` alors que la donnée est sous `signals["network"]["shodan_internetdb"]` | `api/utils/attack_surface.py` | `exposed_services` **toujours vide** (rapport + PDF) |
| B2 | En-têtes HTTP récupérés sur les 10 premiers sous-domaines **par ordre alphabétique** | `api/routes/recon.py::_http_headers_tool` | `admin.`, `vpn.`, `dev.` ignorés au profit de `a1.`, `api-test.` |
| B3 | Takeover testé sur `list(all_subs)[:50]`, ordre d'un `set` arbitraire | `api/routes/recon.py::_subdomain_takeover` | Non reproductible d'un scan à l'autre |
| B4 | Sous-domaines jamais résolus en DNS | `api/routes/recon.py` | Impossible de distinguer vivants et morts, ou de grouper par IP. Shodan n'est interrogé que sur l'IP du domaine principal |
| B5 | Sévérité laissée au LLM | `api/routes/analyze.py` | Finding positif noté `CRITICAL` déjà constaté, score faussé |
| B6 | CVE non vérifiées (ex. `CVE-2023-12345`) non filtrées | `api/utils/finding_sanitizer.py` | Références inventées présentées comme réelles |
| B7 | RAG : **une seule requête** pour tout le rapport, 6 extraits au total | `api/routes/analyze.py` (requête `_rag_query`) | Corpus de 5 Mo quasi inexploité |
| B8 | ATT&CK : correspondance **outil exécuté** → technique | `api/utils/mitre_attack.py` | Tous les rapports affichent la même couverture MITRE, quel que soit le risque réel |
| B9 | Aucun différentiel entre deux scans du même domaine | — | Historique conservé mais inexploité |
| B10 | `tls_config` utilise `sslscan` (dizaines de handshakes vers la cible) | `api/routes/recon.py` | Semi-actif, contredit « strictement passif ». **Clos : conservé (décision D7)** |
| B11 | `tech_stack` relève les **noms** des cookies, pas leurs drapeaux | `api/routes/recon.py` | `Secure` / `HttpOnly` / `SameSite` jamais évalués |
| B12 | 5 outils `skipped` faute de clé gratuite (GitHub, AbuseIPDB, abuse.ch, urlscan, OTX) | `api/.env` | Couverture réduite sans raison |

### 2.4 Failles de sécurité du flux actuel

| # | Problème | Emplacement |
|---|---|---|
| S1 | Le navigateur appelle **directement le webhook n8n** pour la vérification OTP | `web/index.html` (`VERIFY_API_URL`) |
| S2 | UI n8n publiée (`5678:5678`) et **sans authentification** | `docker-compose.yml` |
| S3 | `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` + `ADMIN_PASSWORD_PLAIN` en variable : mot de passe admin lisible depuis n'importe quel Code node | `docker-compose.yml` |
| S4 | n8n appelle l'API avec le **compte admin** (Basic Auth) au lieu d'un compte de service à droits limités | `n8n/generate-credentials.js` |
| S5 | Aucun TLS dans le compose (scripts certbot/nginx cassés) | `scripts/`, `docker-compose.yml` |
| S6 | Les limites de débit des routes du pipeline sont comptées sur l'IP du conteneur n8n : elles deviennent des plafonds **globaux partagés par tous les utilisateurs**, pas des protections par client | `api/extensions.py`, `api/routes/*.py` |
| S7 | L'utilisateur final n'a **aucun accès** à ses résultats hors PDF joint au mail : exports réservés à l'admin | `api/routes/report.py` (`@require_auth`) |
| S8 | N'importe qui peut obtenir un rapport sur le domaine d'un tiers (case de consentement seulement) | `api/routes/crud.py` |
| S9 | **SSRF** : sous-domaines découverts et redirections HTTP jamais validés par `is_safe_domain` (trouvé pendant la phase 0) — ✅ corrigé | `api/routes/recon.py` |

---

## 3. Principes directeurs

1. **Passif strict.** Rien qui ouvre une connexion inhabituelle vers la
   cible : pas de scan de ports, pas de traceroute, pas de fuzzing. Une visite
   HTTP équivalente à un navigateur et des résolutions DNS restent permises.
2. **Le déterministe collecte et note, le LLM oriente et explique.** Sévérité,
   CVE, techniques ATT&CK et surface d'attaque viennent de règles et de
   données. Le LLM contextualise, priorise et rédige.
3. **Données de référence consultées directement, documents dans le RAG.**
   KEV, EPSS, empreintes de takeover : consultation directe. Normes et guides :
   RAG.
4. **Tout finding est traçable** : `source_tool`, `evidence`, `confidence`,
   `observed_at`.
5. **Aucun service interne exposé sur Internet** : seul le reverse proxy est
   public.
6. **Réutiliser l'existant** : PostgreSQL (graphe, RAG, tokens), n8n
   (orchestration), HTML statique (frontend). Aucune nouvelle brique lourde.

---

## 4. Flux actuel et flux cible

### 4.1 Flux actuel

```
Navigateur (index.html)
  │ 1. POST /recon ───────────────────────────► API  (crée le dossier, envoie l'OTP)
  │ 2. POST webhook n8n (code OTP) ───────────► n8n  ◄── exposé publiquement (S1, S2)
                                                 │
                                                 ├─► API /verify_email
                                                 ├─► API /pass_recon        (47 outils, ordre figé)
                                                 ├─► API /analyze/async + /analyze/wait
                                                 ├─► API /generate_final_report
                                                 └─► API /generate_report   (PDF joint au mail)

Résultat utilisateur : uniquement le PDF en pièce jointe.
Exports JSON/CSV : réservés à l'admin.
```

### 4.2 Flux cible

```
                         Internet
                            │
                  ┌─────────▼──────────┐
                  │ Reverse proxy TLS  │  (Caddy ou Traefik, seul service public)
                  └───┬────────────┬───┘
                      │            │
              web (statique)     API Flask
                                   │  réseau Docker interne uniquement
                     ┌─────────────┼──────────────┬──────────────┐
                  PostgreSQL     Redis          Ollama          n8n (privé)

 1. FORMULAIRE        index.html + captcha → POST /recon (API)
                      → dossier stocké en BD (status=pending) → OTP par mail
 2. VÉRIFICATION      POST /verify_email (API, plus n8n)
                      → l'API déclenche n8n en interne
                        (http://n8n:5678/webhook/..., en-tête secret)
 3. SCOPE             domaine → graines (domaine, IP, ASN, registrant)      [déterministe]
 4. COLLECTE V1       WHOIS/RDAP, DNS, CT, subfinder/amass…                 [existant]
 5. NORMALISATION     résolution DNS massive + graphe d'entités en BD       [nouveau]
 6. BOUCLE AGENT      le LLM lit un résumé du graphe et choisit les pivots  [nouveau]
                      et les enrichissements (outils exposés en tool calls),
                      sous budget (N pivots, SCAN_DEADLINE_SECONDS)
 7. SCORING           règles + KEV + CVSS/EPSS → sévérité déterministe      [nouveau]
 8. ATT&CK            finding → techniques rendues possibles + mitigations  [nouveau]
 9. ANALYSE IA        RAG par finding (filtré par collection) → rédaction   [amélioré]
10. DIFF              comparaison avec le scan précédent du même domaine    [nouveau]
11. LIVRABLES         PDF + JSON + CSV + layer ATT&CK Navigator              [amélioré]
12. NOTIFICATION      l'API génère le code d'accès, stocke son empreinte,
                      envoie le mail « Votre rapport est prêt » avec le code
13. CONSULTATION      result.html : saisie du code → session courte
                      → dashboard façon web-check + téléchargements
```

### 4.3 Accès aux résultats par code

```
Fin du pipeline
  code = secrets.token_urlsafe(32)                  # 256 bits
  BD   : access_token_hash = HMAC-SHA256(SERVER_PEPPER, code)
         access_expires_at, access_revoked, access_count, last_access_at
  Mail : le code (jamais stocké en clair)

result.html
  POST /results/access   { code }                   # POST, jamais ?code= dans l'URL
     ├─ rate limit strict par IP
     ├─ recherche par empreinte + hmac.compare_digest
     ├─ vérifie expiration et révocation
     ├─ trace l'accès dans audit_log
     └─► jeton de session signé, courte durée (ex. 1 h), lié à un seul recon_id

  GET /results/report        Authorization: Bearer <session>
  GET /results/export.json   Authorization: Bearer <session>
  GET /results/export.csv    Authorization: Bearer <session>
  GET /results/report.pdf    Authorization: Bearer <session>
```

Le code n'est envoyé qu'une fois. Les appels suivants utilisent la session,
ce qui évite que le code circule à chaque requête.

---

## 5. Plan par phases

Ordre recommandé. Chaque phase est livrable seule et testable.

```
Phase 0 ─► Phase 1 ─► Phase 2 ─┬─► Phase 3 ─► Phase 4 ─► Phase 6
 bugs      sécurité    page    │   fiabilité   ATT&CK     base de
           + flux      résultat│   analyse                connaissance
                               └─► Phase 5 (collecte enrichie, en parallèle)
                                        │
                                        ▼
                               Phase 7 ─► Phase 8
                               graphe     boucle agent
                               + diff     (pivots)
```

### Phase 0 — Corrections rapides ✅ livrée le 2026-10-19

Objectif : rapports immédiatement plus justes, sans changer l'architecture.

- [x] **B1** Clé Shodan corrigée dans `utils/attack_surface.py`
      (`signals["network"]["shodan_internetdb"]`, racine en repli).
- [x] **B2** Sous-domaines priorisés pour les en-têtes
      (`_prioritize_subdomains`, `_SENSITIVE_SUBDOMAIN_KEYWORDS`), tri stable.
- [x] **B3** Sélection déterministe pour le takeover (même fonction).
- [ ] **B12** Créer les 5 clés gratuites (GitHub, AbuseIPDB, abuse.ch,
      urlscan, OTX) et les renseigner dans `api/.env`. **Action de
      l'utilisateur** : création de comptes, rien à coder.
- [x] `api/.env.example` complété (11 variables).
- [x] **S9** (trouvé en cours de phase) Garde anti-SSRF
      `_SsrfGuardedSession` sur la session HTTP du scanner : chaque requête et
      chaque redirection est validée par `is_safe_domain`.
- [x] Outillage de test : `api/Dockerfile.test`, `scripts/run-tests.sh`
      (conteneur sans réseau), marqueurs pytest `security` et `integration`.

**Tests ajoutés** (44, tous verts ; suite complète : 258 verts) :
- `tests/test_subdomain_selection.py` (unitaires, 20) : rang des mots-clés,
  pas de faux positif sur sous-chaîne, déterminisme, takeover reproductible ;
- `tests/test_attack_surface.py` (unitaires, 4) : chaîne réelle scan →
  signaux → surface. Vérifié : échoue sur l'ancien code ;
- `tests/test_security_ssrf.py` (sécurité, 20, dont 2 d'intégration) :
  métadonnées cloud, loopback, noms Docker, nom public → IP interne,
  redirections, `POST /pass_recon` avec sous-domaine piégé.

**Critère de fin :** atteint par les tests. Reste à observer sur un scan
réel (stack démarrée) que `exposed_services` se remplit quand Shodan voit des
ports.

### Phase 1 — Sécurité et nouveau flux utilisateur ✅ livrée le 2026-10-19 (code et tests)

Objectif : plus aucun service interne exposé, flux formulaire → BD → système
piloté par l'API.

**Réseau et n8n**
- [x] Reverse proxy **Caddy** (D5) dans le compose (`caddy/Caddyfile`), seul
      service publié (80/443), TLS automatique. Scripts certbot/nginx et
      dossiers `certbot/`, `nginx/`, `renew-certs.sh/` supprimés.
- [x] `api` et `n8n` publiés sur `127.0.0.1` uniquement, `web` plus du tout.
      Éditeur n8n par tunnel SSH.
- [x] `N8N_ENCRYPTION_KEY` fixe, `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` (plus
      aucun `$env` dans les workflows), `extra_hosts` retiré.
      ⚠️ Compte propriétaire n8n : à créer **à la main** au premier démarrage
      (documenté dans `setup.sh`, README, CLAUDE.md).
- [x] Webhook n8n protégé par une credential *Header Auth* (`X-Pipeline-Secret`).
- [x] **S4** Jeton de service `X-Service-Token` (`utils/auth.py
      ::require_service_or_auth`), accepté seulement par les 6 routes du
      pipeline. `ADMIN_PASSWORD_PLAIN` retiré de n8n. Caddy retire l'en-tête
      des requêtes venues d'Internet.

**Flux**
- [x] **S1** `web/index.html` appelle `POST /verify_email` sur l'API.
- [x] `POST /verify_email` (devenu public) déclenche le webhook n8n en
      interne (`utils/pipeline_trigger.py`), `current_step='queued'`
      (surveillé par le watchdog).
- [x] Workflow `recon-ia-main.json` V3 : déclenchement interne, plus
      d'étape `verify_email` ni de `Respond to Webhook`, appels à
      `http://api:8080`.
- [x] Captcha **Cloudflare Turnstile** (D6) : widget dans `index.html`,
      vérification côté API (`utils/captcha.py`, fail closed).
- [x] *(ajouté)* Consentement `accord` obligatoirement `true` à la création.
- [x] *(ajouté)* OTP : code annulé après 5 essais faux sur un même dossier
      (`otp_attempts`).

**Code d'accès (voir §4.3)**
- [x] Migration : `access_token_hash` (unique), `access_salt`,
      `access_expires_at`, `access_revoked_at`, `access_count`,
      `last_access_at`, `sealed_bundle`, `sealed_pdf`, `sealed_at`,
      `results_purged_at`.
- [x] Code émis en fin de pipeline, mail « rapport prêt » avec le code seul,
      sans pièce jointe (D1). L'ancienne fonction qui joignait le PDF est
      supprimée. Validité 30 jours, révocable (D2).
- [x] **Chiffrement (D3)** `utils/result_vault.py` : HKDF-SHA256 + AES-256-GCM
      avec donnée associée par dossier et par champ ; empreinte de recherche
      `HMAC-SHA256(RESULTS_ACCESS_SECRET, code)`. Scellement commité
      seulement après l'envoi réussi du mail (sinon rollback, rattrapage
      admin `POST /recon/<id>/issue_access`).
- [x] Routes admin de contenu (`report.pdf`, exports, génération) : 403 sur
      un dossier scellé. `to_dict()` n'expose que des métadonnées.
- [x] Dashboard admin : état du coffre affiché, téléchargement retiré pour un
      dossier scellé (livré en phase 2).
- [x] Point d'attention D3 — `pass_recon_cache` (résultats bruts publics en
      clair) : **décision de l'utilisateur (2026-10-19) : conservé en base et
      consultable depuis le dashboard admin.** Plus jamais purgé (une entrée
      expirée n'est plus servie au pipeline mais reste lisible). Routes admin
      `GET /cache`, `/cache/<id>`, `/cache/<id>/export.json`
      (`routes/cache.py`), onglet « Scans bruts (cache) » et bouton « Voir le
      scan brut » dans le détail d'un dossier scellé. Tests :
      `test_cache_admin.py` + `scripts/e2e/dashboard.mjs`.
- [x] Routes `POST /results/access` et `GET /results/{report,report.pdf,
      export.json,export.csv}` (`routes/results.py`), session Fernet d'1 h
      revalidée à chaque requête.
- [x] Limites : 5/min et 30/h sur `/results/access` ; accès comptés
      (`access_count`) en plus de l'`audit_log` (qui ne journalise jamais les
      corps de requête).

**Durcissement API et base**
- [x] **S6** Requêtes porteuses du jeton de service exemptées des limites par
      IP. [ ] Limite par email + domaine sur `/recon` : non faite (l'anti-spam
      existant bloque déjà un second OTP tant que le premier est valide).
- [x] CSP : l'API répond déjà `default-src 'none'` ; `index.html` n'autorise
      en plus que `challenges.cloudflare.com` (Turnstile). CORS : piloté par
      `CORS_ORIGINS`, à fixer sur le domaine du site en production
      (documenté).
- [x] Rôles PostgreSQL à droits minimaux (`migrate.py::ensure_roles`),
      **vérifiés sur la vraie base** : `recon_app` (API : DML sur ses tables,
      aucun DDL) et `rag_writer` (n8n : `rag_documents` seulement ; le droit
      CREATE sur le schéma est indispensable au nœud PGVector, testé). n8n
      ne reçoit plus le mot de passe propriétaire.
- [x] Purge RGPD horaire (`utils/retention.py`) : résultats + identité 7 j
      après expiration/révocation, demandes non vérifiées 7 j, audit 90 j,
      cache expiré.

**Tests ajoutés** (111 ; suite complète : **369 verts**) :
`test_result_vault.py` (39, chiffrement, liaison dossier/champ, altération,
sessions), `test_results_access.py` (35, consultation, oracle, brute-force,
révocation/expiration en cours de session, isolement entre dossiers, routes
admin fermées, scellement en fin de pipeline, échec SMTP),
`test_pipeline_flow.py` (29, consentement, Turnstile, OTP, déclenchement
interne, jeton de service, exemption de limites), `test_retention.py` (7),
`test_end_to_end_flow.py` (1, parcours complet à travers les vraies routes).

**Critère de fin :** atteint **par les tests** pour le parcours complet, les
refus de code, l'absence de code en base et l'isolement des routes.
✅ **Vérifié sur la stack réelle le 2026-10-19** (`setup.sh` sur ce poste,
Caddy sur 8088/8444) :
- provisioning n8n (4 credentials, workflow V3 actif, webhook → 403 sans le
  bon `X-Pipeline-Secret`) ;
- ports depuis l'IP du poste : seuls ceux de Caddy répondent ;
- HTTPS par Caddy (autorité interne, TLS 1.3, redirection 308, HSTS) et
  jeton de service rejeté (401) quand il arrive par Caddy ;
- **parcours complet dans Chrome** (`scripts/e2e/run-full-flow.sh`) :
  formulaire + vrai widget Turnstile (clés de test Cloudflare) → OTP par
  SMTP réel (Mailpit, STARTTLS) → n8n → scan → analyse Ollama → PDF →
  scellement → mail avec code sans pièce jointe → `result.html` → PDF
  déchiffré ; admin refusé sur le contenu, scan brut lisible dans le cache ;
- dashboard admin dans Chrome (`scripts/e2e/dashboard.mjs`, 11
  vérifications).

Ce premier déploiement a révélé **6 défauts**, tous corrigés et documentés
dans CLAUDE.md §8 : registre n8n en 429 (`N8N_IMAGE`), `entrypoint.sh` en
CRLF sous Windows (`.gitattributes`), SQLAlchemy 2.1 et pilote psycopg
(`db_url.py`), analyse refusée sans clé cloud alors qu'Ollama était
disponible (`_any_backend_available`), durée d'analyse négative dans le
dashboard, directives `frame-ancestors`/`X-Frame-Options` ignorées en
balise meta (déplacées dans les en-têtes Caddy).

**Non vérifiable depuis ce poste** : émission d'un certificat Let's Encrypt
public (il faut un nom de domaine public pointant vers le serveur) et envoi
via le vrai serveur SMTP de production (identifiants absents). Le mécanisme
TLS et le chemin SMTP sont validés ; seuls ces deux fournisseurs externes
restent à confirmer au déploiement en production.

### Phase 2 — Page de résultat inspirée de web-check ✅ livrée le 2026-10-19

Objectif : un dashboard de consultation lisible par un non-expert.

Fichiers : `web/result.html`, `web/result.css`, `web/result.js` (vanilla JS,
séparés pour une CSP sans `unsafe-inline`), lien « Voir le résultat » dans
la navigation de `index.html`.

À reprendre de web-check (le design, pas le code React) :
- [x] Thème : fond `#141d2b`, accent `#9fef00`, police PT Mono, cartes avec
      ombre décalée. Variables CSS, thème clair automatique (système) ou
      forcé par le bouton ◐.
- [x] Grille masonry (colonnes CSS), une carte par outil, 3 → 2 → 1 colonnes.
- [x] Barre de suivi des outils : répartition des statuts + pastille par
      outil (clic = aller à sa carte). ⚠️ Pas de durée par outil : elle n'est
      pas conservée dans `scan_results` (seulement la durée totale).
- [x] Modale d'explication par carte (`meta.description`, `meta.indicators`).
- [x] Recherche et filtres par catégorie, **corrigés** par rapport à
      web-check (chaque carte est comparée à la catégorie choisie).
- [x] Téléchargements PDF, JSON, CSV (fetch avec la session + Blob).

Spécifique à Recon-IA :
- [x] En-tête : jauge du score, note, niveau de risque, dates, empreinte
      SHA-256 ; résumé exécutif et tuiles (constats, sous-domaines, services
      exposés, technologies, points forts).
- [x] Constats triés par sévérité, filtre par sévérité, lien vers la carte de
      chaque `source_tool` / `source_tools`, statut du contrôle de preuve.
- [x] Panneau de fiabilité (`grounding_check`, `coverage_check`, outils non
      exploités cliquables).
- [x] Tableau ATT&CK (liens vers attack.mitre.org), en fiches sur mobile.
      Sera enrichi en phase 4.
- [x] Points forts, actions prioritaires, méthodologie et citation.

Dashboard admin (reporté de la phase 1) :
- [x] Cadenas à la place du bouton PDF pour un dossier scellé, avec l'état
      du code en info-bulle ; section « Coffre des résultats » dans le détail
      (état, expiration, consultations, scellement) ; bouton « Révoquer le
      code » ; plus de faux message « Aucune analyse IA » sur un dossier
      scellé.

Sécurité de la page :
- Rendu exclusivement par `textContent`/`createElement`, jamais `innerHTML`.
- CSP : `script-src 'self'`, `style-src 'self'` + Google Fonts, `form-action
  'none'`, `base-uri 'none'`, `object-src 'none'` ; anti-iframe par en-têtes
  Caddy (`X-Frame-Options`, `frame-ancestors`), une balise meta ne pouvant
  pas porter `frame-ancestors`.
- Le code n'est jamais stocké (champ vidé après usage) ; seul le jeton de
  session est gardé en `sessionStorage`, effacé à la fermeture de session.

**Tests** :
- `scripts/e2e/run-result-page.sh` (nouveau) : API réelle avec un dossier
  scellé réaliste contenant du HTML piégé, page servie statiquement, Chrome
  headless piloté par le protocole DevTools. **17 vérifications, toutes
  vertes** : code faux/bon, code jamais stocké, aucune injection HTML ni
  alerte, aucune exception JS ni violation CSP, filtres, téléchargement PDF,
  aucun débordement à 390 px, fermeture de session. Ce test a trouvé 5
  défauts que pytest ne voyait pas (texte « [object HTMLButtonElement] »,
  bouton de filtre illisible, couleur de sévérité sur tout le texte,
  débordement mobile, directive CSP ignorée) — tous corrigés.
- pytest : vue détail admin d'un dossier scellé (`test_results_access.py`).
  Suite complète : **370 verts**.

D8 (capture d'écran du site analysé) : **toujours ouverte**, non implémentée.

### Phase 3 — Fiabilité de l'analyse ✅ livrée le 2026-10-19

Détail : [phases/PHASE_3.md](phases/PHASE_3.md). 43 règles de sévérité,
KEV, retrait des CVE non observées, RAG par constat. Mesure hors ligne sur
fixtures : example.com 0 → 93/100, ancrage 66,7 → 100 %. **À remesurer sur
la stack réelle** (le RAG est simulé dans la mesure).

Objectif : un score et des findings qu'on peut défendre.

- [x] **CISA KEV** : téléchargement quotidien du JSON, consultation directe.
      Une CVE Shodan présente dans KEV passe en sévérité critique.
- [x] **B6** Toute CVE citée par le LLM doit figurer dans `vulns_enriched`,
      sinon elle est retirée (dans `finding_sanitizer.py`).
- [x] **B5** Sévérité déterministe : table de règles par type de constat
      (DMARC absent, HSTS absent, takeover, KEV, EPSS > seuil…). Le LLM peut
      proposer, la règle tranche.
- [x] Ajouter `confidence` (`high` / `medium` / `low`) et `observed_at` au
      schéma des findings (`_OUTPUT_SCHEMA`, prompts cloud et Ollama, exports,
      PDF).
- [x] **B7** RAG réécrit : **une requête par finding**, 2 extraits chacune,
      filtrée par collection (`metadata->>'collection'`). Exemple : un finding
      email ne cherche que dans les RFC, l'ANSSI et les cheat sheets email.
- [x] Mesurer avant et après : `grounding_check`, `coverage_check`,
      `rag_snippets_used` sur un jeu de domaines de référence fixe.

### Phase 4 — MITRE ATT&CK étendu ✅ livrée le 2026-10-19

Détail : [phases/PHASE_4.md](phases/PHASE_4.md). Référentiel ATT&CK
Enterprise **v20.0** (`api/data/attack_reference.json`, 24 techniques,
25 mitigations). Le typosquatting passe de T1584.001 à T1583.001.

Objectif : passer de « ce que notre méthode collecte » à « ce que cette
exposition permet à un attaquant ».

- [x] **B8** Nouvelle table déterministe **finding → techniques rendues
      possibles** (Initial Access, Credential Access, Resource Development), en
      plus de la correspondance outil → technique existante :

| Constat | Technique rendue possible | Mitigation |
|---|---|---|
| DMARC absent ou `p=none` | T1566 Phishing | M1054, M1017 |
| Typosquatting avec MX configuré | T1583.001 → T1566 | M1056, surveillance de marque |
| CVE exposée présente dans KEV | T1190 Exploit Public-Facing Application | M1051, M1050 |
| VPN, RDP, Citrix ou panneau d'admin exposé | T1133 External Remote Services | M1032, M1035 |
| Adresses rôle dans des fuites | T1078 Valid Accounts, T1110.004 | M1032, M1027 |
| Sous-domaine vulnérable au takeover | T1584.001 | Nettoyage des CNAME |
| `.env`, `.git`, config dans les archives | T1552.001 Credentials in Files | M1022 |
| Secrets dans GitHub | T1593.003 → T1552 | Rotation des secrets |

- [x] Mitigations tirées des relations `mitigates` du bundle STIX (remplacent
      M1056 générique quand une technique plus précise s'applique).
- [x] Chaîne d'attaque plausible par rapport (ex. reconnaissance → T1566 →
      T1078). Les ID viennent de la table, le LLM rédige le récit.
- [x] Export **layer ATT&CK Navigator** (JSON) : techniques colorées par
      sévérité, téléchargeable depuis la page de résultat.
- [x] Mettre à jour le référentiel (le module indique Enterprise v15) vers la
      dernière version du bundle `mitre/cti`.
- [x] Optionnel : relations `uses` (groupe → technique), affichées comme
      **contexte**, jamais comme une menace avérée.
- [x] Étendre `data/script_mitre_attack.py` aux techniques du tableau et à
      leurs mitigations (collection `attack` du RAG).

### Phase 5 — Collecte passive enrichie ✅ livrée le 2026-10-19

Détail : [phases/PHASE_5.md](phases/PHASE_5.md). 9 outils ajoutés
(`api/utils/passive_sources/`) ; ceux à clé passent en `skipped` sans clé.
Capture d'écran non faite (D8 ouverte).

Objectif : combler les vraies lacunes, sans contredire le passif strict.
Réalisable en parallèle des phases 3 et 4.

Données et pivots :
- [x] **B4** Résolution DNS massive de tous les sous-domaines → vivant/mort,
      IP, ASN, CDN.
- [x] Shodan InternetDB sur **toutes les IP uniques** (gratuit, sans clé).
- [x] VirusTotal (réputation domaine/IP, passive DNS), clé gratuite.
- [x] GitHub secret dorks (extension de l'outil `github`).
- [x] DNSDumpster (API officielle).
- [x] GrayHatWarfare (buckets cloud exposés), priorité basse.

Repris de web-check (tous passifs) :
- [x] **block-lists** : réponse de 17 résolveurs filtrants (Quad9, AdGuard,
      CleanBrowsing, OpenDNS…).
- [x] **Safe Browsing + PhishTank** (URLhaus est déjà couvert par
      `abusech_check`).
- [x] **B11** Drapeaux des cookies (`Secure`, `HttpOnly`, `SameSite`), lus
      sur la réponse HTTP déjà récupérée.
- [x] **Tranco** : classement du site, sert à pondérer l'exposition.
- [x] **HSTS preload** : éligibilité via hstspreload.org.
- [x] **social-tags / linked-pages** : balises meta et domaines tiers liés.
- [ ] Optionnel : **capture d'écran** de la page d'accueil (ajoute Chromium à
      l'image).

Cohérence passive :
- [x] ~~**B10** `sslscan` en option désactivée par défaut~~ — abandonné,
      décision D7 : `sslscan` est conservé.
- [x] Mettre à jour `utils/mitre_attack.py` pour chaque nouvel outil.

### Phase 6 — Base de connaissance ✅ livrée le 2026-10-19

Détail : [phases/PHASE_6.md](phases/PHASE_6.md). Corpus ANSSI rédigé en
synthèse (cyber.gouv.fr bloque le téléchargement automatique : URL des guides
à vérifier à la main). Empreintes can-i-take-over-xyz branchées sur
`subdomain_takeover` (fin des faux positifs Fastly/Zendesk).

Objectif : un corpus organisé en collections, interrogé finding par finding.

| Collection | Contenu | Mode |
|---|---|---|
| `normes` | OWASP, ASVS, WSTG, Top 10, RFC (existant) + **guides ANSSI** (messagerie, TLS, DNS, sites web) + recommandations TLS Mozilla + CWE/CAPEC des findings courants | RAG |
| `attack` | Techniques et mitigations ATT&CK de la phase 4 | RAG |
| `menaces` | Avis CISA (AA-xxx), domaine public | RAG |
| `explications` | Textes pédagogiques par contrôle (inspirés de la page « About » de web-check, licence MIT) | RAG + modales du dashboard |
| *(hors RAG)* | CISA KEV, EPSS/CVSS, empreintes de takeover (`can-i-take-over-xyz`), Tranco | Consultation directe |

- [x] Ajouter le champ `collection` aux métadonnées d'ingestion
      (`n8n/workflows/rag-ingestion.json`) et réindexer l'existant.
- [x] Un script `data/script_*.py` par nouvelle source, sur le modèle
      existant. Licence de chaque source documentée.
- [x] Statistiques agrégées et anonymisées des scans passés (ex. « 70 % des
      domaines `.bj` scannés n'ont pas de DMARC »), injectées comme contexte
      comparatif. Pas d'indexation vectorielle des scans bruts.

### Phase 7 — Graphe d'entités, différentiel, surveillance ✅ livrée le 2026-10-19

Détail : [phases/PHASE_7.md](phases/PHASE_7.md). Différentiel stocké
**en clair** (données publiques uniquement, sinon le scan suivant ne pourrait
pas s'y comparer) — voir D10. Surveillance opt-in, désactivée par défaut.

- [x] Tables `entity` (type, valeur, première et dernière observation) et
      `relation` (source, cible, type, outil, scan) dans PostgreSQL. Chaîne
      modélisée : organisation → domaine → sous-domaine → IP → ASN →
      certificat → technologie → vulnérabilité.
- [x] **B9** Différentiel avec le scan précédent : nouveaux sous-domaines,
      certificat expirant, DMARC modifié, nouvelle CVE, nouveau port.
      Affiché dans le rapport et le dashboard.
- [x] Rescan planifié optionnel (cron n8n) avec alerte mail sur changement
      significatif.
- [x] Export des hôtes vivants (CSV/JSON) pour une phase active **autorisée**
      en dehors de Recon-IA.

### Phase 8 — Boucle agent (l'IA pilote la recon) ✅ livrée le 2026-10-19 (désactivée par défaut)

Détail : [phases/PHASE_8.md](phases/PHASE_8.md). Étape finale de
`/pass_recon`, `AGENT_RECON_ENABLED=false` par défaut ; refuse `qwen3:1.7b`.
Journal dans le PDF (Méthodologie), pivots repris par le graphe et l'analyse.

Prérequis : phases 5 et 7.

- [x] Exposer les fonctions d'outils de `routes/recon.py` comme tool calls du
      LLM (comme `web_search` aujourd'hui), avec liste blanche stricte d'outils
      passifs.
- [x] Le LLM reçoit un **résumé du graphe** (pas le JSON brut) et choisit les
      pivots : IP → reverse IP, certificat → SAN, sous-domaine sensible →
      en-têtes + Shodan + takeover.
- [x] Budget dur : nombre maximal de pivots, `SCAN_DEADLINE_SECONDS`,
      profondeur maximale. Tout pivot hors du périmètre déclaré est refusé.
- [x] Journal des décisions de l'agent (outil, raison, résultat) inclus dans
      la section Méthodologie du PDF.
- [x] Backend : cloud avec function calling (Gemini, DeepSeek) ou modèle local
      d'au moins 7–8B. `qwen3:1.7b` ne pilotera pas cette boucle de façon
      fiable.

---

## 6. Décisions

Tranchées par l'utilisateur le 2026-10-19 (D1 à D7). D8 et D9 restent
ouvertes et seront posées à l'entrée des phases concernées.

| # | Question | Décision |
|---|---|---|
| D1 | Le PDF reste-t-il joint au mail final ? | ✅ **Non** : le mail ne contient que le code d'accès |
| D2 | Durée de validité du code | ✅ **30 jours**, révocable |
| D3 | Chiffrer les résultats en BD avec une clé dérivée du code ? | ✅ **Oui**. Conséquence assumée : le dashboard admin ne voit plus que les métadonnées (statut, score, durées, compteurs) |
| D4 | Vérification de propriété du domaine (DNS TXT) | ✅ **Reportée** à une version ultérieure : les données collectées sont publiques (recon passive) |
| D5 | Reverse proxy | ✅ **Caddy** |
| D6 | Captcha | ✅ **Cloudflare Turnstile** |
| D7 | `sslscan` | ✅ **Conservé tel quel** : ses résultats sont exploités par la solution. Le point B10 est clos |
| D8 | Capture d'écran (Chromium) | Ouverte — non faite en phase 5 (alourdit l'image) |
| D9 | Backend LLM de référence pour la boucle agent et les mesures | Ouverte — la boucle est livrée mais **désactivée** tant qu'aucun backend capable n'est choisi (proposition : Gemini). `qwen3:1.7b` est refusé |
| D10 | Graphe et différentiel : chiffrés avec le code ou en clair ? | **En clair**, à valider : uniquement des données techniques publiques (comme le cache des scans), aucune donnée du demandeur ni de l'analyse IA ; chiffrés, le scan suivant ne pourrait jamais s'y comparer |
| D11 | Cache des scans bruts | ✅ **Conservé en BD sans purge**, consultable dans le dashboard admin (décision utilisateur du 2026-10-19) |

---

## 7. Écarté, et pourquoi

| Élément | Origine | Raison |
|---|---|---|
| Scan de ports, traceroute | web-check | **Actifs**, contredisent le passif strict |
| Lighthouse / qualité, empreinte carbone | web-check | Sans rapport avec la sécurité |
| Rapports CTI de Mandiant, CrowdStrike, Unit 42, Talos, ESET, Kaspersky… | Recommandation externe | Protégés par le droit d'auteur, lourds à découper, centrés acteurs et malwares, inutiles pour évaluer un domaine. Seuls les avis CISA (domaine public) sont retenus |
| OpenCTI / MISP comme socle | Recommandation externe | Trop lourds (OpenCTI : Elasticsearch, RabbitMQ, MinIO, environ 16 Go de RAM). PostgreSQL suffit pour le graphe. Les clusters MISP Galaxy restent utilisables en simples fichiers JSON |
| Malpedia | Recommandation externe | Base de malwares, hors périmètre |
| Qdrant / Chroma | Recommandation externe | pgvector déjà en place, Qdrant retiré volontairement |
| Fine-tuning (JSONL d'entraînement) | Recommandation externe | RAG + consultation directe : moins cher, traçable |
| Recon-ng, SpiderFoot, Maltego | Recommandation externe | Doublons des 47 outils. Maltego est commercial |
| theHarvester (emails nominatifs) | Recommandation externe | Données personnelles (RGPD). Au mieux, comptages et motifs d'adresses, jamais les adresses |
| SecurityTrails, Censys, RapidDNS, ThreatCrowd, Project Sonar | Audit `CLAUDE.md` §8 | Quotas inutilisables, plan gratuit dégradé, pas d'API officielle, ou service mort |
| T1595.002 et T1597 dans les rapports | Exemple de la recommandation externe | T1595.002 est un scan **actif**, T1597 désigne des sources fermées payantes : aucun ne correspond à ce que fait Recon-IA |

---

## 8. Risques

| Risque | Mitigation |
|---|---|
| Fuite du code d'accès (mail compromis, partage) | Expiration, révocation, journal des accès, pas de PDF en pièce jointe (D1) |
| Code d'accès perdu (D3) | Le rapport chiffré devient illisible, y compris pour l'admin. À annoncer clairement dans le mail. Relancer un scan reste possible |
| Usage abusif contre des domaines tiers | Captcha, rate limit par email et domaine, vérification de propriété (D4), consentement tracé |
| Quotas des API gratuites (VirusTotal ~4 req/min, OTX…) | Cache existant, dégradation propre (`limited`, `skipped`), file d'attente |
| Boucle agent qui dérive hors périmètre ou boucle sans fin | Liste blanche d'outils, budget dur, contrôle de périmètre à chaque pivot |
| Régression des rapports existants | Jeu de domaines de référence, mesures `grounding_check` / `coverage_check` avant et après chaque phase |
| Licences des sources du RAG | Licence documentée par script `data/script_*.py`, sources sous droit d'auteur exclues |
| Petit modèle local trop faible | Mesurer et documenter, backend cloud de référence pour les mesures (D9) |

---

## 9. Annexes

### 9.1 Correspondance web-check → Recon-IA

| Contrôle web-check | État dans Recon-IA | Action |
|---|---|---|
| DNS, DNSSEC, TXT, WHOIS, SSL, en-têtes, redirections, robots, sitemap, security.txt, archives, tech stack, WAF, mail, HSTS (en-tête) | Couvert | — |
| block-lists | Absent | Phase 5 |
| threats (Safe Browsing, PhishTank) | Partiel (URLhaus via `abusech_check`) | Phase 5 |
| cookies (drapeaux) | Noms seulement | Phase 5 |
| rank (Tranco) | Absent | Phase 5 |
| HSTS preload | Absent | Phase 5 |
| social-tags, linked-pages | Partiel (`og:` lu dans `tech_stack`) | Phase 5 |
| screenshot | Absent | D8 |
| ports, trace-route | — | Écarté (actif) |
| quality, carbon | — | Écarté (hors sécurité) |

### 9.2 Fichiers principalement touchés

| Phase | Fichiers |
|---|---|
| 0 | `api/utils/attack_surface.py`, `api/routes/recon.py`, `api/.env.example` |
| 1 | `docker-compose.yml`, `n8n/workflows/recon-ia-main.json`, `n8n/generate-credentials.js`, `n8n/provision-and-start.sh`, `web/index.html`, `api/routes/crud.py`, `api/routes/report.py`, nouveau `api/routes/results.py`, `api/models/recon.py`, `api/migrate.py`, `api/utils/email_sender.py`, `api/extensions.py`, `api/app.py` |
| 2 | nouveau `web/result.html` |
| 3 | `api/routes/analyze.py`, `api/utils/rag_retrieval.py`, `api/utils/finding_sanitizer.py`, `api/utils/ollama_client.py`, `api/utils/pdf_generator.py`, `api/routes/report.py` |
| 4 | `api/utils/mitre_attack.py`, `data/script_mitre_attack.py`, `api/utils/pdf_generator.py`, `web/result.html` |
| 5 | `api/routes/recon.py`, `api/routes/analyze.py` (`_extract_signals`), `api/utils/mitre_attack.py`, `api/Dockerfile` |
| 6 | `data/script_*.py`, `n8n/workflows/rag-ingestion.json`, `api/utils/rag_retrieval.py` |
| 7 | `api/migrate.py`, nouveaux modèles, `api/routes/report.py`, `n8n/workflows/` |
| 8 | `api/routes/analyze.py`, clients LLM (`api/utils/*_client.py`), `api/routes/recon.py` |

### 9.3 Schéma cible d'un finding

```json
{
  "id": "EMAIL-001",
  "title": "DMARC absent",
  "category": "Email",
  "severity": "HIGH",
  "severity_rule": "dmarc_missing",
  "confidence": "high",
  "observed_at": "2026-10-19T10:42:00Z",
  "source_tool": "dmarc_check",
  "source_tools": ["email_config"],
  "evidence": "Aucun enregistrement TXT _dmarc.exemple.bj",
  "attack_enabled": [{"id": "T1566", "name": "Phishing"}],
  "mitigations": [{"id": "M1054", "name": "Software Configuration"}],
  "references": [{"collection": "normes", "source": "RFC 7489"}],
  "recommendation": "Publier une politique DMARC p=quarantine puis p=reject (cf. RFC 7489, guide ANSSI messagerie)."
}
```
