# Phase 7 — Graphe d'entités, différentiel, surveillance

Livrée le 2026-10-19 (code et tests). Plan d'action : `docs/PLAN_ACTION.md`, section « Phase 7 ».

## 1. Vue d'ensemble

| Élément | Fichier |
|---|---|
| Modèles `entity`, `relation` | `api/models/entity_graph.py` |
| Modèles `scan_snapshot`, `watched_domain` | `api/models/scan_monitoring.py` |
| Extraction + upsert du graphe | `api/utils/entity_graph.py` |
| Empreinte de scan + différentiel (B9) | `api/utils/scan_diff.py` |
| Routes graphe / différentiel / surveillance | `api/routes/graph.py` (enregistré dans `routes/__init__.py`) |
| Branchement dans le pipeline | `api/routes/report.py::_record_graph_and_diff` |
| Alerte mail admin | `api/utils/email_sender.py::send_monitoring_alert` (ajout) |
| Migrations + droits `recon_app` | `api/migrate.py` (`PHASE7_MIGRATIONS`, `ROLE_GRANTS`) |
| Workflow n8n de rescan | `n8n/workflows/recon-ia-rescan.json` (inactif) |
| Dashboard | `web/dashboard.html` (onglet + hooks), `web/dashboard-graph.js`, `web/dashboard-graph.css` |
| Tests | `api/tests/test_phase7_{unit,security,integration}.py`, `api/tests/phase7_fixtures.py` |

## 2. Où et quand le graphe est construit

Le dossier est scellé en fin de pipeline : ensuite, le serveur ne peut plus lire `scan_results`.
Le graphe et le différentiel sont donc calculés **dans `POST /recon/<id>/generate_report`, avant le PDF
et avant le scellement**. Cette étape a sa propre transaction (commit séparé, placé avant toute autre
modification du dossier dans la requête). Si elle échoue, l'erreur est journalisée et le rapport
continue sans différentiel (`scan_diff: null` dans la réponse) : elle ne bloque jamais le pipeline.

Les rescans de surveillance n'ont pas de dossier. Ils partent du cache des scans bruts
(`pass_recon_cache`, en clair, jamais purgé).

## 3. Schéma des tables

```
entity(id SERIAL PK, type VARCHAR(20), value VARCHAR(512), attributes TEXT(JSON),
       first_seen TIMESTAMP, last_seen TIMESTAMP, UNIQUE(type, value))
relation(id SERIAL PK, source_id → entity ON DELETE CASCADE, target_id → entity ON DELETE CASCADE,
         type VARCHAR(32), tool VARCHAR(64), root_domain VARCHAR(255),
         recon_id → recon ON DELETE SET NULL, scan_ref VARCHAR(128),
         first_seen, last_seen, UNIQUE(source_id, target_id, type, root_domain))
scan_snapshot(id SERIAL PK, domain, recon_id UNIQUE → recon ON DELETE SET NULL, cache_id,
              scan_ref, source('pipeline'|'rescan'), snapshot_json TEXT, diff_json TEXT,
              previous_snapshot_id, significant BOOLEAN, change_count INTEGER, created_at)
watched_domain(id SERIAL PK, domain UNIQUE, enabled BOOLEAN DEFAULT FALSE, interval_days DEFAULT 7,
               last_rescan_at, last_snapshot_id, last_change_at, last_alert_at, created_at, updated_at)
```

Types d'entité : `organization, domain, subdomain, ip, asn, certificate, technology, vulnerability, port`.

Relations : `owns` (organisation → domaine, champ O= d'un certificat OV/EV), `has_subdomain`,
`resolves_to` (domaine/sous-domaine → IP), `observed_on` (sous-domaine vu par Shodan sur l'IP),
`announced_by` (IP → ASN), `operated_by` (ASN → organisation), `presents_certificate`,
`covers` (certificat → noms du SAN), `uses_technology`, `runs` (IP → CPE), `exposes` (IP → CVE),
`has_port` (IP → « ip:port »). InternetDB ne rattache pas une CVE à un CPE précis : on lie donc la CVE
à l'IP, sans inventer de lien technologie → CVE.

Les migrations n'utilisent que `CREATE ... IF NOT EXISTS` et ne touchent pas à `recon`.
`recon_app` reçoit `SELECT, INSERT, UPDATE, DELETE` sur les quatre tables, `rag_writer` rien.

## 4. Ce qui n'entre jamais dans le graphe (pas de PII)

- Les outils WHOIS/RDAP ne sont pas lus (le titulaire peut être une personne physique), pas plus que
  xposedornot, DKIM, `analysis_result` ou `final_report`. Le graphe ne contient ni l'identité du
  demandeur ni le contenu de l'analyse IA.
- Toute valeur contenant `@` est rejetée. Pour une IP, on ne garde que le pays (ni ville ni code postal).
- Les IP non routables (privées, loopback, métadonnées cloud…) sont écartées.
- Les valeurs sont validées type par type (nom d'hôte sous le domaine racine, ASN, CVE, port 1–65535,
  numéro de série hexadécimal…). Le nombre d'entités par scan est plafonné à 5000.
- Dans l'empreinte et le différentiel, les adresses email des enregistrements SPF/DMARC (`rua=`) sont
  remplacées par `email#<sha256[:10]>` : un changement d'adresse reste détecté.

## 5. Différentiel (B9) — décision de stockage

**Stocké en clair dans `scan_snapshot`, hors du bundle scellé.** Justification :
1. il ne contient que des données techniques publiques, de même nature que `pass_recon_cache`, déjà en
   clair et consultable par l'admin ;
2. le scan suivant doit pouvoir s'y comparer. Chiffré avec le code du demandeur, il serait illisible
   pour toujours, et le différentiel comme la surveillance deviendraient impossibles ;
3. le lien dossier ↔ domaine est déjà en clair dans `recon.domain` : `recon_id` n'apprend rien de plus.

Fonctions :
- `extract_snapshot(raw, domain=None) -> dict` : empreinte (sous-domaines, IP, ports, CVE,
  technologies, certificat, SPF, DMARC, sections `observed`).
- `diff_scans(previous_raw, current_raw, now=None, domain=None) -> dict` : fonction pure. Elle accepte
  des scans bruts ou des empreintes. `previous_raw=None` signifie premier scan (référence).
- `record_scan(domain, raw, scan_ref, now, recon_id=None, cache_id=None, source='pipeline')` : upsert
  par `recon_id`, avec flush.
- `diff_for_recon(recon_id) -> dict | None` : **point d'entrée pour la page de résultat et le PDF**.

Une section n'est comparée que si elle a été observée dans les deux scans (outil en succès). Un outil
en échec ne fait donc pas « disparaître » toutes les IP. La section porte alors `compared: false`.

Format :
```json
{
  "schema_version": 1, "domain": "example.com",
  "has_previous": true, "previous_scan_at": "2026-10-01T10:00:00Z",
  "previous_snapshot_id": 3, "previous_recon_id": 12,
  "significant": true, "change_count": 5,
  "subdomains":   {"compared": true, "added": ["admin.example.com"], "removed": [], "added_count": 1, "removed_count": 0},
  "ips":          {"compared": true, "added": [], "removed": [], "added_count": 0, "removed_count": 0},
  "ports":        {"compared": true, "added": ["93.184.216.34:8080"], "removed": [], "added_count": 1, "removed_count": 0},
  "cves":         {"compared": true, "added": ["CVE-2023-44487"], "removed": [], "added_count": 1, "removed_count": 0},
  "technologies": {"compared": true, "added": [], "removed": [], "added_count": 0, "removed_count": 0},
  "certificate": {"compared": true, "changed": false, "previous": {...}, "current":
                  {"id": "serial:0ABC", "subject_cn": "www.example.com", "issuer": "DigiCert Inc",
                   "not_after": "Dec 31 23:59:59 2026 GMT", "days_until_expiry": 70},
                  "days_until_expiry": 12, "expiring_soon": true, "expired": false},
  "email_security": {
    "spf":   {"compared": true, "changed": false, "previous": "...", "current": "..."},
    "dmarc": {"compared": true, "changed": true, "previous": "v=DMARC1; p=none", "current": "v=DMARC1; p=reject",
              "previous_policy": "none", "current_policy": "reject"}
  },
  "summary": ["1 nouveau(x) sous-domaine(s)", "1 nouveau(x) port(s) exposé(s)", "1 nouvelle(s) CVE",
              "Certificat TLS expirant dans 12 jour(s)", "DMARC modifié"]
}
```
Les listes sont plafonnées à 500 éléments ; les compteurs `*_count` restent exacts.
Est **significatif** : un nouveau sous-domaine, une nouvelle IP, un nouveau port ou une nouvelle CVE ;
un certificat changé, expiré ou qui expire dans moins de 30 jours ; un SPF ou un DMARC modifié. Les
disparitions et les changements de technologies comptent dans `change_count` mais ne déclenchent pas
d'alerte.

## 6. Endpoints

| Méthode | Chemin | Auth | Rôle |
|---|---|---|---|
| GET | `/graph/summary?domain=` | admin | compteurs par type d'entité/relation, dernier différentiel, état de surveillance |
| GET | `/graph/entities?domain=&type=&q=&page=&per_page=` | admin | entités paginées (≤ 200) |
| GET | `/graph/live_hosts?domain=&format=json\|csv&max_age_days=90` | admin | export des hôtes vivants (mention « phase active autorisée hors Recon-IA ») |
| GET | `/graph/snapshots?domain=&significant=&page=` | admin | historique des différentiels |
| GET | `/graph/snapshots/<id>` | admin | un différentiel complet |
| GET | `/recon/<id>/diff` | admin | différentiel d'un dossier (lisible même scellé) |
| GET | `/monitoring` | admin | domaines surveillés + `alert_email_configured` |
| POST | `/monitoring` `{domain, interval_days=7, enabled=false}` | admin | opt-in ; exige un dossier vérifié et consenti du domaine (sinon 409) |
| PATCH | `/monitoring/<id>` `{enabled, interval_days}` | admin | activer/désactiver |
| DELETE | `/monitoring/<id>` | admin | retirer (le graphe et l'historique restent) |
| GET | `/monitoring/due` | service ou admin | rescans dus (≤ `MONITORING_MAX_PER_RUN`, 5 par défaut) |
| POST | `/monitoring/<id>/ingest` | service ou admin | graphe + différentiel depuis la dernière entrée de cache du domaine, alerte admin si significatif ; idempotent (`scan_ref = cache:<id>:<updated_at>`) |

Le jeton de service n'ouvre aucune route admin (vérifié par les tests).

L'export des hôtes vivants contient, pour chaque nom d'hôte, ses IP, leurs ports connus, les outils
sources et `last_seen`. En CSV, deux premières lignes de commentaire `#` portent l'avertissement, les
cellules sont neutralisées contre l'injection de formule et le fichier commence par un BOM UTF-8. En
JSON, l'avertissement est dans le champ `notice`. Les deux formats portent l'en-tête
`X-Recon-IA-Notice`.

## 7. Rescan planifié

Le workflow `n8n/workflows/recon-ia-rescan.json` (id `RcnIaRescanWf007`, `active: false`) enchaîne :
cron 03:00 UTC → `GET /monitoring/due` → pour chaque domaine (un par un),
`POST /pass_recon {domain, force_refresh: true}` (sans `recon_id` : seul le cache est mis à jour, aucun
mail au demandeur) → `POST /monitoring/<id>/ingest`.

Destinataire de l'alerte : `MONITORING_ALERT_EMAIL`, à défaut `ADMIN_NOTIFICATION_EMAIL`. Jamais le
demandeur. Aucune alerte n'est envoyée sans scan précédent.

⚠️ `n8n/provision-and-start.sh` n'importe pas encore ce workflow (fichier hors de mon périmètre). Il
faut ajouter `"recon-ia-rescan:RcnIaRescanWf007:false"` à la boucle d'import, ou l'importer à la main
dans l'éditeur, puis l'activer.

## 8. Dashboard

- Nouvel onglet **« Graphe & surveillance »**. Il contient : les compteurs par type ; la liste filtrable
  des entités ; l'export des hôtes vivants en CSV/JSON (actif seulement quand un domaine est saisi) ;
  l'historique des différentiels avec leur détail ; la gestion de la surveillance (ajout désactivé par
  défaut, activer/désactiver, retirer).
- Dans le détail d'un dossier, une section **« Différentiel avec le scan précédent »** est ajoutée. Elle
  est aussi visible pour un dossier scellé.
- CSP : le code est dans `dashboard-graph.js`/`.css`, sans aucun nouveau script ni style inline, et le
  rendu passe uniquement par `textContent`. Le script inline existant expose `window.ReconDash`
  (`apiFetch`, `apiPost`, `apiSend`, `apiFetchBinary`, `formatDate`, `onUnauthorized`) : ce sont des
  fonctions liées à la session, jamais l'en-tête d'authentification.
- `scripts/e2e/dashboard.mjs` reçoit 4 vérifications de plus (section différentiel, compteurs, export
  désactivé sans domaine, tableau de surveillance).

## 9. RGPD

Les tables de la phase 7 ne contiennent aucune donnée personnelle. Les clés vers `recon` sont en
`ON DELETE SET NULL` : la purge (`utils/retention.py`, non modifié) supprime les demandes non vérifiées
sans casser le graphe (testé).

## 10. Tests

67 tests, tous verts. La suite complète passe aussi : 525 verts.
- `test_phase7_unit.py` : normalisation, extraction de toute la chaîne, attributs, tolérance (outils
  absents ou en échec, quatre formats de résolution DNS des sous-domaines), différentiel (premier scan,
  scans identiques, tous les types de changement, certificat expiré, outil en échec ≠ disparition,
  pureté, masquage des emails, entrées malformées).
- `test_phase7_security.py` (`security`) : 12 routes refusées sans authentification ou avec un faux
  jeton ; 10 routes admin refusées au jeton de service ; aucune PII dans le graphe ni l'empreinte ;
  valeurs hostiles (XSS, SQL, IP internes, ports invalides) ; paramètres et corps malformés ;
  surveillance limitée aux dossiers consentis et désactivée par défaut ; CSV sans formule.
- `test_phase7_integration.py` (`integration`) : flux `generate_report` → graphe → différentiel avant
  scellement sur deux dossiers successifs ; différentiel lisible par l'admin après scellement ; aucun
  doublon quand on régénère ; une erreur du graphe ne bloque pas le rapport ; résumé, entités et hôtes
  vivants ; rescan de surveillance complet avec alerte à l'admin, idempotence ; contenu du mail échappé ;
  purge RGPD ; migrations rejouées deux fois sur SQLite et identiques aux modèles ; droits de `recon_app`.
