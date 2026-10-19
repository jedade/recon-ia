"""
Script de migration manuelle — ajoute les colonnes et tables manquantes.

Utilisation :
    docker exec -it api python migrate.py

Ce script est idempotent : il utilise IF NOT EXISTS pour chaque opération.
Aucune donnée existante n'est modifiée ou supprimée.
"""
import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'), override=True)

# --- Connexion ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    user     = os.getenv('POSTGRES_USER')
    password = quote_plus(os.getenv('POSTGRES_PASSWORD', ''))
    dbname   = os.getenv('POSTGRES_DB')
    database_url = f"postgresql://{user}:{password}@postgres:5432/{dbname}"

from db_url import with_psycopg2  # noqa: E402  (pilote explicite, voir db_url.py)

engine = create_engine(with_psycopg2(database_url))

# ---------------------------------------------------------------------------
# Migrations déclarées
# ---------------------------------------------------------------------------

MIGRATIONS = [

    # ── Table recon : table de base (absente sur une DB neuve — sans elle,
    #    les ALTER TABLE ci-dessous échouent et bloquent tout le démarrage,
    #    entrypoint.sh ayant un `set -e`) ───────────────────────────────────

    ("recon", "(table)",
     """
     CREATE TABLE IF NOT EXISTS recon (
         id           SERIAL PRIMARY KEY,
         domain       VARCHAR(255) NOT NULL,
         firstname    VARCHAR(255) NOT NULL,
         lastname     VARCHAR(255) NOT NULL,
         email        VARCHAR(255) NOT NULL UNIQUE,
         accord       BOOLEAN      NOT NULL DEFAULT FALSE,
         verification BOOLEAN      NOT NULL DEFAULT FALSE,
         status       VARCHAR(20)  NOT NULL DEFAULT 'pending',
         created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
     )
     """),

    # ── Table recon : colonnes ajoutées après le déploiement initial ─────────

    ("recon", "otp_code",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS otp_code VARCHAR(6)"),

    ("recon", "otp_sent_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS otp_sent_at TIMESTAMP"),

    ("recon", "otp_attempts",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS otp_attempts INTEGER NOT NULL DEFAULT 0"),

    ("recon", "start_report_date",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS start_report_date TIMESTAMP"),

    ("recon", "end_report_date",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS end_report_date TIMESTAMP"),

    ("recon", "requested_info",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS requested_info TEXT"),

    ("recon", "scan_results",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS scan_results TEXT"),

    ("recon", "final_report",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS final_report TEXT"),

    ("recon", "current_step",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS current_step VARCHAR(30)"),

    ("recon", "current_step_updated_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS current_step_updated_at TIMESTAMP"),

    ("recon", "execution_time",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS execution_time FLOAT"),

    ("recon", "started_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS started_at TIMESTAMP"),

    ("recon", "completed_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP"),

    ("recon", "updated_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP"),

    ("recon", "pdf_report",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS pdf_report BYTEA"),

    ("recon", "pdf_generated_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS pdf_generated_at TIMESTAMP"),

    ("recon", "analysis_result",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS analysis_result TEXT"),

    ("recon", "analysis_generated_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS analysis_generated_at TIMESTAMP"),

    ("recon", "analysis_expires_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS analysis_expires_at TIMESTAMP"),

    ("recon", "ix_recon_analysis_expires_at",
     "CREATE INDEX IF NOT EXISTS ix_recon_analysis_expires_at ON recon (analysis_expires_at)"),

    # ── Score de sécurité dénormalisé (phase 4) ─────────────────────────────
    # Extrait de analysis_result pour éviter de rapatrier et parser le rapport
    # IA complet à chaque affichage de liste et à chaque calcul de moyenne.
    ("recon", "security_score",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS security_score INTEGER"),

    ("recon", "security_grade",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS security_grade VARCHAR(2)"),

    ("recon", "ix_recon_security_score",
     "CREATE INDEX IF NOT EXISTS ix_recon_security_score ON recon (security_score)"),

    # Backfill des enregistrements existants : renseigne les colonnes depuis le
    # JSON déjà stocké. Idempotent (ne touche que les lignes encore NULL) et
    # sans effet si l'opérateur JSON n'est pas disponible — le modèle sait de
    # toute façon retomber sur le parsing Python pour ces lignes.
    ("recon", "(backfill security_score)",
     """
     UPDATE recon
        SET security_score = NULLIF(analysis_result::json->>'security_score', '')::int,
            security_grade = NULLIF(analysis_result::json->>'security_grade', '')
      WHERE analysis_result IS NOT NULL
        AND security_score IS NULL
     """),

    # ── Tokens IA consommés dénormalisés (mesure de coût/usage, 2026-07-30) ──
    # Même logique que security_score ci-dessus. Le rapport JSON contient déjà
    # `tokens_used` (voir routes/analyze.py::_run_backend et utils/*_client.py).
    ("recon", "tokens_prompt",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS tokens_prompt INTEGER"),

    ("recon", "tokens_completion",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS tokens_completion INTEGER"),

    ("recon", "tokens_total",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS tokens_total INTEGER"),

    # Backfill : les analyses produites AVANT cette colonne n'ont pas de
    # `tokens_used` dans leur JSON (champ ajouté en même temps) — cette requête
    # ne renseignera donc rien pour elles (NULLIF sur une clé absente → NULL),
    # ce qui est le comportement correct (aucune valeur à inventer).
    ("recon", "(backfill tokens_used)",
     """
     UPDATE recon
        SET tokens_prompt     = NULLIF(analysis_result::json->'tokens_used'->>'prompt_tokens', '')::int,
            tokens_completion = NULLIF(analysis_result::json->'tokens_used'->>'completion_tokens', '')::int,
            tokens_total      = NULLIF(analysis_result::json->'tokens_used'->>'total_tokens', '')::int
      WHERE analysis_result IS NOT NULL
        AND tokens_total IS NULL
     """),

    # ── Coffre des résultats : code d'accès + chiffrement (2026-10-19) ───────
    # Voir utils/result_vault.py. `access_token_hash` est UNIQUE : deux
    # dossiers ne peuvent pas partager une empreinte (collision HMAC de
    # 256 bits = impossible en pratique, la contrainte rend l'invariant
    # explicite et sert d'index de recherche).
    ("recon", "sealed_bundle",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS sealed_bundle BYTEA"),

    ("recon", "sealed_pdf",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS sealed_pdf BYTEA"),

    ("recon", "sealed_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS sealed_at TIMESTAMP"),

    ("recon", "access_salt",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS access_salt VARCHAR(32)"),

    ("recon", "access_token_hash",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS access_token_hash VARCHAR(64)"),

    ("recon", "ix_recon_access_token_hash",
     "CREATE UNIQUE INDEX IF NOT EXISTS ix_recon_access_token_hash ON recon (access_token_hash)"),

    ("recon", "access_expires_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS access_expires_at TIMESTAMP"),

    ("recon", "access_revoked_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS access_revoked_at TIMESTAMP"),

    ("recon", "access_count",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS access_count INTEGER NOT NULL DEFAULT 0"),

    ("recon", "last_access_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS last_access_at TIMESTAMP"),

    ("recon", "results_purged_at",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS results_purged_at TIMESTAMP"),

    # ── Métriques de conformité dénormalisées (dashboard recherche/présentation) ──
    # Même logique que security_score/security_grade ci-dessus : extraites une
    # fois au moment du calcul (analyze.py / recon.py) pour que /recon/stats
    # les agrège en SQL/Python léger sans jamais reparser scan_results ou
    # analysis_result (gros blobs `db.deferred`) à chaque requête.
    ("recon", "findings_total_count",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS findings_total_count INTEGER"),

    ("recon", "findings_traceable_count",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS findings_traceable_count INTEGER"),

    ("recon", "mitre_technique_count",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS mitre_technique_count INTEGER"),

    ("recon", "mitre_technique_ids",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS mitre_technique_ids TEXT"),

    ("recon", "tools_status_summary",
     "ALTER TABLE recon ADD COLUMN IF NOT EXISTS tools_status_summary TEXT"),

    # ── Un email = plusieurs scans possibles (2026-07-30) ────────────────────
    # Remplace l'ancien mécanisme de « relance différée » à enregistrement
    # unique par email (colonnes pending_* + contrainte UNIQUE(email)) — voir
    # CLAUDE.md §5 pour la justification complète. Chaque POST /recon crée
    # désormais systématiquement un nouvel enregistrement, y compris pour un
    # email déjà vu : nécessaire pour la reproductibilité scientifique
    # (relancer le même domaine plusieurs fois doit produire plusieurs
    # rapports distincts et conservés, pas un seul réécrit à chaque fois).
    ("recon", "(drop unique email)",
     "ALTER TABLE recon DROP CONSTRAINT IF EXISTS recon_email_key"),

    ("recon", "(drop pending_domain)",
     "ALTER TABLE recon DROP COLUMN IF EXISTS pending_domain"),

    ("recon", "(drop pending_firstname)",
     "ALTER TABLE recon DROP COLUMN IF EXISTS pending_firstname"),

    ("recon", "(drop pending_lastname)",
     "ALTER TABLE recon DROP COLUMN IF EXISTS pending_lastname"),

    ("recon", "(drop pending_accord)",
     "ALTER TABLE recon DROP COLUMN IF EXISTS pending_accord"),

    ("recon", "(drop pending_requested_info)",
     "ALTER TABLE recon DROP COLUMN IF EXISTS pending_requested_info"),

    # ── Table audit_log : crée la table si elle n'existe pas ─────────────────

    ("audit_log", "(table)",
     """
     CREATE TABLE IF NOT EXISTS audit_log (
         id          SERIAL PRIMARY KEY,
         method      VARCHAR(10)  NOT NULL,
         endpoint    VARCHAR(255) NOT NULL,
         status_code INTEGER      NOT NULL,
         duration_ms FLOAT,
         ip_address  VARCHAR(45),
         user_agent  VARCHAR(200),
         created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
     )
     """),

    ("audit_log", "ix_audit_log_created_at",
     "CREATE INDEX IF NOT EXISTS ix_audit_log_created_at  ON audit_log (created_at)"),

    ("audit_log", "ix_audit_log_endpoint",
     "CREATE INDEX IF NOT EXISTS ix_audit_log_endpoint    ON audit_log (endpoint)"),

    ("audit_log", "ix_audit_log_status_code",
     "CREATE INDEX IF NOT EXISTS ix_audit_log_status_code ON audit_log (status_code)"),

    ("audit_log", "ix_audit_log_ip",
     "CREATE INDEX IF NOT EXISTS ix_audit_log_ip          ON audit_log (ip_address)"),

    # ── Table pass_recon_cache : cache des résultats /pass_recon ─────────────

    ("pass_recon_cache", "(table)",
     """
     CREATE TABLE IF NOT EXISTS pass_recon_cache (
         id               SERIAL PRIMARY KEY,

         -- Clé de cache
         domain           VARCHAR(255)  NOT NULL,
         tools_key        VARCHAR(1024) NOT NULL,

         -- Résultat
         result_json      TEXT          NOT NULL,
         scan_duration_s  FLOAT,
         subdomain_count  INTEGER       NOT NULL DEFAULT 0,

         -- Statistiques d'utilisation
         hit_count        INTEGER       NOT NULL DEFAULT 0,
         last_hit_at      TIMESTAMP,

         -- Horodatage
         created_at       TIMESTAMP     NOT NULL DEFAULT NOW(),
         updated_at       TIMESTAMP     NOT NULL DEFAULT NOW(),
         expires_at       TIMESTAMP     NOT NULL,

         -- Contrainte unicité (domain, tools_key)
         CONSTRAINT uq_pass_recon_cache_domain_tools UNIQUE (domain, tools_key)
     )
     """),

    ("pass_recon_cache", "ix_pass_recon_cache_domain",
     "CREATE INDEX IF NOT EXISTS ix_pass_recon_cache_domain         ON pass_recon_cache (domain)"),

    ("pass_recon_cache", "ix_pass_recon_cache_expires",
     "CREATE INDEX IF NOT EXISTS ix_pass_recon_cache_expires        ON pass_recon_cache (expires_at)"),

    ("pass_recon_cache", "ix_pass_recon_cache_domain_expires",
     "CREATE INDEX IF NOT EXISTS ix_pass_recon_cache_domain_expires ON pass_recon_cache (domain, expires_at)"),

    # ── RAG : extension pgvector + table rag_documents ────────────────────────
    # Remplace Pinecone comme store vectoriel du RAG n8n (cheat sheets OWASP,
    # CWE/CAPEC, ASVS/WSTG…) — voir n8n/workflows/rag-ingestion.json. Nécessite
    # l'image `pgvector/pgvector:pg16` (docker-compose.yml) — l'extension
    # n'existe pas sur `postgres:16-alpine`.
    #
    # Schéma volontairement aligné sur les 4 colonnes standard attendues par
    # le nœud LangChain "Postgres PGVector Store" (id/content/metadata/
    # embedding) : source/catégorie du document vivent dans `metadata` (ex:
    # {"source": "owasp_asvs", "category": "web"}) plutôt qu'en colonnes
    # dédiées, que ce nœud ne saurait pas remplir.
    #
    # Dimension 768 = embeddings Ollama `nomic-embed-text:v1.5` (gratuit,
    # local, cohérent avec le reste de la cascade IA). Si un autre modèle
    # d'embedding est utilisé côté n8n, adapter la dimension avant le premier
    # déploiement (un ALTER TYPE sur une table déjà peuplée impose de tout
    # ré-embarquer).

    ("rag_documents", "(extension vector)",
     "CREATE EXTENSION IF NOT EXISTS vector"),

    ("rag_documents", "(table)",
     """
     CREATE TABLE IF NOT EXISTS rag_documents (
         id          SERIAL PRIMARY KEY,
         content     TEXT         NOT NULL,
         metadata    JSONB        NOT NULL DEFAULT '{}',
         embedding   vector(768),
         created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
     )
     """),

    ("rag_documents", "ix_rag_documents_metadata",
     "CREATE INDEX IF NOT EXISTS ix_rag_documents_metadata ON rag_documents USING gin (metadata)"),

    ("rag_documents", "ix_rag_documents_embedding_hnsw",
     "CREATE INDEX IF NOT EXISTS ix_rag_documents_embedding_hnsw "
     "ON rag_documents USING hnsw (embedding vector_cosine_ops)"),
]

# ---------------------------------------------------------------------------
# Phase 7 (2026-10-19) — voir models/entity_graph.py et models/scan_monitoring.py
# ---------------------------------------------------------------------------
# Liste séparée, ajoutée à MIGRATIONS ci-dessous, pour pouvoir être rejouée
# seule par les tests (SQL portable PostgreSQL/SQLite, tests/test_phase7_integration.py).
# Uniquement des CREATE ... IF NOT EXISTS : rejouables à chaque démarrage.
# Les clés étrangères vers recon sont en ON DELETE SET NULL : la purge RGPD
# (utils/retention.py, suppression des demandes jamais vérifiées) ne casse
# ni le graphe ni l'historique des différentiels, qui ne contiennent aucune
# donnée personnelle. Aucune colonne n'est ajoutée à `recon`.
PHASE7_MIGRATIONS = [
    ("entity", "(table)",
     """
     CREATE TABLE IF NOT EXISTS entity (
         id          SERIAL PRIMARY KEY,
         type        VARCHAR(20)  NOT NULL,
         value       VARCHAR(512) NOT NULL,
         attributes  TEXT,
         first_seen  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
         last_seen   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
         CONSTRAINT uq_entity_type_value UNIQUE (type, value)
     )
     """),

    ("entity", "ix_entity_type",
     "CREATE INDEX IF NOT EXISTS ix_entity_type ON entity (type)"),

    ("entity", "ix_entity_last_seen",
     "CREATE INDEX IF NOT EXISTS ix_entity_last_seen ON entity (last_seen)"),

    ("relation", "(table)",
     """
     CREATE TABLE IF NOT EXISTS relation (
         id           SERIAL PRIMARY KEY,
         source_id    INTEGER      NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
         target_id    INTEGER      NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
         type         VARCHAR(32)  NOT NULL,
         tool         VARCHAR(64),
         root_domain  VARCHAR(255) NOT NULL,
         recon_id     INTEGER      REFERENCES recon(id) ON DELETE SET NULL,
         scan_ref     VARCHAR(128),
         first_seen   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
         last_seen    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
         CONSTRAINT uq_relation_edge UNIQUE (source_id, target_id, type, root_domain)
     )
     """),

    ("relation", "ix_relation_root_domain",
     "CREATE INDEX IF NOT EXISTS ix_relation_root_domain ON relation (root_domain)"),

    ("relation", "ix_relation_source",
     "CREATE INDEX IF NOT EXISTS ix_relation_source ON relation (source_id)"),

    ("relation", "ix_relation_target",
     "CREATE INDEX IF NOT EXISTS ix_relation_target ON relation (target_id)"),

    ("scan_snapshot", "(table)",
     """
     CREATE TABLE IF NOT EXISTS scan_snapshot (
         id                    SERIAL PRIMARY KEY,
         domain                VARCHAR(255) NOT NULL,
         recon_id              INTEGER      UNIQUE REFERENCES recon(id) ON DELETE SET NULL,
         cache_id              INTEGER,
         scan_ref              VARCHAR(128) NOT NULL,
         source                VARCHAR(16)  NOT NULL DEFAULT 'pipeline',
         snapshot_json         TEXT         NOT NULL,
         diff_json             TEXT,
         previous_snapshot_id  INTEGER,
         significant           BOOLEAN      NOT NULL DEFAULT FALSE,
         change_count          INTEGER      NOT NULL DEFAULT 0,
         created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
     )
     """),

    ("scan_snapshot", "ix_scan_snapshot_domain_created",
     "CREATE INDEX IF NOT EXISTS ix_scan_snapshot_domain_created ON scan_snapshot (domain, created_at)"),

    ("scan_snapshot", "ix_scan_snapshot_scan_ref",
     "CREATE INDEX IF NOT EXISTS ix_scan_snapshot_scan_ref ON scan_snapshot (scan_ref)"),

    ("watched_domain", "(table)",
     """
     CREATE TABLE IF NOT EXISTS watched_domain (
         id                SERIAL PRIMARY KEY,
         domain            VARCHAR(255) NOT NULL UNIQUE,
         enabled           BOOLEAN      NOT NULL DEFAULT FALSE,
         interval_days     INTEGER      NOT NULL DEFAULT 7,
         last_rescan_at    TIMESTAMP,
         last_snapshot_id  INTEGER,
         last_change_at    TIMESTAMP,
         last_alert_at     TIMESTAMP,
         created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
         updated_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
     )
     """),
]

MIGRATIONS += PHASE7_MIGRATIONS

# ---------------------------------------------------------------------------
# Exécution
# ---------------------------------------------------------------------------

def run():
    ok = 0
    errors = 0
    with engine.connect() as conn:
        for table, column, sql in MIGRATIONS:
            try:
                conn.execute(text(sql))
                conn.commit()
                print(f"  ✓  {table}.{column}")
                ok += 1
            except Exception as e:
                conn.rollback()
                print(f"  ✗  {table}.{column} — {e}")
                errors += 1

    print(f"\n{'='*50}")
    print(f"Migration terminée : {ok} succès, {errors} erreur(s)")
    if errors:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Rôles à droits minimaux (2026-10-19, plan d'action phase 1)
# ---------------------------------------------------------------------------
# Les migrations tournent avec le compte propriétaire ; à l'exécution, l'API
# et n8n utilisent chacun un rôle limité, créé ou resynchronisé ici à chaque
# démarrage (idempotent) quand son mot de passe est fourni :
#
#   recon_app  (API, APP_DB_PASSWORD) : lecture/écriture sur recon, audit_log,
#              pass_recon_cache et les tables de la phase 7 (entity, relation,
#              scan_snapshot, watched_domain) ; lecture seule sur
#              rag_documents ; aucun DDL.
#   rag_writer (n8n, RAG_DB_PASSWORD) : rag_documents UNIQUEMENT (le nœud
#              « Postgres PGVector Store » y écrit, le workflow la vide par
#              TRUNCATE). USAGE + CREATE sur le schéma : le nœud exécute
#              `CREATE TABLE IF NOT EXISTS`, refusé sans CREATE même quand la
#              table existe déjà (vérifié sur la vraie base). Aucun accès à
#              recon/audit_log/pass_recon_cache : une compromission de n8n ne
#              donne plus accès aux dossiers des demandeurs.
#
# psycopg2 interpole les paramètres côté client, d'où la possibilité de passer
# le mot de passe en paramètre à ALTER ROLE (instruction qui n'accepte pas de
# paramètre côté serveur). Les noms de rôles sont des constantes.
ROLE_GRANTS = {
    'recon_app': ('APP_DB_PASSWORD', [
        "GRANT USAGE ON SCHEMA public TO recon_app",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON recon, audit_log, pass_recon_cache TO recon_app",
        # Phase 7 : graphe d'entités, différentiel, surveillance
        "GRANT SELECT, INSERT, UPDATE, DELETE ON entity, relation, scan_snapshot, watched_domain TO recon_app",
        "GRANT SELECT ON rag_documents TO recon_app",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO recon_app",
    ]),
    'rag_writer': ('RAG_DB_PASSWORD', [
        "GRANT USAGE, CREATE ON SCHEMA public TO rag_writer",
        "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON rag_documents TO rag_writer",
        "GRANT USAGE, SELECT ON SEQUENCE rag_documents_id_seq TO rag_writer",
    ]),
}


def ensure_roles():
    errors = 0
    with engine.connect() as conn:
        for role, (env_var, grants) in ROLE_GRANTS.items():
            password = os.getenv(env_var, '')
            if not password:
                print(f"  -  rôle {role} non configuré ({env_var} absent) — compte propriétaire utilisé")
                continue
            try:
                exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {'r': role}).scalar()
                verb = 'ALTER' if exists else 'CREATE'
                conn.execute(text(f"{verb} ROLE {role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                                  f"PASSWORD :pw"), {'pw': password})
                conn.execute(text(f"DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO {role}', "
                                  f"current_database()); END $$"))
                for grant in grants:
                    conn.execute(text(grant))
                conn.commit()
                print(f"  ✓  rôle {role} ({'mis à jour' if exists else 'créé'})")
            except Exception as e:
                conn.rollback()
                print(f"  ✗  rôle {role} — {e}")
                errors += 1
    if errors:
        sys.exit(1)


def backfill_compliance_metrics():
    """
    Renseigne les colonnes de conformité (findings_total_count,
    findings_traceable_count, mitre_technique_count/ids, tools_status_summary)
    pour les analyses produites AVANT l'ajout de ces colonnes.

    Recalcule depuis analysis_result (findings, mitre_attack) et scan_results
    (pour reconstruire les clés d'outils réellement exécutés, même logique que
    _tools_executed() dans routes/analyze.py) — lecture seule sur des blobs
    déjà stockés, aucun nouvel appel IA/OSINT. Idempotent : ne touche que les
    lignes où findings_total_count est encore NULL.
    """
    import json as _json

    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, analysis_result, scan_results FROM recon "
            "WHERE analysis_result IS NOT NULL AND findings_total_count IS NULL"
        )).fetchall()

        if not rows:
            print("\nBackfill conformité : rien à faire (0 ligne concernée).")
            return

        updated = 0
        for recon_id, analysis_json, scan_json in rows:
            try:
                analysis = _json.loads(analysis_json) if analysis_json else {}
            except Exception:
                analysis = {}
            try:
                scan = _json.loads(scan_json) if scan_json else {}
            except Exception:
                scan = {}

            executed_keys = {
                key for key, value in scan.items()
                if isinstance(value, dict) and isinstance(value.get("meta"), dict)
                and value["meta"].get("tool")
            }

            findings = analysis.get("findings") or []
            total = len(findings)
            traceable = sum(
                1 for f in findings
                if isinstance(f, dict) and f.get("source_tool") in executed_keys
            )

            mitre = analysis.get("mitre_attack") or []
            technique_ids = sorted({
                m.get("technique_id") for m in mitre
                if isinstance(m, dict) and m.get("technique_id")
            })

            tool_status_counts: dict = {}
            for key in executed_keys:
                status = scan[key].get("status", "unknown")
                tool_status_counts[status] = tool_status_counts.get(status, 0) + 1

            conn.execute(text(
                "UPDATE recon SET findings_total_count=:total, "
                "findings_traceable_count=:traceable, mitre_technique_count=:mcount, "
                "mitre_technique_ids=:mids, tools_status_summary=:tstatus WHERE id=:id"
            ), {
                "total": total, "traceable": traceable,
                "mcount": len(technique_ids),
                "mids": _json.dumps(technique_ids, ensure_ascii=False),
                "tstatus": _json.dumps(tool_status_counts, ensure_ascii=False),
                "id": recon_id,
            })
            updated += 1
        conn.commit()
        print(f"\nBackfill conformité : {updated} enregistrement(s) mis à jour.")


if __name__ == '__main__':
    print("=== Migration recon-ia ===\n")
    run()
    backfill_compliance_metrics()
    print("\n=== Rôles à droits minimaux ===")
    ensure_roles()  # après les migrations : les GRANT visent des tables existantes
