-- data/sql/reindex_collections.sql
-- ---------------------------------------------------------------------------
-- Phase 6 — rattrapage du champ metadata.collection sur les extraits RAG
-- déjà présents dans rag_documents (ingérés avant l'ajout du nœud
-- « Métadonnées RAG (collection) » de n8n/workflows/rag-ingestion.json).
--
-- Exécutable par le rôle rag_writer (droits SELECT/UPDATE sur rag_documents,
-- cf. ROLE_GRANTS dans api/migrate.py) : aucun DDL, aucune autre table.
-- Idempotent : ne touche que les lignes SANS clé "collection".
--
--   docker exec -i postgres psql -U rag_writer -d "$POSTGRES_DB" \
--        -v ON_ERROR_STOP=1 < data/sql/reindex_collections.sql
--
-- Règle (identique à api/utils/rag_collections.py et au nœud n8n) sur le
-- nom de fichier porté par metadata.source :
--   contient "mitre_attack"          -> attack
--   contient "combined_cisa"         -> menaces
--   contient "combined_explications" -> explications
--   sinon                            -> normes
--
-- Cas des anciennes lignes dont metadata.source ne contient PAS le nom de
-- fichier (ex. "blob", valeur par défaut du chargeur n8n) : on ne peut pas
-- savoir de quel fichier elles viennent. Repli heuristique sur le contenu
-- (identifiants de techniques ATT&CK « T1xxx » + mention ATT&CK) pour la
-- collection attack, normes sinon — les avis CISA et les explications sont
-- de nouvelles sources, absentes de l'existant. Si ce repli ne convient
-- pas, préférer la RÉ-INGESTION complète (voir docs/phases/PHASE_6.md).
-- ---------------------------------------------------------------------------

BEGIN;

-- 1. État avant (pour le journal d'exploitation)
SELECT coalesce(metadata->>'collection', '(aucune)') AS collection,
       count(*)                                        AS lignes
FROM rag_documents
GROUP BY 1
ORDER BY 1;

-- 2. Rattrapage
UPDATE rag_documents
SET metadata = metadata || jsonb_build_object(
    'collection',
    CASE
        WHEN lower(coalesce(metadata->>'source', '')) LIKE '%mitre_attack%'          THEN 'attack'
        WHEN lower(coalesce(metadata->>'source', '')) LIKE '%combined_cisa%'         THEN 'menaces'
        WHEN lower(coalesce(metadata->>'source', '')) LIKE '%combined_explications%' THEN 'explications'
        WHEN lower(coalesce(metadata->>'source', '')) LIKE '%combined_%'             THEN 'normes'
        -- source inconnue : repli heuristique sur le contenu
        WHEN content ~ '\mT1[0-9]{3}(\.[0-9]{3})?\M'
             AND content ILIKE '%att&ck%'                                             THEN 'attack'
        ELSE 'normes'
    END
)
WHERE NOT (metadata ? 'collection');

-- 3. État après
SELECT metadata->>'collection' AS collection, count(*) AS lignes
FROM rag_documents
GROUP BY 1
ORDER BY 1;

COMMIT;
