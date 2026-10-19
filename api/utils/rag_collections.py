# utils/rag_collections.py
"""
Collections du corpus RAG (phase 6) et règle « fichier source → collection ».

Le corpus `rag_documents` est découpé en quatre collections, portées par la
clé `metadata->>'collection'` de chaque extrait (posée à l'ingestion par le
nœud « Métadonnées RAG (collection) » de `n8n/workflows/rag-ingestion.json`,
et rattrapée pour l'existant par `data/sql/reindex_collections.sql`) :

  normes        OWASP (Cheat Sheets, ASVS, WSTG, Top 10), RFC IETF, guides
                ANSSI, recommandations TLS Mozilla, CWE/CAPEC
  attack        MITRE ATT&CK (phase 4 : combined_mitre_attack*.md)
  menaces       avis CISA (combined_cisa_*.md)
  explications  textes pédagogiques par contrôle (combined_explications*.md,
                générés depuis api/data/explanations/*.json)

La règle est volontairement fondée sur le NOM DE FICHIER (convention
`combined_<source>.md`), pour qu'une nouvelle source tombe dans la bonne
collection sans toucher au workflow. Elle existe en TROIS exemplaires qui
doivent rester identiques — c'est vérifié par tests/test_phase6_collections.py :

  - ici (Python, référence) ;
  - l'expression n8n du nœud « Métadonnées RAG (collection) » ;
  - le CASE de data/sql/reindex_collections.sql.
"""
import re

COLLECTIONS = ("normes", "attack", "menaces", "explications")
DEFAULT_COLLECTION = "normes"

# Ordre significatif : première règle qui correspond.
# (motif recherché dans le nom de fichier en minuscules, collection)
SOURCE_RULES = (
    ("mitre_attack", "attack"),
    ("combined_cisa", "menaces"),
    ("combined_explications", "explications"),
)

_BASENAME_RE = re.compile(r"[^/\\]+$")


def collection_for_source(source: str) -> str:
    """Collection d'un fichier du corpus, d'après son nom (chemin accepté)."""
    if not source:
        return DEFAULT_COLLECTION
    m = _BASENAME_RE.search(str(source).strip())
    name = (m.group(0) if m else str(source)).lower()
    for needle, collection in SOURCE_RULES:
        if needle in name:
            return collection
    return DEFAULT_COLLECTION
