# utils/rag_retrieval.py
"""
Recherche RAG (Retrieval-Augmented Generation) sur `rag_documents` (pgvector),
pour ancrer l'analyse IA (routes/analyze.py) dans le corpus OWASP Cheat
Sheets / ASVS / WSTG ingéré par le workflow n8n `rag-ingestion.json`.

Avant ce module, `rag_documents` était alimentée mais JAMAIS interrogée nulle
part dans le code — ni côté API, ni par aucun nœud du workflow n8n principal
(`recon-ia-main.json`, une simple chaîne d'appels HTTP sans nœud vector
store). Le RAG était donc un entrepôt mort : sans effet sur les rapports
produits, quel que soit son contenu. Ce module ferme cet écart en donnant à
`routes/analyze.py` un point d'entrée pour récupérer les extraits pertinents
AVANT l'appel au LLM, injectés dans `signals["rag_context"]` (même principe
que `signals["mitre_attack"]`, calculé déterministiquement côté serveur puis
fourni comme contexte au modèle plutôt que laissé à son imagination).

Dégradation : si Ollama (embeddings) ou Postgres/pgvector sont indisponibles,
ou si `rag_documents` est vide, retourne une liste vide sans lever — l'analyse
IA continue sans contexte RAG plutôt que d'échouer entièrement.
"""
import logging
import os
from typing import Dict, List

import requests
from sqlalchemy import text

from database import db

logger = logging.getLogger(__name__)

_OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://ollama:11434")
_EMBED_MODEL  = "nomic-embed-text:v1.5"  # doit rester IDENTIQUE au modèle utilisé à l'ingestion
_TOP_K        = int(os.getenv("RAG_TOP_K", "6"))
_EMBED_TIMEOUT = int(os.getenv("RAG_EMBED_TIMEOUT", "30"))


def _embed_query(query_text: str) -> List[float]:
    resp = requests.post(
        f"{_OLLAMA_URL}/api/embeddings",
        json={"model": _EMBED_MODEL, "prompt": query_text},
        timeout=_EMBED_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["embedding"]


def retrieve_relevant_docs(query_text: str, top_k: int = _TOP_K) -> List[Dict]:
    """
    Retourne jusqu'à `top_k` extraits OWASP/ASVS/WSTG les plus proches de
    `query_text` par similarité cosinus pgvector (opérateur `<=>`, index HNSW
    déjà créé par migrate.py — pas de scan séquentiel sur la table entière).

    Chaque élément : {"source": str, "content": str}. Liste vide (jamais
    d'exception propagée) si RAG indisponible ou vide — l'appelant doit
    pouvoir continuer l'analyse sans ce contexte.
    """
    if not query_text or not query_text.strip():
        return []

    try:
        vec = _embed_query(query_text)
    except Exception as e:
        logger.warning("[rag_retrieval] Embedding indisponible — analyse sans contexte RAG (%s)", e)
        return []

    vec_literal = "[" + ",".join(f"{v:.8f}" for v in vec) + "]"
    try:
        rows = db.session.execute(
            text(
                "SELECT content, metadata->>'source' AS source "
                "FROM rag_documents "
                "ORDER BY embedding <=> (:qvec)::vector "
                "LIMIT :k"
            ),
            {"qvec": vec_literal, "k": top_k},
        ).fetchall()
    except Exception as e:
        logger.warning("[rag_retrieval] Requête pgvector échouée — analyse sans contexte RAG (%s)", e)
        return []

    if not rows:
        logger.info("[rag_retrieval] rag_documents vide ou aucun résultat — analyse sans contexte RAG")

    return [{"source": r.source or "inconnu", "content": r.content} for r in rows]
