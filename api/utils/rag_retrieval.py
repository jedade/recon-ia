# utils/rag_retrieval.py
"""
Recherche RAG (Retrieval-Augmented Generation) sur `rag_documents` (pgvector),
pour ancrer l'analyse IA (routes/analyze.py) dans le corpus OWASP Cheat
Sheets / ASVS / WSTG / RFC / MITRE ingéré par le workflow n8n
`rag-ingestion.json`.

Avant ce module, `rag_documents` était alimentée mais JAMAIS interrogée nulle
part dans le code — ni côté API, ni par aucun nœud du workflow n8n principal
(`recon-ia-main.json`, une simple chaîne d'appels HTTP sans nœud vector
store). Le RAG était donc un entrepôt mort : sans effet sur les rapports
produits, quel que soit son contenu. Ce module ferme cet écart en donnant à
`routes/analyze.py` un point d'entrée pour récupérer les extraits pertinents
AVANT l'appel au LLM, injectés dans `signals["rag_context"]` (même principe
que `signals["mitre_attack"]`, calculé déterministiquement côté serveur puis
fourni comme contexte au modèle plutôt que laissé à son imagination).

B7 (phase 3, 2026-10-19) — RAG réécrit :
  Avant : UNE requête globale (« technologies + TLS + SPF »), 6 extraits,
  tout le corpus mélangé — un finding email recevait aussi bien un extrait
  WSTG sur l'injection SQL qu'un extrait RFC DMARC.
  Maintenant :
  - **une requête par constat** (`build_rag_context`, avant le LLM : un
    constat par règle observée de utils/severity_rules.py) puis **une
    requête par finding** sans constat associé (`attach_references`, après
    le LLM) ;
  - **2 extraits** par requête (`RAG_SNIPPETS_PER_QUERY`) ;
  - **filtrage par collection** (`metadata->>'collection'`) : la catégorie
    du finding choisit les collections (Email → `normes` + `explications`,
    Reputation → `menaces`…), et tout finding reçoit en plus un extrait de
    la collection `attack` (MITRE ATT&CK) — 1 extrait « catégorie » + 1
    extrait `attack`, complétés l'un par l'autre si une collection est vide ;
  - **repli** : si AUCUNE ligne n'a de champ `collection` (corpus pas encore
    réindexé par la phase 6), requête sans filtre ;
  - chaque finding reçoit `references` : `[{"collection", "source"}]`.

Dégradation : si Ollama (embeddings) ou Postgres/pgvector sont indisponibles,
ou si `rag_documents` est vide, retourne une liste vide sans lever — l'analyse
IA continue sans contexte RAG plutôt que d'échouer entièrement.

Sécurité : toutes les requêtes SQL sont paramétrées (vecteur, collections,
limite) ; le vecteur d'embedding est revalidé (nombres finis uniquement) ;
les extraits sont tronqués avant d'être injectés dans un prompt.
"""
import logging
import math
import os
import time
from typing import Callable, Dict, List, Optional, Tuple

import requests
from sqlalchemy import text

from database import db

logger = logging.getLogger(__name__)

_OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://ollama:11434")
_EMBED_MODEL  = "nomic-embed-text:v1.5"  # doit rester IDENTIQUE au modèle utilisé à l'ingestion
_TOP_K        = int(os.getenv("RAG_TOP_K", "6"))
_EMBED_TIMEOUT = int(os.getenv("RAG_EMBED_TIMEOUT", "30"))
_SNIPPETS     = max(1, min(int(os.getenv("RAG_SNIPPETS_PER_QUERY", "2")), 5))
_MAX_QUERIES  = max(0, min(int(os.getenv("RAG_MAX_QUERIES", "8")), 30))
_MAX_FINDING_QUERIES = max(0, min(int(os.getenv("RAG_MAX_FINDING_QUERIES", "10")), 60))
_MAX_CONTENT  = 1500
_MAX_SOURCE   = 200

COLLECTIONS = ("normes", "attack", "menaces", "explications")

# Catégorie de finding → collections « métier » (la collection `attack` est
# toujours ajoutée en second extrait, voir module docstring).
CATEGORY_COLLECTIONS: Dict[str, Tuple[str, ...]] = {
    "Email":          ("normes", "explications"),
    "DNS":            ("normes", "explications"),
    "SSL":            ("normes", "explications"),
    "Web":            ("normes", "explications"),
    "Subdomain":      ("menaces", "explications"),
    "Infrastructure": ("menaces", "explications"),
    "Reputation":     ("menaces", "explications"),
    "Cloud":          ("menaces", "normes"),
}
_DEFAULT_COLLECTIONS = ("normes", "explications")

# Cache « le corpus a-t-il des collections ? » (évite une requête par appel).
_COLL_CACHE: Dict[str, float] = {"value": -1.0, "at": 0.0}
_COLL_CACHE_TTL_S = 600


def _embed_query(query_text: str) -> List[float]:
    resp = requests.post(
        f"{_OLLAMA_URL}/api/embeddings",
        json={"model": _EMBED_MODEL, "prompt": query_text[:2000]},
        timeout=_EMBED_TIMEOUT,
    )
    resp.raise_for_status()
    vec = resp.json()["embedding"]
    if not isinstance(vec, list) or not vec or len(vec) > 4096:
        raise ValueError("embedding invalide")
    out = [float(v) for v in vec]
    if not all(math.isfinite(v) for v in out):
        raise ValueError("embedding non fini")
    return out


def _vec_literal(vec: List[float]) -> str:
    return "[" + ",".join(f"{v:.8f}" for v in vec) + "]"


def _row(r, collection_fallback: Optional[str] = None) -> Dict:
    return {
        "source":     str(r.source or "inconnu")[:_MAX_SOURCE],
        "content":    str(r.content or "")[:_MAX_CONTENT],
        "collection": (str(r.collection)[:40] if getattr(r, "collection", None) else collection_fallback),
    }


def retrieve_relevant_docs(query_text: str, top_k: int = _TOP_K) -> List[Dict]:
    """
    Retourne jusqu'à `top_k` extraits les plus proches de `query_text` par
    similarité cosinus pgvector (opérateur `<=>`, index HNSW déjà créé par
    migrate.py — pas de scan séquentiel sur la table entière), SANS filtre de
    collection (comportement historique, conservé pour compatibilité).

    Chaque élément : {"source": str, "content": str, "collection": str|None}.
    Liste vide (jamais d'exception propagée) si RAG indisponible ou vide.
    """
    if not query_text or not query_text.strip():
        return []

    try:
        vec = _embed_query(query_text)
    except Exception as e:
        logger.warning("[rag_retrieval] Embedding indisponible — analyse sans contexte RAG (%s)", e)
        return []
    return _search(vec, None, top_k)


def _search(vec: List[float], collections: Optional[Tuple[str, ...]], k: int) -> List[Dict]:
    """Recherche paramétrée ; `collections=None` → sans filtre."""
    k = max(1, min(int(k), 20))
    try:
        if collections:
            cols = [c for c in collections if c in COLLECTIONS]
            if not cols:
                return []
            rows = db.session.execute(
                text(
                    "SELECT content, metadata->>'source' AS source, metadata->>'collection' AS collection "
                    "FROM rag_documents "
                    "WHERE metadata->>'collection' = ANY(:cols) "
                    "ORDER BY embedding <=> (:qvec)::vector "
                    "LIMIT :k"
                ),
                {"qvec": _vec_literal(vec), "cols": cols, "k": k},
            ).fetchall()
        else:
            rows = db.session.execute(
                text(
                    "SELECT content, metadata->>'source' AS source, metadata->>'collection' AS collection "
                    "FROM rag_documents "
                    "ORDER BY embedding <=> (:qvec)::vector "
                    "LIMIT :k"
                ),
                {"qvec": _vec_literal(vec), "k": k},
            ).fetchall()
    except Exception as e:
        logger.warning("[rag_retrieval] Requête pgvector échouée — analyse sans contexte RAG (%s)", e)
        try:
            db.session.rollback()
        except Exception:
            pass
        return []
    return [_row(r) for r in rows]


def corpus_has_collections() -> bool:
    """
    Vrai si au moins une ligne porte `metadata.collection`. Faux si le corpus
    n'est pas encore réindexé (ou si la base est indisponible) → repli sans
    filtre. Résultat mis en cache 10 min.
    """
    now = time.time()
    if _COLL_CACHE["value"] >= 0 and now - _COLL_CACHE["at"] < _COLL_CACHE_TTL_S:
        return bool(_COLL_CACHE["value"])
    try:
        row = db.session.execute(
            text("SELECT 1 FROM rag_documents WHERE metadata->>'collection' IS NOT NULL LIMIT 1")
        ).fetchone()
        value = 1.0 if row else 0.0
    except Exception as e:
        logger.warning("[rag_retrieval] Test des collections impossible (%s) — repli sans filtre", e)
        try:
            db.session.rollback()
        except Exception:
            pass
        value = 0.0
    _COLL_CACHE.update(value=value, at=now)
    if not value:
        logger.info("[rag_retrieval] Aucune collection dans rag_documents — requêtes sans filtre (repli)")
    return bool(value)


class TopicRetriever:
    """
    Une requête = un constat/finding → `_SNIPPETS` extraits filtrés par
    collection. Embeddings mis en cache par texte de requête pour la durée
    d'une analyse. `search_fn` / `embed_fn` injectables (tests, mesure hors
    ligne : tools/measure_phase3.py).
    """

    def __init__(self, embed_fn: Optional[Callable[[str], List[float]]] = None,
                 search_fn: Optional[Callable] = None,
                 has_collections: Optional[bool] = None):
        self._embed = embed_fn or _embed_query
        self._search = search_fn or _search
        self._has_coll = has_collections
        self._vec_cache: Dict[str, Optional[List[float]]] = {}
        self.queries = 0
        self.filtered = None

    def _collections_available(self) -> bool:
        if self._has_coll is None:
            self._has_coll = corpus_has_collections()
        return self._has_coll

    def retrieve(self, query: str, category: Optional[str], k: int = _SNIPPETS) -> List[Dict]:
        query = (query or "").strip()[:500]
        if not query:
            return []
        if query not in self._vec_cache:
            try:
                self._vec_cache[query] = self._embed(query)
            except Exception as e:
                logger.warning("[rag_retrieval] Embedding indisponible (%s)", e)
                self._vec_cache[query] = None
        vec = self._vec_cache[query]
        if vec is None:
            return []
        self.queries += 1

        if not self._collections_available():
            self.filtered = False
            return self._search(vec, None, k)

        self.filtered = True
        primary = tuple(c for c in CATEGORY_COLLECTIONS.get(category or "", _DEFAULT_COLLECTIONS)
                        if c != "attack")
        n_primary = max(1, k - 1)
        rows = list(self._search(vec, primary, n_primary))
        if k - len(rows) > 0:
            rows += self._search(vec, ("attack",), k - len(rows))
        if len(rows) < k:
            # Collection vide d'un côté : on complète avec l'autre.
            seen = {(r["source"], r["content"][:80]) for r in rows}
            for r in self._search(vec, primary + ("attack",), k * 2):
                if len(rows) >= k:
                    break
                if (r["source"], r["content"][:80]) not in seen:
                    rows.append(r)
        return rows[:k]


def build_rag_context(topics: List[Dict], retriever: Optional[TopicRetriever] = None,
                      max_queries: int = _MAX_QUERIES) -> Tuple[List[Dict], Dict]:
    """
    Avant le LLM : une requête par constat. `topics` = [{"id", "query",
    "category"}], déjà triés par priorité (sévérité décroissante).
    Retourne (rag_context, stats). Chaque extrait porte `topic` (id de la
    règle) et `collection`.
    """
    retriever = retriever or TopicRetriever()
    out: List[Dict] = []
    seen = set()
    for t in (topics or [])[:max_queries]:
        for r in retriever.retrieve(t.get("query"), t.get("category")):
            key = (r.get("source"), (r.get("content") or "")[:80])
            if key in seen:
                continue
            seen.add(key)
            out.append({**r, "topic": t.get("id"), "category": t.get("category")})
    return out, {"queries": retriever.queries, "filtered_by_collection": retriever.filtered}


def _ref(r: Dict) -> Dict:
    return {"collection": r.get("collection") or "corpus", "source": r.get("source") or "inconnu"}


def attach_references(findings: List[Dict], rag_context: List[Dict],
                      retriever: Optional[TopicRetriever] = None,
                      max_queries: int = _MAX_FINDING_QUERIES) -> Dict:
    """
    Après le LLM : ajoute `references` [{collection, source}] à chaque finding.
      - finding rattaché à une règle déjà interrogée (`severity_rule` ==
        `topic` d'un extrait) → mêmes extraits, aucune requête de plus ;
      - sinon → une requête (titre + catégorie), dans la limite de
        `max_queries`.
    Les références existantes (`collection: "llm"`) sont conservées.
    """
    by_topic: Dict[str, List[Dict]] = {}
    for r in rag_context or []:
        if r.get("topic"):
            by_topic.setdefault(r["topic"], []).append(r)
    retriever = retriever or TopicRetriever()
    before = retriever.queries
    with_refs = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rows = by_topic.get(f.get("severity_rule") or "")
        if rows is None and retriever.queries - before < max_queries:
            q = " ".join(str(f.get(k) or "") for k in ("title", "category"))[:300]
            rows = retriever.retrieve(q, f.get("category"))
        refs = list(f.get("references") or [])
        # Dédupliqué par source : « RFC 7489 » cité par le modèle ET retrouvé
        # par le RAG n'apparaît qu'une fois (la version RAG porte la collection).
        known = {str(x.get("source")).strip().lower() for x in refs if isinstance(x, dict)}
        added = False
        for r in rows or []:
            ref = _ref(r)
            key = str(ref["source"]).strip().lower()
            if key in known:
                for x in refs:
                    if isinstance(x, dict) and str(x.get("source")).strip().lower() == key \
                            and x.get("collection") == "llm":
                        x["collection"] = ref["collection"]
                continue
            refs.append(ref)
            known.add(key)
            added = True
        f["references"] = refs[:20]
        if added or any(isinstance(x, dict) and x.get("collection") != "llm" for x in refs):
            with_refs += 1
    return {"finding_queries": retriever.queries - before, "findings_with_rag_references": with_refs}
