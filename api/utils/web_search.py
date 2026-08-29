# utils/web_search.py
"""
Client de recherche web pour enrichissement IA.

Provider par défaut : DuckDuckGo (gratuit, sans clé API).
Provider alternatif  : Tavily (si TAVILY_API_KEY présent dans .env).

Usage :
    from utils.web_search import search_web
    results = search_web("WordPress 6.9 CVE 2025", max_results=5)
    # [{"title": ..., "url": ..., "snippet": ...}, ...]
"""

import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def search_web(query: str, max_results: int = 5) -> List[Dict[str, str]]:
    """
    Lance une recherche web et retourne une liste de résultats.
    Chaque résultat : {"title": str, "url": str, "snippet": str}

    Utilise Tavily en priorité si TAVILY_API_KEY est défini, sinon DuckDuckGo.
    """
    if not query or not query.strip():
        return []

    tavily_key = os.getenv("TAVILY_API_KEY", "").strip()
    if tavily_key:
        results = _search_tavily(query, max_results, tavily_key)
        if results:
            return results

    return _search_ddg(query, max_results)


# ── DuckDuckGo ────────────────────────────────────────────────────────────────

def _search_ddg(query: str, max_results: int) -> List[Dict[str, str]]:
    """
    DuckDuckGo via ddgs (anciennement duckduckgo-search).
    Essaie les deux noms de package pour compatibilité.
    """
    DDGS_cls = None
    try:
        # Nouveau nom de paquet (>= 7.x renommé en ddgs)
        from ddgs import DDGS as _DDGS
        DDGS_cls = _DDGS
    except ImportError:
        pass

    if DDGS_cls is None:
        try:
            # Ancien nom (< 7.x) — toujours fonctionnel mais deprecated
            from duckduckgo_search import DDGS as _DDGS  # noqa: F401
            DDGS_cls = _DDGS
        except ImportError:
            logger.error(
                "Aucun package de recherche installé. "
                "Lancez : pip install ddgs"
            )
            return []

    try:
        results = []
        with DDGS_cls() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                # Le champ URL peut être 'href' (ancien) ou 'url' (nouveau)
                url = r.get("href") or r.get("url", "")
                # Le champ snippet peut être 'body' (ancien) ou 'description' (nouveau)
                snippet = r.get("body") or r.get("description") or r.get("snippet", "")
                results.append({
                    "title":   r.get("title", ""),
                    "url":     url,
                    "snippet": snippet[:600],
                })

        logger.debug("DDG '%s' → %d résultats", query, len(results))
        return results

    except Exception as e:
        logger.warning("DuckDuckGo search failed pour '%s': %s", query, e)
        return []


# ── Tavily ────────────────────────────────────────────────────────────────────

def _search_tavily(query: str, max_results: int, api_key: str) -> List[Dict[str, str]]:
    """Tavily Search API — qualité supérieure, nécessite TAVILY_API_KEY."""
    try:
        import requests as _req

        resp = _req.post(
            "https://api.tavily.com/search",
            json={
                "api_key":      api_key,
                "query":        query,
                "max_results":  max_results,
                "search_depth": "advanced",
            },
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()

        results = [
            {
                "title":   r.get("title", ""),
                "url":     r.get("url", ""),
                "snippet": r.get("content", "")[:600],
            }
            for r in data.get("results", [])
        ]
        logger.debug("Tavily '%s' → %d résultats", query, len(results))
        return results

    except Exception as e:
        logger.warning("Tavily failed pour '%s': %s — fallback DuckDuckGo", query, e)
        return []
