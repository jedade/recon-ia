# utils/passive_sources/__init__.py
"""
Sources passives de la phase 5 (collecte enrichie).

Chaque module de ce paquet est PUR vis-à-vis du réseau : il reçoit la session
HTTP (en pratique `routes.recon._http`, protégée anti-SSRF) ou une fonction de
requête DNS en paramètre. Cela permet :
  - de garantir que tout appel HTTP passe par `_SsrfGuardedSession` ;
  - de tester chaque outil avec des réponses simulées (tests sans réseau).

Les helpers ci-dessous sont partagés : lecture bornée des réponses tierces et
masquage des secrets (clés d'API) dans les messages d'erreur.
"""
import json
import logging

logger = logging.getLogger(__name__)

# Taille maximale lue sur une réponse d'API tierce (octets). Une réponse plus
# grosse est rejetée : une API compromise ou un proxy hostile ne doit pas
# pouvoir faire exploser la mémoire du worker ni le volume de scan_results.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024

# Taille maximale d'un extrait brut conservé dans raw_output.
RAW_EXCERPT_CHARS = 2000


class ResponseTooLarge(ValueError):
    """La réponse dépasse la taille autorisée."""


class InvalidResponse(ValueError):
    """La réponse n'a pas le format attendu (JSON invalide, type inattendu)."""


def read_bounded(resp, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """
    Lit le corps d'une réponse `requests` sans dépasser `max_bytes`.

    Utilise `iter_content` (réponse obtenue avec `stream=True`) ; à défaut
    (réponse simulée), retombe sur `.content`. Lève ResponseTooLarge si la
    limite est franchie — on ne tronque pas silencieusement un JSON.
    """
    declared = None
    try:
        declared = int((getattr(resp, "headers", None) or {}).get("Content-Length") or 0)
    except (TypeError, ValueError):
        declared = None
    if declared and declared > max_bytes:
        _close(resp)
        raise ResponseTooLarge(f"réponse annoncée trop volumineuse ({declared} octets)")

    chunks = []
    total = 0
    iter_content = getattr(resp, "iter_content", None)
    try:
        if callable(iter_content):
            for chunk in iter_content(chunk_size=65536):
                if not chunk:
                    continue
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLarge(f"réponse trop volumineuse (> {max_bytes} octets)")
                chunks.append(chunk)
            return b"".join(chunks)
        content = getattr(resp, "content", b"") or b""
        if isinstance(content, str):
            content = content.encode("utf-8", errors="replace")
        if len(content) > max_bytes:
            raise ResponseTooLarge(f"réponse trop volumineuse (> {max_bytes} octets)")
        return content
    finally:
        _close(resp)


def _close(resp) -> None:
    try:
        close = getattr(resp, "close", None)
        if callable(close):
            close()
    except Exception:
        pass


def read_json(resp, max_bytes: int = DEFAULT_MAX_BYTES, expect=dict):
    """Lit et décode un JSON borné ; vérifie le type racine attendu."""
    body = read_bounded(resp, max_bytes)
    try:
        data = json.loads(body.decode("utf-8", errors="replace") or "null")
    except ValueError as e:
        raise InvalidResponse(f"JSON invalide : {e}") from None
    if expect is not None and not isinstance(data, expect):
        raise InvalidResponse(f"JSON inattendu : {type(data).__name__} au lieu de {expect.__name__}")
    return data


def scrub(text, *secrets) -> str:
    """Retire toute occurrence des secrets fournis d'un texte (messages d'erreur)."""
    text = "" if text is None else str(text)
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "***")
    return text


def excerpt(text, limit: int = RAW_EXCERPT_CHARS) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[:limit] + "…[tronqué]"


def as_str(value, limit: int = 300):
    """Chaîne bornée, ou None si la valeur n'est pas une chaîne."""
    if not isinstance(value, str):
        return None
    return value[:limit]


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def skipped(env_var: str, url: str) -> dict:
    """Résultat standard d'un outil dont la clé d'API est absente."""
    return {
        "status": "skipped",
        "data": {},
        "error": f"{env_var} non configuré — clé gratuite sur {url}",
        "raw_output": "",
    }
