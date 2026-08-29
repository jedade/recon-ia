# utils/ollama_lock.py
"""
Verrou distribué (Redis) limitant l'exécution simultanée de l'analyse Ollama.

Ollama tourne en CPU seul, instance unique et partagée par tout le projet
(fallback IA du slot 5 ET embeddings RAG). Deux analyses Map-Reduce
simultanées ne s'exécutent pas réellement en parallèle sur ce matériel :
elles se partagent le même CPU et se ralentissent mutuellement de façon
imprévisible (constaté par ailleurs : un worker gunicorn OOM-killé pendant
un usage concurrent RAG+analyse — voir CLAUDE.md §8). Ce verrou sérialise
donc explicitement l'accès à Ollama pour l'analyse IA, plutôt que de laisser
plusieurs analyses se dégrader silencieusement en compétition pour le même
CPU — un scan qui attend son tour, visible comme tel dans le dashboard, vaut
mieux qu'un scan qui rame sans qu'on sache pourquoi.

Distribué via Redis (pas un simple `threading.Lock`) car gunicorn tourne en
plusieurs processus workers (`--workers 2`) : un verrou en mémoire d'un
worker ne protège pas contre un appel concurrent lancé par l'AUTRE worker,
qui est un processus Python entièrement séparé.

Dégradation : si `REDIS_URL` est absent ou Redis injoignable, le verrou est
un no-op (permissif) — cohérent avec le repli déjà en place pour le rate
limiter (`extensions.py`) plutôt qu'un blocage strict qui casserait le
développement local sans Redis.
"""
import contextlib
import logging
import os

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv('REDIS_URL', '').strip()
_LOCK_NAME = 'ollama_analysis_lock'
# TTL de sécurité du verrou lui-même : doit dépasser largement la pire durée
# déjà mesurée d'une analyse Map-Reduce complète (~20-25 min) pour ne
# jamais expirer PENDANT une analyse légitime encore en cours (ce qui
# autoriserait un second appel concurrent à tort) — sert uniquement de
# filet si le processus qui détient le verrou meurt sans le relâcher
# (crash, OOM-kill) : évite un deadlock permanent.
_LOCK_TIMEOUT_S = int(os.getenv('OLLAMA_LOCK_TIMEOUT_S', 2700))          # 45 min
# Délai max d'attente avant d'abandonner plutôt que d'attendre indéfiniment.
# Le watchdog (utils/stale_scan_watchdog.py) rattrape de toute façon un
# blocage anormal, mais un délai explicite ici donne tout de suite un
# message d'erreur clair (via l'exception levée) plutôt qu'un scan qui
# resterait en file d'attente jusqu'au sweep du watchdog.
_ACQUIRE_TIMEOUT_S = int(os.getenv('OLLAMA_LOCK_ACQUIRE_TIMEOUT_S', 3600))  # 60 min

_client = None
if _REDIS_URL:
    try:
        import redis
        _client = redis.from_url(_REDIS_URL)
        _client.ping()
    except Exception as e:
        logger.warning(
            "ollama_lock — Redis indisponible (%s), verrou désactivé (no-op) — "
            "plusieurs analyses Ollama pourraient s'exécuter simultanément.", e,
        )
        _client = None
else:
    logger.warning(
        "ollama_lock — REDIS_URL absent, verrou désactivé (no-op) — "
        "plusieurs analyses Ollama pourraient s'exécuter simultanément."
    )


@contextlib.contextmanager
def ollama_slot(on_wait=None):
    """
    Context manager acquérant le verrou avant toute utilisation d'Ollama pour
    l'analyse IA (Map-Reduce). Bloque l'appelant tant qu'une autre analyse
    tient le verrou, jusqu'à `OLLAMA_LOCK_ACQUIRE_TIMEOUT_S`.

    `on_wait` : callback optionnel invoqué UNE FOIS si l'acquisition doit
    attendre — permet à l'appelant de refléter l'attente (ex. positionner
    `current_step='analyzing_ai_queued'`) sans coupler ce module au modèle
    Recon.

    Lève `TimeoutError` si le verrou reste occupé au-delà du délai max —
    l'appelant (routes/analyze.py) traite déjà toute exception de ce bloc
    comme un échec d'analyse (statut 'failed' + notification email).
    """
    if _client is None:
        yield
        return

    lock = _client.lock(_LOCK_NAME, timeout=_LOCK_TIMEOUT_S)
    acquired = lock.acquire(blocking=False)
    if not acquired:
        logger.info("ollama_lock — Ollama occupé, mise en attente (max %ds)", _ACQUIRE_TIMEOUT_S)
        if on_wait:
            try:
                on_wait()
            except Exception:
                logger.exception("ollama_lock — erreur dans le callback on_wait")
        acquired = lock.acquire(blocking=True, blocking_timeout=_ACQUIRE_TIMEOUT_S)
        if not acquired:
            raise TimeoutError(
                f"Ollama est resté occupé plus de {_ACQUIRE_TIMEOUT_S // 60} minutes — abandon."
            )
    try:
        yield
    finally:
        try:
            lock.release()
        except Exception:
            pass  # déjà expiré (TTL dépassé) ou déjà relâché — rien à faire
