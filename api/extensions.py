# extensions.py
"""
Extensions Flask partagées.

Stockage du rate limiter
────────────────────────
Le stockage "memory://" est PAR PROCESSUS. Sous gunicorn multi-workers, chaque
worker tient donc son propre compteur : une limite de « 20 par heure »
autoriserait en réalité 20 × nb_workers requêtes, et tous les compteurs
seraient perdus à chaque redémarrage.

On utilise donc Redis (partagé entre workers) dès que REDIS_URL est défini,
avec un repli explicite et signalé sur "memory://" pour ne pas casser le
développement local ni les tests, qui n'ont pas de Redis.
"""
import logging
import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv('REDIS_URL', '').strip()

if _REDIS_URL:
    _STORAGE_URI = _REDIS_URL
else:
    _STORAGE_URI = 'memory://'
    logger.warning(
        "REDIS_URL non défini — rate limiter en mémoire (compteurs NON partagés "
        "entre workers et perdus au redémarrage). Acceptable en développement ; "
        "définissez REDIS_URL en production multi-workers."
    )

limiter = Limiter(
    key_func=get_remote_address,
    # Plafond par défaut pour toute route SANS @limiter.limit(...) dédié —
    # notamment GET /recon et GET /recon/stats, tous deux interrogés par le
    # polling du dashboard (rafraîchissement toutes les 30s, `web/dashboard.html`
    # ::refreshAll()) : à eux seuls, ~240 requêtes/heure, largement au-dessus
    # de l'ancien défaut (60/h). Toutes les requêtes n8n partageant en plus la
    # même IP (voir CLAUDE.md §8), le budget par défaut était systématiquement
    # épuisé par le trafic de routine avant même d'atteindre POST /pass_recon
    # (constaté en conditions réelles : 429 sur pass_recon sans aucun abus).
    # Relevé pour un usage self-hosted mono-tenant (un seul compte admin) —
    # POST /recon (anonyme, le plus sensible) garde son propre plafond dédié
    # bien plus bas (20/h), inchangé.
    default_limits=["5000 per day", "1000 per hour"],
    storage_uri=_STORAGE_URI,
)


@limiter.request_filter
def _exempt_pipeline_service():
    """
    Exempte des limites par IP les appels de n8n porteurs du jeton de service
    (utils/auth.py). Ces appels partagent tous l'IP du conteneur n8n : les
    limiter par IP revenait à imposer un plafond COMMUN à tous les
    utilisateurs de la plateforme (CLAUDE.md §8, point S6 du plan d'action).
    Le débit du pipeline reste borné en amont, par les limites des routes
    publiques qui le déclenchent (POST /recon, POST /verify_email).
    """
    from utils.auth import is_service_request
    return is_service_request()
