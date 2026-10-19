# utils/auth.py
"""
Décorateur d'authentification HTTP Basic.

Sécurité :
- Comparaison du nom d'utilisateur via hmac.compare_digest() pour résister aux attaques
  par mesure du temps (timing attack).
- Le mot de passe est validé via werkzeug.check_password_hash (bcrypt/pbkdf2).
- Les deux vérifications sont toujours effectuées (pas de court-circuit) pour
  éviter de révéler si c'est le login ou le mot de passe qui est faux.
- En cas d'échec, l'en-tête WWW-Authenticate est inclus conformément à la RFC 7235.

Jeton de service (2026-10-19, plan d'action phase 1)
─────────────────────────────────────────────────────
n8n appelait l'API avec le compte ADMIN (Basic Auth), ce qui obligeait à lui
confier `ADMIN_PASSWORD_PLAIN` en clair. Il utilise désormais un jeton de
service dédié (`PIPELINE_SERVICE_TOKEN`, en-tête `X-Service-Token`), accepté
UNIQUEMENT par les routes du pipeline (`require_service_or_auth`) — jamais
par les routes d'administration (`require_auth`). Les requêtes porteuses de
ce jeton sont exemptées des limites de débit par IP (extensions.py) : elles
venaient toutes de l'IP du conteneur n8n et épuisaient un plafond commun à
tous les utilisateurs. Le reverse proxy retire cet en-tête des requêtes
venues d'Internet (défense en profondeur, voir Caddyfile).
"""
import hmac
import logging
import os
from functools import wraps

from flask import request, jsonify
from werkzeug.security import check_password_hash
from config import ADMIN_USERNAME, ADMIN_PASSWORD_HASH

logger = logging.getLogger(__name__)

_401_HEADERS = {"WWW-Authenticate": 'Basic realm="OSINT API"'}


def require_auth(f):
    """Vérifie les credentials HTTP Basic avant d'autoriser l'accès à l'endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth:
            logger.warning("Requête sans en-tête Authorization: %s %s",
                           request.method, request.path)
            return jsonify({"success": False, "error": "Authentification requise."}), 401, _401_HEADERS

        # Comparaison résistante aux timing attacks pour le nom d'utilisateur
        username_ok = hmac.compare_digest(
            auth.username.encode("utf-8"),
            ADMIN_USERNAME.encode("utf-8")
        )
        # check_password_hash est déjà résistant aux timing attacks
        password_ok = check_password_hash(ADMIN_PASSWORD_HASH, auth.password)

        if not username_ok or not password_ok:
            # Ne pas logger le nom d'utilisateur (évite l'énumération dans les logs)
            logger.warning("Authentification échouée — IP: %s — méthode: %s %s",
                           request.remote_addr, request.method, request.path)
            return jsonify({"success": False, "error": "Identifiants invalides."}), 401, _401_HEADERS

        logger.debug("Authentification réussie pour: %s", auth.username)
        return f(*args, **kwargs)
    return decorated_function


SERVICE_TOKEN_HEADER = 'X-Service-Token'


def _service_token() -> str:
    token = os.getenv('PIPELINE_SERVICE_TOKEN', '')
    return token if len(token) >= 32 else ''


def is_service_request() -> bool:
    """Vrai si la requête porte le jeton de service valide (comparaison en temps constant)."""
    expected = _service_token()
    supplied = request.headers.get(SERVICE_TOKEN_HEADER, '')
    if not expected or not supplied:
        return False
    return hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8'))


def require_service_or_auth(f):
    """
    Routes du pipeline : accepte le jeton de service (n8n) OU l'admin.

    Un jeton présent mais faux est refusé d'emblée, sans retomber sur le
    Basic Auth, pour que l'échec reste visible dans les journaux.
    """
    admin_protected = require_auth(f)

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get(SERVICE_TOKEN_HEADER):
            if is_service_request():
                return f(*args, **kwargs)
            logger.warning("Jeton de service invalide — IP: %s — %s %s",
                           request.remote_addr, request.method, request.path)
            return jsonify({"success": False, "error": "Jeton de service invalide."}), 401
        return admin_protected(*args, **kwargs)
    return decorated_function