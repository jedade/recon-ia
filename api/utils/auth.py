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
"""
import hmac
import logging
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