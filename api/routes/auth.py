# routes/auth.py
"""
Endpoint d'authentification admin.

POST /auth/login
  Body JSON : { "email": "...", "password": "..." }
  Retourne 200 si les identifiants correspondent à ADMIN_EMAIL + ADMIN_PASSWORD du .env.
  Retourne 401 sinon.

Sécurité :
  - Comparaison résistante aux timing attacks (hmac.compare_digest).
  - Le mot de passe est validé via werkzeug.check_password_hash.
  - Les deux vérifications sont toujours effectuées (pas de court-circuit).
  - Aucun détail sur ce qui est incorrect n'est exposé au client.
"""
import hmac
import logging

from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash
from flasgger import swag_from
from config import ADMIN_USERNAME, ADMIN_PASSWORD_HASH
from extensions import limiter

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Connexion admin au dashboard',
    'description': (
        'Valide les identifiants admin (email + mot de passe). '
        'Retourne `{"success": true}` si les credentials sont corrects.\n\n'
        'Cet endpoint ne génère pas de token — les appels API suivants utilisent '
        '**HTTP Basic Auth** avec les mêmes identifiants.\n\n'
        '⚠️ Endpoint public (pas d\'authentification préalable requise).'
    ),
    'security': [],
    'parameters': [
        {
            'name': 'body', 'in': 'body', 'required': True,
            'schema': {
                'type': 'object',
                'required': ['email', 'password'],
                'properties': {
                    'email': {
                        'type': 'string',
                        'format': 'email',
                        'example': 'admin@example.com',
                        'description': 'Email administrateur'
                    },
                    'password': {
                        'type': 'string',
                        'format': 'password',
                        'example': 'motdepasse',
                        'description': 'Mot de passe administrateur'
                    }
                },
                'additionalProperties': False
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Authentification réussie',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "message": "Authentification réussie."
                    }
                }
            }
        },
        400: {'description': 'Email ou mot de passe manquant'},
        401: {'description': 'Identifiants invalides'},
    }
})
def login():
    """Valide les credentials admin (email + mot de passe) et retourne le statut."""
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"success": False, "error": "Email et mot de passe requis."}), 400

    # Comparaisons résistantes aux timing attacks
    email_ok = hmac.compare_digest(
        email.encode('utf-8'),
        ADMIN_USERNAME.encode('utf-8')
    )
    password_ok = check_password_hash(ADMIN_PASSWORD_HASH, password)

    if not email_ok or not password_ok:
        logger.warning(
            "Tentative de connexion échouée pour: %r — IP: %s",
            email, request.remote_addr
        )
        return jsonify({"success": False, "error": "Identifiants invalides."}), 401

    logger.info("Connexion admin réussie pour: %s — IP: %s", email, request.remote_addr)
    return jsonify({"success": True, "message": "Authentification réussie."}), 200
