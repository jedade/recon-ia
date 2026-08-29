# errors/handlers.py
"""
Gestionnaires d'erreurs HTTP globaux.

Format de réponse standardisé pour toutes les erreurs :
  {"success": false, "error": "<message>", "status": <code>}

Codes gérés :
  400 Bad Request           — requête malformée
  401 Unauthorized          — authentification requise ou invalide
  403 Forbidden             — accès refusé
  404 Not Found             — endpoint ou ressource introuvable
  405 Method Not Allowed    — méthode HTTP non supportée
  429 Too Many Requests     — rate limit atteint
  500 Internal Server Error — erreur serveur non gérée
"""
import logging
from flask import jsonify

logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """Enregistre tous les gestionnaires d'erreurs sur l'application Flask."""

    @app.errorhandler(400)
    def bad_request(error):
        logger.warning("400 Bad Request: %s", error)
        return jsonify({
            "success": False,
            "error": "Requête invalide — vérifiez le format et les champs envoyés",
            "status": 400,
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        logger.warning("401 Unauthorized: %s", error)
        return jsonify({
            "success": False,
            "error": "Authentification requise",
            "status": 401,
        }), 401, {"WWW-Authenticate": 'Basic realm="OSINT API"'}

    @app.errorhandler(403)
    def forbidden(error):
        logger.warning("403 Forbidden: %s", error)
        return jsonify({
            "success": False,
            "error": "Accès refusé",
            "status": 403,
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        logger.info("404 Not Found: %s %s", error, "→ voir /apidocs")
        return jsonify({
            "success": False,
            "error": "Endpoint ou ressource introuvable",
            "hint": "Consultez la documentation à /apidocs",
            "status": 404,
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        logger.warning("405 Method Not Allowed: %s", error)
        return jsonify({
            "success": False,
            "error": "Méthode HTTP non autorisée sur cet endpoint",
            "status": 405,
        }), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        logger.warning("429 Too Many Requests: %s", error)
        return jsonify({
            "success": False,
            "error": "Limite de requêtes atteinte — réessayez plus tard",
            "status": 429,
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("500 Internal Server Error: %s", error, exc_info=True)
        return jsonify({
            "success": False,
            "error": "Erreur interne du serveur",
            "hint": "Contactez le support ou consultez les logs",
            "status": 500,
        }), 500
