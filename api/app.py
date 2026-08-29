# app.py
"""
Factory de l'application Flask — OSINT API.

Initialise dans l'ordre :
  1. Logging structuré (console, niveau INFO en prod, DEBUG activable via LOG_LEVEL)
  2. Configuration applicative (Swagger, DB URI, limites)
  3. CORS (origines configurables via CORS_ORIGINS)
  4. Base de données (SQLAlchemy)
  5. Rate limiting (Flask-Limiter)
  6. En-têtes de sécurité HTTP (after_request)
  7. Logging console + persistance DB de chaque requête (before/after_request)
  8. Routes (blueprints)
  9. Gestionnaires d'erreurs globaux

Journalisation en base de données
───────────────────────────────────
Chaque requête HTTP est tracée dans la table `audit_log` :
  - Méthode, chemin, code HTTP, durée, IP client, User-Agent (tronqué)
  - Les chemins Swagger (statiques) sont exclus pour éviter le bruit
  - Les erreurs de persistance des logs ne propagent jamais vers le client
"""
import os
import sys
import time
import logging
import logging.config
from flask import Flask, request, g
from flask_cors import CORS
from config import app_config
from routes import register_routes
from errors.handlers import register_error_handlers
from database import db
from extensions import limiter

# ---------------------------------------------------------------------------
# Configuration du logging
# ---------------------------------------------------------------------------

def _build_logging_config() -> dict:
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                'datefmt': '%Y-%m-%dT%H:%M:%S',
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'standard',
                'level': log_level,
            },
        },
        'root': {
            'handlers': ['console'],
            'level': log_level,
        },
        # Réduire le bruit des librairies externes
        'loggers': {
            'werkzeug': {'level': 'WARNING'},
            'urllib3': {'level': 'WARNING'},
        },
    }


# Chemins exclus de l'audit DB (documentation Swagger + santé)
_AUDIT_EXCLUDE_PREFIXES = ('/apidocs', '/flasgger_static', '/redoc', '/')


def _should_audit(path: str) -> bool:
    """Retourne True si ce chemin doit être enregistré dans audit_log."""
    for prefix in _AUDIT_EXCLUDE_PREFIXES:
        if path == prefix or path.startswith(prefix + '/') or path.startswith(prefix + '?'):
            return False
    return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_app():
    logging.config.dictConfig(_build_logging_config())
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app_config(app)

    # ------------------------------------------------------------------
    # Confiance dans le reverse-proxy
    # ------------------------------------------------------------------
    # Sans ProxyFix, request.remote_addr vaut l'IP du proxy pour TOUTES les
    # requêtes. Conséquences concrètes : le rate limiter (key_func=
    # get_remote_address) place le monde entier dans un seul compartiment —
    # un attaquant seul épuise le quota et met l'API hors service pour tous —
    # et audit_log enregistre une IP inutile, rendant la traçabilité illusoire.
    #
    # TRUSTED_PROXY_COUNT doit valoir le nombre EXACT de proxys de confiance
    # devant l'application. Le surévaluer permettrait à un client de forger
    # X-Forwarded-For et d'usurper une IP pour contourner le rate limiting ;
    # la valeur 0 désactive la prise en compte des en-têtes.
    _proxy_count = int(os.getenv('TRUSTED_PROXY_COUNT', '1'))
    if _proxy_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count,
        )
        logger.info("ProxyFix actif — %d proxy(s) de confiance", _proxy_count)
    else:
        logger.info("ProxyFix désactivé (TRUSTED_PROXY_COUNT=0)")

    # SECRET_KEY — valider qu'elle est définie et suffisamment longue
    secret = os.getenv('SECRET_KEY', '')
    if not secret or len(secret) < 32:
        logger.warning(
            "⚠️  SECRET_KEY absente ou trop courte (< 32 chars) — "
            "définissez SECRET_KEY dans .env pour la production"
        )
    app.config['SECRET_KEY'] = secret or os.urandom(32).hex()

    # CORS — origines configurables ; en production CORS_ORIGINS doit être défini explicitement
    cors_origins = os.getenv('CORS_ORIGINS', '')
    if not cors_origins:
        if os.getenv('FLASK_ENV', 'production') == 'development':
            origins = '*'
            logger.warning("CORS ouvert (*) — mode développement uniquement. "
                           "Définissez CORS_ORIGINS en production.")
        else:
            origins = []   # production : aucune origine cross-domain par défaut
            logger.warning("CORS_ORIGINS non défini — requêtes cross-origin refusées. "
                           "Définissez CORS_ORIGINS dans .env pour autoriser des origines.")
    else:
        origins = [o.strip() for o in cors_origins.split(',')]
    CORS(app, resources={r"/*": {"origins": origins}})
    logger.info("CORS configuré — origines: %s", origins)

    db.init_app(app)
    limiter.init_app(app)

    # ------------------------------------------------------------------
    # En-têtes de sécurité HTTP
    # ------------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        """Ajoute les en-têtes de sécurité à chaque réponse."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Cache-Control'] = 'no-store'
        # HSTS — force HTTPS pendant 1 an, sous-domaines inclus
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # CSP — API JSON : aucune ressource externe nécessaire
        response.headers['Content-Security-Policy'] = "default-src 'none'"
        # Désactiver toutes les API navigateur non nécessaires
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        # Masquer le serveur (ne pas révéler Flask/Werkzeug)
        response.headers['Server'] = 'OSINT-API'
        return response

    # ------------------------------------------------------------------
    # Logging des requêtes — console + persistance DB
    # ------------------------------------------------------------------
    @app.before_request
    def log_request_start():
        """Enregistre le début de chaque requête et stocke le timestamp."""
        g._request_start = time.perf_counter()
        if not request.path.startswith('/apidocs') and not request.path.startswith('/flasgger_static'):
            logger.info("→ %s %s — IP: %s — UA: %.60s",
                        request.method, request.path,
                        request.remote_addr,
                        request.headers.get('User-Agent', ''))

    @app.after_request
    def log_request_end(response):
        """
        Log la fin de requête (console) et persiste l'entrée dans audit_log (DB).

        La persistance DB est silencieuse — une erreur DB ne doit jamais
        interrompre la réponse envoyée au client.
        """
        elapsed_ms = (time.perf_counter() - g.get('_request_start', time.perf_counter())) * 1000

        # Log console (hors Swagger)
        if not request.path.startswith('/apidocs') and not request.path.startswith('/flasgger_static'):
            level = logging.WARNING if response.status_code >= 400 else logging.INFO
            logger.log(level, "← %s %s → %s (%.1f ms)",
                       request.method, request.path, response.status_code, elapsed_ms)

        # Persistance DB — uniquement les endpoints métier
        if _should_audit(request.path):
            try:
                from models.audit_log import AuditLog
                entry = AuditLog(
                    method=request.method,
                    endpoint=request.path,
                    status_code=response.status_code,
                    duration_ms=elapsed_ms,
                    ip_address=request.remote_addr,
                    user_agent=(request.headers.get('User-Agent', '')[:200] or None),
                )
                db.session.add(entry)
                db.session.commit()
            except Exception as audit_error:
                # Ne jamais laisser une erreur d'audit affecter la réponse client
                logger.error("Erreur persistance audit_log: %s", audit_error)
                try:
                    db.session.rollback()
                except Exception:
                    pass

        return response

    # ------------------------------------------------------------------
    # Tables DB + routes + erreurs
    # ------------------------------------------------------------------
    with app.app_context():
        from models.recon import Recon
        from models.audit_log import AuditLog
        from models.pass_recon_cache import PassReconCache
        from sqlalchemy import text
        db.create_all()
        # Migration sans downtime — ajoute otp_sent_at si absent (PostgreSQL)
        try:
            db.session.execute(text(
                "ALTER TABLE recon ADD COLUMN IF NOT EXISTS otp_sent_at TIMESTAMP"
            ))
            db.session.commit()
        except Exception as _mig_err:
            db.session.rollback()
            logger.warning("Migration otp_sent_at ignorée : %s", _mig_err)
        logger.info("Tables DB vérifiées/créées (recon + audit_log + pass_recon_cache)")

    register_routes(app)
    register_error_handlers(app)

    # Watchdog des scans silencieusement bloqués (voir utils/stale_scan_watchdog.py)
    # — jamais sous pytest (même détection que config.py) : un thread daemon
    # tournant en arrière-plan pendant la suite de tests n'a aucune utilité et
    # peut interférer avec la base SQLite en mémoire des tests.
    _under_pytest = (
        'pytest' in sys.modules
        or os.getenv('PYTEST_CURRENT_TEST') is not None
        or os.getenv('TESTING', '').lower() in ('1', 'true', 'yes')
    )
    if not _under_pytest:
        from utils.stale_scan_watchdog import start_watchdog
        start_watchdog(app)

    logger.info("OSINT API démarrée — LOG_LEVEL=%s", os.getenv('LOG_LEVEL', 'INFO'))
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=8080, debug=False)
