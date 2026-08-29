# routes/__init__.py
"""
Enregistrement centralisé de tous les blueprints Flask.

Ordre d'enregistrement :
  0. auth        — POST /auth/login  (authentification admin)
  1. welcome     — GET /  (public)
  2. crud        — CRUD /recon + /verify_email + /result + /report
  3. logs        — GET /logs + GET /logs/stats  (audit sécurisé)
  4. recon       — POST /pass_recon  (reconnaissance passive)
  5. dns_info    — POST /dns_info
  6. analyze     — POST /analyze  (analyse IA Groq + OpenRouter + recherche web)
  7. report      — POST /recon/<id>/generate_final_report  (rapport narratif IA)
                   POST /recon/<id>/generate_report         (PDF + email)
                   GET  /recon/<id>/report.pdf              (téléchargement)
                   GET  /recon/<id>/export.json             (dump reproductible)
                   GET  /recon/<id>/export.csv              (findings tabulaires)
  8. stats       — GET  /recon/stats  (KPI agrégés en SQL sur toute la table)

Note de routage : `/recon/stats` ne rentre pas en conflit avec `/recon/<int:id>`
— le convertisseur `int` ne matche pas la chaîne « stats ».
"""

def register_routes(app):
    """Enregistre tous les blueprints de routes sur l'application Flask."""
    from routes.auth import auth_bp
    from routes.welcome import welcome_bp
    from routes.crud import crud_bp
    from routes.logs import logs_bp
    from routes.recon import pass_recon_bp
    from routes.dns_info import dns_info_bp
    from routes.analyze import analyze_bp
    from routes.report import report_bp
    from routes.stats import stats_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(welcome_bp)
    app.register_blueprint(crud_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(pass_recon_bp)
    app.register_blueprint(dns_info_bp)
    app.register_blueprint(analyze_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(stats_bp)
