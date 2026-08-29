# routes/welcome.py
"""
Page d'accueil de l'API — liste complète des endpoints disponibles.
Endpoint public (pas d'authentification requise).
"""
from flask import Blueprint, jsonify
from flasgger import swag_from

welcome_bp = Blueprint('welcome', __name__)


@welcome_bp.route('/', methods=['GET'])
@swag_from({
    'tags': ['Documentation'],
    'security': [],
    'summary': 'Page d\'accueil — liste de tous les endpoints disponibles',
    'description': 'Retourne les métadonnées de l\'API et le catalogue complet des endpoints. Endpoint public.',
    'responses': {
        200: {'description': 'Informations sur l\'API et liste des endpoints'}
    }
})
def welcome():
    """Retourne les informations générales de l'API et le catalogue des endpoints."""
    return jsonify({
        "success": True,
        "message": "Bienvenue dans l'API OSINT",
        "version": "1.1.0",
        "description": "API de reconnaissance OSINT — analyse de domaines, emails, SSL, DNS et sous-domaines",
        "documentation": {
            "swagger_ui": "/apidocs",
            "redoc": "/redoc",
        },
        "endpoints": {
            # --- Authentification ---
            "POST   /auth/login": "Connexion admin (vérification des identifiants — ne génère pas de token)",
            # --- CRUD Enregistrements ---
            "POST   /recon": "Créer un enregistrement de reconnaissance + envoi OTP",
            "POST   /verify_email": "Valider le code OTP pour activer l'enregistrement",
            "GET    /recon": "Lister tous les enregistrements (paginé, ?page=1&per_page=20)",
            "GET    /recon/<id>": "Détail d'un enregistrement (sans données sensibles)",
            "PUT    /recon/<id>": "Mettre à jour les champs d'identité",
            "DELETE /recon/<id>": "Supprimer définitivement un enregistrement",
            # --- Workflow n8n ---
            "PATCH  /recon/<id>/result": "Mettre à jour les résultats d'exécution (webhook n8n)",
            "GET    /recon/<id>/report": "Rapport complet avec scan_results + final_report (restreint)",
            # --- Audit ---
            "GET    /logs": "Logs d'audit paginés avec filtres (method, status, endpoint, IP, dates)",
            "GET    /logs/stats": "Statistiques d'usage : codes HTTP, top endpoints, top IPs, taux d'erreur",
            # --- OSINT passif ---
            "POST   /pass_recon": "Reconnaissance passive : 47 outils OSINT, exécution parallèle en 2 vagues",
            "POST   /dns_info": "Collecte DNS/IP complète (host, nslookup, dnsrecon, dig)",
            # --- Analyse IA ---
            "POST   /analyze": "Synthèse IA des résultats de scan (cascade Gemini→Cerebras→Groq→OpenRouter→Ollama)",
            "GET    /analyze/status": "Disponibilité des providers IA configurés",
            "POST   /analyze/async": "Lance l'analyse IA en tâche de fond, retourne immédiatement",
            "GET    /analyze/wait/<id>": "Attend la fin d'une analyse IA lancée en asynchrone",
            # --- Rapport final ---
            "POST   /recon/<id>/generate_final_report": "Génère le rapport narratif IA (sans PDF ni email)",
            "POST   /recon/<id>/generate_report": "Génère le PDF et l'envoie par email au demandeur",
            "GET    /recon/<id>/report.pdf": "Télécharge le rapport PDF déjà généré",
            "GET    /recon/<id>/export.json": "Export JSON reproductible (provenance, hash SHA-256, citation)",
            "GET    /recon/<id>/export.csv": "Export CSV tabulaire des findings, un par ligne",
            # --- Statistiques ---
            "GET    /recon/stats": "KPI agrégés en SQL sur l'ensemble des enregistrements",
        },
        "authentication": "HTTP Basic Auth — en-tête Authorization: Basic <base64(user:password)>",
        "status": "active",
    }), 200
