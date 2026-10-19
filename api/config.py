# config.py
import os
import sys
from dotenv import load_dotenv
from urllib.parse import quote_plus
from db_url import with_psycopg2

# ---------------------------------------------------------------------------
# Chargement des variables d'environnement
# ---------------------------------------------------------------------------
# En exécution normale (local, Docker/docker-compose) on conserve override=True :
# c'est le comportement historique, le .env du projet est la source de vérité et
# doit primer sur d'éventuelles variables résiduelles du shell ou de l'image.
#
# En exécution de tests (pytest), override=True est destructeur : tests/conftest.py
# positionne explicitement DATABASE_URL='sqlite:///:memory:' (ainsi que les
# identifiants admin/SMTP factices) via patch.dict('os.environ', ...) AVANT
# d'importer l'application. Le load_dotenv() déclenché à l'import de ce module
# écrasait alors ces valeurs par celles de production (DATABASE_URL pointant sur
# l'hôte Docker `postgres`), faisant échouer la suite hors Docker pour une raison
# purement environnementale.
#
# On désactive donc l'override uniquement sous pytest : les variables déjà
# positionnées par les tests sont respectées, tandis que les variables absentes
# de l'environnement de test continuent d'être fournies par le .env.
# La production/Docker garde strictement le comportement précédent.
_UNDER_PYTEST = (
    'pytest' in sys.modules
    or os.getenv('PYTEST_CURRENT_TEST') is not None
    or os.getenv('TESTING', '').lower() in ('1', 'true', 'yes')
)

load_dotenv(
    dotenv_path=os.path.join(os.path.dirname(__file__), '.env'),
    override=not _UNDER_PYTEST,
)

# Récupérer les identifiants admin depuis .env
ADMIN_USERNAME = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD')

if not ADMIN_USERNAME or not ADMIN_PASSWORD_HASH:
    raise ValueError("❌ Les variables ADMIN_EMAIL et ADMIN_PASSWORD doivent être définies dans .env")

# ---------------------------------------------------------------------------
# Redis — stockage partagé du rate limiter
# ---------------------------------------------------------------------------
# Point de déclaration centralisé ; la consommation effective est dans
# extensions.py, qui replie sur "memory://" avec un avertissement si la
# variable est absente (développement local sans Redis).
REDIS_URL = os.getenv('REDIS_URL', '').strip()

# ---------------------------------------------------------------------------
# Clés d'API optionnelles des outils de reconnaissance passive
# ---------------------------------------------------------------------------
# Aucune n'est obligatoire : chaque outil se dégrade proprement si sa clé est
# absente (les fonctions de routes/recon.py relisent os.getenv au moment de
# l'exécution, ces constantes servent de point de déclaration centralisé).
#
# GITHUB_TOKEN : outil `github` (github-subdomains) → status "skipped" si absent.
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
# OTX_API_KEY  : outil `otx_passive_dns` (AlienVault OTX). Sans clé, la requête est
#                tentée en accès anonyme ; si OTX refuse (401/403), l'outil retourne
#                status "limited" au lieu de "success".
OTX_API_KEY = os.getenv('OTX_API_KEY', '')

def app_config(app):
    """Configuration globale de l'application Flask"""
    app.config['SWAGGER'] = {
        'title': 'OSINT API',
        'uiversion': 3,
        'version': '1.0.0',
        'description': """
        API complète pour l'analyse de renseignement sur sources ouvertes (OSINT).
        Cette API permet d'effectuer diverses analyses de sécurité et de reconnaissance.
        """,
        'termsOfService': '',
        'contact': {
            'name': 'Support API',
            'url': 'https://example.com/support',
            'email': 'support@example.com'
        },
        'license': {
            'name': 'MIT',
            'url': 'https://opensource.org/licenses/MIT'
        },
        'schemes': ['http', 'https'],
        'consumes': ['application/json'],
        'produces': ['application/json'],
        'tags': [
            {
                'name': 'Authentication',
                'description': 'Authentification admin — connexion au dashboard'
            },
            {
                'name': 'CRUD - Reconnaissance',
                'description': 'Gestion des enregistrements de reconnaissance (créer, lire, mettre à jour, supprimer)'
            },
            {
                'name': 'Audit - Logs',
                'description': 'Consultation des logs d\'audit et statistiques d\'usage de l\'API'
            },
            {
                'name': 'Subdomain Analysis',
                'description': 'Reconnaissance passive multi-outils : WHOIS, DNS, crt.sh, subfinder, amass…'
            },
            {
                'name': 'DNS/IP Information',
                'description': 'Collecte DNS/IP complète : host, nslookup, dnsrecon, dig'
            },
            {
                'name': 'Documentation',
                'description': 'Catalogue des endpoints et métadonnées de l\'API'
            }
        ]
    }

    # Initialisation de Swagger
    from flasgger import Swagger
    cfg = app.config['SWAGGER']
    swagger = Swagger(app, template={
        "info": {
            "title": cfg['title'],
            "version": cfg['version'],
            "description": cfg['description'],
            "termsOfService": cfg.get('termsOfService', ''),
            "contact": cfg.get('contact', {}),
            "license": cfg.get('license', {}),
        },
        "tags": cfg['tags'],
        "schemes": cfg.get('schemes', ['http', 'https']),
        "consumes": cfg.get('consumes', ['application/json']),
        "produces": cfg.get('produces', ['application/json']),
        "securityDefinitions": {
            "BasicAuth": {
                "type": "basic",
                "description": "HTTP Basic Auth — Email admin + mot de passe admin"
            }
        },
        "security": [{"BasicAuth": []}]
    })
    # Rôle applicatif à droits minimaux (2026-10-19) : si APP_DB_PASSWORD est
    # défini, l'API s'exécute avec le rôle `recon_app` (lecture/écriture sur
    # ses tables, AUCUN droit DDL ni accès propriétaire), créé par migrate.py
    # — qui, lui, garde le compte propriétaire (DATABASE_URL/POSTGRES_*).
    # Prioritaire sur DATABASE_URL, que `load_dotenv(override=True)` recharge
    # depuis api/.env avec le compte propriétaire.
    app_db_password = os.getenv('APP_DB_PASSWORD', '')
    # DATABASE_URL override (utilisé en test pour SQLite in-memory)
    database_url = os.getenv('DATABASE_URL')
    if app_db_password and not _UNDER_PYTEST and os.getenv('POSTGRES_DB'):
        database_url = (
            f"postgresql://{os.getenv('APP_DB_USER', 'recon_app')}:{quote_plus(app_db_password)}"
            f"@postgres:5432/{os.getenv('POSTGRES_DB')}"
        )
    if not database_url:
        username = os.getenv('POSTGRES_USER')
        encoded_password = quote_plus(os.getenv('POSTGRES_PASSWORD', ''))
        host = "postgres"
        port = 5432
        dbname = os.getenv('POSTGRES_DB')
        if not username or not dbname:
            raise ValueError("❌ POSTGRES_USER et POSTGRES_DB doivent être définis dans .env")
        database_url = f"postgresql://{username}:{encoded_password}@{host}:{port}/{dbname}"

    app.config['SQLALCHEMY_DATABASE_URI'] = with_psycopg2(database_url)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 Mo max — protection DoS