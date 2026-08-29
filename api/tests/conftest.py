# tests/conftest.py
import os
import pytest
from unittest.mock import patch
from werkzeug.security import generate_password_hash

# ---------------------------------------------------------------------------
# Environnement de test — appliqué DÈS L'IMPORT de ce conftest
# ---------------------------------------------------------------------------
# pytest importe conftest.py avant de collecter les modules de test. Or certains
# modules (ex: tests/test_new_tools.py) importent `routes.recon` au niveau module,
# ce qui importe `config` — et `config` fige ADMIN_USERNAME / ADMIN_PASSWORD_HASH
# à l'import. Si l'environnement de test n'était posé que dans la fixture `app`,
# ces constantes étaient déjà figées sur les valeurs du .env réel et toutes les
# routes authentifiées répondaient 401 pendant la suite complète (alors que les
# tests passaient isolément). On pose donc l'environnement ici, en amont de toute
# collecte. `config` détecte pytest et n'écrase pas ces valeurs avec le .env.
#
# ADMIN_EMAIL est la variable réellement lue par config.ADMIN_USERNAME ;
# ADMIN_DOMAIN est conservée par compatibilité avec l'ancienne configuration.
TEST_PASSWORD = 'testpassword'
TEST_ENV = {
    'TESTING': '1',
    'ADMIN_DOMAIN': 'admin',
    'ADMIN_EMAIL': 'admin',
    'ADMIN_PASSWORD': generate_password_hash(TEST_PASSWORD),
    'DATABASE_URL': 'sqlite:///:memory:',
    # Sans ceci, `config.py` (override=False sous pytest) hérite du
    # REDIS_URL réel d'api/.env (redis://redis:6379/0, résolu uniquement
    # dans le réseau docker) : le rate limiter tente une vraie connexion
    # Redis en test, provoquant des erreurs/lenteurs sur toute la suite.
    # Vide → repli sur le stockage mémoire (voir extensions.py).
    'REDIS_URL': '',
    'POSTGRES_USER': 'test',
    'POSTGRES_PASSWORD': 'test',
    'POSTGRES_DB': 'testdb',
    'SMTP_USERNAME': 'test@example.com',
    'SMTP_PASSWORD': 'smtppass',
    'SMTP_SERVER': 'smtp.example.com',
    'SMTP_PORT': '587',
}
os.environ.update(TEST_ENV)


@pytest.fixture
def app():
    """Crée une instance Flask de test avec une base SQLite en mémoire."""
    with patch.dict('os.environ', TEST_ENV):
        from app import create_app
        flask_app = create_app()
        flask_app.config['TESTING'] = True
        flask_app.config['RATELIMIT_ENABLED'] = False

        with flask_app.app_context():
            from database import db
            db.create_all()
            yield flask_app
            db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers():
    """Headers d'authentification Basic valides."""
    import base64
    credentials = base64.b64encode(f'admin:{TEST_PASSWORD}'.encode()).decode('utf-8')
    return {'Authorization': f'Basic {credentials}'}


@pytest.fixture
def bad_auth_headers():
    """Headers d'authentification invalides."""
    import base64
    credentials = base64.b64encode(b'admin:wrongpassword').decode('utf-8')
    return {'Authorization': f'Basic {credentials}'}
