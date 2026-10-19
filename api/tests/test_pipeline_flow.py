# tests/test_pipeline_flow.py
"""
Nouveau flux public (plan d'action, phase 1) :
formulaire → POST /recon (captcha + consentement) → OTP par mail →
POST /verify_email (public, tentatives limitées) → l'API déclenche n8n en
interne → n8n appelle les routes du pipeline avec le jeton de service.
"""
from unittest.mock import MagicMock, patch

import pytest

from extensions import limiter
from models.recon import Recon

SERVICE_TOKEN = 'service-token-de-test-0123456789abcdefghij'
WEBHOOK_SECRET = 'webhook-secret-de-test-0123456789abcdefgh'
FORM = {'domain': 'example.com', 'firstname': 'Ada', 'lastname': 'Lovelace',
        'email': 'ada@example.com', 'accord': True}


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def pipeline_env(monkeypatch):
    monkeypatch.setenv('N8N_PIPELINE_WEBHOOK_URL', 'http://n8n:5678/webhook/recon-ia-pipeline')
    monkeypatch.setenv('N8N_WEBHOOK_SECRET', WEBHOOK_SECRET)


@pytest.fixture
def service_env(monkeypatch):
    monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', SERVICE_TOKEN)


def _submit(client, **overrides):
    with patch('routes.crud.send_verification_email', return_value=True) as mail:
        resp = client.post('/recon', json={**FORM, **overrides})
    return resp, mail


def _otp(app, email='ada@example.com'):
    return Recon.query.filter_by(email=email).order_by(Recon.id.desc()).first()


def _ok(status=200):
    resp = MagicMock()
    resp.status_code = status
    return resp


class TestCreateRecon:
    @pytest.mark.parametrize('accord', [False, None, 'true', 1])
    def test_consent_must_be_true(self, client, accord):
        resp, mail = _submit(client, accord=accord)
        assert resp.status_code == 400
        mail.assert_not_called()

    def test_public_creation_without_captcha_in_dev(self, client):
        resp, mail = _submit(client)
        assert resp.status_code == 201
        mail.assert_called_once()


@pytest.mark.security
class TestTurnstile:
    @pytest.fixture(autouse=True)
    def _secret(self, monkeypatch):
        monkeypatch.setenv('TURNSTILE_SECRET_KEY', 'turnstile-secret')

    def test_missing_token_rejected_before_any_mail(self, client):
        resp, mail = _submit(client)
        assert resp.status_code == 400
        mail.assert_not_called()

    def test_valid_token_accepted(self, client):
        cf = MagicMock()
        cf.json.return_value = {'success': True}
        with patch('utils.captcha.requests.post', return_value=cf) as post:
            resp, mail = _submit(client, turnstile_token='jeton-valide')
        assert resp.status_code == 201
        sent = post.call_args.kwargs['data']
        assert sent['secret'] == 'turnstile-secret'
        assert sent['response'] == 'jeton-valide'

    def test_refused_token(self, client):
        cf = MagicMock()
        cf.json.return_value = {'success': False, 'error-codes': ['invalid-input-response']}
        with patch('utils.captcha.requests.post', return_value=cf):
            resp, mail = _submit(client, turnstile_token='jeton-forge')
        assert resp.status_code == 400
        mail.assert_not_called()

    def test_cloudflare_unreachable_fails_closed(self, client):
        with patch('utils.captcha.requests.post', side_effect=Exception('timeout')):
            resp, mail = _submit(client, turnstile_token='jeton')
        assert resp.status_code == 400
        mail.assert_not_called()

    def test_oversized_token_rejected_without_network(self, client):
        with patch('utils.captcha.requests.post') as post:
            resp, _ = _submit(client, turnstile_token='x' * 5000)
        assert resp.status_code == 400
        post.assert_not_called()


class TestVerifyEmail:
    def test_public_route_no_admin_needed(self, client, app):
        _submit(client)
        code = _otp(app).otp_code
        resp = client.post('/verify_email', json={'email': 'ada@example.com', 'code': code})
        assert resp.status_code == 200
        assert resp.get_json()['data']['verification'] is True

    @pytest.mark.security
    def test_code_cancelled_after_max_attempts(self, client, app):
        _submit(client)
        good = _otp(app).otp_code
        wrong = '000000' if good != '000000' else '111111'
        for _ in range(5):
            assert client.post('/verify_email',
                               json={'email': 'ada@example.com', 'code': wrong}).status_code == 400
        recon = _otp(app)
        assert recon.otp_code is None and recon.otp_attempts == 5
        # Le bon code ne marche plus : il faut redemander un code
        resp = client.post('/verify_email', json={'email': 'ada@example.com', 'code': good})
        assert resp.status_code in (400, 404)
        assert _otp(app).verification is False

    @pytest.mark.integration
    def test_success_triggers_pipeline_internally(self, client, app, pipeline_env):
        _submit(client)
        recon = _otp(app)
        with patch('utils.pipeline_trigger.requests.post', return_value=_ok()) as post:
            resp = client.post('/verify_email',
                               json={'email': 'ada@example.com', 'code': recon.otp_code})

        assert resp.status_code == 200
        assert resp.get_json()['pipeline_started'] is True
        args, kwargs = post.call_args
        assert args[0] == 'http://n8n:5678/webhook/recon-ia-pipeline'
        assert kwargs['json'] == {'recon_id': recon.id}
        assert kwargs['headers'] == {'X-Pipeline-Secret': WEBHOOK_SECRET}
        recon = _otp(app)
        assert recon.status == 'running' and recon.current_step == 'queued'

    @pytest.mark.integration
    @pytest.mark.parametrize('failure', [Exception('connexion refusée'), _ok(401)])
    def test_trigger_failure_reported(self, client, app, pipeline_env, failure):
        _submit(client)
        kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
        with patch('utils.pipeline_trigger.requests.post', **kwargs):
            resp = client.post('/verify_email',
                               json={'email': 'ada@example.com', 'code': _otp(app).otp_code})
        assert resp.status_code == 200
        assert resp.get_json()['pipeline_started'] is False
        assert _otp(app).status == 'pending'

    def test_unconfigured_trigger_makes_no_call(self, client, app):
        _submit(client)
        with patch('utils.pipeline_trigger.requests.post') as post:
            resp = client.post('/verify_email',
                               json={'email': 'ada@example.com', 'code': _otp(app).otp_code})
        assert resp.get_json()['pipeline_started'] is False
        post.assert_not_called()


@pytest.mark.security
class TestServiceToken:
    def _service(self, token=SERVICE_TOKEN):
        return {'X-Service-Token': token}

    def test_pipeline_route_accepts_service_token(self, client, service_env):
        # 400 = authentifié, corps invalide (aucun scan lancé)
        assert client.post('/pass_recon', json={}, headers=self._service()).status_code == 400

    def test_wrong_service_token_rejected(self, client, service_env, auth_headers):
        resp = client.post('/pass_recon', json={}, headers={**self._service('x' * 40), **auth_headers})
        assert resp.status_code == 401

    def test_admin_still_accepted_on_pipeline_routes(self, client, auth_headers):
        assert client.post('/pass_recon', json={}, headers=auth_headers).status_code == 400

    @pytest.mark.parametrize('method,path', [
        ('get', '/recon'), ('get', '/recon/stats'), ('get', '/logs'),
        ('get', '/analyze/status'), ('post', '/recon/1/revoke_access'),
        ('post', '/recon/1/issue_access'), ('get', '/recon/1/export.json'),
    ])
    def test_service_token_never_opens_admin_routes(self, client, service_env, method, path):
        assert getattr(client, method)(path, headers=self._service()).status_code == 401

    def test_short_token_configuration_disables_service_auth(self, client, monkeypatch):
        monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', 'court')
        assert client.post('/pass_recon', json={}, headers=self._service('court')).status_code == 401

    def test_service_calls_exempt_from_ip_rate_limits(self, client, service_env, auth_headers):
        """S6 : n8n ne doit plus partager un plafond par IP avec tous les utilisateurs."""
        statuses = {client.post('/pass_recon', json={}, headers=self._service()).status_code
                    for _ in range(35)}
        assert statuses == {400}
        admin = [client.post('/pass_recon', json={}, headers=auth_headers).status_code
                 for _ in range(31)]
        assert admin[-1] == 429


def test_watchdog_covers_queued_step():
    from utils.stale_scan_watchdog import _STEP_TIMEOUTS_S, _ERROR_TYPE_BY_STEP
    assert 'queued' in _STEP_TIMEOUTS_S and 'queued' in _ERROR_TYPE_BY_STEP


class TestAnalysisBackendAvailability:
    """Sans clé cloud, le repli Ollama local doit suffire (bug du 2026-10-19)."""

    @pytest.fixture
    def no_cloud_keys(self, monkeypatch):
        import routes.analyze as analyze
        for name in ('_GEMINI_API_KEY', '_CEREBRAS_API_KEY', '_GROQ_API_KEY', '_OPENROUTER_API_KEY'):
            monkeypatch.setattr(analyze, name, '')
        monkeypatch.setattr(analyze, '_DEEPSEEK_ENABLED', False)
        return analyze

    def test_ollama_with_model_is_enough(self, no_cloud_keys, monkeypatch):
        monkeypatch.setattr('utils.ollama_client.OllamaClient.is_available', lambda self: True)
        monkeypatch.setattr('utils.ollama_client.OllamaClient.model_loaded', lambda self: True)
        assert no_cloud_keys._any_backend_available() is True

    @pytest.mark.parametrize('available,loaded', [(False, False), (True, False)])
    def test_nothing_available(self, no_cloud_keys, monkeypatch, available, loaded):
        monkeypatch.setattr('utils.ollama_client.OllamaClient.is_available', lambda self: available)
        monkeypatch.setattr('utils.ollama_client.OllamaClient.model_loaded', lambda self: loaded)
        assert no_cloud_keys._any_backend_available() is False

    def test_route_returns_503_only_when_nothing_available(self, client, no_cloud_keys, monkeypatch, service_env):
        monkeypatch.setattr('utils.ollama_client.OllamaClient.is_available', lambda self: False)
        resp = client.post('/analyze/async', json={'recon_id': 1},
                           headers={'X-Service-Token': SERVICE_TOKEN})
        assert resp.status_code == 503
        monkeypatch.setattr('utils.ollama_client.OllamaClient.is_available', lambda self: True)
        monkeypatch.setattr('utils.ollama_client.OllamaClient.model_loaded', lambda self: True)
        resp = client.post('/analyze/async', json={'recon_id': 999},
                           headers={'X-Service-Token': SERVICE_TOKEN})
        assert resp.status_code == 404  # au-delà du contrôle de backend : dossier inexistant
