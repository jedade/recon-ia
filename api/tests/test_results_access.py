# tests/test_results_access.py
"""
Consultation des résultats par code d'accès (routes/results.py) et
fermeture des routes admin sur un dossier scellé (routes/report.py).

Plan d'action, phase 1 — décisions D1 (pas de PDF dans le mail), D2
(30 jours, révocable), D3 (résultats chiffrés).
"""
import hashlib
import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from database import db
from extensions import limiter
from models.recon import Recon
from routes.report import _canonical_json
from utils import result_vault

pytestmark = pytest.mark.integration

SCAN = {'whois': {'status': 'success', 'data': {'registrar': 'MARQUEUR-SCAN'},
                  'meta': {'tool': 'WHOIS', 'category': 'Domain Intelligence'}}}
ANALYSIS = {
    'security_score': 72, 'security_grade': 'B', 'risk_level': 'MEDIUM',
    'findings': [{'id': 'EMAIL-001', 'title': 'DMARC absent', 'severity': 'HIGH',
                  'source_tool': 'whois', 'evidence': '=HYPERLINK("x")'}],
}
FINAL = {'executive_summary': 'MARQUEUR-RAPPORT'}
PDF = b'%PDF-1.4 MARQUEUR-PDF'


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def _make_recon(accord=True, **overrides):
    recon = Recon(
        domain='example.com', firstname='Ada', lastname='Lovelace',
        email='ada@example.com', accord=accord, verification=True,
        status='success', current_step='completed',
        scan_results=json.dumps(SCAN), analysis_result=json.dumps(ANALYSIS),
        final_report=json.dumps(FINAL), pdf_report=PDF,
        start_report_date=datetime.utcnow() - timedelta(minutes=5),
        end_report_date=datetime.utcnow(),
    )
    # Comme le vrai pipeline : dénormalise score/grade (colonnes en clair
    # qui survivent au scellement)
    recon.set_analysis_result(ANALYSIS)
    for k, v in overrides.items():
        setattr(recon, k, v)
    db.session.add(recon)
    db.session.commit()
    return recon


@pytest.fixture
def sealed(app):
    """Dossier scellé + son code d'accès (comme en fin de pipeline)."""
    recon = _make_recon()
    code = result_vault.seal_recon(recon)
    db.session.commit()
    return recon, code


def _open(client, code):
    return client.post('/results/access', json={'code': code})


def _token(client, code):
    resp = _open(client, code)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['data']['session_token']


def _bearer(token):
    return {'Authorization': f'Bearer {token}'}


class TestOpenSession:
    def test_valid_code_opens_session(self, client, sealed):
        recon, code = sealed
        resp = _open(client, code)
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['session_token']
        assert data['expires_in'] == 3600
        assert data['recon']['domain'] == 'example.com'
        assert data['recon']['security_score'] is None or isinstance(data['recon']['security_score'], int)
        db.session.refresh(recon)
        assert recon.access_count == 1
        assert recon.last_access_at is not None

    def test_code_with_surrounding_spaces_accepted(self, client, sealed):
        _, code = sealed
        assert _open(client, f'  {code}\n').status_code == 200

    @pytest.mark.security
    @pytest.mark.parametrize('code', [None, '', 'short', 'x' * 43, 'A' * 200, 12345])
    def test_wrong_or_malformed_code_same_generic_answer(self, client, sealed, code):
        resp = _open(client, code)
        assert resp.status_code == 401
        assert resp.get_json()['error'] == "Code d'accès invalide."

    @pytest.mark.security
    def test_code_in_query_string_is_ignored(self, client, sealed):
        _, code = sealed
        resp = client.post(f'/results/access?code={code}')
        assert resp.status_code == 401

    @pytest.mark.security
    def test_revoked_code(self, client, sealed):
        recon, code = sealed
        recon.access_revoked_at = datetime.utcnow()
        db.session.commit()
        assert _open(client, code).status_code == 403

    @pytest.mark.security
    def test_expired_code(self, client, sealed):
        recon, code = sealed
        recon.access_expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        assert _open(client, code).status_code == 410

    @pytest.mark.security
    def test_brute_force_rate_limited(self, client, sealed):
        statuses = [_open(client, result_vault.generate_access_code()).status_code
                    for _ in range(6)]
        assert statuses[:5] == [401] * 5
        assert statuses[5] == 429

    @pytest.mark.security
    def test_unconfigured_server_refuses(self, client, sealed, monkeypatch):
        _, code = sealed
        monkeypatch.setenv('RESULTS_ACCESS_SECRET', '')
        assert _open(client, code).status_code == 503


class TestConsultation:
    def test_report_matches_original_data(self, client, sealed):
        _, code = sealed
        resp = client.get('/results/report', headers=_bearer(_token(client, code)))
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['scan_results'] == SCAN
        assert data['analysis_result']['findings'][0]['title'] == 'DMARC absent'
        assert data['final_report'] == FINAL
        # Même empreinte de reproductibilité qu'avant chiffrement
        expected = hashlib.sha256(_canonical_json(SCAN).encode()).hexdigest()
        assert data['provenance']['dataset_sha256'] == expected
        assert data['provenance']['data_integrity']['corrupted'] is False

    def test_downloads(self, client, sealed):
        _, code = sealed
        headers = _bearer(_token(client, code))

        pdf = client.get('/results/report.pdf', headers=headers)
        assert pdf.status_code == 200 and pdf.data == PDF
        assert pdf.headers['Content-Type'] == 'application/pdf'

        js = client.get('/results/export.json', headers=headers)
        assert js.status_code == 200
        assert json.loads(js.data)['scan_results'] == SCAN
        assert 'attachment' in js.headers['Content-Disposition']

        csv = client.get('/results/export.csv', headers=headers)
        assert csv.status_code == 200
        text = csv.data.decode('utf-8-sig')
        assert 'DMARC absent' in text
        # Neutralisation de l'injection de formule conservée
        assert "'=HYPERLINK" in text

    def test_export_requires_consent(self, client, app):
        recon = _make_recon(accord=False)
        code = result_vault.seal_recon(recon)
        db.session.commit()
        headers = _bearer(_token(client, code))
        assert client.get('/results/export.json', headers=headers).status_code == 403
        assert client.get('/results/export.csv', headers=headers).status_code == 403

    @pytest.mark.security
    @pytest.mark.parametrize('headers', [
        {}, {'Authorization': 'Basic abc'}, {'Authorization': 'Bearer '},
        {'Authorization': 'Bearer pas-un-jeton'},
    ])
    def test_session_required(self, client, sealed, headers):
        for path in ('/results/report', '/results/report.pdf',
                     '/results/export.json', '/results/export.csv'):
            assert client.get(path, headers=headers).status_code == 401

    @pytest.mark.security
    def test_access_code_is_not_a_session(self, client, sealed):
        _, code = sealed
        assert client.get('/results/report', headers=_bearer(code)).status_code == 401

    @pytest.mark.security
    def test_revocation_cuts_open_sessions(self, client, sealed):
        recon, code = sealed
        headers = _bearer(_token(client, code))
        recon.access_revoked_at = datetime.utcnow()
        db.session.commit()
        assert client.get('/results/report', headers=headers).status_code == 403

    @pytest.mark.security
    def test_expiry_cuts_open_sessions(self, client, sealed):
        recon, code = sealed
        headers = _bearer(_token(client, code))
        recon.access_expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        assert client.get('/results/report', headers=headers).status_code == 410

    @pytest.mark.security
    def test_session_cannot_read_another_record(self, client, sealed):
        """Une session porte la clé d'UN dossier : impossible de lire un autre."""
        _, code = sealed
        other = _make_recon(domain='victime.example')
        result_vault.seal_recon(other)
        db.session.commit()
        _, key = result_vault.read_session(_token(client, code))
        forged = result_vault.issue_session(other.id, key)
        assert client.get('/results/report', headers=_bearer(forged)).status_code == 401


@pytest.mark.security
class TestAdminCannotReadSealedContent:
    @pytest.mark.parametrize('method,path', [
        ('get', '/recon/{id}/report.pdf'),
        ('get', '/recon/{id}/export.json'),
        ('get', '/recon/{id}/export.csv'),
        ('post', '/recon/{id}/generate_report'),
        ('post', '/recon/{id}/generate_final_report'),
    ])
    def test_admin_routes_refuse_sealed(self, client, auth_headers, sealed, method, path):
        recon, _ = sealed
        resp = getattr(client, method)(path.format(id=recon.id), headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['results_sealed'] is True

    def test_admin_detail_view_shows_vault_state_without_content(self, client, auth_headers, sealed):
        """Vue détail du dashboard (GET /recon/<id>/report) sur un dossier scellé."""
        recon, code = sealed
        _open(client, code)
        resp = client.get(f'/recon/{recon.id}/report', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['results_sealed'] is True
        assert data['access_state'] == 'active' and data['access_count'] == 1
        assert data['scan_results'] is None and data['analysis_result'] is None
        assert data['final_report'] is None
        assert 'MARQUEUR' not in resp.get_data(as_text=True)
        assert data['security_score'] == 72  # métadonnée dénormalisée conservée

    def test_admin_listing_exposes_metadata_only(self, client, auth_headers, sealed):
        recon, code = sealed
        resp = client.get(f'/recon/{recon.id}', headers=auth_headers)
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert code not in body
        assert recon.access_token_hash not in body
        assert 'MARQUEUR' not in body
        assert resp.get_json()['data']['results_sealed'] is True


class TestPipelineSealing:
    """Fin de pipeline : generate_report scelle et envoie le code (sans PDF)."""

    def _generate(self, client, auth_headers, recon_id):
        return client.post(f'/recon/{recon_id}/generate_report', json={},
                           headers=auth_headers)

    def test_seals_and_mails_code_without_attachment(self, client, auth_headers, app):
        recon = _make_recon(pdf_report=None)
        with patch('routes.report.generate_pdf', return_value=PDF), \
             patch('routes.report.send_results_ready_email') as mail:
            resp = self._generate(client, auth_headers, recon.id)

        assert resp.status_code == 200
        assert resp.get_json()['data']['results_sealed'] is True
        kwargs = mail.call_args.kwargs
        assert 'pdf_bytes' not in kwargs
        code = kwargs['access_code']
        assert kwargs['results_url'] == 'https://recon.example.test/result.html'

        db.session.refresh(recon)
        assert recon.scan_results is None and recon.pdf_report is None
        # Le code envoyé ouvre bien le dossier
        assert client.get('/results/report.pdf',
                          headers=_bearer(_token(client, code))).data == PDF

    def test_mail_failure_keeps_record_unsealed(self, client, auth_headers, app):
        """Sans mail, le code serait perdu : rien ne doit être scellé."""
        recon = _make_recon(pdf_report=None)
        with patch('routes.report.generate_pdf', return_value=PDF), \
             patch('routes.report.send_results_ready_email', side_effect=Exception('SMTP down')):
            resp = self._generate(client, auth_headers, recon.id)

        data = resp.get_json()['data']
        assert data['email_sent'] is False and data['results_sealed'] is False
        db.session.refresh(recon)
        assert recon.sealed_at is None and recon.access_token_hash is None
        assert json.loads(recon.scan_results) == SCAN

        # Rattrapage admin une fois le SMTP rétabli
        with patch('routes.report.send_results_ready_email') as mail:
            retry = client.post(f'/recon/{recon.id}/issue_access', headers=auth_headers)
        assert retry.status_code == 200
        assert mail.call_args.kwargs['access_code']
        assert client.post(f'/recon/{recon.id}/issue_access',
                           headers=auth_headers).status_code == 409

    def test_unconfigured_vault_does_not_seal(self, client, auth_headers, app, monkeypatch):
        monkeypatch.setenv('RESULTS_ACCESS_SECRET', '')
        recon = _make_recon(pdf_report=None)
        with patch('routes.report.generate_pdf', return_value=PDF), \
             patch('routes.report.send_results_ready_email') as mail:
            data = self._generate(client, auth_headers, recon.id).get_json()['data']
        assert data['results_sealed'] is False
        assert 'RESULTS_ACCESS_SECRET' in data['email_error']
        mail.assert_not_called()

    def test_revoke_access(self, client, auth_headers, sealed):
        recon, code = sealed
        resp = client.post(f'/recon/{recon.id}/revoke_access', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['data']['access_state'] == 'revoked'
        assert _open(client, code).status_code == 403

    @pytest.mark.security
    def test_admin_endpoints_require_auth(self, client, sealed):
        recon, _ = sealed
        for path in ('issue_access', 'revoke_access'):
            assert client.post(f'/recon/{recon.id}/{path}').status_code == 401
