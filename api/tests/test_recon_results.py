# tests/test_recon_results.py
"""
Tests des endpoints de résultats d'exécution :
  PATCH /recon/<id>/result  — mise à jour par n8n
  GET   /recon/<id>/report  — rapport complet (données sensibles)

Format de réponse attendu :
  PATCH result → {"success": true, "message": "...", "data": {"id": N, "status": "...",
                  "execution_time": N|null, "end_report_date": "..."}}
  GET report   → {"success": true, "data": {"scan_results": {...}, "final_report": "...", ...}}
  GET standard → {"success": true, "data": {...}}  — sans scan_results ni final_report

Cycle de vie des dates de rapport :
  start_report_date → positionné automatiquement à la vérification email (POST /verify_email)
  end_report_date   → positionné automatiquement à chaque appel PATCH /result
  execution_time    → calculé automatiquement (end_report_date - start_report_date) en secondes
"""
import pytest
from unittest.mock import patch


def _create_recon(client, auth_headers, email='result@example.com'):
    """Crée un enregistrement de test et retourne le dict 'data'."""
    with patch('routes.crud.send_verification_email'):
        resp = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Test',
            'lastname': 'User',
            'email': email,
            'accord': True,
            'requested_info': 'Analyser sous-domaines et SSL',
        }, headers=auth_headers)
    assert resp.status_code == 201
    return resp.get_json()['data']


def _create_and_verify_recon(client, auth_headers, app, email='verified@example.com'):
    """Crée un enregistrement et le vérifie par OTP pour déclencher start_report_date."""
    _create_recon(client, auth_headers, email=email)
    with app.app_context():
        from models.recon import Recon
        recon = Recon.query.filter_by(email=email).first()
        code = recon.otp_code
    resp = client.post('/verify_email', json={'email': email, 'code': code},
                       headers=auth_headers)
    assert resp.status_code == 200
    return resp.get_json()['data']


class TestUpdateReconResult:
    def test_update_status_success(self, client, auth_headers):
        """PATCH /result positionne end_report_date automatiquement."""
        recon = _create_recon(client, auth_headers)
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'started_at': '2025-09-13T10:00:00',
            'completed_at': '2025-09-13T10:00:42',
            'final_report': 'Aucune vulnérabilité critique détectée.',
            'scan_results': {'subdomains': ['mail.example.com'], 'ssl': 'OK'},
        }, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['success'] is True
        assert body['data']['status'] == 'success'
        assert body['data']['end_report_date'] is not None

    def test_patch_sets_end_report_date_automatically(self, client, auth_headers):
        """end_report_date doit être rempli automatiquement à chaque PATCH."""
        recon = _create_recon(client, auth_headers, email='enddate@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
        }, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'end_report_date' in body['data']
        assert body['data']['end_report_date'] is not None

    def test_execution_time_computed_from_report_dates(self, client, auth_headers, app):
        """execution_time est calculé depuis start_report_date (email vérifié) et end_report_date (PATCH)."""
        recon = _create_and_verify_recon(client, auth_headers, app,
                                         email='exectime@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'final_report': 'Rapport final.',
        }, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        # execution_time doit être calculé (≥ 0)
        assert body['data']['execution_time'] is not None
        assert body['data']['execution_time'] >= 0.0

    def test_execution_time_none_without_start_report_date(self, client, auth_headers):
        """Sans start_report_date (email non vérifié), execution_time reste None."""
        recon = _create_recon(client, auth_headers, email='nostart@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['data']['execution_time'] is None

    def test_end_report_date_visible_in_standard_get(self, client, auth_headers):
        """end_report_date doit être visible dans GET /recon/<id>."""
        recon = _create_recon(client, auth_headers, email='endget@example.com')
        client.patch(f'/recon/{recon["id"]}/result', json={'status': 'success'},
                     headers=auth_headers)
        resp = client.get(f'/recon/{recon["id"]}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert 'end_report_date' in data
        assert data['end_report_date'] is not None

    def test_update_status_running(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='running@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'running',
            'started_at': '2025-09-13T10:00:00',
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_invalid_status_returns_400(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='badstatus@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'hacked',
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['success'] is False

    def test_invalid_date_format_returns_400(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='baddate@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'completed_at': '13/09/2025',
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['success'] is False

    def test_nonexistent_recon_returns_404(self, client, auth_headers):
        resp = client.patch('/recon/99999/result', json={'status': 'success'},
                            headers=auth_headers)
        assert resp.status_code == 404

    def test_no_auth_returns_401(self, client):
        resp = client.patch('/recon/1/result', json={'status': 'success'})
        assert resp.status_code == 401

    def test_no_json_returns_400_or_415(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='nojson@example.com')
        resp = client.patch(f'/recon/{recon["id"]}/result', headers=auth_headers)
        assert resp.status_code in (400, 415)


class TestGetReconReport:
    def test_report_contains_sensitive_fields(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='report@example.com')
        client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'execution_time': 10.0,
            'scan_results': {'dns': {'A': '93.184.216.34'}},
            'final_report': 'Rapport complet : domaine sain.',
        }, headers=auth_headers)

        resp = client.get(f'/recon/{recon["id"]}/report', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['success'] is True
        data = body['data']
        assert 'scan_results' in data
        assert 'final_report' in data
        assert data['final_report'] == 'Rapport complet : domaine sain.'
        assert data['scan_results']['dns']['A'] == '93.184.216.34'

    def test_standard_get_does_not_expose_results(self, client, auth_headers):
        """Les données sensibles ne doivent PAS apparaître dans GET /recon/<id>."""
        recon = _create_recon(client, auth_headers, email='hidden@example.com')
        client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'scan_results': {'secret': 'data'},
            'final_report': 'Rapport secret',
        }, headers=auth_headers)

        resp = client.get(f'/recon/{recon["id"]}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert 'scan_results' not in data
        assert 'final_report' not in data

    def test_requested_info_stored(self, client, auth_headers):
        recon = _create_recon(client, auth_headers, email='reqinfo@example.com')
        resp = client.get(f'/recon/{recon["id"]}', headers=auth_headers)
        assert resp.get_json()['data']['requested_info'] == 'Analyser sous-domaines et SSL'

    def test_status_tracked_in_standard_get(self, client, auth_headers, app):
        """
        Le statut et execution_time sont visibles dans GET standard (pas sensibles).

        execution_time est calculé par le serveur (end_report_date -
        start_report_date) et n'est jamais lu depuis le corps de la requête :
        l'enregistrement doit donc être vérifié par OTP pour que
        start_report_date existe et que la durée soit calculable.
        """
        recon = _create_and_verify_recon(client, auth_headers, app,
                                         email='status@example.com')
        client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'failed',
        }, headers=auth_headers)
        resp = client.get(f'/recon/{recon["id"]}', headers=auth_headers)
        data = resp.get_json()['data']
        assert data['status'] == 'failed'
        assert data['execution_time'] is not None
        assert data['execution_time'] >= 0

    def test_execution_time_ignores_client_supplied_value(self, client, auth_headers, app):
        """
        Garde-fou : une durée fournie par le client est ignorée au profit du
        calcul serveur — sinon n8n pourrait falsifier les métriques publiées.
        """
        recon = _create_and_verify_recon(client, auth_headers, app,
                                         email='notrust@example.com')
        client.patch(f'/recon/{recon["id"]}/result', json={
            'status': 'success',
            'execution_time': 99999.0,
        }, headers=auth_headers)
        data = client.get(f'/recon/{recon["id"]}', headers=auth_headers).get_json()['data']
        assert data['execution_time'] != 99999.0

    def test_report_nonexistent_returns_404(self, client, auth_headers):
        resp = client.get('/recon/99999/report', headers=auth_headers)
        assert resp.status_code == 404

    def test_report_no_auth_returns_401(self, client):
        resp = client.get('/recon/1/report')
        assert resp.status_code == 401
