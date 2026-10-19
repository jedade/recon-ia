# tests/test_end_to_end_flow.py
"""
Parcours complet du demandeur, de bout en bout, à travers les vraies routes
Flask (plan d'action, phase 1). Seuls les appels externes sont simulés :
SMTP, webhook n8n, outils OSINT, LLM, génération PDF.

  formulaire → POST /recon → OTP → POST /verify_email → (API → n8n)
  → n8n, jeton de service : /pass_recon → analyse → /generate_final_report
  → /generate_report (scelle + mail avec code) → /results/* avec le code
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from database import db
from extensions import limiter
from models.recon import Recon

pytestmark = pytest.mark.integration

SERVICE = {'X-Service-Token': 'service-token-de-test-0123456789abcdefghij'}
PDF = b'%PDF-1.4 rapport de test'
ANALYSIS = {'security_score': 64, 'security_grade': 'C', 'risk_level': 'MEDIUM',
            'findings': [{'id': 'DNS-001', 'title': 'DNSSEC absent', 'severity': 'MEDIUM',
                          'source_tool': 'dns_records', 'evidence': 'A 93.184.216.34'}]}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    limiter.reset()
    monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', SERVICE['X-Service-Token'])
    monkeypatch.setenv('N8N_PIPELINE_WEBHOOK_URL', 'http://n8n:5678/webhook/recon-ia-pipeline')
    monkeypatch.setenv('N8N_WEBHOOK_SECRET', 'webhook-secret-de-test-0123456789abcdefgh')
    yield
    limiter.reset()


def test_full_user_journey(client, app, monkeypatch):
    import routes.recon as recon_routes

    # 1. Formulaire
    with patch('routes.crud.send_verification_email', return_value=True):
        resp = client.post('/recon', json={'domain': 'example.com', 'firstname': 'Ada',
                                           'lastname': 'Lovelace', 'email': 'ada@example.com',
                                           'accord': True})
    assert resp.status_code == 201
    recon_id = resp.get_json()['data']['id']
    otp = db.session.get(Recon, recon_id).otp_code

    # 2. Vérification → l'API déclenche n8n en interne
    accepted = MagicMock(status_code=202)
    with patch('utils.pipeline_trigger.requests.post', return_value=accepted) as webhook:
        resp = client.post('/verify_email', json={'email': 'ada@example.com', 'code': otp})
    assert resp.get_json()['pipeline_started'] is True
    assert webhook.call_args.kwargs['json'] == {'recon_id': recon_id}

    # 3. n8n : scan OSINT avec le jeton de service (outil simulé)
    monkeypatch.setattr(recon_routes, '_dns_records', lambda d: {
        'status': 'success', 'data': {'A': ['93.184.216.34']}, 'raw_output': 'A 93.184.216.34'})
    resp = client.post('/pass_recon', json={'recon_id': recon_id, 'tools': ['dns_records'],
                                            'force_refresh': True}, headers=SERVICE)
    assert resp.status_code == 200

    # 4. Analyse IA (simulée : on écrit le résultat comme le ferait /analyze)
    recon = db.session.get(Recon, recon_id)
    recon.set_analysis_result(ANALYSIS)
    db.session.commit()

    # 5. Rapport narratif puis PDF + scellement + mail avec le code
    with patch('utils.final_report_generator.generate_final_report',
               return_value={'executive_summary': 'Synthèse de test'}):
        assert client.post(f'/recon/{recon_id}/generate_final_report', json={},
                           headers=SERVICE).status_code == 200
    with patch('routes.report.generate_pdf', return_value=PDF), \
         patch('routes.report.send_results_ready_email') as mail:
        resp = client.post(f'/recon/{recon_id}/generate_report', json={}, headers=SERVICE)
    assert resp.status_code == 200
    assert resp.get_json()['data']['results_sealed'] is True
    code = mail.call_args.kwargs['access_code']

    # Plus rien de lisible en base, même pour l'admin
    recon = db.session.get(Recon, recon_id)
    assert recon.scan_results is None and recon.analysis_result is None
    assert recon.final_report is None and recon.pdf_report is None
    assert recon.status == 'success' and recon.current_step == 'completed'

    # 6. Le demandeur consulte avec son code
    token = client.post('/results/access', json={'code': code}).get_json()['data']['session_token']
    headers = {'Authorization': f'Bearer {token}'}
    report = client.get('/results/report', headers=headers).get_json()['data']
    assert report['scan_results']['dns_records']['data'] == {'A': ['93.184.216.34']}
    assert report['analysis_result']['findings'][0]['title'] == 'DNSSEC absent'
    assert report['final_report']['executive_summary'] == 'Synthèse de test'
    assert client.get('/results/report.pdf', headers=headers).data == PDF
    assert 'DNSSEC absent' in client.get('/results/export.csv', headers=headers).data.decode('utf-8-sig')
    assert json.loads(client.get('/results/export.json', headers=headers).data)['provenance']['recon_id'] == recon_id
