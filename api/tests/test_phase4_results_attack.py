# tests/test_phase4_results_attack.py
"""
Phase 4 côté consultation : GET /results/export.navigator.json (mêmes
protections que les autres exports), vue ATT&CK de GET /results/report
(constats annotés + chaîne d'attaque) et sections ATT&CK du PDF.
"""
import json
from datetime import datetime, timedelta

import pytest

from database import db
from extensions import limiter
from models.recon import Recon
from utils import result_vault

pytestmark = pytest.mark.integration

SCAN = {'dmarc_check': {'status': 'success', 'data': {'present': False},
                        'meta': {'tool': 'DMARC', 'category': 'Email / Messagerie'}}}
ANALYSIS = {
    'security_score': 55, 'security_grade': 'D', 'risk_level': 'HIGH',
    'findings': [
        {'id': 'EMAIL-001', 'title': 'Aucune politique DMARC', 'severity': 'HIGH',
         'source_tool': 'dmarc_check', 'confidence': 'high', 'observed_at': '2026-10-19T10:42:00Z',
         'references': [{'collection': 'normes', 'source': 'RFC 7489'}],
         # Valeurs « LLM » à écraser par la table
         'attack_enabled': [{'id': 'T9999', 'name': '<b>faux</b>'}]},
        {'id': 'NET-001', 'title': 'RDP exposé sur Internet', 'severity': 'CRITICAL',
         'source_tool': 'shodan_internetdb'},
        {'id': 'WEB-001', 'title': '<script>alert(1)</script> DMARC absent', 'severity': 'LOW',
         'source_tool': 'security_headers'},
    ],
    'mitre_attack': [{'technique_id': 'T1590.002', 'technique_name': 'DNS', 'tactic': 'Reconnaissance',
                      'matched_tools': ['dmarc_check']}],
}
NAV = '/results/export.navigator.json'


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def _sealed(accord=True, analysis=ANALYSIS):
    recon = Recon(
        domain='example.com', firstname='Ada', lastname='Lovelace', email='ada@example.com',
        accord=accord, verification=True, status='success', current_step='completed',
        scan_results=json.dumps(SCAN), analysis_result=json.dumps(analysis),
        final_report=json.dumps({'executive_summary': 'x'}), pdf_report=b'%PDF-1.4 x',
        start_report_date=datetime.utcnow() - timedelta(minutes=5), end_report_date=datetime.utcnow(),
    )
    recon.set_analysis_result(analysis)
    db.session.add(recon)
    db.session.commit()
    code = result_vault.seal_recon(recon)
    db.session.commit()
    return recon, code


def _bearer(client, code):
    resp = client.post('/results/access', json={'code': code})
    assert resp.status_code == 200, resp.get_json()
    return {'Authorization': 'Bearer ' + resp.get_json()['data']['session_token']}


class TestNavigatorExport:
    def test_download_layer(self, client, app):
        recon, code = _sealed()
        resp = client.get(NAV, headers=_bearer(client, code))
        assert resp.status_code == 200
        assert resp.mimetype == 'application/json'
        disposition = resp.headers['Content-Disposition']
        assert disposition == f'attachment; filename="recon_ia_attack_navigator_example.com_{recon.id}.json"'
        assert resp.headers['X-Content-Type-Options'] == 'nosniff'
        layer = json.loads(resp.data)
        assert layer['versions']['layer'] == '4.5'
        assert layer['domain'] == 'enterprise-attack'
        by_id = {t['techniqueID']: t for t in layer['techniques']}
        assert set(by_id) == {'T1566', 'T1133', 'T1590.002'}
        assert by_id['T1566']['score'] == 3          # HIGH (EMAIL-001) > LOW (WEB-001)
        assert by_id['T1133']['score'] == 4
        assert by_id['T1590.002']['score'] == 0
        assert 'T9999' not in resp.get_data(as_text=True)

    @pytest.mark.security
    def test_layer_has_no_markup_from_llm(self, client, app):
        _, code = _sealed()
        body = client.get(NAV, headers=_bearer(client, code)).get_data(as_text=True)
        assert '<script>' not in body and '<b>' not in body

    @pytest.mark.security
    @pytest.mark.parametrize('headers', [{}, {'Authorization': 'Bearer '}, {'Authorization': 'Bearer forged'},
                                         {'Authorization': 'Basic YWRtaW46dGVzdHBhc3N3b3Jk'}])
    def test_session_required(self, client, app, headers):
        _sealed()
        resp = client.get(NAV, headers=headers)
        assert resp.status_code == 401
        assert 'Content-Disposition' not in resp.headers

    @pytest.mark.security
    def test_access_code_is_not_a_session(self, client, app):
        _, code = _sealed()
        assert client.get(NAV, headers={'Authorization': f'Bearer {code}'}).status_code == 401

    @pytest.mark.security
    def test_consent_required(self, client, app):
        _, code = _sealed(accord=False)
        resp = client.get(NAV, headers=_bearer(client, code))
        assert resp.status_code == 403
        assert 'Content-Disposition' not in resp.headers

    @pytest.mark.security
    def test_revocation_cuts_session(self, client, app):
        recon, code = _sealed()
        headers = _bearer(client, code)
        recon.access_revoked_at = datetime.utcnow()
        db.session.commit()
        assert client.get(NAV, headers=headers).status_code == 403

    @pytest.mark.security
    def test_expiry_cuts_session(self, client, app):
        recon, code = _sealed()
        headers = _bearer(client, code)
        recon.access_expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        assert client.get(NAV, headers=headers).status_code == 410

    def test_analysis_without_findings(self, client, app):
        _, code = _sealed(analysis={'security_score': 90, 'findings': None, 'mitre_attack': 'oops'})
        resp = client.get(NAV, headers=_bearer(client, code))
        assert resp.status_code == 200
        assert json.loads(resp.data)['techniques'] == []


class TestReportAttackView:
    def test_report_has_annotated_findings_and_chain(self, client, app):
        _, code = _sealed()
        data = client.get('/results/report', headers=_bearer(client, code)).get_json()['data']
        findings = {f['id']: f for f in data['analysis_result']['findings']}
        assert findings['EMAIL-001']['attack_enabled'] == [{'id': 'T1566', 'name': 'Phishing'}]
        assert [m['id'] for m in findings['EMAIL-001']['mitigations']] == ['M1054', 'M1017']
        assert findings['EMAIL-001']['confidence'] == 'high'          # champs phase 3 conservés
        assert findings['NET-001']['attack_enabled'][0]['id'] == 'T1133'
        attack = data['attack']
        assert attack['attack_version'].split('.')[0].isdigit()
        stages = [s['stage'] for s in attack['chain']]
        assert stages == ['reconnaissance', 'initial-access']
        assert set(attack['context']) == {'T1566', 'T1133'}

    def test_export_json_stays_raw_dataset(self, client, app):
        """L'annotation est une vue : l'export JSON (jeu de données citable) n'est pas modifié."""
        _, code = _sealed()
        body = json.loads(client.get('/results/export.json', headers=_bearer(client, code)).data)
        first = body['analysis_result']['findings'][0]
        assert first['attack_enabled'] == [{'id': 'T9999', 'name': '<b>faux</b>'}]


class TestPdfAttackSections:
    def _texts(self, story):
        from reportlab.platypus import Paragraph, Table
        out = []

        def walk(node):
            if isinstance(node, Paragraph):
                out.append(node.text)
            elif isinstance(node, Table):
                for row in node._cellvalues:
                    for cell in row:
                        for c in (cell if isinstance(cell, (list, tuple)) else [cell]):
                            walk(c)
            elif hasattr(node, '_content'):
                for c in node._content:
                    walk(c)
        for n in story:
            walk(n)
        return ' '.join(out)

    def test_findings_and_chain_sections(self):
        from utils import pdf_generator as pg
        analysis = pg._with_attack(ANALYSIS)
        story = []
        pg._build_findings(story, analysis)
        pg._build_attack_chain(story, analysis)
        text = self._texts(story)
        assert 'Rend possible' in text and '<b>T1566</b> Phishing' in text
        assert 'M1054' in text and 'Confiance : <b>élevée</b>' in text
        assert 'RFC 7489 (normes)' in text
        assert 'T9999' not in text
        assert 'Initial Access' in text and 'T1133' in text
        assert '&lt;script&gt;' in text and '<script>' not in text

    def test_generate_pdf_end_to_end(self):
        from utils.pdf_generator import generate_pdf
        pdf = generate_pdf(ANALYSIS)
        assert pdf.startswith(b'%PDF')

    def test_pdf_survives_annotation_failure(self, monkeypatch):
        from utils import attack_enablement, pdf_generator
        monkeypatch.setattr(attack_enablement, 'annotate_findings', lambda *a, **k: 1 / 0)
        assert pdf_generator._with_attack(ANALYSIS) is ANALYSIS
        assert pdf_generator.generate_pdf(ANALYSIS).startswith(b'%PDF')
