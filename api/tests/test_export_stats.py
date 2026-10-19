# tests/test_export_stats.py
"""
Tests des endpoints d'export académique et d'agrégation KPI (phase 3).

  GET /recon/stats            — agrégats SQL sur l'ensemble des données
  GET /recon/<id>/export.json — dump structuré + provenance reproductible
  GET /recon/<id>/export.csv  — findings tabulaires

Couvre également le filtrage serveur du paramètre `status` sur GET /recon.
"""
import csv
import hashlib
import io
import json
from datetime import datetime

import pytest


# ── Fixtures / helpers ────────────────────────────────────────────────────────

SCAN_RESULTS = {
    "domain": "example.com",
    "dns_records": {
        "meta": {
            "tool": "dnspython",
            "category": "DNS / Réseau",
            "description": "Enregistrements DNS publics",
        },
        "status": "success",
        "data": {"A": ["93.184.216.34"]},
        "raw_output": "example.com. 86400 IN A 93.184.216.34",
    },
    "shodan_internetdb": {
        "meta": {
            "tool": "Shodan InternetDB",
            "category": "Réputation / Threat Intel",
            "description": "Ports et CVE observés passivement",
        },
        "status": "success",
        "data": {"ports": [80, 443]},
        "raw_output": "ports: 80, 443",
    },
    # Bloc sans meta — ne doit jamais être compté comme un outil
    "cache": {"hit": False, "scan_duration_s": 12.5, "ttl_days": 7},
}

ANALYSIS_RESULT = {
    "domain": "example.com",
    "risk_score": 42,
    "risk_level": "MEDIUM",
    "security_score": 70,
    "security_grade": "B",
    "model_used": "groq+openrouter (merged)",
    "executive_summary": "Résumé de test.",
    "findings": [
        {
            "id": "DNS-001",
            "category": "DNS",
            "severity": "HIGH",
            "title": "Absence de DNSSEC",
            "description": "Le domaine ne signe pas ses réponses DNS.",
            "evidence": "Aucun enregistrement DS trouvé",
            "source_tool": "dns_records",
            "web_sources": ["https://example.org/dnssec"],
        },
        {
            "id": "NET-002",
            "category": "Infrastructure",
            "severity": "LOW",
            "title": "Port 80 ouvert",
            "description": "HTTP en clair exposé.",
            "evidence": "ports: 80, 443",
            "source_tool": "shodan_internetdb",
            "web_sources": [],
        },
    ],
}


def _make_recon(app, **overrides):
    """Insère un enregistrement Recon directement en base et retourne son id."""
    from database import db
    from models.recon import Recon

    fields = {
        'domain': 'example.com',
        'firstname': 'Jean',
        'lastname': 'Dupont',
        'email': 'export@example.com',
        'accord': True,
        'verification': True,
        'status': 'success',
    }
    fields.update(overrides)

    # L'analyse passe par set_analysis_result() — chemin d'écriture réel, qui
    # alimente aussi les colonnes dénormalisées security_score/grade.
    analysis = fields.pop('analysis_result', None)

    with app.app_context():
        recon = Recon(**fields)
        if analysis is not None:
            recon.set_analysis_result(analysis)
        db.session.add(recon)
        db.session.commit()
        return recon.id


@pytest.fixture
def full_recon(app):
    """Enregistrement complet : scan + analyse + PDF + horodatages cohérents."""
    started = datetime(2026, 7, 20, 10, 0, 0)
    completed = datetime(2026, 7, 20, 10, 0, 42)
    return _make_recon(
        app,
        scan_results=json.dumps(SCAN_RESULTS, ensure_ascii=False),
        analysis_result=json.dumps(ANALYSIS_RESULT, ensure_ascii=False),
        analysis_generated_at=datetime(2026, 7, 20, 10, 2, 0),
        analysis_expires_at=datetime(2099, 1, 1),
        pdf_report=b'%PDF-1.4 fake',
        pdf_generated_at=datetime(2026, 7, 20, 10, 3, 0),
        started_at=started,
        completed_at=completed,
        start_report_date=datetime(2026, 7, 20, 9, 59, 0),
        end_report_date=completed,
        execution_time=102.0,
    )


# ── GET /recon/stats ──────────────────────────────────────────────────────────

class TestReconStats:
    def test_requires_auth(self, client):
        assert client.get('/recon/stats').status_code == 401

    def test_empty_database_returns_zeros(self, client, auth_headers):
        resp = client.get('/recon/stats', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['total_recons'] == 0
        assert data['pdf_generated'] == 0
        assert data['analyses_completed'] == 0
        assert data['success_rate_pct'] == 0.0
        assert data['avg_security_score'] is None

    def test_counts_reflect_all_records(self, app, client, auth_headers):
        _make_recon(app, email='a@example.com', status='success',
                    pdf_report=b'pdf', analysis_result=json.dumps(ANALYSIS_RESULT))
        _make_recon(app, email='b@example.com', status='failed')
        _make_recon(app, email='c@example.com', status='pending')
        _make_recon(app, email='d@example.com', status='running')

        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['total_recons'] == 4
        assert data['pdf_generated'] == 1
        assert data['analyses_completed'] == 1
        assert data['in_progress'] == 2          # pending + running
        assert data['by_status'] == {'pending': 1, 'running': 1,
                                     'success': 1, 'failed': 1}
        assert data['success_rate_pct'] == 25.0

    def test_kpi_not_capped_by_pagination(self, app, client, auth_headers):
        """
        Régression : les KPI portaient sur une seule page (max 100 lignes).
        Avec 120 enregistrements, les totaux doivent valoir 120, pas 100.
        """
        for i in range(120):
            _make_recon(app, email=f'bulk{i}@example.com', status='success')

        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['total_recons'] == 120
        assert data['by_status']['success'] == 120
        assert data['success_rate_pct'] == 100.0

    def test_avg_security_score_is_real_average(self, app, client, auth_headers):
        for i, score in enumerate([60, 80]):
            _make_recon(app, email=f'score{i}@example.com',
                        analysis_result=json.dumps({'security_score': score}))
        # Analyse illisible et analyse sans score : ignorées, pas comptées comme 0
        _make_recon(app, email='broken@example.com', analysis_result='{not json')
        _make_recon(app, email='noscore@example.com', analysis_result=json.dumps({'x': 1}))

        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['avg_security_score'] == 70.0
        assert data['scored_recons'] == 2

    def test_scan_and_flow_durations_are_distinct(self, app, client, auth_headers):
        """
        `avg_scan_duration_s` mesure completed_at - started_at (le scan), pas
        execution_time qui est la durée totale du flux, attente utilisateur
        incluse. Confondre les deux surestimait le KPI d'un ordre de grandeur.
        """
        _make_recon(
            app, email='dur@example.com',
            started_at=datetime(2026, 7, 20, 10, 0, 0),
            completed_at=datetime(2026, 7, 20, 10, 0, 30),   # scan = 30 s
            execution_time=600.0,                             # flux = 600 s
        )
        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['avg_scan_duration_s'] == 30.0
        assert data['avg_flow_duration_s'] == 600.0

    def test_computed_at_is_utc_with_z(self, client, auth_headers):
        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['computed_at'].endswith('Z')


# ── Filtrage serveur du statut ────────────────────────────────────────────────

class TestReconStatusFilter:
    def test_status_filter_applied_server_side(self, app, client, auth_headers):
        _make_recon(app, email='s1@example.com', status='success')
        _make_recon(app, email='s2@example.com', status='success')
        _make_recon(app, email='f1@example.com', status='failed')

        body = client.get('/recon?status=success', headers=auth_headers).get_json()
        assert body['total'] == 2
        assert body['status_filter'] == 'success'
        assert all(r['status'] == 'success' for r in body['data'])

    def test_invalid_status_returns_400(self, client, auth_headers):
        resp = client.get('/recon?status=bogus', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['success'] is False

    def test_domain_filter_applied_server_side(self, app, client, auth_headers):
        """
        Le filtre domaine doit être appliqué en SQL : filtrer côté client après
        pagination masquerait les résultats des autres pages.
        """
        _make_recon(app, email='d1@example.com', domain='alpha.example.com')
        _make_recon(app, email='d2@example.com', domain='beta.example.com')
        _make_recon(app, email='d3@example.com', domain='alpha.test')

        body = client.get('/recon?domain=alpha', headers=auth_headers).get_json()
        assert body['total'] == 2
        assert body['domain_filter'] == 'alpha'
        assert all('alpha' in r['domain'] for r in body['data'])

    def test_domain_filter_escapes_like_wildcards(self, app, client, auth_headers):
        """Un '%' ne doit pas se comporter comme un joker et tout retourner."""
        _make_recon(app, email='w1@example.com', domain='example.com')
        body = client.get('/recon?domain=%', headers=auth_headers).get_json()
        assert body['total'] == 0

    def test_per_page_reported_is_the_one_served(self, app, client, auth_headers):
        """La réponse doit annoncer la taille de page réellement servie."""
        _make_recon(app, email='pp@example.com')
        body = client.get('/recon?per_page=-5', headers=auth_headers).get_json()
        assert body['per_page'] > 0

    def test_no_filter_returns_all(self, app, client, auth_headers):
        _make_recon(app, email='n1@example.com', status='success')
        _make_recon(app, email='n2@example.com', status='failed')
        body = client.get('/recon', headers=auth_headers).get_json()
        assert body['total'] == 2
        assert body['status_filter'] is None


# ── Score inclus dans la liste (suppression du N+1) ──────────────────────────

class TestScoreInListing:
    def test_security_score_included_in_listing(self, client, auth_headers, full_recon):
        body = client.get('/recon', headers=auth_headers).get_json()
        row = next(r for r in body['data'] if r['id'] == full_recon)
        assert row['security_score'] == 70
        assert row['security_grade'] == 'B'

    def test_score_null_without_analysis(self, app, client, auth_headers):
        rid = _make_recon(app, email='noana@example.com')
        body = client.get('/recon', headers=auth_headers).get_json()
        row = next(r for r in body['data'] if r['id'] == rid)
        assert row['security_score'] is None

    def test_timestamps_are_utc_with_z(self, client, auth_headers, full_recon):
        body = client.get(f'/recon/{full_recon}', headers=auth_headers).get_json()
        assert body['data']['created_at'].endswith('Z')
        assert body['data']['started_at'].endswith('Z')

    def test_durations_are_frozen(self, client, auth_headers, full_recon):
        """Les durées viennent des horodatages persistés, jamais de l'heure courante."""
        data = client.get(f'/recon/{full_recon}', headers=auth_headers).get_json()['data']
        assert data['scan_duration_s'] == 42.0    # completed_at - started_at
        assert data['flow_duration_s'] == 102.0   # end_report_date - start_report_date


# ── GET /recon/<id>/export.json ───────────────────────────────────────────────

class TestDenormalisedScore:
    """Colonnes dénormalisées + chargement différé des blobs (phase 4)."""

    def test_setter_populates_columns(self, app):
        from models.recon import Recon
        with app.app_context():
            r = Recon(domain='x.test', firstname='A', lastname='B',
                      email='den1@example.com', accord=True)
            r.set_analysis_result({'security_score': 77, 'security_grade': 'B+'})
            assert r.security_score == 77
            assert r.security_grade == 'B+'

    def test_setter_accepts_serialised_json(self, app):
        from models.recon import Recon
        with app.app_context():
            r = Recon(domain='x.test', firstname='A', lastname='B',
                      email='den2@example.com', accord=True)
            r.set_analysis_result(json.dumps({'security_score': 40, 'security_grade': 'D'}))
            assert r.security_score == 40

    def test_setter_tolerates_missing_score(self, app):
        from models.recon import Recon
        with app.app_context():
            r = Recon(domain='x.test', firstname='A', lastname='B',
                      email='den3@example.com', accord=True)
            r.set_analysis_result({'findings': []})
            assert r.security_score is None

    def test_legacy_rows_fall_back_to_json_parsing(self, app):
        """
        Un enregistrement écrit avant la migration (colonne vide, JSON présent)
        doit continuer à exposer son score.
        """
        from database import db
        from models.recon import Recon
        with app.app_context():
            r = Recon(domain='x.test', firstname='A', lastname='B',
                      email='legacy@example.com', accord=True)
            # Écriture directe, sans passer par le setter : simule l'existant.
            r.analysis_result = json.dumps({'security_score': 55, 'security_grade': 'C'})
            db.session.add(r)
            db.session.commit()
            assert r.security_summary() == {'security_score': 55, 'security_grade': 'C'}

    def test_unscored_analyses_are_reported(self, app, client, auth_headers):
        """L'écart de backfill doit être visible, pas silencieux."""
        from database import db
        from models.recon import Recon
        with app.app_context():
            r = Recon(domain='x.test', firstname='A', lastname='B',
                      email='unscored@example.com', accord=True)
            r.analysis_result = json.dumps({'security_score': 50})
            db.session.add(r)
            db.session.commit()

        data = client.get('/recon/stats', headers=auth_headers).get_json()['data']
        assert data['unscored_analyses'] == 1

    def test_listing_does_not_load_blobs(self, app, client, auth_headers, full_recon):
        """
        Cœur du point 5 : GET /recon ne doit plus rapatrier scan_results,
        analysis_result, final_report ni le PDF. On l'observe via l'état de
        chargement des attributs différés après la requête.
        """
        from sqlalchemy import inspect as sa_inspect
        from models.recon import Recon

        with app.app_context():
            rows = Recon.query.all()
            assert rows
            unloaded = sa_inspect(rows[0]).unloaded
            for blob in ('scan_results', 'analysis_result', 'final_report', 'pdf_report'):
                assert blob in unloaded, f'{blob} a été chargé alors qu\'il est deferred'

            # …tout en exposant correctement les indicateurs de présence,
            # calculés en SQL et non en chargeant les blobs.
            row = next(r for r in rows if r.id == full_recon)
            assert row.has_pdf is True
            assert row.has_analysis is True
            assert row.security_score == 70

    def test_has_flags_false_when_absent(self, app, client, auth_headers):
        rid = _make_recon(app, email='flags@example.com')
        body = client.get('/recon', headers=auth_headers).get_json()
        row = next(r for r in body['data'] if r['id'] == rid)
        assert row['has_pdf'] is False
        assert row['has_analysis'] is False


class TestExportJson:
    def test_requires_auth(self, full_recon, client):
        assert client.get(f'/recon/{full_recon}/export.json').status_code == 401

    def test_nonexistent_returns_404(self, client, auth_headers):
        assert client.get('/recon/99999/export.json', headers=auth_headers).status_code == 404

    def test_returns_attachment(self, client, auth_headers, full_recon):
        resp = client.get(f'/recon/{full_recon}/export.json', headers=auth_headers)
        assert resp.status_code == 200
        assert 'application/json' in resp.headers['Content-Type']
        assert 'attachment' in resp.headers['Content-Disposition']

    def test_top_level_structure(self, client, auth_headers, full_recon):
        body = client.get(f'/recon/{full_recon}/export.json',
                          headers=auth_headers).get_json()
        assert set(body) >= {'provenance', 'scan_results',
                             'analysis_result', 'final_report', 'citation'}
        assert body['scan_results'] == SCAN_RESULTS
        assert body['analysis_result'] == ANALYSIS_RESULT

    def test_provenance_fields(self, client, auth_headers, full_recon):
        prov = client.get(f'/recon/{full_recon}/export.json',
                          headers=auth_headers).get_json()['provenance']
        assert prov['schema_version'] == '1.0'
        assert prov['generated_at'].endswith('Z')
        assert prov['recon_id'] == full_recon
        assert prov['domain'] == 'example.com'
        # Seuls les blocs porteurs de meta.tool comptent comme outils
        assert sorted(prov['tools_requested']) == ['dns_records', 'shodan_internetdb']
        assert prov['scan_duration_s'] == 42.0
        assert prov['ai_backend_used'] == 'groq+openrouter (merged)'
        assert prov['cache_hit'] is False

    def test_dataset_sha256_matches_canonical_json(self, client, auth_headers, full_recon):
        prov = client.get(f'/recon/{full_recon}/export.json',
                          headers=auth_headers).get_json()['provenance']
        expected = hashlib.sha256(
            json.dumps(SCAN_RESULTS, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, default=str).encode('utf-8')
        ).hexdigest()
        assert prov['dataset_sha256'] == expected

    def test_dataset_sha256_is_stable(self, client, auth_headers, full_recon):
        """Deux exports du même jeu de données produisent la même empreinte."""
        url = f'/recon/{full_recon}/export.json'
        h1 = client.get(url, headers=auth_headers).get_json()['provenance']['dataset_sha256']
        h2 = client.get(url, headers=auth_headers).get_json()['provenance']['dataset_sha256']
        assert h1 == h2

    def test_citation_contains_domain_and_hash(self, client, auth_headers, full_recon):
        body = client.get(f'/recon/{full_recon}/export.json',
                          headers=auth_headers).get_json()
        citation = body['citation']
        assert 'ReconIA' in citation
        assert 'example.com' in citation
        assert '2 outils passifs' in citation
        assert body['provenance']['dataset_sha256'] in citation

    def test_export_refused_without_consent(self, app, client, auth_headers):
        """Un export « citable » ne doit pas sortir de données non consenties."""
        rid = _make_recon(app, email='noconsent@example.com', accord=False,
                          scan_results=json.dumps(SCAN_RESULTS))
        resp = client.get(f'/recon/{rid}/export.json', headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['success'] is False
        assert client.get(f'/recon/{rid}/export.csv',
                          headers=auth_headers).status_code == 403

    def test_corrupted_data_is_flagged_not_silently_empty(self, app, client, auth_headers):
        """
        Un scan_results illisible ne doit pas produire un export d'apparence
        valide annonçant « 0 outil » : l'écart doit être explicite.
        """
        rid = _make_recon(app, email='corrupt@example.com',
                          scan_results='{ceci nest pas du json')
        body = client.get(f'/recon/{rid}/export.json',
                          headers=auth_headers).get_json()
        integrity = body['provenance']['data_integrity']
        assert integrity['scan_results_stored'] is True
        assert integrity['scan_results_parsed'] is False
        assert integrity['corrupted'] is True

    def test_integrity_clean_on_valid_record(self, client, auth_headers, full_recon):
        integrity = client.get(f'/recon/{full_recon}/export.json',
                               headers=auth_headers).get_json()['provenance']['data_integrity']
        assert integrity['corrupted'] is False
        assert integrity['scan_results_parsed'] is True

    def test_export_without_scan_data(self, app, client, auth_headers):
        """Un enregistrement vide s'exporte sans erreur, sans hash inventé."""
        rid = _make_recon(app, email='empty@example.com', status='pending')
        body = client.get(f'/recon/{rid}/export.json', headers=auth_headers).get_json()
        assert body['scan_results'] is None
        assert body['provenance']['dataset_sha256'] is None
        assert body['provenance']['tools_requested'] == []


# ── GET /recon/<id>/export.csv ────────────────────────────────────────────────

EXPECTED_COLUMNS = [
    'finding_id', 'tool', 'tool_category', 'target', 'indicator', 'value',
    'severity', 'confidence', 'source_tool', 'source_url', 'collected_at',
    'grounding_status', 'observed_at', 'severity_rule', 'attack_enabled', 'mitigations',
]


def _parse_csv(resp):
    text = resp.get_data(as_text=True).lstrip('\ufeff')
    return list(csv.DictReader(io.StringIO(text)))


class TestExportCsv:
    def test_requires_auth(self, full_recon, client):
        assert client.get(f'/recon/{full_recon}/export.csv').status_code == 401

    def test_nonexistent_returns_404(self, client, auth_headers):
        assert client.get('/recon/99999/export.csv', headers=auth_headers).status_code == 404

    def test_content_type_and_disposition(self, client, auth_headers, full_recon):
        resp = client.get(f'/recon/{full_recon}/export.csv', headers=auth_headers)
        assert resp.status_code == 200
        assert 'text/csv' in resp.headers['Content-Type']
        assert 'attachment' in resp.headers['Content-Disposition']
        assert '.csv' in resp.headers['Content-Disposition']

    def test_column_order(self, client, auth_headers, full_recon):
        rows = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                     headers=auth_headers))
        assert list(rows[0].keys()) == EXPECTED_COLUMNS

    def test_grounding_status_empty_when_absent(self, client, auth_headers, full_recon):
        """ANALYSIS_RESULT n'a pas de champ `grounding` (analyse antérieure au
        contrôle d'ancrage) — la colonne doit être vide, jamais fabriquée."""
        rows = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                     headers=auth_headers))
        assert all(r['grounding_status'] == '' for r in rows)

    def test_grounding_status_reflects_finding_grounding(self, app, client, auth_headers):
        analysis = {
            **ANALYSIS_RESULT,
            "findings": [
                {**ANALYSIS_RESULT["findings"][0], "grounding": {"status": "verified"}},
                {**ANALYSIS_RESULT["findings"][1], "grounding": {"status": "evidence_not_found"}},
            ],
        }
        recon_id = _make_recon(
            app, email='grounding@example.com',
            scan_results=json.dumps(SCAN_RESULTS, ensure_ascii=False),
            analysis_result=json.dumps(analysis, ensure_ascii=False),
        )
        rows = _parse_csv(client.get(f'/recon/{recon_id}/export.csv', headers=auth_headers))
        assert [r['grounding_status'] for r in rows] == ['verified', 'evidence_not_found']

    def test_one_row_per_finding(self, client, auth_headers, full_recon):
        rows = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                     headers=auth_headers))
        assert len(rows) == len(ANALYSIS_RESULT['findings'])
        assert [r['finding_id'] for r in rows] == ['DNS-001', 'NET-002']

    def test_tool_resolved_from_scan_meta(self, client, auth_headers, full_recon):
        """`tool`/`tool_category` proviennent de meta.* de l'outil source (phase 2)."""
        rows = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                     headers=auth_headers))
        first = rows[0]
        assert first['source_tool'] == 'dns_records'
        assert first['tool'] == 'dnspython'
        assert first['tool_category'] == 'DNS / Réseau'
        assert rows[1]['tool'] == 'Shodan InternetDB'

    def test_field_mapping(self, client, auth_headers, full_recon):
        row = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                    headers=auth_headers))[0]
        assert row['target'] == 'example.com'
        assert row['indicator'] == 'Absence de DNSSEC'
        assert row['value'] == 'Aucun enregistrement DS trouvé'
        assert row['severity'] == 'HIGH'
        assert row['source_url'] == 'https://example.org/dnssec'
        assert row['collected_at'].endswith('Z')

    def test_confidence_left_empty_when_absent(self, client, auth_headers, full_recon):
        """Le schéma des findings ne porte pas `confidence` — jamais de valeur fabriquée."""
        rows = _parse_csv(client.get(f'/recon/{full_recon}/export.csv',
                                     headers=auth_headers))
        assert all(r['confidence'] == '' for r in rows)

    def test_formula_injection_is_neutralised(self, app, client, auth_headers):
        """
        Une valeur commençant par '=' ne doit pas rester exécutable à
        l'ouverture dans Excel (CWE-1236). Les findings proviennent de sorties
        d'outils et de texte généré par l'IA : le contenu n'est pas de confiance.
        """
        malicious = dict(ANALYSIS_RESULT)
        malicious['findings'] = [{
            'id': 'X-001',
            'severity': 'LOW',
            'title': '=cmd|\' /C calc\'!A0',
            'evidence': '+HYPERLINK("http://evil.tld")',
            'source_tool': 'dns_records',
        }]
        rid = _make_recon(app, email='inject@example.com',
                          scan_results=json.dumps(SCAN_RESULTS),
                          analysis_result=json.dumps(malicious))

        row = _parse_csv(client.get(f'/recon/{rid}/export.csv',
                                    headers=auth_headers))[0]
        assert row['indicator'].startswith("'=")
        assert row['value'].startswith("'+")

    def test_filename_is_sanitised(self, app, client, auth_headers):
        """
        Le nom de fichier reprend le domaine (donnée utilisateur) : aucun
        guillemet ni retour à la ligne ne doit pouvoir atteindre l'en-tête
        Content-Disposition.
        """
        rid = _make_recon(app, email='badname@example.com',
                          domain='evil".com\r\nX-Injected: 1')
        resp = client.get(f'/recon/{rid}/export.csv', headers=auth_headers)
        disposition = resp.headers['Content-Disposition']
        assert '\r' not in disposition and '\n' not in disposition
        assert disposition.count('"') == 2      # uniquement les délimiteurs
        assert 'X-Injected' not in resp.headers

    def test_header_only_without_analysis(self, app, client, auth_headers):
        rid = _make_recon(app, email='nocsv@example.com')
        resp = client.get(f'/recon/{rid}/export.csv', headers=auth_headers)
        assert resp.status_code == 200
        rows = _parse_csv(resp)
        assert rows == []
        assert resp.get_data(as_text=True).lstrip('\ufeff').startswith('finding_id,')
