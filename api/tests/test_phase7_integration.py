# tests/test_phase7_integration.py
"""
Intégration phase 7 : flux réel generate_report → graphe → différentiel (avant
scellement), lecture du différentiel d'un dossier scellé, ingestion d'un
rescan de surveillance avec alerte admin, export des hôtes vivants,
migrations idempotentes et droits du rôle applicatif.
"""
import importlib
import json
import sys
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, inspect, text

from database import db
from extensions import limiter
from models.entity_graph import Entity, Relation
from models.pass_recon_cache import PassReconCache
from models.recon import Recon
from models.scan_monitoring import ScanSnapshot, WatchedDomain
from tests.phase7_fixtures import DOMAIN, IP1, IP2, raw_scan
from utils.scan_diff import diff_for_recon

pytestmark = pytest.mark.integration

SERVICE = {'X-Service-Token': 'service-token-de-test-0123456789abcdefghij'}
PDF = b'%PDF-1.4 test'
ANALYSIS = {'security_score': 60, 'security_grade': 'C', 'risk_level': 'MEDIUM', 'findings': []}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    limiter.reset()
    monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', SERVICE['X-Service-Token'])
    monkeypatch.setenv('MONITORING_ALERT_EMAIL', 'admin-alerts@recon.example.test')
    yield
    limiter.reset()


def _recon(raw, email='ada@example.org'):
    recon = Recon(domain=DOMAIN, firstname='Ada', lastname='Lovelace', email=email, accord=True,
                  verification=True, status='running', scan_results=json.dumps(raw))
    recon.set_analysis_result(ANALYSIS)
    db.session.add(recon)
    db.session.commit()
    return recon.id


def _generate(client, recon_id):
    with patch('routes.report.generate_pdf', return_value=PDF), \
         patch('routes.report.send_results_ready_email') as mail:
        resp = client.post(f'/recon/{recon_id}/generate_report', json={}, headers=SERVICE)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['data'], mail


def _second_scan():
    raw = raw_scan()
    raw['all_subdomains']['data'].append('admin.example.com')
    raw['dns_records']['data']['A'] = [IP1, IP2]
    raw['shodan_internetdb']['data']['ips'][0]['vulns'].append('CVE-2023-44487')
    raw['dmarc_check']['data']['record'] = 'v=DMARC1; p=reject'
    return raw


def test_report_flow_builds_graph_and_diff_before_sealing(client, auth_headers, app):
    first_id = _recon(raw_scan())
    data, _ = _generate(client, first_id)
    assert data['results_sealed'] is True
    assert data['scan_diff']['has_previous'] is False

    # Graphe construit malgré le scellement (scan_results désormais effacé)
    assert db.session.get(Recon, first_id).scan_results is None
    assert Entity.query.filter_by(type='subdomain', value='api.example.com').count() == 1
    assert Relation.query.filter_by(root_domain=DOMAIN, recon_id=first_id).count() > 0

    second_id = _recon(_second_scan(), email='bob@example.org')
    data, _ = _generate(client, second_id)
    summary = data['scan_diff']
    assert summary['has_previous'] is True and summary['significant'] is True

    diff = diff_for_recon(second_id)
    assert diff['subdomains']['added'] == ['admin.example.com']
    assert diff['ips']['added'] == [IP2]
    assert diff['cves']['added'] == ['CVE-2023-44487']
    assert diff['email_security']['dmarc']['changed'] is True
    assert diff['previous_recon_id'] == first_id

    # Unicité (type, valeur) : l'entité vue deux fois reste une seule ligne
    assert Entity.query.filter_by(type='ip', value=IP1).count() == 1
    ent = Entity.query.filter_by(type='subdomain', value='admin.example.com').one()
    assert ent.first_seen == ent.last_seen

    # Lisible par l'admin même scellé
    resp = client.get(f'/recon/{second_id}/diff', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()['data']['diff']['cves']['added'] == ['CVE-2023-44487']
    assert client.get(f'/recon/{second_id}/report.pdf', headers=auth_headers).status_code == 403


def test_regenerating_report_does_not_duplicate_snapshot(client, app):
    recon_id = _recon(raw_scan())
    with patch('routes.report.generate_pdf', return_value=PDF):
        for _ in range(2):
            assert client.post(f'/recon/{recon_id}/generate_report', json={'send_email': False},
                               headers=SERVICE).status_code == 200
    assert ScanSnapshot.query.filter_by(recon_id=recon_id).count() == 1


def test_graph_failure_never_blocks_report(client, app):
    recon_id = _recon(raw_scan())
    with patch('utils.entity_graph.build_graph_from_raw', side_effect=RuntimeError('boom')):
        data, mail = _generate(client, recon_id)
    assert data['scan_diff'] is None and data['results_sealed'] is True
    assert mail.called


def test_summary_entities_and_live_hosts(client, auth_headers, app):
    _generate(client, _recon(raw_scan()))
    summary = client.get(f'/graph/summary?domain={DOMAIN}', headers=auth_headers).get_json()['data']
    assert summary['entities_by_type']['ip'] == 1
    assert summary['entities_by_type']['vulnerability'] == 1
    assert summary['snapshots_total'] == 1

    ents = client.get(f'/graph/entities?domain={DOMAIN}&type=port', headers=auth_headers).get_json()
    assert {e['value'] for e in ents['data']} == {f'{IP1}:80', f'{IP1}:443'}

    resp = client.get(f'/graph/live_hosts?domain={DOMAIN}', headers=auth_headers)
    body = resp.get_json()
    assert 'autorisation écrite' in body['notice']
    hosts = {h['host']: h for h in body['hosts']}
    assert hosts[DOMAIN]['ips'][0]['ip'] == IP1 and hosts[DOMAIN]['ips'][0]['ports'] == [80, 443]
    assert 'www.example.com' in hosts                  # vu par Shodan sur l'IP
    assert all(ip['ip'] != '10.0.0.5' for h in body['hosts'] for ip in h['ips'])

    snaps = client.get(f'/graph/snapshots?domain={DOMAIN}', headers=auth_headers).get_json()
    assert snaps['total'] == 1 and snaps['data'][0]['has_previous'] is False


def _cache(raw, updated_at):
    entry = PassReconCache.query.filter_by(domain=DOMAIN).first()
    if entry is None:
        entry = PassReconCache(domain=DOMAIN, tools_key='all', result_json='{}',
                               expires_at=datetime.utcnow() + timedelta(days=30))
        db.session.add(entry)
    entry.result_json = json.dumps(raw)
    entry.updated_at = updated_at
    db.session.commit()
    return entry


def test_monitoring_rescan_flow_alerts_admin_only(client, auth_headers, app):
    _generate(client, _recon(raw_scan()))
    watch = client.post('/monitoring', headers=auth_headers,
                        json={'domain': DOMAIN, 'interval_days': 3}).get_json()['data']
    assert client.patch(f"/monitoring/{watch['id']}", headers=auth_headers,
                        json={'enabled': True}).status_code == 200

    due = client.get('/monitoring/due', headers=SERVICE).get_json()['data']
    assert [d['domain'] for d in due] == [DOMAIN]

    # Pas encore de cache : 409 explicite
    assert client.post(f"/monitoring/{watch['id']}/ingest", headers=SERVICE, json={}).status_code == 409

    _cache(_second_scan(), datetime.utcnow())
    with patch('utils.email_sender.send_monitoring_alert', return_value=True) as alert:
        resp = client.post(f"/monitoring/{watch['id']}/ingest", headers=SERVICE, json={})
        body = resp.get_json()
        assert resp.status_code == 200 and body['already_ingested'] is False
        assert body['alert_sent'] is True and body['data']['significant'] is True
        assert alert.call_args.args[0] == 'admin-alerts@recon.example.test'   # admin, pas le demandeur
        assert alert.call_args.args[1] == DOMAIN

        # Même mise à jour du cache : idempotent, aucune nouvelle alerte
        again = client.post(f"/monitoring/{watch['id']}/ingest", headers=SERVICE, json={}).get_json()
        assert again['already_ingested'] is True and alert.call_count == 1

    snap = ScanSnapshot.query.filter_by(source='rescan').one()
    assert snap.recon_id is None and snap.cache_id is not None
    row = db.session.get(WatchedDomain, watch['id'])
    assert row.last_rescan_at and row.last_change_at and row.last_alert_at
    # Rescan fait : plus dû avant 3 jours
    assert client.get('/monitoring/due', headers=SERVICE).get_json()['data'] == []
    assert client.delete(f"/monitoring/{watch['id']}", headers=auth_headers).status_code == 200


def test_monitoring_alert_email_content(app, monkeypatch):
    from utils import email_sender
    from utils.scan_diff import diff_scans
    sent = {}

    class _SMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): pass
        def login(self, *a): pass
        def sendmail(self, sender, to, msg): sent.update(to=to, msg=msg)

    monkeypatch.setattr(email_sender.smtplib, 'SMTP', _SMTP)
    raw = _second_scan()
    raw['all_subdomains']['data'].append('x<script>.example.com')
    diff = diff_scans(raw_scan(), raw, domain=DOMAIN)
    assert email_sender.send_monitoring_alert('admin@recon.example.test', DOMAIN, diff) is True
    assert sent['to'] == 'admin@recon.example.test'
    assert '<script>' not in sent['msg']


def test_retention_purge_keeps_graph(app):
    from utils.retention import purge
    stale = Recon(domain=DOMAIN, firstname='X', lastname='Y', email='x@y.z', accord=True,
                  verification=False, created_at=datetime.utcnow() - timedelta(days=30))
    db.session.add(stale)
    db.session.commit()
    from utils.entity_graph import build_graph_from_raw
    build_graph_from_raw(DOMAIN, raw_scan(), scan_ref='cache:1:x')
    db.session.commit()
    assert purge()['unverified_deleted'] == 1
    assert Entity.query.count() > 0 and Relation.query.count() > 0


# ── Migrations ────────────────────────────────────────────────────────────────

def _import_migrate(monkeypatch):
    import dotenv
    # migrate.py charge api/.env avec override=True : neutralisé ici pour ne pas
    # écraser l'environnement de test.
    monkeypatch.setattr(dotenv, 'load_dotenv', lambda *a, **k: False)
    sys.modules.pop('migrate', None)
    return importlib.import_module('migrate')


def test_phase7_migrations_idempotent_and_match_models(monkeypatch, tmp_path):
    migrate = _import_migrate(monkeypatch)
    engine = create_engine(f'sqlite:///{tmp_path / "m.db"}')
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE recon (id INTEGER PRIMARY KEY)'))
    for _ in range(2):  # rejouées : aucune erreur
        with engine.begin() as conn:
            for _table, _col, sql in migrate.PHASE7_MIGRATIONS:
                conn.execute(text(sql))
    assert all(sql.lstrip().upper().startswith(('CREATE TABLE IF NOT EXISTS', 'CREATE INDEX IF NOT EXISTS'))
               for _t, _c, sql in migrate.PHASE7_MIGRATIONS)
    assert set(migrate.PHASE7_MIGRATIONS) <= set(migrate.MIGRATIONS)

    insp = inspect(engine)
    for model in (Entity, Relation, ScanSnapshot, WatchedDomain):
        created = {c['name'] for c in insp.get_columns(model.__tablename__)}
        assert created == {c.name for c in model.__table__.columns}, model.__tablename__
    # Les migrations de la phase 7 arrivent après la création de recon (clé étrangère)
    names = [t for t, _c, _s in migrate.MIGRATIONS]
    assert names.index('recon') < names.index('relation')


def test_app_role_granted_on_phase7_tables(monkeypatch):
    migrate = _import_migrate(monkeypatch)
    grants = ' '.join(migrate.ROLE_GRANTS['recon_app'][1])
    for table in ('entity', 'relation', 'scan_snapshot', 'watched_domain'):
        assert table in grants
    assert not any(t in ' '.join(migrate.ROLE_GRANTS['rag_writer'][1])
                   for t in ('entity', 'relation', 'scan_snapshot', 'watched_domain'))
