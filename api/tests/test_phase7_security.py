# tests/test_phase7_security.py
"""Sécurité phase 7 : contrôle d'accès, absence de PII, entrées malformées."""
import json

import pytest

from database import db
from extensions import limiter
from models.entity_graph import Entity
from models.recon import Recon
from models.scan_monitoring import ScanSnapshot, WatchedDomain
from tests.phase7_fixtures import DOMAIN, raw_scan
from utils.entity_graph import build_graph_from_raw, extract_graph
from utils.scan_diff import record_scan

pytestmark = pytest.mark.security

SERVICE = {'X-Service-Token': 'service-token-de-test-0123456789abcdefghij'}

ADMIN_ONLY = [
    ('GET', '/graph/summary'), ('GET', '/graph/entities'),
    ('GET', f'/graph/live_hosts?domain={DOMAIN}'), ('GET', '/graph/snapshots'),
    ('GET', '/graph/snapshots/1'), ('GET', '/recon/1/diff'),
    ('GET', '/monitoring'), ('POST', '/monitoring'), ('PATCH', '/monitoring/1'),
    ('DELETE', '/monitoring/1'),
]
SERVICE_OK = [('GET', '/monitoring/due'), ('POST', '/monitoring/1/ingest')]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    limiter.reset()
    monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', SERVICE['X-Service-Token'])
    yield
    limiter.reset()


def _call(client, method, path, headers=None):
    return client.open(path, method=method, headers=headers or {}, json={})


@pytest.mark.parametrize('method,path', ADMIN_ONLY + SERVICE_OK)
def test_refused_without_auth(client, app, method, path, bad_auth_headers):
    assert _call(client, method, path).status_code == 401
    assert _call(client, method, path, bad_auth_headers).status_code == 401
    assert _call(client, method, path, {'X-Service-Token': 'x' * 40}).status_code == 401


@pytest.mark.parametrize('method,path', ADMIN_ONLY)
def test_service_token_cannot_reach_admin_routes(client, app, method, path):
    assert _call(client, method, path, SERVICE).status_code == 401


def test_service_token_accepted_on_pipeline_routes(client, app):
    assert client.get('/monitoring/due', headers=SERVICE).status_code == 200
    # watch inexistant : 404 (et non 401) → l'authentification est passée
    assert client.post('/monitoring/999/ingest', headers=SERVICE, json={}).status_code == 404


def test_graph_contains_no_pii(app):
    recon = Recon(domain=DOMAIN, firstname='Ada', lastname='Lovelace', email='ada@lovelace.org',
                  accord=True, verification=True, requested_info='secret')
    db.session.add(recon)
    db.session.commit()
    raw = raw_scan()
    raw['tech_stack']['data']['server'] = 'contact admin@example.com'
    raw['ssl_info']['data']['subject']['organizationName'] = 'boss@example.com'
    build_graph_from_raw(DOMAIN, raw, scan_ref=f'recon:{recon.id}', recon_id=recon.id)
    record_scan(DOMAIN, raw, scan_ref=f'recon:{recon.id}', recon_id=recon.id)
    db.session.commit()

    dump = json.dumps([e.to_dict() for e in Entity.query.all()])
    dump += ScanSnapshot.query.first().snapshot_json + ScanSnapshot.query.first().diff_json
    for secret in ('@', 'Ada', 'Lovelace', 'Jean Dupont', 'secret', 'Los Angeles', '90001'):
        assert secret not in dump, secret


def test_analysis_content_never_read(app):
    raw = raw_scan(analysis_result={'findings': [{'title': 'SECRET-IA'}]},
                   final_report={'status': 'success', 'data': {'subdomains': ['ia.example.com']}})
    g = extract_graph(DOMAIN, raw)
    assert 'SECRET-IA' not in json.dumps([list(k) for k in g['entities']])
    assert ('subdomain', 'ia.example.com') not in g['entities']


def test_hostile_values_are_rejected(app):
    raw = raw_scan()
    raw['all_subdomains']['data'] = ['<script>.example.com', "x'; DROP TABLE entity;--.example.com",
                                     'a' * 300 + '.example.com', 'ok.example.com', None, 12, {'a': 1}]
    raw['dns_records']['data']['A'] = ['169.254.169.254', '127.0.0.1', '::1', 'not-an-ip']
    raw['shodan_internetdb']['data']['ips'][0]['ports'] = [-1, 0, 99999, 'abc', True]
    raw['shodan_internetdb']['data']['ips'][0]['vulns'] = ['CVE-<img>', 'rm -rf']
    g = extract_graph(DOMAIN, raw)
    subs = {v for t, v in g['entities'] if t == 'subdomain'}
    assert 'ok.example.com' in subs
    assert not any('<' in s or "'" in s or len(s) > 253 for s in subs)
    ips = {v for t, v in g['entities'] if t == 'ip'}
    assert not ips & {'169.254.169.254', '127.0.0.1', '::1'}
    ports = {v for t, v in g['entities'] if t == 'port'}
    assert ports == set()                                        # aucun port invalide retenu
    assert {v for t, v in g['entities'] if t == 'vulnerability'} == set()


@pytest.mark.parametrize('qs', ['domain=../../etc', 'domain=a%0d%0aX:1', 'domain=<x>',
                                'type=hacker', 'domain=example.com&format=xml'])
def test_malformed_query_params(client, auth_headers, app, qs):
    path = '/graph/live_hosts?' + qs if 'format' in qs else '/graph/entities?' + qs
    assert client.get(path, headers=auth_headers).status_code == 400


def test_live_hosts_requires_domain(client, auth_headers, app):
    assert client.get('/graph/live_hosts', headers=auth_headers).status_code == 400


@pytest.mark.parametrize('body', [None, [], {'domain': 12}, {'domain': 'bad domain'},
                                  {'domain': DOMAIN, 'interval_days': 0},
                                  {'domain': DOMAIN, 'interval_days': 'x'},
                                  {'domain': DOMAIN, 'enabled': 'yes'}])
def test_monitoring_malformed_body(client, auth_headers, app, body):
    db.session.add(Recon(domain=DOMAIN, firstname='A', lastname='B', email='a@b.c',
                         accord=True, verification=True))
    db.session.commit()
    resp = client.post('/monitoring', headers=auth_headers, json=body) if body is not None \
        else client.post('/monitoring', headers=auth_headers, data='pas du json',
                         content_type='application/json')
    assert resp.status_code == 400


def test_monitoring_requires_consented_recon(client, auth_headers, app):
    db.session.add(Recon(domain='noconsent.org', firstname='A', lastname='B', email='a@b.c',
                         accord=False, verification=True))
    db.session.commit()
    for domain in ('neverseen.org', 'noconsent.org'):
        assert client.post('/monitoring', headers=auth_headers,
                           json={'domain': domain}).status_code == 409
    assert WatchedDomain.query.count() == 0


def test_monitoring_disabled_by_default(client, auth_headers, app):
    db.session.add(Recon(domain=DOMAIN, firstname='A', lastname='B', email='a@b.c',
                         accord=True, verification=True))
    db.session.commit()
    data = client.post('/monitoring', headers=auth_headers, json={'domain': DOMAIN}).get_json()['data']
    assert data['enabled'] is False and data['is_due'] is False
    assert client.get('/monitoring/due', headers=SERVICE).get_json()['data'] == []
    # Ingestion refusée tant que la surveillance n'est pas activée
    assert client.post(f"/monitoring/{data['id']}/ingest", headers=SERVICE, json={}).status_code == 409


def test_live_hosts_csv_neutralizes_formulas(client, auth_headers, app):
    raw = raw_scan()
    build_graph_from_raw(DOMAIN, raw, scan_ref='t')
    db.session.commit()
    resp = client.get(f'/graph/live_hosts?domain={DOMAIN}&format=csv', headers=auth_headers)
    assert resp.status_code == 200
    body = resp.data.decode('utf-8-sig')
    assert body.startswith('# Export issu') and 'autorisation écrite' in body
    for line in body.splitlines()[3:]:
        assert not line.startswith(('=', '+', '-', '@'))
    assert 'attachment' in resp.headers['Content-Disposition']
