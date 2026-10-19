# tests/test_cache_admin.py
"""Consultation admin du cache des scans bruts (routes/cache.py)."""
import json
from datetime import datetime, timedelta

import pytest

from database import db
from models.pass_recon_cache import PassReconCache

SERVICE = {'X-Service-Token': 'service-token-de-test-0123456789abcdefghij'}


def _entry(domain, valid=True, result=None):
    entry = PassReconCache(
        domain=domain, tools_key='dns_records,whois',
        result_json=json.dumps(result if result is not None else {'whois': {'data': {'registrar': 'OVH'}}}),
        scan_duration_s=12.5, subdomain_count=3,
        expires_at=datetime.utcnow() + (timedelta(days=5) if valid else -timedelta(days=1)),
    )
    db.session.add(entry)
    db.session.commit()
    return entry


class TestListing:
    def test_list_with_filters(self, client, auth_headers, app):
        _entry('alpha.example')
        _entry('beta.example', valid=False)
        _entry('gamma.test')

        data = client.get('/cache', headers=auth_headers).get_json()
        assert data['total'] == 3
        assert 'result' not in data['data'][0]  # liste = métadonnées seulement

        only_valid = client.get('/cache?valid=true', headers=auth_headers).get_json()
        assert sorted(e['domain'] for e in only_valid['data']) == ['alpha.example', 'gamma.test']
        expired = client.get('/cache?valid=false', headers=auth_headers).get_json()
        assert [e['domain'] for e in expired['data']] == ['beta.example']
        assert expired['data'][0]['is_valid'] is False

        by_domain = client.get('/cache?domain=EXAMPLE', headers=auth_headers).get_json()
        assert by_domain['total'] == 2

    def test_invalid_filter(self, client, auth_headers, app):
        assert client.get('/cache?valid=peut-etre', headers=auth_headers).status_code == 400

    def test_pagination_bounded(self, client, auth_headers, app):
        for i in range(3):
            _entry(f'd{i}.example')
        data = client.get('/cache?per_page=500&page=1', headers=auth_headers).get_json()
        assert data['per_page'] == 100


class TestDetail:
    def test_full_raw_result(self, client, auth_headers, app):
        entry = _entry('alpha.example')
        data = client.get(f'/cache/{entry.id}', headers=auth_headers).get_json()['data']
        assert data['result']['whois']['data']['registrar'] == 'OVH'
        assert data['corrupted'] is False

    def test_expired_entry_still_readable(self, client, auth_headers, app):
        entry = _entry('old.example', valid=False)
        assert client.get(f'/cache/{entry.id}', headers=auth_headers).status_code == 200

    def test_corrupted_entry_reported(self, client, auth_headers, app):
        entry = _entry('bad.example')
        entry.result_json = '{pas du json'
        db.session.commit()
        data = client.get(f'/cache/{entry.id}', headers=auth_headers).get_json()['data']
        assert data['corrupted'] is True and data['result'] is None

    def test_export_download(self, client, auth_headers, app):
        entry = _entry('alpha.example')
        resp = client.get(f'/cache/{entry.id}/export.json', headers=auth_headers)
        assert resp.status_code == 200
        assert 'attachment' in resp.headers['Content-Disposition']
        assert json.loads(resp.data)['scan_results']['whois']['data']['registrar'] == 'OVH'

    def test_unknown_entry(self, client, auth_headers, app):
        assert client.get('/cache/999', headers=auth_headers).status_code == 404


@pytest.mark.security
class TestAccess:
    @pytest.mark.parametrize('path', ['/cache', '/cache/1', '/cache/1/export.json'])
    def test_admin_only(self, client, app, monkeypatch, path):
        monkeypatch.setenv('PIPELINE_SERVICE_TOKEN', SERVICE['X-Service-Token'])
        _entry('alpha.example')
        assert client.get(path).status_code == 401
        assert client.get(path, headers=SERVICE).status_code == 401

    def test_filename_sanitized(self, client, auth_headers, app):
        entry = _entry('evil"\r\nX-Injected: 1.example')
        resp = client.get(f'/cache/{entry.id}/export.json', headers=auth_headers)
        assert 'X-Injected' not in resp.headers
        assert '\r' not in resp.headers['Content-Disposition']
