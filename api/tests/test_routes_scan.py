# tests/test_routes_scan.py
import pytest
from unittest.mock import patch, MagicMock


class TestDnsInfo:
    def test_missing_domain_returns_400(self, client, auth_headers):
        response = client.post('/dns_info', json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_invalid_domain_returns_400(self, client, auth_headers):
        response = client.post('/dns_info', json={'domain': '../etc/passwd'}, headers=auth_headers)
        assert response.status_code == 400

    def test_injection_domain_returns_400(self, client, auth_headers):
        response = client.post('/dns_info', json={'domain': '`whoami`.com'}, headers=auth_headers)
        assert response.status_code == 400
