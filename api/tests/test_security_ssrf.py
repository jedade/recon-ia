# tests/test_security_ssrf.py
"""
Garde anti-SSRF de la session HTTP partagée du scanner
(`routes.recon._SsrfGuardedSession`, plan d'action phase 0).

Scénarios d'attaque couverts :
- un sous-domaine découvert qui résout vers une adresse interne ;
- une redirection HTTP du domaine validé vers une adresse interne ;
- les adresses littérales sensibles (métadonnées cloud, loopback, services
  Docker internes).

Aucun test ne sort sur le réseau : la résolution DNS
(`utils.validators.resolve_domain_ips`) et le transport HTTP (adaptateur
`requests`) sont simulés.
"""
import io
import ipaddress
from unittest.mock import patch

import pytest
import requests
from requests.adapters import HTTPAdapter

import routes.recon as recon
from routes.recon import UnsafeTargetError, _build_http_session, _http_headers_tool

pytestmark = pytest.mark.security

PUBLIC_IP = "93.184.216.34"
INTERNAL_IP = "10.0.0.5"

# Résolution DNS simulée : nom → adresses
DNS = {
    "example.com": [PUBLIC_IP],
    "public.example.com": [PUBLIC_IP],
    "admin.example.com": [PUBLIC_IP],
    "evil.example.com": [INTERNAL_IP],
    "metadata.example.com": ["169.254.169.254"],
    "mixed.example.com": [PUBLIC_IP, "127.0.0.1"],
    "internal.attacker.tld": [INTERNAL_IP],
}


def fake_resolve(name):
    return [ipaddress.ip_address(a) for a in DNS.get(name, [])]


class RecordingAdapter(HTTPAdapter):
    """Transport HTTP simulé : enregistre chaque URL réellement envoyée."""

    def __init__(self, responses=None):
        super().__init__()
        self.responses = responses or {}
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append(request.url)
        host = requests.utils.urlparse(request.url).hostname
        status, headers = self.responses.get(host, (200, {"Server": "fake"}))
        resp = requests.Response()
        resp.status_code = status
        resp.headers.update(headers)
        resp.url = request.url
        resp.request = request
        resp._content = b""
        resp.raw = io.BytesIO(b"")
        return resp


@pytest.fixture
def guarded(monkeypatch):
    """Session du scanner avec DNS et transport simulés."""
    monkeypatch.setattr("utils.validators.resolve_domain_ips", fake_resolve)
    session = _build_http_session()
    adapter = RecordingAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session, adapter


class TestGuardBlocksInternalTargets:
    @pytest.mark.parametrize("url", [
        "http://169.254.169.254/latest/meta-data/",   # métadonnées cloud
        "http://127.0.0.1:6379/",                     # loopback
        "http://[::1]/",                              # loopback IPv6
        "http://10.1.2.3/",                           # réseau privé
        "http://redis:6379/",                         # service Docker interne
        "http://ollama:11434/api/tags",
        "http://postgres:5432/",
        "http://localhost/",
        "http://evil.example.com/",                   # nom public → IP interne
        "http://metadata.example.com/",
        "http://mixed.example.com/",                  # une seule IP interne suffit
    ])
    def test_internal_target_never_contacted(self, guarded, url):
        session, adapter = guarded
        with pytest.raises(UnsafeTargetError):
            session.get(url, timeout=1)
        assert adapter.sent == []

    def test_public_target_allowed(self, guarded):
        session, adapter = guarded
        resp = session.get("https://public.example.com/", timeout=1)
        assert resp.status_code == 200
        assert adapter.sent == ["https://public.example.com/"]

    def test_unsafe_error_is_a_requests_exception(self):
        # Les outils qui attrapent RequestException restent robustes.
        assert issubclass(UnsafeTargetError, requests.exceptions.RequestException)


class TestGuardOnRedirects:
    def test_redirect_to_internal_host_is_blocked(self, guarded):
        session, adapter = guarded
        adapter.responses["public.example.com"] = (
            302, {"Location": "http://internal.attacker.tld/admin"})
        with pytest.raises(UnsafeTargetError):
            session.get("http://public.example.com/", allow_redirects=True, timeout=1)
        # Le premier saut est parti, le second (interne) jamais
        assert adapter.sent == ["http://public.example.com/"]

    def test_redirect_to_metadata_ip_is_blocked(self, guarded):
        session, adapter = guarded
        adapter.responses["public.example.com"] = (
            301, {"Location": "http://169.254.169.254/latest/meta-data/"})
        with pytest.raises(UnsafeTargetError):
            session.head("http://public.example.com/", allow_redirects=True, timeout=1)
        assert len(adapter.sent) == 1

    def test_redirect_to_public_host_followed(self, guarded):
        session, adapter = guarded
        adapter.responses["example.com"] = (301, {"Location": "https://admin.example.com/"})
        resp = session.get("http://example.com/", allow_redirects=True, timeout=1)
        assert resp.status_code == 200
        assert adapter.sent == ["http://example.com/", "https://admin.example.com/"]


class TestGuardCache:
    def test_host_checked_once_within_ttl(self, guarded):
        session, _ = guarded
        with patch("routes.recon.is_safe_domain", return_value=(True, None)) as check:
            for _ in range(5):
                session.get("https://public.example.com/x", timeout=1)
        assert check.call_count == 1


class TestHeadersToolSsrf:
    def test_internal_subdomain_marked_blocked(self, guarded, monkeypatch):
        session, adapter = guarded
        monkeypatch.setattr(recon, "_http", session)
        out = _http_headers_tool({"evil.example.com", "public.example.com"})

        assert out["data"]["evil.example.com"]["status"] == "blocked"
        assert out["data"]["public.example.com"]["status"] == "success"
        assert not any("evil.example.com" in u for u in adapter.sent)


@pytest.mark.integration
class TestPassReconSsrf:
    """Bout en bout : POST /pass_recon avec un sous-domaine piégé."""

    def test_scan_never_reaches_internal_subdomain(
            self, client, auth_headers, guarded, monkeypatch):
        session, adapter = guarded
        monkeypatch.setattr(recon, "_http", session)
        monkeypatch.setattr(recon, "_crtsh_tool", lambda d: {
            "status": "success",
            "data": {"subdomains": ["evil.example.com", "admin.example.com"], "count": 2},
            "raw_output": "",
        })
        monkeypatch.setattr(recon._resolver, "resolve",
                            lambda *a, **k: (_ for _ in ()).throw(recon._dns_resolver.NXDOMAIN()))

        resp = client.post("/pass_recon", json={
            "domain": "example.com",
            "tools": ["crtsh", "headers", "subdomain_takeover"],
            "force_refresh": True,
        }, headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()["data"]
        headers = data["headers"]["data"]
        assert headers["evil.example.com"]["status"] == "blocked"
        assert headers["admin.example.com"]["status"] == "success"
        assert not any("evil.example.com" in u for u in adapter.sent)

    def test_domain_resolving_internally_is_rejected(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr("utils.validators.resolve_domain_ips", fake_resolve)
        resp = client.post("/pass_recon", json={
            "domain": "evil.example.com", "tools": ["headers"], "force_refresh": True,
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "refusé" in resp.get_json()["error"]
