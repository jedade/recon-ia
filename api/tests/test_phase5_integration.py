# tests/test_phase5_integration.py
"""
Tests d'intégration de la phase 5 (marqueur `integration`) : les nouveaux outils
dans le flux réel POST /pass_recon, réseau simulé.

Vérifie l'intégration (clés présentes, meta de la phase 2 préservée, statut
skipped sans clé, dnsdumpster alimentant l'union all_subdomains, dns_mass
consommant ces sous-domaines).
"""
import pytest

import routes.recon as recon

pytestmark = pytest.mark.integration


def _post(client, auth_headers, tools, domain="example.com"):
    return client.post("/pass_recon", json={
        "domain": domain, "tools": tools, "force_refresh": True,
    }, headers=auth_headers)


class TestPhase5InScanFlow:
    def test_new_tools_present_with_meta(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(recon, "_site_ranking_tool", lambda d: {
            "status": "success", "data": {"rank": 1234, "hsts_preloaded": True},
            "raw_output": ""})
        data = _post(client, auth_headers, ["site_ranking"]).get_json()["data"]
        assert data["site_ranking"]["status"] == "success"
        assert data["site_ranking"]["meta"].get("tool")
        assert data["site_ranking"]["meta"].get("category") == "Web / HTTP"

    def test_tools_without_key_are_skipped_not_fatal(self, client, auth_headers, monkeypatch):
        # Aucune clé configurée → skipped propre, pas d'erreur 500
        for var in ("VIRUSTOTAL_API_KEY", "DNSDUMPSTER_API_KEY",
                    "GRAYHATWARFARE_API_KEY", "GITHUB_TOKEN"):
            monkeypatch.setenv(var, "")
        monkeypatch.setattr(recon, "_ip_info", lambda d: {
            "status": "success", "data": {"ips": [], "count": 0}, "raw_output": ""})
        resp = _post(client, auth_headers,
                     ["virustotal", "dnsdumpster", "grayhatwarfare", "github_dorks"])
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        for tool in ("virustotal", "dnsdumpster", "grayhatwarfare", "github_dorks"):
            assert data[tool]["status"] == "skipped"

    def test_dnsdumpster_feeds_all_subdomains(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(recon, "_dnsdumpster_tool", lambda d: {
            "status": "success",
            "data": {"subdomains": ["api.example.com", "vpn.example.com"], "count": 2},
            "raw_output": ""})
        data = _post(client, auth_headers, ["dnsdumpster"]).get_json()["data"]
        assert set(data["all_subdomains"]["data"]) == {"api.example.com", "vpn.example.com"}

    def test_dns_mass_consumes_discovered_subdomains(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(recon, "_dnsdumpster_tool", lambda d: {
            "status": "success",
            "data": {"subdomains": ["web.example.com"], "count": 1}, "raw_output": ""})
        captured = {}

        def fake_dns_mass(all_subs, domain):
            captured["subs"] = set(all_subs)
            return {"status": "success", "data": {"hosts": [], "count": 0}, "raw_output": ""}

        monkeypatch.setattr(recon, "_dns_mass_tool", fake_dns_mass)
        _post(client, auth_headers, ["dnsdumpster", "dns_mass"])
        assert "web.example.com" in captured["subs"]

    def test_failing_phase5_tool_does_not_break_scan(self, client, auth_headers, monkeypatch):
        def boom(d):
            raise RuntimeError("blocklists cassé")
        monkeypatch.setattr(recon, "_blocklists_tool", boom)
        monkeypatch.setattr(recon, "_site_ranking_tool", lambda d: {
            "status": "success", "data": {"rank": 1}, "raw_output": ""})
        data = _post(client, auth_headers, ["blocklists", "site_ranking"]).get_json()["data"]
        assert data["blocklists"]["status"] == "error"
        assert data["site_ranking"]["status"] == "success"

    def test_web_metadata_in_flow(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(recon, "_web_metadata_tool", lambda d: {
            "status": "success",
            "data": {"cookie_count": 1, "insecure_cookies": ["sid"],
                     "all_cookies_secure": False, "social_tags": {}, "linked_domains": []},
            "raw_output": ""})
        data = _post(client, auth_headers, ["web_metadata"]).get_json()["data"]
        assert data["web_metadata"]["data"]["insecure_cookies"] == ["sid"]
