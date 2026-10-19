# tests/test_phase8_integration.py
"""
Tests d'intégration de la phase 8 (marqueur `integration`) : boucle agent
complète dans POST /pass_recon, avec LLM factice et outils de recon.py
simulés (réseau coupé). Vérifie aussi la désactivation propre.
"""
import json

import pytest

import routes.recon as recon
from tests.phase8_fixtures import PUBLIC_IP, SECOND_IP, ScriptedBackend, fake_resolve

pytestmark = pytest.mark.integration

TOOLS = ["crtsh", "ip_info", "dns_records", "shodan_internetdb", "subdomain_takeover"]


@pytest.fixture
def scan_env(monkeypatch):
    """Outils de la vague classique + outils pivots simulés ; enregistre les appels."""
    calls = []
    monkeypatch.setattr("utils.validators.resolve_domain_ips", fake_resolve)
    for var in ("GEMINI_API_KEY", "DEEPSEEK_API_KEY", "DEEPSEEK_CONFIRM_EXTERNAL_SHARING",
                "AGENT_OLLAMA_MODEL", "AGENT_BACKEND", "AGENT_RECON_ENABLED"):
        monkeypatch.delenv(var, raising=False)

    def crtsh(domain):
        calls.append(("crtsh", domain))
        if domain == "example.com":
            subs = ["admin.example.com", "www.example.com", "dev.example.com"]
        else:
            subs = [f"api.{domain}", "attacker.tld"]
        return {"status": "success", "data": {"subdomains": subs, "count": len(subs)},
                "raw_output": "[]"}

    def dns_records(domain):
        calls.append(("dns_records", domain))
        ip = PUBLIC_IP if domain == "example.com" else SECOND_IP
        return {"status": "success", "data": {"A": [ip], "AAAA": [], "CNAME": [], "MX": []},
                "raw_output": ""}

    def shodan(domain, ips=None):
        calls.append(("shodan_internetdb", tuple(ips or ())))
        ip = (ips or [PUBLIC_IP])[0]
        return {"status": "success", "data": {
            "ips": [{"ip": ip, "ports": [443], "vulns": ["CVE-2023-44487"],
                     "hostnames": ["www.example.com"]}],
            "ports": [443], "vulns": ["CVE-2023-44487"], "hostnames": ["www.example.com"]},
            "raw_output": ""}

    def reverse_ip(domain, ip=None):
        calls.append(("reverse_ip", ip))
        return {"status": "success", "data": {"ip": ip, "domains": ["shop.example.com"], "count": 1},
                "raw_output": ""}

    def asn_info(domain, ip=None):
        calls.append(("asn_info", ip))
        return {"status": "success", "data": {"ip_queried": ip or PUBLIC_IP, "asn": "AS15133",
                                              "asn_name": "EDGECAST", "prefix_count": 3},
                "raw_output": ""}

    def headers(subs):
        subs = list(subs)
        calls.append(("headers", tuple(sorted(subs))))
        return {"status": "success", "data": {s: {"status": "success", "scheme": "https",
                                                 "http_status": 200, "data": {"Server": "nginx"}}
                                             for s in subs}, "raw_output": ""}

    def takeover(all_subs, domain):
        calls.append(("subdomain_takeover", tuple(sorted(all_subs))))
        return {"status": "success", "data": {"vulnerable": [], "vulnerable_count": 0,
                                              "checked_count": len(all_subs)}, "raw_output": ""}

    monkeypatch.setattr(recon, "_crtsh_tool", crtsh)
    monkeypatch.setattr(recon, "_dns_records", dns_records)
    monkeypatch.setattr(recon, "_shodan_internetdb", shodan)
    monkeypatch.setattr(recon, "_reverse_ip", reverse_ip)
    monkeypatch.setattr(recon, "_asn_info", asn_info)
    monkeypatch.setattr(recon, "_http_headers_tool", headers)
    monkeypatch.setattr(recon, "_subdomain_takeover", takeover)
    monkeypatch.setattr(recon, "_ip_info", lambda d: {"status": "success", "data": {
        "ips": [{"ip": PUBLIC_IP, "org": "AS15133 Edgecast Inc", "country": "US"}], "count": 1},
        "raw_output": ""})
    return calls


def _post(client, auth_headers, **extra):
    body = {"domain": "example.com", "tools": TOOLS, "force_refresh": True}
    body.update(extra)
    return client.post("/pass_recon", json=body, headers=auth_headers)


def _use_backend(monkeypatch, backend):
    monkeypatch.setattr("utils.recon_agent.select_backend", lambda: (backend, ""))


class TestAgentInPassRecon:
    def test_full_loop(self, client, auth_headers, scan_env, monkeypatch):
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        # graphe (0) → shop. via reverse IP (1) → IP de shop. (2) → internetdb : profondeur 3
        monkeypatch.setenv("AGENT_MAX_DEPTH", "3")
        backend = ScriptedBackend([
            [("internetdb", {"ip": PUBLIC_IP, "reason": "IP exposée"}),
             ("reverse_ip", {"ip": PUBLIC_IP, "reason": "co-hébergement"}),
             ("asn_lookup", {"ip": PUBLIC_IP, "reason": "opérateur"})],
            [("crtsh_subdomains", {"hostname": "dev.example.com", "reason": "SAN de dev"}),
             ("takeover_check", {"hostname": "dev.example.com", "reason": "CNAME"})],
            [("http_headers", {"hostname": "api.dev.example.com", "reason": "nouveau nom"}),
             ("resolve_host", {"hostname": "shop.example.com", "reason": "vu en reverse IP"}),
             ("http_headers", {"hostname": "attacker.tld", "reason": "hors périmètre"})],
            [("internetdb", {"ip": SECOND_IP, "reason": "IP de shop"})],
            "Synthèse : 8 pivots utiles.",
        ])
        _use_backend(monkeypatch, backend)
        resp = _post(client, auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        # Le flux classique est intact
        for tool in TOOLS:
            assert data[tool]["status"] == "success"
        agent = data["agent_pivots"]
        assert agent["status"] == "success"
        journal = agent["data"]
        assert journal["stop_reason"] == "llm_finished"
        assert journal["backend"] == {"name": "fake", "model": "fake-8b"}
        assert journal["usage"]["pivots_executed"] == 8
        assert journal["usage"]["pivots_refused"] == 1
        refused = [d for d in journal["decisions"] if d["outcome"] == "refused"]
        assert refused[0]["arguments"] == {"hostname": "attacker.tld"}
        assert refused[0]["refusal"]["code"] == "out_of_scope"
        assert journal["final_message"] == "Synthèse : 8 pivots utiles."
        assert len(journal["results"]) == 8
        # Les fonctions de recon.py ont reçu les IP / noms validés
        assert ("reverse_ip", PUBLIC_IP) in scan_env
        assert ("asn_info", PUBLIC_IP) in scan_env
        assert ("shodan_internetdb", (SECOND_IP,)) in scan_env
        assert ("crtsh", "dev.example.com") in scan_env
        assert ("headers", ("api.dev.example.com",)) in scan_env
        assert ("subdomain_takeover", ("dev.example.com",)) in scan_env
        assert ("dns_records", "shop.example.com") in scan_env
        assert not any("attacker.tld" in json.dumps(c) for c in scan_env if c[0] == "headers")
        assert journal["scope"]["discovered_hosts"] >= 2
        assert journal["scope"]["discovered_ips"] == 1
        # Le LLM a reçu un résumé, pas le JSON brut
        user = backend.calls[0]["messages"][1]["content"]
        assert "counts" in user and "raw_output" not in user

    def test_results_cached_with_agent_pivots(self, client, auth_headers, scan_env, monkeypatch):
        from models.pass_recon_cache import PassReconCache
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        _use_backend(monkeypatch, ScriptedBackend([
            [("internetdb", {"ip": PUBLIC_IP, "reason": "r"})], "fin"]))
        assert _post(client, auth_headers).status_code == 200
        entry = PassReconCache.query.filter_by(domain="example.com").first()
        cached = json.loads(entry.result_json)
        assert cached["agent_pivots"]["data"]["usage"]["pivots_executed"] == 1

    def test_disabled_by_default(self, client, auth_headers, scan_env, monkeypatch):
        def must_not_run():
            pytest.fail("la boucle ne doit pas démarrer")
        monkeypatch.setattr("utils.recon_agent.select_backend", must_not_run)
        data = _post(client, auth_headers).get_json()["data"]
        assert "agent_pivots" not in data
        assert data["crtsh"]["status"] == "success"

    def test_body_can_only_disable(self, client, auth_headers, scan_env, monkeypatch):
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        monkeypatch.setattr("utils.recon_agent.select_backend",
                            lambda: pytest.fail("désactivée par le corps"))
        data = _post(client, auth_headers, agent_recon=False).get_json()["data"]
        assert "agent_pivots" not in data

    def test_skipped_without_capable_backend(self, client, auth_headers, scan_env, monkeypatch):
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        monkeypatch.setenv("AGENT_OLLAMA_MODEL", "qwen3:1.7b")   # trop petit
        monkeypatch.setenv("DEEPSEEK_API_KEY", "k")              # sans confirmation
        resp = _post(client, auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        agent = data["agent_pivots"]
        assert agent["status"] == "skipped"
        assert agent["data"]["stop_reason"] == "no_backend"
        assert "trop petit" in agent["error"]
        assert agent["data"]["decisions"] == []
        assert data["shodan_internetdb"]["status"] == "success"

    def test_llm_failure_does_not_break_scan(self, client, auth_headers, scan_env, monkeypatch):
        from utils.agent_llm import AgentLLMError

        class Down(ScriptedBackend):
            def chat(self, *a, **k):
                raise AgentLLMError("gemini HTTP 503")
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        _use_backend(monkeypatch, Down([]))
        resp = _post(client, auth_headers)
        assert resp.status_code == 200
        agent = resp.get_json()["data"]["agent_pivots"]
        assert agent["status"] == "error" and agent["data"]["stop_reason"] == "llm_error"

    def test_unexpected_agent_crash_contained(self, client, auth_headers, scan_env, monkeypatch):
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")

        def crash(*a, **k):
            raise RuntimeError("bug")
        monkeypatch.setattr("utils.recon_agent.run_agent_pivots", crash)
        resp = _post(client, auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["data"]["agent_pivots"]["status"] == "error"

    def test_requires_auth(self, client, scan_env, monkeypatch):
        monkeypatch.setenv("AGENT_RECON_ENABLED", "true")
        resp = client.post("/pass_recon", json={"domain": "example.com", "tools": TOOLS})
        assert resp.status_code == 401
