# tests/test_phase3_integration.py
"""
Intégration phase 3 : la vraie route POST /analyze (et le chemin async
_run_bg_analysis) avec un backend LLM simulé (repli Ollama), KEV et RAG
simulés — vérifie que le rapport final porte les sévérités déterministes,
`severity_rule`, `confidence`, `observed_at`, `references`, sans CVE non
observée, avec un score calculé à partir des sévérités finales.
Aucun appel réseau.
"""
import json
import os
import re
from unittest.mock import MagicMock

import pytest

from database import db
from models.recon import Recon

pytestmark = pytest.mark.integration

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "phase3")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


CORPUS = _load("rag_corpus.json")["documents"]


def _lexical_search(vec, collections, k):
    q = set(vec)
    rows = []
    for d in CORPUS:
        if collections and d["collection"] not in collections:
            continue
        s = len(q & set(re.findall(r"[a-z0-9]{3,}", (d["content"] + " " + d["source"]).lower())))
        if s:
            rows.append((-s, d["source"], d))
    rows.sort(key=lambda t: (t[0], t[1]))
    return [{"source": d["source"], "content": d["content"], "collection": d["collection"]} for *_, d in rows[:k]]


@pytest.fixture
def offline_llm(monkeypatch):
    """Cascade réduite au repli Ollama, qui renvoie une sortie LLM de fixture."""
    import routes.analyze as an
    import utils.kev as kev_mod
    import utils.rag_retrieval as rr
    from utils import ollama_client as oc

    for name in ("_GEMINI_API_KEY", "_CEREBRAS_API_KEY", "_GROQ_API_KEY", "_OPENROUTER_API_KEY"):
        monkeypatch.setattr(an, name, "")
    monkeypatch.setattr(an, "_DEEPSEEK_ENABLED", False)
    monkeypatch.setattr(oc.OllamaClient, "is_available", lambda self: True)
    monkeypatch.setattr(oc.OllamaClient, "model_loaded", lambda self: True)

    kev_catalog = kev_mod._parse_catalog(_load("kev_catalog.json"))
    monkeypatch.setattr(kev_mod, "kev_entries",
                        lambda ids, allow_fetch=True: {c: kev_catalog[c] for c in ids if c in kev_catalog})
    monkeypatch.setattr(rr, "_embed_query", lambda q: sorted(set(re.findall(r"[a-z0-9]{3,}", q.lower()))))
    monkeypatch.setattr(rr, "_search", _lexical_search)
    monkeypatch.setattr(rr, "corpus_has_collections", lambda: True)

    seen = {}

    def use(llm_fixture):
        def fake_map_reduce(self, signals, tool_handler, map_rounds=3):
            seen["signals"] = signals
            return {"role": "assistant", "content": json.dumps(_load(llm_fixture))}, [], []
        monkeypatch.setattr(oc.OllamaClient, "map_reduce_agentic_chat", fake_map_reduce)
        return seen
    return use


def _post(client, auth_headers, scan):
    return client.post("/analyze", json={"recon_json": scan}, headers=auth_headers)


class TestAnalyzeRoute:
    def test_example_com_report_is_defensible(self, client, auth_headers, offline_llm):
        seen = offline_llm("llm_example_com.json")
        resp = _post(client, auth_headers, _load("scan_example_com.json"))
        assert resp.status_code == 200, resp.get_json()
        rep = resp.get_json()["data"]

        # Score déterministe : plus de 0/100 sur un domaine sain
        assert rep["security_score"] >= 80
        assert rep["risk_score"] == 100 - rep["security_score"] and rep["risk_score_llm"] == 100
        assert rep["risk_level"] == "MEDIUM"
        assert rep["findings_summary"]["critical"] == 0 and rep["findings_summary"]["high"] == 0

        by_title = {f["title"]: f for f in rep["findings"]}
        assert by_title["DNSBL propre et SPF correctement configuré"]["severity"] == "INFO"
        assert by_title["HSTS non configuré"]["severity_rule"] == "hsts_missing"
        assert "DNSSEC absent" not in by_title                    # contredit par la donnée
        assert not any("CVE-2023-12345" in json.dumps(f) for f in rep["findings"])   # B6

        for f in rep["findings"]:
            assert f["confidence"] in ("high", "medium", "low")
            assert f["observed_at"] == "2026-10-19T10:42:00Z"
            assert f["severity_rule"]
            assert all(set(r) == {"collection", "source"} for r in f["references"])
        assert rep["severity_check"]["contradicted_dropped"] == 1
        assert rep["severity_check"]["dropped_unverified_cve"] == 1
        assert rep["coverage_check"]["rag_filtered_by_collection"] is True
        assert rep["coverage_check"]["findings_with_rag_references"] >= 1

        # Contexte fourni au modèle : constats déterministes + RAG par constat
        sig = seen["signals"]
        assert any(c["rule"] == "hsts_missing" for c in sig["deterministic_findings"])
        assert sig["rag_context"] and all(r.get("topic") for r in sig["rag_context"])

    def test_vuln_target_kev_and_injection(self, client, auth_headers, offline_llm):
        seen = offline_llm("llm_vuln_target.json")
        rep = _post(client, auth_headers, _load("scan_vuln_target.json")).get_json()["data"]
        rules = {f["severity_rule"]: f for f in rep["findings"]}
        assert rules["cve_kev"]["severity"] == "CRITICAL"
        assert rules["port_database_exposed"]["severity"] == "HIGH"
        assert rules["dmarc_missing"]["severity"] == "HIGH"
        assert rules["subdomain_takeover"]["generated_by"] == "rule"
        assert rep["risk_level"] == "CRITICAL"
        assert rep["severity_check"]["kev_cves"] == ["CVE-2021-44228"]
        assert seen["signals"]["network"]["shodan_internetdb"]["kev_cves"] == ["CVE-2021-44228"]
        assert not any("CVE-2099-99999" in json.dumps(f) for f in rep["findings"])
        refs = {r["source"] for r in rules["cve_kev"]["references"]}
        assert "MITRE ATT&CK T1190" in refs
        # immediate_actions typées et bornées
        assert all(1 <= a["priority"] <= 3 for a in rep["immediate_actions"])

    def test_phase4_hook_applied_in_route(self, client, auth_headers, offline_llm, monkeypatch):
        import sys
        import types
        mod = types.ModuleType("utils.attack_enablement")

        def annotate_findings(findings, signals):
            for f in findings:
                f["attack_enabled"] = [{"id": "T1566", "name": "Phishing"}] if f.get("category") == "Email" else []
                f["mitigations"] = []
            return findings
        mod.annotate_findings = annotate_findings
        monkeypatch.setitem(sys.modules, "utils.attack_enablement", mod)
        offline_llm("llm_vuln_target.json")
        rep = _post(client, auth_headers, _load("scan_vuln_target.json")).get_json()["data"]
        email = [f for f in rep["findings"] if f["category"] == "Email"]
        assert email and all(f["attack_enabled"][0]["id"] == "T1566" for f in email)

    def test_rag_unavailable_does_not_break_analysis(self, client, auth_headers, offline_llm, monkeypatch):
        import utils.rag_retrieval as rr
        offline_llm("llm_example_com.json")
        monkeypatch.setattr(rr, "_embed_query", MagicMock(side_effect=OSError("ollama embeddings down")))
        resp = _post(client, auth_headers, _load("scan_example_com.json"))
        assert resp.status_code == 200
        rep = resp.get_json()["data"]
        assert rep["coverage_check"]["rag_snippets_available"] == 0
        assert rep["security_score"] >= 80


class TestAsyncPath:
    def test_background_analysis_persists_phase3_fields(self, app, offline_llm):
        import routes.analyze as an
        offline_llm("llm_vuln_target.json")
        scan = _load("scan_vuln_target.json")
        r = Recon(domain="vuln-target.test", firstname="A", lastname="B", email="a@b.test", accord=True,
                  status="running")
        db.session.add(r)
        db.session.commit()
        an._bg_running[r.id] = True
        an._run_bg_analysis(app, r.id, scan, None, 2, 1)
        db.session.expire_all()
        rec = db.session.get(Recon, r.id)
        rep = json.loads(rec.analysis_result)
        assert rep["_backend"] == "ollama"
        assert any(f["severity_rule"] == "cve_kev" and f["severity"] == "CRITICAL" for f in rep["findings"])
        assert all(f.get("observed_at") == "2026-10-18T08:00:00Z" for f in rep["findings"])
        assert rec.security_score == rep["security_score"]
        assert r.id not in an._bg_running


class TestMeasurementScript:
    def test_before_after_offline(self):
        import tools.measure_phase3 as m
        corpus = m.LexicalCorpus(CORPUS)
        for _, scan_f, llm_f in m.CASES:
            scan, llm = _load(scan_f), _load(llm_f)
            before = m._summary(m.run_before(scan, llm, corpus))
            after = m._summary(m.run_after(scan, llm, corpus))
            assert before["unverified_cves_left"] and not after["unverified_cves_left"]
            assert after["grounding_verified_pct"] >= before["grounding_verified_pct"]
            assert after["rag_queries"] > before["rag_queries"]
            assert after["findings_with_rag_refs"] > 0
        ex_before = m._summary(m.run_before(_load("scan_example_com.json"), _load("llm_example_com.json"), corpus))
        ex_after = m._summary(m.run_after(_load("scan_example_com.json"), _load("llm_example_com.json"), corpus))
        assert ex_before["security_score"] == 0 and ex_after["security_score"] >= 80
