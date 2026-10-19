# tests/test_phase3_unit.py
"""
Tests unitaires de la phase 3 (fiabilité de l'analyse) : KEV, sévérité
déterministe (B5), validation des CVE (B6), RAG par constat (B7),
`confidence` / `observed_at`, score déterministe, point d'accroche phase 4.
Aucun appel réseau (le conteneur de test tourne avec --network none).
"""
import json
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "phase3")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def _tool(data, status="success", raw="", category="Test"):
    return {"status": status, "meta": {"tool": "T", "category": category}, "data": data, "raw_output": raw}


@pytest.fixture
def registry():
    from routes.recon import TOOLS_REGISTRY
    return TOOLS_REGISTRY


# ══════════════════════════════════════════════════════════════════════════════
#  CISA KEV
# ══════════════════════════════════════════════════════════════════════════════

class _Resp:
    def __init__(self, payload=None, status=200, raw=None):
        self.status_code = status
        self._raw = raw if raw is not None else json.dumps(payload).encode()

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._raw), chunk_size):
            yield self._raw[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def kev(tmp_path, monkeypatch):
    import utils.kev as kev_mod
    kev_mod._reset_for_tests()
    monkeypatch.setattr(kev_mod, "_CACHE_PATH", str(tmp_path / "kev.json"))
    monkeypatch.setattr(kev_mod, "_ENABLED", True)
    yield kev_mod
    kev_mod._reset_for_tests()


class TestKev:
    def test_parse_keeps_only_valid_ids(self, kev):
        cat = kev._parse_catalog(_load("kev_catalog.json"))
        assert set(cat) == {"CVE-2021-44228", "CVE-2014-0160"}
        assert cat["CVE-2021-44228"]["ransomware"] == "Known"

    def test_parse_rejects_bad_payload(self, kev):
        assert kev._parse_catalog([]) is None
        assert kev._parse_catalog({"vulnerabilities": "x"}) is None

    def test_download_then_cached_on_disk_and_memory(self, kev, monkeypatch, tmp_path):
        get = MagicMock(return_value=_Resp(_load("kev_catalog.json")))
        monkeypatch.setattr(kev.requests, "get", get)
        assert kev.kev_entries(["CVE-2021-44228", "CVE-2000-0001"]) == {
            "CVE-2021-44228": kev._mem["cves"]["CVE-2021-44228"]}
        assert get.call_count == 1
        # Deuxième appel : cache mémoire, aucun téléchargement.
        kev.kev_entries(["CVE-2021-44228"])
        assert get.call_count == 1
        # Nouveau processus (mémoire vide) : relu depuis le disque.
        kev._reset_for_tests()
        assert "CVE-2021-44228" in kev.kev_entries(["CVE-2021-44228"])
        assert get.call_count == 1
        assert json.loads((tmp_path / "kev.json").read_text())["cves"]

    def test_refresh_at_most_once_per_period(self, kev, monkeypatch):
        get = MagicMock(return_value=_Resp(_load("kev_catalog.json")))
        monkeypatch.setattr(kev.requests, "get", get)
        kev.refresh()
        kev.refresh()
        assert get.call_count == 1
        # Cache périmé → nouveau téléchargement.
        kev._mem["fetched_at"] -= kev._REFRESH_S + 1
        with open(kev._CACHE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        data["fetched_at_ts"] -= kev._REFRESH_S + 1
        with open(kev._CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        kev.refresh()
        assert get.call_count == 2

    def test_network_failure_is_not_blocking(self, kev, monkeypatch, caplog):
        monkeypatch.setattr(kev.requests, "get", MagicMock(side_effect=OSError("réseau coupé")))
        assert kev.kev_entries(["CVE-2021-44228"]) == {}
        assert "KEV" in caplog.text
        # Après un échec, pas de nouvelle tentative avant KEV_RETRY_MINUTES.
        get = MagicMock(return_value=_Resp(_load("kev_catalog.json")))
        monkeypatch.setattr(kev.requests, "get", get)
        kev.kev_entries(["CVE-2021-44228"])
        assert get.call_count == 0

    def test_http_error_keeps_stale_cache(self, kev, monkeypatch):
        monkeypatch.setattr(kev.requests, "get", MagicMock(return_value=_Resp(_load("kev_catalog.json"))))
        kev.refresh()
        kev._reset_for_tests()
        with open(kev._CACHE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        data["fetched_at_ts"] = 0
        with open(kev._CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        monkeypatch.setattr(kev.requests, "get", MagicMock(return_value=_Resp({}, status=503)))
        assert "CVE-2021-44228" in kev.kev_entries(["CVE-2021-44228"])

    def test_disabled(self, kev, monkeypatch):
        monkeypatch.setattr(kev, "_ENABLED", False)
        get = MagicMock()
        monkeypatch.setattr(kev.requests, "get", get)
        assert kev.kev_entries(["CVE-2021-44228"]) == {}
        get.assert_not_called()

    def test_status_without_network(self, kev):
        assert kev.status()["loaded"] is False

    def test_watchdog_refresh_never_raises(self, monkeypatch):
        import utils.stale_scan_watchdog as wd
        import utils.kev as kev_mod
        monkeypatch.setattr(kev_mod, "refresh", MagicMock(side_effect=RuntimeError("boom")))
        wd._run_kev_refresh()   # ne lève pas


# ══════════════════════════════════════════════════════════════════════════════
#  B6 + validation du sanitizer
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizer:
    def test_unverified_cve_only_basis_drops_finding(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        stats = {}
        out = sanitize_findings(
            [{"title": "Serveur vulnérable à CVE-2023-12345", "evidence": "CVE-2023-12345",
              "source_tool": "shodan_internetdb"}], registry, observed_cves=set(), stats=stats)
        assert out == [] and stats["dropped_unverified_cve"] == 1
        assert stats["cves_removed"] == ["CVE-2023-12345"]

    def test_unverified_cve_stripped_when_finding_has_other_basis(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        out = sanitize_findings([{
            "title": "Apache 2.4.49 obsolète", "evidence": "Server: Apache/2.4.49 (Ubuntu) CVE-2099-0001",
            "description": "Version vulnérable (CVE-2099-0001, CVE-2021-41773).",
            "recommendation": "Mettre à jour (CVE-2099-0001).", "source_tool": "tech_stack",
            "references": ["CVE-2099-0001", "CVE-2021-41773", "CWE-22"],
            "web_sources": ["https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "https://httpd.apache.org/security/"],
        }], registry, observed_cves={"CVE-2021-41773"})
        f = out[0]
        blob = json.dumps(f)
        assert "CVE-2099-0001" not in blob
        assert "CVE-2021-41773" in f["description"]
        assert {"collection": "llm", "source": "CVE-2021-41773"} in f["references"]
        assert f["web_sources"] == ["https://httpd.apache.org/security/"]

    def test_observed_cve_kept(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        out = sanitize_findings([{"title": "Log4Shell CVE-2021-44228", "evidence": "vulns: CVE-2021-44228",
                                  "source_tool": "shodan_internetdb"}], registry,
                                observed_cves={"CVE-2021-44228"})
        assert out and "CVE-2021-44228" in out[0]["title"]

    def test_references_become_objects_and_are_validated(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        out = sanitize_findings([{"title": "x", "evidence": "y", "references": [
            "RFC 7489", "CWE-79", "T1566", "OWASP A05:2021", "CWE-XXX", "RFC XXXX",
            "n'importe quoi", 42, {"collection": "normes", "source": "ANSSI messagerie"}]}], registry)
        sources = [r["source"] for r in out[0]["references"]]
        assert sources == ["RFC 7489", "CWE-79", "T1566", "OWASP A05:2021", "ANSSI messagerie"]
        assert all(r["collection"] == "llm" for r in out[0]["references"])

    def test_severity_and_confidence_normalized(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        out = sanitize_findings([
            {"title": "a", "severity": "Critique", "confidence": "Élevée"},
            {"title": "b", "severity": "moyen", "confidence": "bof"},
            {"title": "c", "severity": "???"},
        ], registry)
        assert [f["severity"] for f in out] == ["CRITICAL", "MEDIUM", "INFO"]
        assert out[0]["_llm_confidence"] == "high" and "_llm_confidence" not in out[1]

    def test_observed_at_set_by_server(self, registry):
        from utils.finding_sanitizer import sanitize_findings, to_iso_utc
        iso = to_iso_utc("2026-10-19T10:42:00")
        assert iso == "2026-10-19T10:42:00Z"
        assert to_iso_utc("2026-10-19T12:42:00+02:00") == "2026-10-19T10:42:00Z"
        assert to_iso_utc("pas une date") is None
        out = sanitize_findings([{"title": "a", "observed_at": "1999-01-01T00:00:00Z"}], registry, observed_at=iso)
        assert out[0]["observed_at"] == iso

    def test_category_ids_and_tool_resolution(self, registry):
        from utils.finding_sanitizer import sanitize_findings
        out = sanitize_findings([
            {"id": "DNS-001", "title": "a", "category": "DNS|SSL|Email", "source_tool": "dnsbl_analysis"},
            {"id": "DNS-001", "title": "b", "category": "Email"},
        ], registry)
        assert out[0]["source_tool"] == "dnsbl_check" and out[0]["category"] == "Reputation"
        assert out[0]["id"] != out[1]["id"]

    def test_strengths_deduplicated(self):
        from utils.finding_sanitizer import sanitize_strengths
        assert sanitize_strengths(["a", "a", 3, None, "b"]) == ["a", "b"]
        assert sanitize_strengths("pas une liste") == []


# ══════════════════════════════════════════════════════════════════════════════
#  B5 — sévérité déterministe
# ══════════════════════════════════════════════════════════════════════════════

def _apply(findings, scan, kev=None):
    from utils.severity_rules import apply_severity_rules
    return apply_severity_rules(findings, scan, kev or {}, "2026-10-19T10:42:00Z")


class TestSeverityRules:
    def test_positive_finding_never_high(self):
        scan = _load("scan_example_com.json")
        out, s = _apply([{"title": "DNSBL propre et SPF correctement configuré", "severity": "CRITICAL",
                          "evidence": "clean"}], scan)
        assert out[0]["severity"] == "INFO" and out[0]["severity_rule"] == "positive_observation"
        assert out[0]["severity_llm"] == "CRITICAL"

    def test_rule_overrides_llm_severity(self):
        scan = _load("scan_example_com.json")
        out, _ = _apply([{"title": "HSTS non configuré", "severity": "CRITICAL"}], scan)
        assert out[0]["severity"] == "MEDIUM" and out[0]["severity_rule"] == "hsts_missing"

    def test_contradicted_finding_dropped(self):
        scan = _load("scan_example_com.json")      # DNSSEC actif
        out, s = _apply([{"title": "DNSSEC absent", "severity": "HIGH"}], scan)
        assert out == [] and s["contradicted_dropped"] == 1
        assert s["dropped"][0]["rule"] == "dnssec_missing"

    def test_contrast_wording_kept_as_info(self):
        scan = _load("scan_example_com.json")
        out, s = _apply([{"title": "Certificat", "evidence": "DNSSEC absent mais zone partielle",
                          "severity": "HIGH"}], scan)
        assert out[0]["severity"] == "INFO" and out[0]["severity_rule"] == "contradicted_by_data"

    def test_kev_cve_is_critical(self):
        scan = _load("scan_vuln_target.json")
        kev = {"CVE-2021-44228": {}}
        out, s = _apply([{"title": "Log4j CVE-2021-44228", "severity": "LOW",
                          "evidence": "vulns: CVE-2021-44228"}], scan, kev)
        assert out[0]["severity"] == "CRITICAL" and out[0]["severity_rule"] == "cve_kev"
        assert s["kev_cves"] == ["CVE-2021-44228"]

    def test_cve_without_kev_uses_epss_then_cvss(self):
        from utils.severity_rules import classify_cve
        assert classify_cve({"id": "CVE-1", "epss": 0.5, "cvss": 3.0}, {}) == "cve_epss_high"
        assert classify_cve({"id": "CVE-1", "epss": 0.001, "cvss": 9.8}, {}) == "cve_cvss_critical"
        assert classify_cve({"id": "CVE-1", "epss": None, "cvss": 7.5}, {}) == "cve_cvss_high"
        assert classify_cve({"id": "CVE-1", "epss": None, "cvss": None}, {}) == "cve_cvss_low"
        assert classify_cve({"id": "CVE-1", "epss": 0.0}, {"CVE-1": {}}) == "cve_kev"

    def test_cvss_parsing_variants(self):
        from utils.severity_rules import _num
        assert _num("9.8") == 9.8 and _num({"baseScore": 7.1}) == 7.1
        assert _num(True) is None and _num("abc") is None

    def test_database_port_is_high(self):
        scan = _load("scan_vuln_target.json")
        out, _ = _apply([{"title": "Port MySQL 3306 exposé", "severity": "LOW"}], scan)
        assert out[0]["severity"] == "HIGH" and out[0]["severity_rule"] == "port_database_exposed"

    def test_dmarc_and_spf_rules(self):
        scan = _load("scan_vuln_target.json")
        out, _ = _apply([{"title": "DMARC absent", "severity": "LOW"},
                         {"title": "SPF en softfail (~all)", "severity": "HIGH"}], scan)
        assert [(f["severity"], f["severity_rule"]) for f in out[:2]] == [
            ("HIGH", "dmarc_missing"), ("LOW", "spf_softfail")]

    def test_dmarc_p_none(self):
        scan = {"dmarc_check": _tool({"present": True, "policy": "none"})}
        out, _ = _apply([{"title": "Politique DMARC p=none", "severity": "CRITICAL"}], scan)
        assert out[0]["severity"] == "MEDIUM" and out[0]["severity_rule"] == "dmarc_p_none"

    def test_cert_expired_and_expiring(self):
        expired = {"ssl_info": _tool({"expired": True, "days_until_expiry": -3})}
        out, _ = _apply([{"title": "Certificat TLS expiré", "severity": "LOW"}], expired)
        assert out[0]["severity"] == "HIGH"
        expiring = _load("scan_vuln_target.json")
        out, _ = _apply([{"title": "Certificat expirant dans 9 jours", "severity": "LOW"}], expiring)
        assert out[0]["severity_rule"] == "cert_expiring" and out[0]["severity"] == "MEDIUM"

    def test_unknown_data_caps_at_medium(self):
        out, _ = _apply([{"title": "HSTS absent", "severity": "CRITICAL"}], {})
        assert out[0]["severity"] == "MEDIUM" and out[0]["severity_rule"] == "unverified"

    def test_unmatched_llm_finding_capped(self):
        out, s = _apply([{"title": "Dette technique générale", "severity": "CRITICAL"},
                         {"title": "Observation divers", "severity": "LOW"}], {})
        assert (out[0]["severity"], out[0]["severity_rule"]) == ("MEDIUM", "llm_capped")
        assert (out[1]["severity"], out[1]["severity_rule"]) == ("LOW", "llm_proposed")

    def test_missing_high_constat_injected(self):
        scan = _load("scan_vuln_target.json")
        out, s = _apply([], scan, {"CVE-2021-44228": {}})
        rules = {f["severity_rule"] for f in out}
        assert {"subdomain_takeover", "cve_kev", "dmarc_missing", "port_database_exposed"} <= rules
        assert all(f["generated_by"] == "rule" for f in out)
        # MEDIUM/LOW non injectés (seuil HIGH par défaut)
        assert "spf_softfail" not in rules and "dnssec_missing" not in rules

    def test_duplicate_rule_findings_merged(self):
        scan = _load("scan_example_com.json")
        out, s = _apply([{"id": "A", "title": "HSTS absent", "source_tool": "security_headers"},
                         {"id": "B", "title": "Strict-Transport-Security manquant", "source_tool": "http_observatory"}],
                        scan)
        assert len(out) == 1 and "http_observatory" in out[0]["source_tools"]
        assert s["duplicates_dropped"] == 1

    def test_subdomain_header_missing_counts(self):
        scan = {"security_headers": _tool({"headers": {"strict-transport-security": {"present": True}}}),
                "headers": _tool({"mail.x.test": {"status": "success", "data": {"Server": "nginx"}}})}
        from utils.severity_rules import detect_observations
        obs = detect_observations(scan)
        assert obs["hsts_missing"]["state"] == "observed"
        assert "mail.x.test" in obs["hsts_missing"]["subjects"]

    def test_finalize_confidence(self):
        from utils.severity_rules import finalize_confidence
        fs = [{"_conf": "high", "grounding": {"status": "verified"}},
              {"_conf": "high", "grounding": {"status": "evidence_not_found"}},
              {"grounding": {"status": "verified"}},
              {},
              {"_conf": "high", "grounding": {"status": "verified"}, "_llm_confidence": "low"},
              {"_conf": "medium", "generated_by": "rule"}]
        finalize_confidence(fs)
        assert [f["confidence"] for f in fs] == ["high", "medium", "medium", "low", "low", "medium"]
        assert all("_conf" not in f and "_llm_confidence" not in f for f in fs)

    def test_risk_level_from_findings(self):
        from utils.severity_rules import risk_level_from_findings
        assert risk_level_from_findings([]) == "LOW"
        assert risk_level_from_findings([{"severity": "INFO"}, {"severity": "HIGH"}]) == "HIGH"

    def test_rag_topics_sorted_by_severity(self):
        from utils.severity_rules import detect_observations, rag_topics
        topics = rag_topics(detect_observations(_load("scan_vuln_target.json"), {"CVE-2021-44228": {}}))
        assert topics[0]["id"] == "cve_kev"
        assert all(set(t) == {"id", "query", "category"} for t in topics)

    def test_score_is_deterministic_and_positive_does_not_hurt(self):
        from utils.analysis_merger import compute_security_score
        scan = _load("scan_example_com.json")
        out, _ = _apply(_load("llm_example_com.json")["findings"], scan)
        s1 = compute_security_score({"findings": out, "strengths": []})["security_score"]
        s2 = compute_security_score({"findings": out, "strengths": []})["security_score"]
        assert s1 == s2 and s1 >= 80


# ══════════════════════════════════════════════════════════════════════════════
#  B7 — RAG par constat, filtré par collection
# ══════════════════════════════════════════════════════════════════════════════

def _fake_search(corpus):
    calls = []

    def search(vec, collections, k):
        calls.append((collections, k))
        rows = [d for d in corpus if not collections or d["collection"] in collections]
        return [dict(r) for r in rows[:k]]
    return search, calls


CORPUS = [
    {"source": "RFC 7489", "content": "dmarc", "collection": "normes"},
    {"source": "Expl DMARC", "content": "pourquoi dmarc", "collection": "explications"},
    {"source": "T1566", "content": "phishing", "collection": "attack"},
    {"source": "KEV", "content": "exploited", "collection": "menaces"},
]


class TestRag:
    def test_one_query_two_snippets_category_plus_attack(self):
        from utils.rag_retrieval import TopicRetriever
        search, calls = _fake_search(CORPUS)
        r = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=True)
        rows = r.retrieve("DMARC absent", "Email")
        assert [x["collection"] for x in rows] == ["normes", "attack"]
        assert calls[0][0] == ("normes", "explications") and calls[1][0] == ("attack",)
        assert r.queries == 1

    def test_fallback_without_collections(self):
        from utils.rag_retrieval import TopicRetriever
        search, calls = _fake_search(CORPUS)
        r = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=False)
        rows = r.retrieve("DMARC absent", "Email")
        assert calls == [(None, 2)] and len(rows) == 2 and r.filtered is False

    def test_fill_when_attack_empty(self):
        from utils.rag_retrieval import TopicRetriever
        corpus = [d for d in CORPUS if d["collection"] != "attack"]
        search, _ = _fake_search(corpus)
        rows = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=True) \
            .retrieve("DMARC", "Email")
        assert len(rows) == 2

    def test_embedding_failure_returns_empty(self):
        from utils.rag_retrieval import TopicRetriever

        def boom(q):
            raise OSError("ollama absent")
        assert TopicRetriever(embed_fn=boom, search_fn=lambda *a: [1], has_collections=True).retrieve("x", "Web") == []

    def test_build_context_one_query_per_topic_dedup(self):
        from utils.rag_retrieval import TopicRetriever, build_rag_context
        search, _ = _fake_search(CORPUS)
        r = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=True)
        ctx, stats = build_rag_context([{"id": "dmarc_missing", "query": "a", "category": "Email"},
                                        {"id": "spf_missing", "query": "b", "category": "Email"}], r)
        assert stats["queries"] == 2 and stats["filtered_by_collection"] is True
        assert ctx[0]["topic"] == "dmarc_missing" and ctx[0]["category"] == "Email"
        assert len(ctx) == 2          # mêmes extraits pour le 2e constat → dédupliqués

    def test_attach_references(self):
        from utils.rag_retrieval import TopicRetriever, attach_references
        search, _ = _fake_search(CORPUS)
        r = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=True)
        findings = [{"title": "DMARC absent", "category": "Email", "severity_rule": "dmarc_missing",
                     "references": [{"collection": "llm", "source": "RFC 7489"}]},
                    {"title": "Autre", "category": "Reputation", "severity_rule": "llm_proposed", "references": []}]
        ctx = [{"source": "RFC 7489", "collection": "normes", "topic": "dmarc_missing", "content": "x"},
               {"source": "T1566", "collection": "attack", "topic": "dmarc_missing", "content": "y"}]
        stats = attach_references(findings, ctx, r)
        assert findings[0]["references"] == [{"collection": "normes", "source": "RFC 7489"},
                                             {"collection": "attack", "source": "T1566"}]
        assert stats["finding_queries"] == 1          # seul le finding sans constat interroge
        cols = [x["collection"] for x in findings[1]["references"]]
        assert cols[1] == "attack" and cols[0] in ("menaces", "explications")
        assert stats["findings_with_rag_references"] == 2

    def test_attach_respects_query_budget(self):
        from utils.rag_retrieval import TopicRetriever, attach_references
        search, _ = _fake_search(CORPUS)
        r = TopicRetriever(embed_fn=lambda q: [0.1], search_fn=search, has_collections=True)
        findings = [{"title": f"f{i}", "category": "Web"} for i in range(5)]
        stats = attach_references(findings, [], r, max_queries=2)
        assert stats["finding_queries"] == 2

    def test_retrieve_relevant_docs_degrades(self, monkeypatch):
        import utils.rag_retrieval as rr
        monkeypatch.setattr(rr, "_embed_query", MagicMock(side_effect=OSError("x")))
        assert rr.retrieve_relevant_docs("q") == [] and rr.retrieve_relevant_docs("  ") == []


# ══════════════════════════════════════════════════════════════════════════════
#  Prompts, Ollama, point d'accroche phase 4
# ══════════════════════════════════════════════════════════════════════════════

class TestPromptsAndHooks:
    def test_output_schema_has_new_fields(self):
        import routes.analyze as an
        f = an._OUTPUT_SCHEMA["findings"][0]
        assert "confidence" in f and "observed_at" in f
        assert "confidence" in an._SYSTEM_PROMPT_GROQ and "observed_at" in an._SYSTEM_PROMPT_OPENROUTER
        assert "shodan_internetdb.vulns" in an._SYSTEM_PROMPT_GROQ

    def test_ollama_prompts_have_new_fields(self):
        from utils import ollama_client as oc
        assert "confidence" in oc._REDUCE_OUTPUT_SCHEMA["findings"][0]
        assert "observed_at" in oc._REDUCE_OUTPUT_SCHEMA["findings"][0]
        assert '"confidence"' in oc._MAP_SYSTEM_PROMPT and "CVE-XXXX" not in oc._MAP_SYSTEM_PROMPT

    def test_ollama_section_guidance_filters_by_category(self):
        from utils import ollama_client as oc
        signals = {"rag_context": [{"source": "RFC 7489", "content": "dmarc", "category": "Email"},
                                   {"source": "WSTG", "content": "xss", "category": "Web"}],
                   "deterministic_findings": [{"category": "Email", "title": "DMARC absent",
                                               "severity": "HIGH", "source_tool": "email_config"}]}
        assert "RFC 7489" in oc._section_guidance("email", signals)
        assert "WSTG" not in oc._section_guidance("email", signals)
        assert "DMARC absent" in oc._section_constats("email", signals)
        assert oc._section_constats("ssl_tls", signals).strip() == "(aucun)"
        # Le prompt MAP se formate sans clé manquante
        oc._MAP_SYSTEM_PROMPT.format(section_label="x", domain="d", global_context="g", section_data="{}",
                                     section_constats="c", section_guidance="g")

    def test_attack_hook_noop_without_module(self, monkeypatch):
        import routes.analyze as an
        monkeypatch.setitem(sys.modules, "utils.attack_enablement", None)   # ImportError
        fs = [{"id": "A"}]
        assert an._annotate_attack(fs, {}) is fs

    def test_attack_hook_called_when_present(self, monkeypatch):
        import routes.analyze as an
        mod = types.ModuleType("utils.attack_enablement")

        def annotate_findings(findings, signals):
            for f in findings:
                f["attack_enabled"] = [{"id": "T1566", "name": "Phishing"}]
                f["mitigations"] = []
            return findings
        mod.annotate_findings = annotate_findings
        monkeypatch.setitem(sys.modules, "utils.attack_enablement", mod)
        out = an._annotate_attack([{"id": "A"}], {"domain": "x"})
        assert out[0]["attack_enabled"][0]["id"] == "T1566"

    def test_attack_hook_failure_is_contained(self, monkeypatch):
        import routes.analyze as an
        mod = types.ModuleType("utils.attack_enablement")
        mod.annotate_findings = MagicMock(side_effect=RuntimeError("bug phase 4"))
        monkeypatch.setitem(sys.modules, "utils.attack_enablement", mod)
        fs = [{"id": "A"}]
        assert an._annotate_attack(fs, {}) is fs
        mod.annotate_findings = MagicMock(return_value="pas une liste")
        assert an._annotate_attack(fs, {}) is fs

    def test_merger_dedups_reference_objects(self):
        from utils.analysis_merger import _merge_findings
        a = [{"category": "Email", "title": "DMARC absent",
              "references": [{"collection": "normes", "source": "RFC 7489"}]}]
        b = [{"category": "Email", "title": "DMARC absent",
              "references": [{"collection": "normes", "source": "RFC 7489"}, {"collection": "attack", "source": "T1566"}]}]
        refs = _merge_findings(a, b)[0]["references"]
        assert len(refs) == 2

    def test_final_report_summary_carries_new_fields(self):
        from utils.final_report_generator import _extract_analysis_summary
        s = _extract_analysis_summary({"findings": [{"severity_rule": "dmarc_missing", "confidence": "high",
                                                     "observed_at": "2026-10-19T10:42:00Z"}]})
        f = s["findings"][0]
        assert (f["severity_rule"], f["confidence"], f["observed_at"]) == (
            "dmarc_missing", "high", "2026-10-19T10:42:00Z")
