# tests/test_grounding_check.py
"""Tests du contrôle d'ancrage (utils/grounding_check.py)."""
from utils.grounding_check import compute_grounding_check


def _scan(**tools):
    return tools


def _tool(status="success", raw_output="", data=None, tool="Test Tool", category="Test"):
    return {
        "status": status,
        "meta": {"tool": tool, "category": category},
        "data": data or {},
        "raw_output": raw_output,
    }


class TestVerified:
    def test_evidence_found_in_raw_output(self):
        scan = _scan(dns_records=_tool(raw_output="A record: 93.184.216.34, no DNSSEC found"))
        report = {"findings": [{
            "source_tool": "dns_records",
            "evidence": "no DNSSEC found",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "verified"
        assert summary["verified"] == 1
        assert summary["verified_pct"] == 100.0

    def test_evidence_found_in_data_field(self):
        scan = _scan(ssl_info=_tool(data={"issuer": "DigiCert", "days_remaining": 3}))
        report = {"findings": [{
            "source_tool": "ssl_info",
            "evidence": "days_remaining 3",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "verified"
        assert summary["verified"] == 1

    def test_multiple_source_tools_one_verifies(self):
        scan = _scan(
            whois=_tool(raw_output="Registrar: OVH"),
            dns_records=_tool(raw_output="unrelated content"),
        )
        report = {"findings": [{
            "source_tool": "dns_records",
            "source_tools": ["dns_records", "whois"],
            "evidence": "Registrar: OVH",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "verified"
        assert summary["verified"] == 1


class TestNotVerified:
    def test_evidence_not_present_anywhere(self):
        scan = _scan(dns_records=_tool(raw_output="A record: 93.184.216.34"))
        report = {"findings": [{
            "source_tool": "dns_records",
            "evidence": "MX record points to a suspicious host in Russia",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "evidence_not_found"
        assert summary["evidence_not_found"] == 1
        assert summary["verified"] == 0

    def test_unknown_tool_name_hallucinated(self):
        scan = _scan(dns_records=_tool(raw_output="A record: 93.184.216.34"))
        report = {"findings": [{
            "source_tool": "nmap_scan",  # jamais exécuté par ce projet
            "evidence": "port 22 open",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "unknown_tool"
        assert summary["unknown_tool"] == 1

    def test_tool_present_but_not_successful(self):
        scan = _scan(xposedornot_breaches=_tool(status="skipped"))
        report = {"findings": [{
            "source_tool": "xposedornot_breaches",
            "evidence": "3 breaches found",
        }]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "tool_not_successful"
        assert summary["tool_not_successful"] == 1

    def test_no_source_tool_cited(self):
        scan = _scan(dns_records=_tool(raw_output="A record: 93.184.216.34"))
        report = {"findings": [{"evidence": "no DNSSEC"}]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "no_source_cited"
        assert summary["no_source_cited"] == 1

    def test_no_evidence_text_provided(self):
        scan = _scan(dns_records=_tool(raw_output="A record: 93.184.216.34"))
        report = {"findings": [{"source_tool": "dns_records", "evidence": ""}]}
        summary = compute_grounding_check(report, scan)
        assert report["findings"][0]["grounding"]["status"] == "no_evidence_text"


class TestSummaryAndSafety:
    def test_empty_findings_list(self):
        summary = compute_grounding_check({"findings": []}, {})
        assert summary["total_findings"] == 0
        assert summary["verified_pct"] is None

    def test_missing_findings_key(self):
        summary = compute_grounding_check({}, {})
        assert summary["total_findings"] == 0

    def test_scan_results_none_does_not_crash(self):
        report = {"findings": [{"source_tool": "dns_records", "evidence": "x"}]}
        summary = compute_grounding_check(report, None)
        assert report["findings"][0]["grounding"]["status"] == "unknown_tool"
        assert summary["total_findings"] == 1

    def test_additive_does_not_remove_existing_fields(self):
        report = {
            "risk_score": 42,
            "security_score": 58,
            "findings": [{
                "id": "DNS-001", "severity": "HIGH", "source_tool": "dns_records",
                "evidence": "present", "recommendation": "fix it",
            }],
        }
        scan = _scan(dns_records=_tool(raw_output="present in raw output"))
        compute_grounding_check(report, scan)
        f = report["findings"][0]
        assert f["id"] == "DNS-001"
        assert f["severity"] == "HIGH"
        assert f["recommendation"] == "fix it"
        assert report["risk_score"] == 42
        assert report["security_score"] == 58

    def test_mixed_findings_percentage(self):
        scan = _scan(
            dns_records=_tool(raw_output="no DNSSEC configured"),
            ssl_info=_tool(raw_output="cert issued by DigiCert"),
        )
        report = {"findings": [
            {"source_tool": "dns_records", "evidence": "no DNSSEC configured"},
            {"source_tool": "ssl_info", "evidence": "totally fabricated claim"},
        ]}
        summary = compute_grounding_check(report, scan)
        assert summary["total_findings"] == 2
        assert summary["verified"] == 1
        assert summary["verified_pct"] == 50.0
