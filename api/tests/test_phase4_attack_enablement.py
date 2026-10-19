# tests/test_phase4_attack_enablement.py
"""
Table déterministe constat → techniques rendues possibles + mitigations,
chaîne d'attaque plausible et layer ATT&CK Navigator (utils/attack_enablement.py,
plan d'action phase 4, B8).
"""
import copy
import json

import pytest

from utils.attack_enablement import (
    annotate_findings, attack_csv_fields, build_attack_chain, build_navigator_layer,
    technique_context,
)


def _f(title, severity="HIGH", **kw):
    return {"id": kw.pop("id", "F-1"), "title": title, "severity": severity, **kw}


def _ids(finding, key="attack_enabled"):
    return [x["id"] for x in finding[key]]


def _one(finding, signals=None):
    return annotate_findings([finding], signals or {})[0]


# ──────────────────────────────────────────────────────────────────────────
#  Une ligne de la table du plan = un test
# ──────────────────────────────────────────────────────────────────────────

class TestTableRows:
    def test_dmarc_missing(self):
        out = _one(_f("Aucune politique DMARC", source_tool="dmarc_check", category="Email"))
        assert _ids(out) == ["T1566"]
        assert _ids(out, "mitigations") == ["M1054", "M1017"]
        assert out["attack_enabled"][0]["name"] == "Phishing"
        assert out["mitigations"][0]["name"] == "Software Configuration"
        assert out["attack_rules"] == ["dmarc_weak"]

    def test_dmarc_p_none(self):
        assert _ids(_one(_f("Politique DMARC en p=none (surveillance)", "MEDIUM"))) == ["T1566"]

    def test_dmarc_by_severity_rule_only(self):
        """Phase 3 pose severity_rule : reconnu même avec un titre libre."""
        assert _ids(_one(_f("Usurpation du domaine possible", severity_rule="dmarc_missing"))) == ["T1566"]

    def test_dmarc_strict_is_not_a_weakness(self):
        assert _ids(_one(_f("DMARC p=reject correctement configuré", "LOW"))) == []

    def test_typosquatting_without_mx(self):
        out = _one(_f("Domaines de typosquatting enregistrés", source_tool="typosquatting"),
                   {"brand_protection": {"mx_configured_count": 0, "suspicious_domains": ["exarnple.bj"],
                                         "status": "success"}})
        assert _ids(out) == ["T1583.001"]
        assert _ids(out, "mitigations") == ["M1056"]

    def test_typosquatting_with_mx_enables_phishing(self):
        out = _one(_f("Domaines de typosquatting enregistrés", source_tool="typosquatting"),
                   {"brand_protection": {"mx_configured_count": 2, "suspicious_domains": ["a", "b"],
                                         "status": "success"}})
        assert _ids(out) == ["T1583.001", "T1566"]
        assert "M1017" in _ids(out, "mitigations")

    def test_typosquatting_mx_from_text_when_no_signals(self):
        out = _one(_f("Typosquatting : 2 domaines avec MX configuré"))
        assert _ids(out) == ["T1583.001", "T1566"]

    def test_kev_cve_by_rule(self):
        out = _one(_f("CVE-2024-3400 exposée", "CRITICAL", severity_rule="cve_kev",
                      source_tool="shodan_internetdb"))
        assert _ids(out) == ["T1190"]
        assert _ids(out, "mitigations") == ["M1051", "M1050"]

    def test_kev_cve_by_title(self):
        assert _ids(_one(_f("CVE-2023-4966 présente dans le catalogue CISA KEV", "CRITICAL"))) == ["T1190"]

    def test_kev_cve_confirmed_by_signals(self):
        signals = {"network": {"shodan_internetdb": {"vulns_enriched": [
            {"cve": "CVE-2023-4966", "cvss": 9.4, "kev": True}]}}}
        out = _one(_f("CVE-2023-4966 sur le pare-feu", "CRITICAL", evidence="vulns: CVE-2023-4966"), signals)
        assert "T1190" in _ids(out)

    def test_plain_cve_not_in_kev_enables_nothing(self):
        signals = {"network": {"shodan_internetdb": {"vulns_enriched": [{"cve": "CVE-2020-0001", "kev": False}]}}}
        assert _ids(_one(_f("CVE-2020-0001 annoncée par Shodan", "MEDIUM"), signals)) == []

    @pytest.mark.parametrize("title", [
        "RDP exposé sur Internet (port 3389)",
        "Portail VPN Fortinet accessible",
        "Citrix NetScaler Gateway exposé",
        "Panneau d'administration phpMyAdmin public",
        "Interface d'administration exposée sur admin.example.bj",
    ])
    def test_remote_services(self, title):
        out = _one(_f(title))
        assert _ids(out) == ["T1133"]
        assert _ids(out, "mitigations") == ["M1032", "M1035"]

    def test_remote_word_boundary(self):
        """« rdp » dans « wordpress » n'est pas un RDP exposé."""
        assert _ids(_one(_f("Version de WordPress divulguée", "LOW"))) == []

    def test_breached_accounts(self):
        out = _one(_f("Adresses rôle du domaine dans 3 fuites de données",
                      source_tool="xposedornot_breaches"))
        assert _ids(out) == ["T1110.004", "T1078"]
        assert _ids(out, "mitigations") == ["M1032", "M1027"]

    def test_takeover(self):
        out = _one(_f("Sous-domaine vulnérable au takeover (CNAME orphelin vers S3)", "CRITICAL",
                      source_tool="subdomain_takeover"))
        assert _ids(out) == ["T1584.001"]
        assert _ids(out, "mitigations") == ["M1056"]
        assert "CNAME" in out["mitigation_advice"]

    def test_archived_env_file(self):
        out = _one(_f("Fichier .env présent dans les archives Wayback", "MEDIUM", source_tool="archive_history"))
        assert _ids(out) == ["T1552.001"]
        assert _ids(out, "mitigations") == ["M1022"]

    def test_git_dir_found_by_gau(self):
        assert _ids(_one(_f("Répertoire .git référencé dans les URL historiques", source_tool="gau_urls"))) == ["T1552.001"]

    def test_github_secrets(self):
        out = _one(_f("Clé API AWS dans un dépôt GitHub public", "CRITICAL", source_tool="github"))
        assert _ids(out) == ["T1593.003", "T1552"]
        assert set(_ids(out, "mitigations")) == {"M1013", "M1047", "M1027"}

    def test_github_without_secret_is_recon_only(self):
        assert _ids(_one(_f("Sous-domaines internes cités dans un dépôt GitHub", "LOW", source_tool="github"))) == []


# ──────────────────────────────────────────────────────────────────────────
#  Robustesse de la reconnaissance
# ──────────────────────────────────────────────────────────────────────────

class TestRecognition:
    def test_accents_and_case_ignored(self):
        assert _ids(_one(_f("DMARC ABSENT — PROTECTION INEXISTANTE"))) == ["T1566"]

    def test_info_findings_enable_nothing(self):
        assert _ids(_one(_f("Aucune politique DMARC", "INFO"))) == []

    def test_unknown_finding(self):
        out = _one(_f("DNSSEC désactivé", "MEDIUM", source_tool="dnssec"))
        assert out["attack_enabled"] == [] and out["mitigations"] == [] and out["attack_rules"] == []
        assert out["mitigation_advice"] == ""

    def test_description_is_not_used(self):
        """La description (texte libre du LLM) peut citer un autre sujet : ignorée."""
        out = _one(_f("En-têtes de sécurité incomplets", "LOW",
                      description="Comme DMARC absent, cela facilite le phishing via RDP exposé."))
        assert out["attack_enabled"] == []

    def test_multiple_rules_union_in_chain_order(self):
        out = _one(_f("Fuite de comptes et RDP exposé", source_tool="xposedornot_breaches"))
        assert _ids(out) == ["T1110.004", "T1078", "T1133"]

    def test_takeover_infirmed_by_signals(self):
        signals = {"subdomains": {"takeover": {"vulnerable_count": 0, "checked_count": 12}}}
        assert _ids(_one(_f("Risque de takeover sur dev.example.bj"), signals)) == []

    def test_takeover_negative_phrasing(self):
        assert _ids(_one(_f("Aucun sous-domaine vulnérable au takeover", "LOW"))) == []

    def test_dmarc_infirmed_by_signals(self):
        signals = {"email": {"dmarc": {"present": True, "policy": "reject", "percentage": 100}}}
        assert _ids(_one(_f("DMARC absent"), signals)) == []

    def test_dmarc_quarantine_partial_pct_still_weak(self):
        signals = {"email": {"dmarc": {"present": True, "policy": "quarantine", "percentage": 10}}}
        assert _ids(_one(_f("DMARC faible : pct=10"), signals)) == ["T1566"]

    def test_breaches_infirmed_by_zero_count(self):
        signals = {"breaches": {"breach_count": 0}}
        assert _ids(_one(_f("Fuite de données des adresses email", source_tool="xposedornot_breaches"), signals)) == []

    def test_typosquat_infirmed_by_empty_tool_result(self):
        signals = {"brand_protection": {"status": "success", "suspicious_domains": [], "mx_configured_count": 0}}
        assert _ids(_one(_f("Typosquatting possible"), signals)) == []

    def test_weird_types_do_not_crash(self):
        weird = [{"title": None, "severity": None}, {"title": 42, "source_tools": "github", "severity": "HIGH"},
                 {"title": ["x"], "severity_rule": 3, "category": {"a": 1}, "severity": "CRITICAL"},
                 "pas un dict", None, 7]
        out = annotate_findings(weird, {"email": "pas un dict", "breaches": []})
        assert out[3:] == ["pas un dict", None, 7]
        assert all(o["attack_enabled"] == [] for o in out[:3])

    def test_non_list_input(self):
        assert annotate_findings(None, None) == []
        assert annotate_findings("x", {}) == []


# ──────────────────────────────────────────────────────────────────────────
#  Idempotence, immutabilité, défiance envers le LLM
# ──────────────────────────────────────────────────────────────────────────

FINDINGS = [
    _f("Aucune politique DMARC", id="EMAIL-001", source_tool="dmarc_check"),
    _f("Adresses du domaine dans des fuites", id="LEAK-001", source_tool="xposedornot_breaches", severity="MEDIUM"),
    _f("RDP exposé (3389)", id="NET-002", source_tool="shodan_internetdb", severity="CRITICAL"),
    _f("DNSSEC désactivé", id="DNS-001", source_tool="dnssec", severity="LOW"),
]


class TestIdempotenceAndTrust:
    def test_idempotent(self):
        once = annotate_findings(FINDINGS, {})
        twice = annotate_findings(once, {})
        assert once == twice

    def test_input_not_mutated(self):
        before = copy.deepcopy(FINDINGS)
        annotate_findings(FINDINGS, {})
        assert FINDINGS == before

    @pytest.mark.security
    def test_llm_attack_ids_are_ignored(self):
        f = _f("DNSSEC désactivé", "MEDIUM", attack_enabled=[{"id": "T1190", "name": "x"},
                                                           {"id": "T9999", "name": "<script>"}],
               mitigations=[{"id": "M0000", "name": "inventée"}], attack_rules=["fake"],
               mitigation_advice="<img onerror=alert(1)>")
        out = _one(f)
        assert out["attack_enabled"] == [] and out["mitigations"] == []
        assert out["attack_rules"] == [] and out["mitigation_advice"] == ""

    @pytest.mark.security
    def test_llm_ids_replaced_by_table_ids(self):
        f = _f("DMARC absent", attack_enabled=[{"id": "T1059", "name": "Command and Scripting Interpreter"}])
        assert _ids(_one(f)) == ["T1566"]

    @pytest.mark.security
    def test_names_come_from_reference_not_from_finding(self):
        f = _f("DMARC absent", attack_enabled=[{"id": "T1566", "name": "<b>injecté</b>"}])
        assert _one(f)["attack_enabled"] == [{"id": "T1566", "name": "Phishing"}]

    @pytest.mark.security
    def test_unknown_technique_in_rule_is_dropped(self, monkeypatch):
        """Une technique absente du référentiel (révoquée) n'est jamais émise."""
        from utils import attack_enablement
        rules = copy.deepcopy(attack_enablement.RULES)
        for r in rules:
            r["match"] = next(x["match"] for x in attack_enablement.RULES if x["rule"] == r["rule"])
        rules[0]["techniques"] = ["T1566", "T9998", "javascript:alert(1)"]
        monkeypatch.setattr(attack_enablement, "RULES", rules)
        assert _ids(_one(_f("DMARC absent"))) == ["T1566"]

    def test_mitigation_fallback_to_official(self, monkeypatch):
        """Mitigation préférée non reliée par le bundle → mitigations officielles de la technique."""
        from utils import attack_enablement
        rules = [dict(r) for r in attack_enablement.RULES]
        rules[0] = {**rules[0], "mitigations": ["M1056"]}   # M1056 ne mitige pas T1566
        monkeypatch.setattr(attack_enablement, "RULES", rules)
        mits = _ids(_one(_f("DMARC absent")), "mitigations")
        assert "M1056" not in mits and {"M1054", "M1017"} <= set(mits)


# ──────────────────────────────────────────────────────────────────────────
#  Chaîne d'attaque plausible
# ──────────────────────────────────────────────────────────────────────────

class TestAttackChain:
    def test_chain_structure_and_order(self):
        chain = build_attack_chain(annotate_findings(FINDINGS, {}))
        assert [s["stage"] for s in chain] == ["reconnaissance", "credential-access", "initial-access"]
        assert [s["order"] for s in chain] == [1, 2, 3]
        recon = chain[0]
        # Techniques de reconnaissance des outils sources des constats retenus
        assert {t["id"] for t in recon["techniques"]} == {"T1590.002", "T1589.002", "T1596.005"}
        access = chain[2]
        assert access["tactic_id"] == "TA0001"
        assert {t["id"] for t in access["techniques"]} == {"T1566", "T1078", "T1133"}
        assert access["max_severity"] == "CRITICAL"
        t1566 = next(t for t in access["techniques"] if t["id"] == "T1566")
        assert t1566["finding_ids"] == ["EMAIL-001"] and t1566["name"] == "Phishing"
        assert "DNS-001" not in sum((s["finding_ids"] for s in chain), [])

    def test_resource_development_stage(self):
        chain = build_attack_chain(annotate_findings(
            [_f("Typosquatting avec MX", id="BRAND-001", source_tool="typosquatting")], {}))
        assert [s["stage"] for s in chain] == ["resource-development", "initial-access"]

    def test_empty_when_nothing_enabled(self):
        assert build_attack_chain(annotate_findings([_f("DNSSEC désactivé", "LOW")], {})) == []
        assert build_attack_chain([]) == []
        assert build_attack_chain(None) == []

    def test_deterministic(self):
        a = annotate_findings(FINDINGS, {})
        assert build_attack_chain(a) == build_attack_chain(copy.deepcopy(a))

    @pytest.mark.security
    def test_chain_revalidates_ids(self):
        """Des constats NON annotés portant des ID inventés ne produisent aucune étape."""
        forged = [{"id": "X", "title": "x", "severity": "HIGH",
                   "attack_enabled": [{"id": "T9999"}, {"id": "T1059"}, {"id": "<script>"}, "T1566"]}]
        assert build_attack_chain(forged) == []

    @pytest.mark.security
    def test_forged_finding_id_replaced(self):
        out = annotate_findings([_f("DMARC absent", id="<img src=x onerror=alert(1)>")], {})
        chain = build_attack_chain(out)
        assert chain[-1]["finding_ids"] == ["F-001"]


# ──────────────────────────────────────────────────────────────────────────
#  Layer ATT&CK Navigator
# ──────────────────────────────────────────────────────────────────────────

MITRE = [{"technique_id": "T1590.002", "matched_tools": ["dmarc_check", "dns_records"]},
         {"technique_id": "T9999", "matched_tools": ["x"]},
         {"technique_id": "T1596.005", "matched_tools": ["shodan_internetdb", "<script>"]}]


class TestNavigatorLayer:
    def _layer(self, findings=FINDINGS, mitre=MITRE, domain="example.bj"):
        return build_navigator_layer(annotate_findings(findings, {}), mitre, domain)

    def test_layer_format(self):
        layer = self._layer()
        assert layer["versions"]["layer"] == "4.5"
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"].isdigit()
        assert layer["name"] == "ReconIA — example.bj"
        for key in ("filters", "layout", "gradient", "legendItems", "techniques", "sorting"):
            assert key in layer
        json.loads(json.dumps(layer))   # sérialisable

    def test_colored_by_max_severity(self):
        layer = self._layer()
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert by_id["T1566"]["score"] == 3 and by_id["T1566"]["color"] == "#f97316"
        assert by_id["T1133"]["score"] == 4 and by_id["T1133"]["color"] == "#ef4444"
        assert by_id["T1078"]["score"] == 2
        assert by_id["T1566"]["tactic"] == "initial-access"
        assert by_id["T1110.004"]["tactic"] == "credential-access"
        assert "EMAIL-001" in by_id["T1566"]["comment"] and "Aucune politique DMARC" in by_id["T1566"]["comment"]

    def test_max_severity_across_findings(self):
        layer = self._layer([_f("DMARC absent", "LOW", id="A"), _f("DMARC p=none", "CRITICAL", id="B")], [])
        (t,) = layer["techniques"]
        assert t["score"] == 4 and "A [LOW]" in t["comment"] and "B [CRITICAL]" in t["comment"]

    def test_recon_techniques_grey(self):
        by_id = {t["techniqueID"]: t for t in self._layer()["techniques"]}
        assert by_id["T1590.002"]["score"] == 0 and by_id["T1590.002"]["tactic"] == "reconnaissance"
        assert "dmarc_check" in by_id["T1590.002"]["comment"]

    @pytest.mark.security
    def test_invalid_ids_and_tools_excluded(self):
        layer = self._layer()
        ids = {t["techniqueID"] for t in layer["techniques"]}
        assert "T9999" not in ids
        assert all("<script>" not in t["comment"] for t in layer["techniques"])

    @pytest.mark.security
    def test_no_injection_in_layer(self):
        evil = _f('DMARC absent"},{"techniqueID":"T1059","score":99} <script>alert(1)</script> \x00',
                  id='EMAIL-1')
        layer = build_navigator_layer(annotate_findings([evil], {}), [], 'evil"<script>.bj')
        body = json.dumps(layer)
        parsed = json.loads(body)
        assert [t["techniqueID"] for t in parsed["techniques"]] == ["T1566"]
        comment = parsed["techniques"][0]["comment"]
        assert "<" not in comment and ">" not in comment and "\x00" not in comment and " " not in comment
        assert "<" not in parsed["name"]
        assert all(t["color"].startswith("#") and len(t["color"]) == 7 for t in parsed["techniques"])

    def test_comment_length_bounded(self):
        many = [_f("DMARC absent " + "x" * 400, id=f"E-{i}") for i in range(40)]
        (t,) = build_navigator_layer(annotate_findings(many, {}), [], "x")["techniques"]
        assert len(t["comment"]) <= 1500

    def test_empty_layer(self):
        layer = build_navigator_layer([], None, "")
        assert layer["techniques"] == [] and layer["name"] == "ReconIA"


# ──────────────────────────────────────────────────────────────────────────
#  Aides annexes
# ──────────────────────────────────────────────────────────────────────────

def test_attack_csv_fields():
    out = annotate_findings([FINDINGS[1]], {})[0]
    fields = attack_csv_fields(out)
    assert fields["attack_enabled"] == "T1110.004 Brute Force: Credential Stuffing; T1078 Valid Accounts"
    assert fields["mitigations"] == "M1032 Multi-factor Authentication; M1027 Password Policies"
    assert attack_csv_fields({"attack_enabled": [{"id": "=cmd|' /C calc'!A0"}]})["attack_enabled"] == ""
    assert attack_csv_fields(None) == {"attack_enabled": "", "mitigations": ""}


def test_technique_context_is_context_only():
    ctx = technique_context(["T1566", "T9999", "<x>", None])
    assert set(ctx) == {"T1566"}
    assert isinstance(ctx["T1566"]["groups_count"], int)
    assert len(ctx["T1566"]["groups_sample"]) <= 5
