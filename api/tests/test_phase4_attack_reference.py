# tests/test_phase4_attack_reference.py
"""
Référentiel ATT&CK local (api/data/attack_reference.json, généré par
data/script_mitre_attack.py depuis le bundle STIX mitre/cti) — phase 4.

Vérifie que le fichier versionné couvre toutes les techniques utilisées par
utils/mitre_attack.py et utils/attack_enablement.py (un oubli de
régénération échoue ici), et que le chargeur rejette toute entrée mal formée.
"""
import json

import pytest

from utils import mitre_attack
from utils.attack_enablement import RULES, TECHNIQUE_STAGE
from utils.mitre_attack import (
    REFERENCE_PATH, TECHNIQUES, TOOL_TECHNIQUES, load_reference,
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    mitre_attack._reset_reference_cache()
    yield
    mitre_attack._reset_reference_cache()


def test_reference_file_is_versioned_and_recent():
    ref = load_reference()
    major = int(ref["attack_version"].split(".")[0])
    assert major >= 18, "le référentiel doit suivre la dernière version d'ATT&CK (v15 dépassée)"
    assert ref["domain"] == "enterprise-attack"
    assert ref["source"].startswith("https://raw.githubusercontent.com/mitre/cti/")


def test_attack_version_helper():
    assert mitre_attack.attack_version() == load_reference()["attack_version"]


def test_all_tool_techniques_are_in_reference():
    ref = load_reference()
    used = {t for ids in TOOL_TECHNIQUES.values() for t in ids} | set(TECHNIQUES)
    missing = used - set(ref["techniques"])
    assert not missing, f"Régénérer data/script_mitre_attack.py : {missing}"


def test_all_rule_techniques_are_in_reference():
    ref = load_reference()
    used = set(TECHNIQUE_STAGE)
    for rule in RULES:
        used.update(rule["techniques"])
        used.update((rule.get("with_mx") or {}).get("techniques", []))
    assert not (used - set(ref["techniques"]))


def test_curated_names_match_official_names():
    """Les noms écrits à la main dans mitre_attack.TECHNIQUES = noms ATT&CK officiels."""
    ref = load_reference()
    for tid, meta in TECHNIQUES.items():
        assert meta["name"] == ref["techniques"][tid]["name"], tid


def test_plan_mitigations_are_official_for_their_technique():
    """Chaque mitigation préférée de la table est bien reliée (relation `mitigates`) à une technique de sa règle."""
    ref = load_reference()
    for rule in RULES:
        techs = list(rule["techniques"]) + list((rule.get("with_mx") or {}).get("techniques", []))
        official = {m for t in techs for m in ref["techniques"][t]["mitigations"]}
        prefs = list(rule["mitigations"]) + list((rule.get("with_mx") or {}).get("mitigations", []))
        for m in prefs:
            assert m in official, f"{rule['rule']} : {m} ne mitige aucune de {techs}"


def test_expected_official_relations():
    ref = load_reference()
    t = ref["techniques"]
    assert {"M1054", "M1017"} <= set(t["T1566"]["mitigations"])
    assert {"M1051", "M1050"} <= set(t["T1190"]["mitigations"])
    assert {"M1032", "M1035"} <= set(t["T1133"]["mitigations"])
    assert "M1022" in t["T1552.001"]["mitigations"]
    assert t["T1583.001"]["name"] == "Acquire Infrastructure: Domains"
    assert "initial-access" in t["T1078"]["tactics"]


def test_typosquatting_maps_to_acquire_infrastructure():
    """Correctif phase 4 : un domaine imitant la marque est ACQUIS (T1583.001), pas compromis."""
    assert TOOL_TECHNIQUES["typosquatting"] == ["T1583.001"]
    assert TOOL_TECHNIQUES["subdomain_takeover"] == ["T1584.001"]


@pytest.mark.security
def test_loader_rejects_malformed_ids(tmp_path):
    bad = {
        "attack_version": "20.0<script>",
        "tactics": {"TA0001": {"name": "Initial Access", "shortname": "initial-access"},
                    "TAxx": {"name": "x", "shortname": "evil"},
                    "TA0002": {"name": "y", "shortname": "Bad Short<"}},
        "mitigations": {"M1054": {"name": "Software Configuration"}, "M10541": {"name": "x"},
                        "javascript:": {"name": "x"}},
        "techniques": {
            "T1566": {"name": "Phishing\x00\x1b[31m", "tactics": ["initial-access", "evil"],
                      "mitigations": ["M1054", "M10541", "M9999"], "groups_count": "12",
                      "groups_sample": ["A" * 500]},
            "T1566.1": {"name": "x"}, "<img>": {"name": "x"}, "T15660": {"name": "x"},
        },
    }
    path = tmp_path / "ref.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    ref = load_reference(str(path))
    assert set(ref["techniques"]) == {"T1566"}
    assert set(ref["mitigations"]) == {"M1054"}
    assert set(ref["tactics"]) == {"TA0001"}
    tech = ref["techniques"]["T1566"]
    assert tech["mitigations"] == ["M1054"]
    assert tech["tactics"] == ["initial-access"]
    assert "\x00" not in tech["name"] and "\x1b" not in tech["name"]
    assert tech["groups_count"] == 0             # chaîne, pas un entier → ignoré
    assert len(tech["groups_sample"][0]) <= 60
    assert len(ref["attack_version"]) <= 20


@pytest.mark.security
@pytest.mark.parametrize("content", ["", "not json", "[]", '{"techniques": []}'])
def test_unreadable_reference_fails_closed(tmp_path, content):
    path = tmp_path / "ref.json"
    path.write_text(content, encoding="utf-8")
    ref = load_reference(str(path))
    assert ref["techniques"] == {} and ref["mitigations"] == {}


def test_missing_reference_fails_closed(tmp_path):
    ref = load_reference(str(tmp_path / "absent.json"))
    assert ref["techniques"] == {}


def test_reference_path_points_to_api_data():
    assert REFERENCE_PATH.replace("\\", "/").endswith("data/attack_reference.json")
