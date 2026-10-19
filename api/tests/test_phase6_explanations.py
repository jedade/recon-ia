# tests/test_phase6_explanations.py
"""
Phase 6 — textes pédagogiques par contrôle (api/data/explanations/*.json,
utils/explanations.py) : JSON bien formé, schéma respecté, sans HTML,
couverture des contrôles demandés, rendu markdown pour le RAG.
"""
import json
import os

import pytest

from utils import explanations as ex

EXPECTED_CONTROLS = {
    "dmarc", "spf", "dkim", "hsts", "csp", "cookies", "tls", "dnssec", "caa",
    "takeover", "ports_exposes", "fuites_donnees", "listes_blocage", "tranco",
}


def _files():
    return sorted(f for f in os.listdir(ex.EXPLANATIONS_DIR) if f.endswith(".json"))


class TestContenu:
    def test_couverture_des_controles(self):
        assert EXPECTED_CONTROLS <= set(ex.load_all())

    def test_chaque_fichier_valide(self):
        for name in _files():
            with open(os.path.join(ex.EXPLANATIONS_DIR, name), encoding="utf-8") as f:
                entry = json.load(f)
            assert ex.validate(entry, name[:-5]) == [], name

    def test_attribution_web_check(self):
        for entry in ex.load_all().values():
            assert "web-check" in entry["credits"] and "MIT" in entry["credits"]

    def test_get_et_for_tool(self):
        assert ex.get("dmarc")["titre"].startswith("DMARC")
        assert ex.get("inexistant") is None
        assert any(e["id"] == "dmarc" for e in ex.for_tool("dmarc_check"))

    def test_rendu_markdown(self):
        md = ex.render_markdown(ex.get("hsts"))
        assert md.startswith("# Explication — HSTS")
        for section in ("## Pourquoi c'est important", "## Risque", "## Comment corriger",
                        "## Références"):
            assert section in md

    def test_corpus_un_document_par_controle(self):
        corpus = ex.render_corpus()
        assert corpus.count("# Explication — ") == len(ex.load_all())


@pytest.mark.security
class TestSecurite:
    def test_json_strict_utf8(self):
        for name in _files():
            raw = open(os.path.join(ex.EXPLANATIONS_DIR, name), "rb").read()
            raw.decode("utf-8")
            json.loads(raw)

    def test_aucun_html(self):
        for name in _files():
            text = open(os.path.join(ex.EXPLANATIONS_DIR, name), encoding="utf-8").read()
            assert "<" not in text and ">" not in text, name

    def test_references_https(self):
        for entry in ex.load_all().values():
            for ref in entry["references"]:
                assert ref["url"].startswith("https://")

    @pytest.mark.parametrize("bad,err", [
        ({"titre": "<b>x</b>"}, "HTML interdit"),
        ({"references": [{"titre": "x", "url": "javascript:alert(1)"}]}, "URL"),
        ({"references": [{"titre": "x", "url": "http://exemple.bj"}]}, "URL"),
        ({"pourquoi": "&lt;script&gt;"}, "HTML interdit"),
        ({"id": "../etc"}, "id invalide"),
        ({"inattendu": "x"}, "clé inconnue"),
        ({"categorie": "Autre"}, "catégorie"),
        ({"risque": "a\x07b"}, "contrôle"),
    ])
    def test_validate_rejette(self, bad, err):
        entry = dict(ex.get("dmarc"))
        entry.update(bad)
        errors = ex.validate(entry)
        assert any(err in e for e in errors), errors

    def test_get_id_hostile(self):
        assert ex.get("../../etc/passwd") is None
        assert ex.get(None) is None

    def test_fichier_invalide_refuse(self, tmp_path):
        (tmp_path / "piege.json").write_text(json.dumps({"id": "piege", "titre": "<img src=x>"}),
                                             encoding="utf-8")
        with pytest.raises(ValueError):
            ex.load_all(str(tmp_path))
