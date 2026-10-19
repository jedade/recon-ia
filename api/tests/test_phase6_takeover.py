# tests/test_phase6_takeover.py
"""
Phase 6 — empreintes can-i-take-over-xyz en consultation directe
(utils/takeover_fingerprints.py, api/data/takeover_fingerprints.json).
"""
import json

import pytest

from utils import takeover_fingerprints as tf


class TestFichierLocal:
    def test_fichier_charge(self):
        fps = tf.load_fingerprints()
        assert len(fps) >= 30
        assert all(isinstance(f["cname"], list) for f in fps)

    def test_attribution_licence(self):
        doc = json.load(open(tf.FINGERPRINTS_PATH, encoding="utf-8"))
        assert "CC BY 4.0" in doc["licence"]
        assert doc["count"] == len(doc["fingerprints"])

    def test_service_vulnerable_connu(self):
        fp = tf.match_cname("monapp.eu-west-1.elasticbeanstalk.com.")
        assert fp and "beanstalk" in fp["service"].lower()
        assert fp["vulnerable"] is True and fp["nxdomain"] is True

    def test_github_pages_cas_limite(self):
        """can-i-take-over-xyz classe GitHub Pages en « Edge case », sans CNAME
        de référence : le fichier ne doit pas le déclarer vulnérable (alors que
        routes/recon.py::TAKEOVER_SERVICES le signale)."""
        gh = [f for f in tf.load_fingerprints() if f["service"].lower() == "github"]
        assert gh and not gh[0]["vulnerable"]
        fp = tf.match_cname("monprojet.github.io")
        assert fp is None or not fp["vulnerable"]


class TestCorrespondance:
    @pytest.fixture
    def path(self, tmp_path):
        p = tmp_path / "fp.json"
        p.write_text(json.dumps({"fingerprints": [
            {"service": "S3", "cname": ["s3.amazonaws.com"], "status": "Vulnerable", "vulnerable": True},
            {"service": "AWS", "cname": ["amazonaws.com"], "status": "Not vulnerable", "vulnerable": False},
            {"service": "Fastly", "cname": ["fastly.net"], "status": "Edge case", "vulnerable": False},
            {"cname": ["sans-service.example"]},
        ]}), encoding="utf-8")
        return str(p)

    def test_suffixe_le_plus_long(self, path):
        assert tf.match_cname("bucket.s3.amazonaws.com", path)["service"] == "S3"
        assert tf.match_cname("x.elb.amazonaws.com", path)["service"] == "AWS"

    @pytest.mark.security
    def test_pas_de_correspondance_par_sous_chaine(self, path):
        # recon.py utilise `in` : « evilfastly.net » correspondrait à tort.
        assert tf.match_cname("evilfastly.net", path) is None
        assert tf.match_cname("fastly.net.attacker.example", path) is None

    def test_entrees_invalides(self, path):
        assert tf.match_cname("", path) is None
        assert tf.match_cname(None, path) is None
        assert tf.match_cname("x.sans-service.example", path) is None

    def test_fichier_absent_ou_corrompu(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{pas du json", encoding="utf-8")
        assert tf.load_fingerprints(str(bad)) == []
        assert tf.match_cname("a.github.io", str(tmp_path / "absent.json")) is None
