# tests/test_phase6_scan_stats.py
"""
Phase 6 — statistiques agrégées et anonymisées des scans passés
(utils/scan_stats.py).

- unitaires : extraction des caractéristiques (scan brut et signaux),
  agrégation, arrondi, TLD ;
- sécurité : k-anonymat, aucun nom de domaine dans la sortie, exclusion du
  domaine courant, TLD hostile rejeté, robustesse (jamais d'exception) ;
- intégration : base SQLite de test (fixture `app`), lignes
  pass_recon_cache réelles → compute_stats / comparative_context.
"""
import json
from datetime import datetime, timedelta

import pytest

from utils import scan_stats
from utils.scan_stats import (FEATURE_KEYS, _aggregate, comparative_context, compute_stats,
                              features_from_scan, features_from_signals, tld_of)


# ---------------------------------------------------------------------------
# Fabrique de scans bruts (format pass_recon_cache.result_json)
# ---------------------------------------------------------------------------

def make_scan(domain, *, dmarc=True, policy="reject", spf="v=spf1 -all", dkim=True,
              dnssec=True, caa=True, hsts=True, csp=True, legacy_tls=False,
              ports=(80, 443), takeover=0, listed=0, breaches=0, sec_txt=True):
    return {
        "domain": domain,
        "dmarc_check": {"status": "success" if dmarc else "no_data",
                        "data": {"present": dmarc, "policy": policy if dmarc else None}},
        "email_config": {"status": "success", "data": {
            "spf": spf, "spf_status": "found" if spf else "not_found",
            "dmarc_status": "found" if dmarc else "not_found"}},
        "spf_analysis": {"status": "success", "data": {"mechanisms": []}},
        "dkim_check": {"status": "success", "data": {"found": [{"selector": "s1", "has_key": dkim}]}},
        "mta_sts_check": {"status": "no_data", "data": {"present": False}},
        "dnssec": {"status": "success", "data": {"enabled": dnssec}},
        "caa_check": {"status": "success" if caa else "no_data", "data": {"present": caa}},
        "security_headers": {"status": "success", "data": {"headers": {
            "strict-transport-security": {"present": hsts},
            "content-security-policy": {"present": csp}}}},
        "tls_config": {"status": "success", "data": {"protocols": {
            "SSLv2": False, "SSLv3": False, "TLSv1.0": legacy_tls, "TLSv1.1": False,
            "TLSv1.2": True, "TLSv1.3": True}}},
        "ssl_info": {"status": "success", "data": {"expired": False, "expiry_warning": False}},
        "security_txt": {"status": "success" if sec_txt else "not_found", "data": {}},
        "shodan_internetdb": {"status": "success", "data": {"ports": list(ports)}},
        "subdomain_takeover": {"status": "success", "data": {"vulnerable_count": takeover}},
        "dnsbl_check": {"status": "success", "data": {"listed_count": listed, "clean": not listed}},
        "xposedornot_breaches": {"status": "success", "data": {"breach_count": breaches}},
    }


def make_signals(domain, *, dmarc=False):
    """Signaux compacts au format routes/analyze.py::_extract_signals."""
    return {
        "domain": domain,
        "email": {
            "dmarc": {"present": dmarc, "policy": "reject" if dmarc else None},
            "config": {"spf": "v=spf1 ~all", "spf_status": "found"},
            "dkim": {"found": []},
            "mta_sts": {"present": False},
        },
        "dns": {"dnssec": {"enabled": False}},
        "ssl_tls": {"caa": {"present": False}, "tls_config": {"protocols": {"TLSv1.0": True}},
                    "certificate": {"expired": False, "expiry_warning": False}},
        "web": {"security_headers": {"headers": {"strict-transport-security": {"present": True},
                                                 "content-security-policy": {"present": False}}},
                "security_txt_status": "not_found"},
        "network": {"shodan_internetdb": {"ports": [22, 443], "status": "success"},
                    "dnsbl": {"clean": True, "listed": []}},
        "subdomains": {"takeover": {"vulnerable_count": 0}},
        "breaches": {"status": "success", "breach_count": 3},
    }


@pytest.fixture(autouse=True)
def _reset():
    scan_stats.reset_cache()
    yield
    scan_stats.reset_cache()


# ---------------------------------------------------------------------------
# Unitaires
# ---------------------------------------------------------------------------

class TestFeatures:
    def test_scan_sain(self):
        f = features_from_scan(make_scan("a.bj"))
        assert f["dmarc_absent"] is False
        assert f["dmarc_policy_none"] is False
        assert f["spf_absent"] is False and f["spf_permissive"] is False
        assert f["dkim_absent"] is False
        assert f["dnssec_absent"] is False
        assert f["hsts_absent"] is False and f["csp_absent"] is False
        assert f["tls_legacy"] is False
        assert f["admin_ports_exposed"] is False
        assert f["security_txt_absent"] is False
        assert f["mta_sts_absent"] is True

    def test_scan_faible(self):
        f = features_from_scan(make_scan("a.bj", dmarc=False, spf="v=spf1 +all", dkim=False,
                                         dnssec=False, caa=False, hsts=False, csp=False,
                                         legacy_tls=True, ports=(22, 3306), takeover=1,
                                         listed=1, breaches=2, sec_txt=False))
        for key in ("dmarc_absent", "spf_permissive", "dkim_absent", "dnssec_absent", "caa_absent",
                    "hsts_absent", "csp_absent", "tls_legacy", "admin_ports_exposed",
                    "takeover_candidate", "dnsbl_listed", "breaches_found", "security_txt_absent"):
            assert f[key] is True, key
        # DMARC absent → la politique n'est pas évaluable
        assert f["dmarc_policy_none"] is None

    def test_dmarc_p_none(self):
        assert features_from_scan(make_scan("a.bj", policy="none"))["dmarc_policy_none"] is True

    def test_spf_absent_et_qualifieurs(self):
        assert features_from_scan(make_scan("a.bj", spf=""))["spf_absent"] is True
        assert features_from_scan(make_scan("a.bj", spf="v=spf1 ?all"))["spf_permissive"] is True
        assert features_from_scan(make_scan("a.bj", spf="v=spf1 ~all"))["spf_permissive"] is False

    def test_outil_en_erreur_non_evaluable(self):
        scan = make_scan("a.bj")
        scan["dnssec"] = {"status": "error", "error": "timeout"}
        scan["tls_config"] = {"status": "timeout"}
        f = features_from_scan(scan)
        assert f["dnssec_absent"] is None
        assert f["tls_legacy"] is None

    def test_scan_vide_ou_invalide(self):
        assert all(v is None for v in features_from_scan({}).values())
        assert all(v is None for v in features_from_scan({"data": "x"}).values())
        assert all(v is None for v in features_from_signals(None).values())

    def test_enveloppe_data(self):
        f = features_from_scan({"success": True, "data": make_scan("a.bj", dmarc=False)})
        assert f["dmarc_absent"] is True

    def test_signaux_compacts(self):
        f = features_from_signals(make_signals("x.bj"))
        assert f["dmarc_absent"] is True
        assert f["spf_permissive"] is False
        assert f["dkim_absent"] is True
        assert f["dnssec_absent"] is True
        assert f["caa_absent"] is True
        assert f["tls_legacy"] is True
        assert f["hsts_absent"] is False and f["csp_absent"] is True
        assert f["admin_ports_exposed"] is True
        assert f["security_txt_absent"] is True
        assert f["breaches_found"] is True
        assert f["dnsbl_listed"] is False

    def test_meme_resultat_scan_et_signaux(self):
        """Les deux adaptateurs doivent s'accorder sur un même état."""
        scan = make_scan("a.bj", dmarc=False, dnssec=False, csp=False)
        sig = {
            "email": {"dmarc": scan["dmarc_check"]["data"], "config": scan["email_config"]["data"],
                      "dkim": scan["dkim_check"]["data"]},
            "dns": {"dnssec": scan["dnssec"]["data"]},
            "web": {"security_headers": scan["security_headers"]["data"]},
        }
        fs, fg = features_from_scan(scan), features_from_signals(sig)
        for key in ("dmarc_absent", "spf_absent", "dkim_absent", "dnssec_absent", "csp_absent"):
            assert fs[key] == fg[key], key


class TestHelpers:
    @pytest.mark.parametrize("domain,tld", [
        ("exemple.bj", "bj"), ("Sous.Exemple.FR.", "fr"), ("x.xn--p1ai", "xn--p1ai"),
        ("localhost", "localhost"), ("1.2.3.4", None), ("", None), (None, None),
        ("a.b'--", None),
    ])
    def test_tld_of(self, domain, tld):
        assert tld_of(domain) == tld

    def test_arrondi_5(self):
        rows = [(f"h{i}", "bj", {"dmarc_absent": i < 7}) for i in range(10)]
        stats = _aggregate(rows, "bj", None, 10)
        assert stats["features"]["dmarc_absent"] == {"n": 10, "pct": 70}
        rows = [(f"h{i}", "bj", {"dmarc_absent": i < 2}) for i in range(11)]  # 18,2 %
        assert _aggregate(rows, "bj", None, 10)["features"]["dmarc_absent"]["pct"] == 20

    def test_toutes_les_caracteristiques_ont_un_libelle(self):
        assert len(set(FEATURE_KEYS)) == len(FEATURE_KEYS)
        for key, label in scan_stats.FEATURES:
            assert label and not label.endswith(".")


# ---------------------------------------------------------------------------
# Sécurité
# ---------------------------------------------------------------------------

@pytest.mark.security
class TestAnonymat:
    def test_k_anonymat_sous_le_seuil(self):
        rows = [(f"h{i}", "bj", {"dmarc_absent": True}) for i in range(9)]
        stats = _aggregate(rows, "bj", None, 10)
        assert stats["features"] == {}
        assert stats["sample_size"] is None

    def test_k_anonymat_par_caracteristique(self):
        """Le seuil s'applique au dénominateur de CHAQUE statistique."""
        rows = [(f"h{i}", "bj", {"dmarc_absent": True, "dnssec_absent": True if i < 5 else None})
                for i in range(12)]
        feats = _aggregate(rows, "bj", None, 10)["features"]
        assert "dmarc_absent" in feats
        assert "dnssec_absent" not in feats  # 5 domaines évaluables seulement

    def test_plancher_absolu(self, monkeypatch):
        monkeypatch.setenv("SCAN_STATS_MIN_SAMPLE", "1")
        assert scan_stats.min_sample() == 5
        monkeypatch.setenv("SCAN_STATS_MIN_SAMPLE", "abc")
        assert scan_stats.min_sample() == 10

    def test_exclusion_du_domaine_courant(self):
        rows = [(f"h{i}", "bj", {"dmarc_absent": True}) for i in range(10)]
        assert _aggregate(rows, "bj", None, 10)["features"]
        # Le domaine courant fait partie des 10 : une fois exclu, plus de stat.
        assert _aggregate(rows, "bj", "h3", 10)["features"] == {}

    def test_tld_hostile_rejete(self, monkeypatch):
        monkeypatch.setattr(scan_stats, "_load_rows", lambda now=None: [])
        for bad in ("bj' OR 1=1--", "%", "b_j", "../etc", "<script>", "a" * 70):
            assert compute_stats(bad)["features"] == {}
            assert compute_stats(bad)["scope"] is None

    def test_aucune_exception(self, monkeypatch):
        def boom(now=None):
            raise RuntimeError("base indisponible")
        monkeypatch.setattr(scan_stats, "_load_rows", boom)
        assert comparative_context("bj", make_signals("x.bj")) == []
        assert comparative_context(None, None) == []
        assert comparative_context("bj", {"domain": 42}) == []


# ---------------------------------------------------------------------------
# Intégration (SQLite de test)
# ---------------------------------------------------------------------------

def _insert(db, domain, result, *, tools="a,b", days_ago=0):
    from models.pass_recon_cache import PassReconCache
    now = datetime.utcnow() - timedelta(days=days_ago)
    db.session.add(PassReconCache(domain=domain, tools_key=tools, result_json=json.dumps(result),
                                  created_at=now, updated_at=now,
                                  expires_at=now + timedelta(days=30)))


@pytest.fixture
def populated(app):
    """12 domaines .bj (8 sans DMARC) + 10 domaines .fr (tous avec DMARC)."""
    from database import db
    for i in range(12):
        _insert(db, f"site{i}.bj", make_scan(f"site{i}.bj", dmarc=i >= 8, dnssec=False))
    for i in range(10):
        _insert(db, f"org{i}.fr", make_scan(f"org{i}.fr", dmarc=True))
    db.session.commit()
    return db


@pytest.mark.integration
class TestIntegration:
    def test_compute_stats_tld(self, populated):
        stats = compute_stats("bj")
        assert stats["scope"] == ".bj"
        assert stats["sample_size"] == 12
        assert stats["features"]["dmarc_absent"] == {"n": 12, "pct": 65}  # 66,7 % → 65
        assert stats["features"]["dnssec_absent"]["pct"] == 100

    def test_compute_stats_global(self, populated):
        stats = compute_stats()
        assert stats["sample_size"] == 22
        assert stats["features"]["dmarc_absent"]["pct"] == 35  # 8/22 = 36,4 %

    def test_dedoublonnage_par_domaine(self, populated):
        from database import db
        # Un second jeu d'outils plus récent pour site0.bj : un seul domaine compté,
        # et c'est le scan le plus récent qui l'emporte.
        _insert(db, "site0.bj", make_scan("site0.bj", dmarc=True), tools="x")
        db.session.commit()
        stats = compute_stats("bj")
        assert stats["sample_size"] == 12
        assert stats["features"]["dmarc_absent"]["pct"] == 60  # 7/12 = 58,3 %

    def test_fenetre_glissante(self, populated):
        from database import db
        for i in range(5):
            _insert(db, f"vieux{i}.bj", make_scan(f"vieux{i}.bj"), days_ago=400)
        db.session.commit()
        assert compute_stats("bj")["sample_size"] == 12

    def test_comparative_context_tld(self, populated):
        sentences = comparative_context("bj", make_signals("nouveau.bj"))
        assert sentences
        joined = " ".join(sentences)
        assert "domaines .bj" in joined
        assert any("DMARC" in s and "65 %" in s for s in sentences)
        assert len(sentences) <= scan_stats.MAX_SENTENCES

    @pytest.mark.security
    def test_aucun_domaine_dans_la_sortie(self, populated):
        sentences = comparative_context(".bj", make_signals("site3.bj"))
        stats_json = json.dumps([compute_stats("bj"), compute_stats(), compute_stats("fr")])
        blob = " ".join(sentences) + stats_json
        for name in [f"site{i}" for i in range(12)] + [f"org{i}" for i in range(10)]:
            assert name not in blob
        assert "nouveau" not in blob

    @pytest.mark.security
    def test_domaine_courant_exclu_de_sa_comparaison(self, populated):
        # 12 domaines .bj ; si site3.bj est le domaine analysé, il en reste 11.
        sentences = comparative_context("bj", make_signals("site3.bj"))
        assert any("échantillon : 11" in s for s in sentences)

    def test_repli_tous_tld(self, populated):
        """TLD sous le seuil → statistique tous TLD."""
        from database import db
        for i in range(3):
            _insert(db, f"x{i}.ci", make_scan(f"x{i}.ci", dmarc=False))
        db.session.commit()
        sentences = comparative_context("ci", make_signals("autre.ci"))
        assert sentences
        assert all(".ci" not in s for s in sentences)
        assert any("tous TLD" in s for s in sentences)

    @pytest.mark.security
    def test_base_trop_petite_rien(self, app):
        from database import db
        for i in range(4):
            _insert(db, f"p{i}.bj", make_scan(f"p{i}.bj", dmarc=False))
        db.session.commit()
        assert comparative_context("bj", make_signals("q.bj")) == []
        assert compute_stats("bj")["features"] == {}

    def test_cache_incremental(self, populated, monkeypatch):
        compute_stats("bj")
        calls = []
        real = scan_stats.features_from_scan
        monkeypatch.setattr(scan_stats, "features_from_scan",
                            lambda r: calls.append(1) or real(r))
        compute_stats("bj")
        assert calls == []  # rien n'a changé : aucun result_json relu

    def test_json_corrompu_ignore(self, populated):
        from database import db
        from models.pass_recon_cache import PassReconCache
        now = datetime.utcnow()
        db.session.add(PassReconCache(domain="casse.bj", tools_key="a", result_json="{pas du json",
                                      created_at=now, updated_at=now,
                                      expires_at=now + timedelta(days=1)))
        db.session.commit()
        stats = compute_stats("bj")
        assert stats["features"]["dmarc_absent"]["n"] == 12
