# tests/test_attack_surface.py
"""
`build_attack_surface` (plan d'action, phase 0, bug B1) : les ports Shodan
étaient lus à la racine de `signals` alors que `_extract_signals` les range
sous `signals["network"]`, d'où un `exposed_services` toujours vide.
"""
from routes.analyze import _extract_signals
from utils.attack_surface import build_attack_surface


def _scan(ports):
    """Résultat brut minimal de pass_recon, tel que stocké en BD."""
    return {
        "domain": "example.com",
        "shodan_internetdb": {"status": "success", "data": {"ports": ports}},
        "all_subdomains": {"data": ["a.example.com", "b.example.com"], "count": 2},
        "tech_stack": {"status": "success", "data": {"server": "nginx", "cms": ["WordPress"]}},
    }


class TestExposedServices:
    def test_ports_from_real_signals_are_reported(self):
        """Chaîne réelle : scan brut → _extract_signals → attack_surface."""
        surface = build_attack_surface(_extract_signals(_scan([22, 443])))
        services = [s["service_type"] for s in surface["exposed_services"]]
        assert services == ["port 22", "port 443"]
        assert all(s["host"] == "example.com" for s in surface["exposed_services"])

    def test_legacy_root_level_still_supported(self):
        surface = build_attack_surface({"domain": "x.tld", "shodan_internetdb": {"ports": [80]}})
        assert [s["service_type"] for s in surface["exposed_services"]] == ["port 80"]

    def test_no_shodan_data(self):
        assert build_attack_surface({"domain": "x.tld"})["exposed_services"] == []

    def test_other_fields_unchanged(self):
        surface = build_attack_surface(_extract_signals(_scan([])))
        assert surface["total_subdomains"] == 2
        assert "nginx" in surface["technologies"]
        assert "WordPress" in surface["technologies"]
