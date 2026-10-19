"""
Couverture de l'analyse : un outil compte comme examiné s'il est cité par un
constat ou un point fort, s'il a un avis du modèle (tool_reviews), ou si une
règle de sévérité a lu ses données. Avis validés côté serveur.
"""
import pytest

from routes.analyze import _sanitize_tool_reviews
from utils.coverage_check import compute_coverage_check
from utils.severity_rules import detect_observations


def _scan(*keys, status='success'):
    return {k: {'status': status, 'meta': {'tool': k}, 'data': {'x': 1}} for k in keys}


class TestToolReviewsSanitizer:
    def test_keeps_known_tools_only(self):
        out = _sanitize_tool_reviews([{'tool': 'whois', 'verdict': 'ras', 'note': 'ok'},
                                      {'tool': 'inexistant', 'verdict': 'ras'}], _scan('whois'))
        assert [r['tool'] for r in out] == ['whois']

    def test_one_review_per_tool_and_verdict_enum(self):
        out = _sanitize_tool_reviews([{'tool': 'whois', 'verdict': 'RAS'}, {'tool': 'whois', 'verdict': 'info'},
                                      {'tool': 'dnssec', 'verdict': 'pirate'}], _scan('whois', 'dnssec'))
        assert out == [{'tool': 'whois', 'verdict': 'ras', 'note': ''}, {'tool': 'dnssec', 'verdict': 'info', 'note': ''}]

    @pytest.mark.security
    def test_failed_tools_cannot_be_reviewed(self):
        """Un outil en échec n'a pas de données : un avis dessus serait inventé."""
        assert _sanitize_tool_reviews([{'tool': 'whois', 'verdict': 'ras'}], _scan('whois', status='error')) == []

    @pytest.mark.security
    def test_note_is_bounded_and_not_a_container(self):
        out = _sanitize_tool_reviews([{'tool': 'whois', 'verdict': 'ras', 'note': 'x' * 5000},
                                      'pas un objet', None], _scan('whois'))
        assert len(out) == 1 and len(out[0]['note']) <= 200

    @pytest.mark.parametrize('value', [None, 'texte', 42, {'tool': 'whois'}])
    def test_invalid_container(self, value):
        assert _sanitize_tool_reviews(value, _scan('whois')) == []


class TestCoverage:
    def test_reviews_and_rules_count_as_examined(self):
        scan = _scan('whois', 'dnssec', 'dns_mass', 'blocklists')
        report = {'findings': [], 'strengths': [], 'tool_reviews': [{'tool': 'whois', 'verdict': 'ras'}]}
        cov = compute_coverage_check(report, scan, rule_examined=['dnssec'])
        assert cov['tools_covered_count'] == 2 and cov['coverage_pct'] == 50.0
        assert cov['tools_covered_by_model'] == 1 and cov['tools_covered_by_rules'] == 1
        assert cov['tools_unreferenced'] == ['blocklists', 'dns_mass']

    def test_full_coverage(self):
        scan = _scan('whois', 'dnssec')
        report = {'findings': [{'source_tool': 'whois'}], 'tool_reviews': [{'tool': 'dnssec', 'verdict': 'ras'}]}
        cov = compute_coverage_check(report, scan)
        assert cov['coverage_pct'] == 100.0 and cov['tools_unreferenced'] == []

    def test_model_coverage_kept_separately(self):
        scan = _scan('whois', 'dnssec')
        cov = compute_coverage_check({'findings': []}, scan, rule_examined=['whois', 'dnssec'])
        assert cov['coverage_pct'] == 100.0 and cov['model_coverage_pct'] == 0.0

    def test_rules_only_count_tools_with_data(self):
        cov = compute_coverage_check({'findings': []}, _scan('whois'), rule_examined=['dnssec'])
        assert cov['tools_covered_by_rules'] == 0


class TestRulesTrackExaminedTools:
    def test_examined_tools_reported(self):
        scan = {'dmarc_check': {'status': 'success', 'data': {'present': False}},
                'dnssec': {'status': 'success', 'data': {'enabled': True}},
                'whois': {'status': 'error', 'data': {}}}
        tools = detect_observations(scan)['_examined_tools']['tools']
        assert 'dmarc_check' in tools and 'dnssec' in tools and 'whois' not in tools

    def test_tracking_is_reset_between_calls(self):
        detect_observations({'dnssec': {'status': 'success', 'data': {'enabled': True}}})
        assert detect_observations({})['_examined_tools']['tools'] == []
