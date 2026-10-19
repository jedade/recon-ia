"""
Graphiques du rapport PDF (utils/pdf_visuals.py) et structure du rapport :
couverture sans score, synthèse avec jauge et graphiques, carte des serveurs.
"""
from types import SimpleNamespace

import pytest
from reportlab.graphics.shapes import Drawing, String
from reportlab.platypus import Paragraph

from utils import pdf_generator as pg
from utils import pdf_visuals as pv


def _ip_info(*ips):
    return {'ip_info': {'status': 'success', 'meta': {'tool': 'IP'}, 'data': {'ips': list(ips)}}}


def _strings(drawing):
    out = []

    def walk(node):
        for child in getattr(node, 'contents', []) or []:
            if isinstance(child, String):
                out.append(child.text)
            walk(child)
    walk(drawing)
    return out


class TestGauge:
    def test_score_and_grade_drawn(self):
        texts = _strings(pv.score_gauge(72, 'C'))
        assert '72' in texts and 'Note C' in texts

    def test_missing_score(self):
        assert 'n/a' in _strings(pv.score_gauge(None))

    @pytest.mark.parametrize('score', [-20, 0, 100, 250])
    def test_out_of_range_scores_are_clamped(self, score):
        assert isinstance(pv.score_gauge(score, 'X'), Drawing)


class TestCharts:
    def test_severity_parts_count_and_ignore_unknown(self):
        parts = dict((label, n) for label, n, _ in pv.severity_parts(
            [{'severity': 'high'}, {'severity': 'HIGH'}, {'severity': 'LOW'}, {'severity': 'bogus'}, None]))
        assert parts['Élevée'] == 2 and parts['Faible'] == 1 and sum(parts.values()) == 3

    def test_donut_with_no_data(self):
        assert isinstance(pv.donut([('a', 0, pv.CYAN)], '0', 'X'), Drawing)

    def test_category_bars_none_without_findings(self):
        assert pv.category_bars([]) is None
        assert isinstance(pv.category_bars([{'category': 'Email'}]), Drawing)

    def test_status_parts(self):
        scan = {'a': {'meta': {'tool': 'A'}, 'status': 'success'}, 'b': {'meta': {'tool': 'B'}, 'status': 'error'},
                'cache': {'hit': False}}
        parts, ok, total = pv.status_parts(scan)
        assert (ok, total) == (1, 2)


class TestGeo:
    def test_points_grouped_by_place(self):
        pts = pv.geo_points(_ip_info(
            {'ip': '1.1.1.1', 'loc': '48.85,2.35', 'city': 'Paris', 'country': 'FR', 'org': 'AS16276 OVH SAS'},
            {'ip': '1.1.1.2', 'loc': '48.85,2.35', 'city': 'Paris', 'country': 'FR', 'org': 'AS16276 OVH SAS'}))
        assert len(pts) == 1 and pts[0]['ips'] == ['1.1.1.1', '1.1.1.2'] and pts[0]['orgs'] == ['OVH SAS']

    @pytest.mark.security
    @pytest.mark.parametrize('loc', ['abc', '95,10', '10,200', '', None, '1;2'])
    def test_invalid_locations_ignored(self, loc):
        assert pv.geo_points(_ip_info({'ip': '1.1.1.1', 'loc': loc})) == []

    @pytest.mark.security
    def test_hostile_city_drawn_as_plain_text(self):
        """Une valeur venue de la cible n'est qu'une chaîne dessinée, jamais du balisage."""
        pts = pv.geo_points(_ip_info({'ip': '1.1.1.1', 'loc': '6.37,2.39', 'city': '<b>Cotonou</b>', 'country': 'BJ'}))
        texts = _strings(pv.world_map(pts))
        assert any('<b>Cotonou</b>' in t for t in texts)

    def test_world_map_none_without_points(self):
        assert pv.world_map([]) is None

    def test_land_data_present(self):
        assert len(pv._land_rings()) > 100


class TestInfraGraph:
    def test_graph_nodes(self):
        scan = {**_ip_info({'ip': '1.1.1.1', 'org': 'AS1 Hébergeur'}),
                'dns_records': {'status': 'success', 'data': {'A': ['1.1.1.1']}},
                'dns_mass': {'status': 'success', 'data': {'hosts': [
                    {'subdomain': 'www.ex.bj', 'status': 'alive', 'ips': ['1.1.1.1']},
                    {'subdomain': 'old.ex.bj', 'status': 'dead', 'ips': []}]}}}
        texts = _strings(pv.infra_graph('ex.bj', scan))
        assert 'ex.bj' in texts and '1.1.1.1' in texts and 'www' in texts and 'old' not in texts

    def test_graph_none_when_nothing_observed(self):
        assert pv.infra_graph('ex.bj', {}) is None


class TestReportStructure:
    def test_cover_has_no_score(self):
        """Comme un rapport d'audit : identification seulement sur la page de garde."""
        story = []
        recon = SimpleNamespace(id=7, domain='ex.bj', firstname='Ada', lastname='Lovelace')
        pg._build_cover(story, {'domain': 'ex.bj', 'security_score': 64, 'security_grade': 'C',
                                'risk_level': 'HIGH', 'findings': [{}] * 9}, recon, {})
        texts = ' '.join(p.getPlainText() for p in story if isinstance(p, Paragraph))
        assert 'ex.bj' in texts and '64' not in texts and 'HIGH' not in texts

    def test_full_pdf_with_visuals(self):
        scan = {**_ip_info({'ip': '1.1.1.1', 'loc': '48.85,2.35', 'city': 'Paris', 'country': 'FR'}),
                'dns_records': {'status': 'success', 'data': {'A': ['1.1.1.1']}}}
        pdf = pg.generate_pdf({'domain': 'ex.bj', 'security_score': 64, 'security_grade': 'C',
                               'findings': [{'id': 'A', 'title': 'DMARC absent', 'severity': 'HIGH', 'category': 'Email'}]},
                              recon=SimpleNamespace(id=7, domain='ex.bj', firstname='A', lastname='B', email='a@b.c'),
                              scan_data=scan)
        assert pdf.startswith(b'%PDF') and len(pdf) > 20000
