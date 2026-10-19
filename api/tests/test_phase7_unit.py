# tests/test_phase7_unit.py
"""Unitaires phase 7 : extraction du graphe et différentiel entre scans."""
import copy
from datetime import datetime

from tests.phase7_fixtures import DOMAIN, IP1, IP2, raw_scan
from utils.entity_graph import (
    certificate_id, extract_graph, norm_asn, norm_cve, norm_hostname, norm_ip, norm_port,
)
from utils.scan_diff import diff_scans, extract_snapshot

NOW = datetime(2026, 10, 19, 12, 0, 0)


def _values(graph, etype):
    return {v for t, v in graph['entities'] if t == etype}


def _rels(graph, rtype):
    return {(s[1], t[1]) for (s, t, r) in graph['relations'] if r == rtype}


class TestNormalization:
    def test_hostname(self):
        assert norm_hostname('WWW.Example.COM.') == 'www.example.com'
        assert norm_hostname('*.dev.example.com', 'example.com') == 'dev.example.com'
        assert norm_hostname('evil.other.org', 'example.com') is None
        assert norm_hostname('notexample.com', 'example.com') is None
        assert norm_hostname('a@b.example.com') is None
        assert norm_hostname('bad host.example.com') is None
        assert norm_hostname(None) is None and norm_hostname(42) is None

    def test_ip_only_global(self):
        assert norm_ip(IP1) == IP1
        for bad in ('10.0.0.5', '127.0.0.1', '169.254.169.254', '192.168.1.1', 'abc', '', None):
            assert norm_ip(bad) is None

    def test_misc(self):
        assert norm_asn('AS15133 Edgecast') == 'AS15133' and norm_asn(15133) == 'AS15133'
        assert norm_asn('nope') is None and norm_asn(True) is None
        assert norm_cve('cve-2021-23017') == 'CVE-2021-23017' and norm_cve('CVE-21-1') is None
        assert norm_port('443') == 443 and norm_port(0) is None and norm_port(70000) is None
        assert certificate_id({'serial_number': '0a:bc'}) == 'serial:0ABC'
        assert certificate_id({'not_after': 'x'}).startswith('sha256:')
        assert certificate_id({}) is None


class TestGraphExtraction:
    def test_full_chain(self):
        g = extract_graph(DOMAIN, raw_scan())
        assert _values(g, 'domain') == {DOMAIN}
        assert {'www.example.com', 'api.example.com', 'mail.example.com', 'dev.example.com',
                'shop.example.com'} <= _values(g, 'subdomain')
        assert 'evil.other.org' not in _values(g, 'subdomain')
        assert _values(g, 'ip') == {IP1}                     # 10.0.0.5 écartée
        assert _values(g, 'asn') == {'AS15133'}
        assert _values(g, 'port') == {f'{IP1}:80', f'{IP1}:443'}
        assert _values(g, 'vulnerability') == {'CVE-2021-23017'}
        assert {'nginx/1.18.0', 'WordPress', 'jQuery', 'cpe:/a:nginx:nginx:1.18.0'} <= _values(g, 'technology')
        assert 'Example Corp' in _values(g, 'organization')
        assert _values(g, 'certificate') == {'serial:0ABC1234'}
        # Chaîne organisation → domaine → sous-domaine → IP → ASN …
        assert ('Example Corp', DOMAIN) in _rels(g, 'owns')
        assert (DOMAIN, 'api.example.com') in _rels(g, 'has_subdomain')
        assert (DOMAIN, IP1) in _rels(g, 'resolves_to')
        assert (IP1, 'AS15133') in _rels(g, 'announced_by')
        assert (DOMAIN, 'serial:0ABC1234') in _rels(g, 'presents_certificate')
        assert ('serial:0ABC1234', 'shop.example.com') in _rels(g, 'covers')
        assert (IP1, 'CVE-2021-23017') in _rels(g, 'exposes')
        assert ('www.example.com', IP1) in _rels(g, 'observed_on')

    def test_attributes(self):
        g = extract_graph(DOMAIN, raw_scan())
        assert g['entities'][('vulnerability', 'CVE-2021-23017')]['cvss'] == 7.7
        assert g['entities'][('certificate', 'serial:0ABC1234')]['issuer'] == 'DigiCert Inc'
        assert g['entities'][('ip', IP1)] == {'country': 'US'}   # ni ville ni code postal

    def test_tolerant_to_missing_and_failed_tools(self):
        assert extract_graph(DOMAIN, {})['entities'] == {('domain', DOMAIN): {}}
        assert extract_graph(DOMAIN, None)['entities'] == {}
        assert extract_graph('not a domain', raw_scan())['entities'] == {}
        raw = raw_scan(dns_records={'status': 'error', 'data': {'A': [IP2]}},
                       ssl_info={'status': 'timeout', 'data': {}},
                       shodan_internetdb={'status': 'success', 'data': {'ips': 'pas une liste'}})
        g = extract_graph(DOMAIN, raw)
        assert IP2 not in _values(g, 'ip')           # outil en échec ignoré
        assert not _values(g, 'certificate') and not _values(g, 'port')

    def test_subdomain_resolution_formats(self):
        for data in ({'resolved': {'api.example.com': [IP2]}},
                     {'api.example.com': {'A': [IP2]}},
                     [{'host': 'api.example.com', 'ips': [IP2]}]):
            g = extract_graph(DOMAIN, raw_scan(subdomain_resolution={'status': 'success', 'data': data}))
            assert ('api.example.com', IP2) in _rels(g, 'resolves_to'), data


class TestDiff:
    def test_first_scan_is_baseline(self):
        diff = diff_scans(None, raw_scan(), now=NOW, domain=DOMAIN)
        assert diff['has_previous'] is False
        assert diff['subdomains']['added'] == [] and diff['change_count'] == 0
        assert diff['significant'] is False
        assert diff['certificate']['days_until_expiry'] == 73

    def test_identical_scans(self):
        diff = diff_scans(raw_scan(), raw_scan(), now=NOW, domain=DOMAIN)
        assert diff['has_previous'] and diff['change_count'] == 0 and not diff['significant']
        assert diff['summary'] == []

    def test_detects_all_changes(self):
        prev = raw_scan()
        cur = raw_scan()
        cur['all_subdomains']['data'] = ['www.example.com', 'admin.example.com']
        cur['crtsh']['data']['subdomains'] = []
        cur['ssl_info']['data']['serial_number'] = 'FFFF'
        cur['ssl_info']['data']['not_after'] = 'Nov  2 00:00:00 2026 GMT'
        cur['dmarc_check']['data']['record'] = 'v=DMARC1; p=reject'
        cur['dmarc_check']['data']['policy'] = 'reject'
        cur['email_config']['data']['spf'] = 'v=spf1 +all'
        ip = cur['shodan_internetdb']['data']['ips'][0]
        ip['ports'] = [80, 443, 8080]
        ip['vulns'] = ['CVE-2021-23017', 'CVE-2023-44487']
        cur['dns_records']['data']['A'] = [IP1, IP2]

        diff = diff_scans(prev, cur, now=NOW, domain=DOMAIN)
        assert diff['significant'] is True
        assert diff['subdomains']['added'] == ['admin.example.com']
        assert 'api.example.com' in diff['subdomains']['removed']
        assert diff['ips']['added'] == [IP2]
        assert diff['ports']['added'] == [f'{IP1}:8080']
        assert diff['cves']['added'] == ['CVE-2023-44487']
        assert diff['certificate']['changed'] and diff['certificate']['expiring_soon']
        assert diff['certificate']['days_until_expiry'] == 13
        assert diff['email_security']['dmarc']['changed']
        assert diff['email_security']['dmarc']['current_policy'] == 'reject'
        assert diff['email_security']['spf']['changed']
        assert any('CVE' in s for s in diff['summary'])

    def test_expired_certificate(self):
        cur = raw_scan()
        cur['ssl_info']['data']['not_after'] = 'Oct  1 00:00:00 2026 GMT'
        diff = diff_scans(raw_scan(), cur, now=NOW, domain=DOMAIN)
        assert diff['certificate']['expired'] and diff['significant']

    def test_failed_tool_is_not_a_disappearance(self):
        cur = raw_scan(shodan_internetdb={'status': 'error', 'data': {}},
                       dns_records={'status': 'timeout', 'data': {}})
        cur.pop('all_subdomains')
        cur['crtsh'] = {'status': 'error', 'data': {'subdomains': []}}
        diff = diff_scans(raw_scan(), cur, now=NOW, domain=DOMAIN)
        assert diff['ports']['compared'] is False and diff['ports']['removed'] == []
        assert diff['cves']['compared'] is False
        assert diff['subdomains']['compared'] is False

    def test_removals_alone_not_significant(self):
        cur = raw_scan()
        cur['all_subdomains']['data'] = ['www.example.com']
        diff = diff_scans(raw_scan(), cur, now=NOW, domain=DOMAIN)
        assert diff['subdomains']['removed_count'] >= 1 and diff['significant'] is False

    def test_snapshot_input_and_purity(self):
        prev, cur = raw_scan(), raw_scan()
        before = copy.deepcopy(prev)
        snap = extract_snapshot(prev, DOMAIN)
        assert diff_scans(snap, cur, now=NOW, domain=DOMAIN)['change_count'] == 0
        assert prev == before                      # entrées non modifiées

    def test_snapshot_masks_emails(self):
        snap = extract_snapshot(raw_scan(), DOMAIN)
        assert '@' not in snap['dmarc'] and 'email#' in snap['dmarc']
        assert snap['dmarc_policy'] == 'none'

    def test_malformed_inputs(self):
        for bad in (None, 'x', 42, [], {'ssl_info': 'nope'}, {'shodan_internetdb': {'data': None}}):
            diff = diff_scans(bad, bad, now=NOW, domain=DOMAIN)
            assert isinstance(diff, dict) and diff['change_count'] == 0
