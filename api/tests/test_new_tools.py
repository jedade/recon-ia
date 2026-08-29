# tests/test_new_tools.py
"""
Tests des outils de reconnaissance passive ajoutés en phase 2 :
shodan_internetdb, otx_passive_dns, rdap_info
ainsi que l'extension `historical_urls` de archive_history.

Les appels réseau sont systématiquement mockés — aucun test ne sort sur Internet.
"""
import pytest
from unittest.mock import patch, MagicMock

import requests

from routes.recon import (
    TOOLS_REGISTRY,
    _shodan_internetdb,
    _otx_passive_dns,
    _rdap_info,
    _archive_history,
)


def _resp(status_code=200, json_data=None, text=None):
    """Fabrique une fausse réponse requests."""
    r = MagicMock()
    r.status_code = status_code
    r.text = text if text is not None else str(json_data)
    r.json.return_value = json_data
    r.raise_for_status.return_value = None
    return r


# ---------------------------------------------------------------------------
# Registre & orchestration
# ---------------------------------------------------------------------------

class TestRegistry:
    NEW_TOOLS = ['shodan_internetdb', 'otx_passive_dns', 'rdap_info']

    def test_new_tools_in_registry(self):
        for tool in self.NEW_TOOLS:
            assert tool in TOOLS_REGISTRY, f"{tool} absent de TOOLS_REGISTRY"

    def test_registry_metadata_complete(self):
        for tool in self.NEW_TOOLS:
            meta = TOOLS_REGISTRY[tool]
            assert meta.get('tool'), f"{tool}: meta.tool manquant"
            assert meta.get('category'), f"{tool}: meta.category manquant"
            assert meta.get('description'), f"{tool}: meta.description manquant"
            assert isinstance(meta.get('indicators'), dict) and meta['indicators']

    def test_archive_history_declares_historical_urls(self):
        assert 'historical_urls' in TOOLS_REGISTRY['archive_history']['indicators']


# ---------------------------------------------------------------------------
# shodan_internetdb
# ---------------------------------------------------------------------------

class TestShodanInternetDB:
    PAYLOAD = {
        "ip": "1.2.3.4",
        "ports": [80, 443, 22],
        "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
        "vulns": ["CVE-2021-23017"],
        "hostnames": ["www.example.com"],
        "tags": ["cdn"],
    }

    def test_success(self):
        with patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)) as g:
            res = _shodan_internetdb('example.com', ips=['1.2.3.4'])
        assert res['status'] == 'success'
        assert res['data']['ports'] == [22, 80, 443]
        assert res['data']['vulns'] == ['CVE-2021-23017']
        assert res['data']['cpes'] == ['cpe:/a:nginx:nginx:1.18.0']
        assert res['data']['ips'][0]['status'] == 'success'
        # _shodan_internetdb enchaîne un appel d'enrichissement CVE (circl.lu) :
        # on vérifie le PREMIER appel, pas le dernier.
        assert 'internetdb.shodan.io/1.2.3.4' in g.call_args_list[0][0][0]

    def test_reuses_ips_without_dns_resolution(self):
        """Les IP fournies par ip_info sont réutilisées : aucune résolution DNS."""
        with patch('routes.recon._resolve_ips') as resolve, \
             patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)):
            _shodan_internetdb('example.com', ips=['1.2.3.4'])
        resolve.assert_not_called()

    def test_resolves_when_no_ip_given(self):
        with patch('routes.recon._resolve_ips', return_value=['5.6.7.8']) as resolve, \
             patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)):
            res = _shodan_internetdb('example.com')
        resolve.assert_called_once()
        assert res['status'] == 'success'

    def test_404_is_no_data_not_error(self):
        with patch('routes.recon._http.get', return_value=_resp(404, None, text='not found')):
            res = _shodan_internetdb('example.com', ips=['1.2.3.4'])
        assert res['status'] == 'no_data'
        assert res['data']['ips'][0]['status'] == 'no_data'

    def test_no_ipv4_returns_error(self):
        with patch('routes.recon._resolve_ips', return_value=[]):
            res = _shodan_internetdb('example.com', ips=['2001:db8::1'])
        assert res['status'] == 'error'

    def test_timeout(self):
        with patch('routes.recon._http.get', side_effect=requests.exceptions.Timeout()):
            res = _shodan_internetdb('example.com', ips=['1.2.3.4'])
        assert res['data']['ips'][0]['status'] == 'timeout'


# ---------------------------------------------------------------------------
# otx_passive_dns
# ---------------------------------------------------------------------------

class TestOtxPassiveDns:
    PAYLOAD = {
        "passive_dns": [
            {"address": "1.2.3.4", "hostname": "example.com",
             "record_type": "A", "first": "2019-01-01T00:00:00", "last": "2020-01-01T00:00:00"},
            {"address": "5.6.7.8", "hostname": "www.example.com",
             "record_type": "A", "first": "2020-01-02T00:00:00", "last": "2026-01-01T00:00:00"},
        ]
    }

    def test_success_without_key(self, monkeypatch):
        monkeypatch.delenv('OTX_API_KEY', raising=False)
        with patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)) as g:
            res = _otx_passive_dns('example.com')
        assert res['status'] == 'success'
        assert res['data']['count'] == 2
        assert res['data']['unique_ips'] == ['1.2.3.4', '5.6.7.8']
        assert res['data']['authenticated'] is False
        assert 'X-OTX-API-KEY' not in g.call_args.kwargs['headers']

    def test_api_key_sent_as_header(self, monkeypatch):
        monkeypatch.setenv('OTX_API_KEY', 'secret-key')
        with patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)) as g:
            res = _otx_passive_dns('example.com')
        assert g.call_args.kwargs['headers']['X-OTX-API-KEY'] == 'secret-key'
        assert res['data']['authenticated'] is True

    @pytest.mark.parametrize('code', [401, 403])
    def test_auth_error_returns_limited(self, monkeypatch, code):
        monkeypatch.delenv('OTX_API_KEY', raising=False)
        with patch('routes.recon._http.get', return_value=_resp(code, None, text='forbidden')):
            res = _otx_passive_dns('example.com')
        assert res['status'] == 'limited'
        assert 'OTX_API_KEY' in res['error']

    def test_404_returns_no_data(self, monkeypatch):
        monkeypatch.delenv('OTX_API_KEY', raising=False)
        with patch('routes.recon._http.get', return_value=_resp(404, None, text='nope')):
            res = _otx_passive_dns('example.com')
        assert res['status'] == 'no_data'

    def test_timeout(self, monkeypatch):
        monkeypatch.delenv('OTX_API_KEY', raising=False)
        with patch('routes.recon._http.get', side_effect=requests.exceptions.Timeout()):
            res = _otx_passive_dns('example.com')
        assert res['status'] == 'timeout'


# ---------------------------------------------------------------------------
# rdap_info
# ---------------------------------------------------------------------------

class TestRdapInfo:
    PAYLOAD = {
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                         ["fn", {}, "text", "RESERVED-IANA"]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@example-registrar.com"]]],
            },
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:44Z"},
        ],
        "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
        "secureDNS": {"delegationSigned": True},
        "port43": "whois.verisign-grs.com",
    }

    def test_success(self):
        with patch('routes.recon._http.get', return_value=_resp(200, self.PAYLOAD)) as g:
            res = _rdap_info('example.com')
        assert res['status'] == 'success'
        d = res['data']
        assert d['registrar'] == 'RESERVED-IANA'
        assert d['registrar_iana_id'] == '376'
        assert d['abuse_email'] == 'abuse@example-registrar.com'
        assert d['events']['registration'] == '1995-08-14T04:00:00Z'
        assert d['events']['expiration'] == '2027-08-13T04:00:00Z'
        assert d['events']['last_changed'] == '2026-08-14T07:01:44Z'
        assert d['nameservers'] == ['a.iana-servers.net', 'b.iana-servers.net']
        assert d['dnssec_delegated'] is True
        assert d['status'] == ['client transfer prohibited']
        assert 'rdap.org/domain/example.com' in g.call_args[0][0]

    @pytest.mark.parametrize('code', [404, 400, 501])
    def test_tld_without_rdap_returns_unavailable(self, code):
        with patch('routes.recon._http.get', return_value=_resp(code, None, text='')):
            res = _rdap_info('example.xyzzy')
        assert res['status'] == 'unavailable'

    def test_server_error(self):
        with patch('routes.recon._http.get', return_value=_resp(500, None, text='boom')):
            res = _rdap_info('example.com')
        assert res['status'] == 'error'

    def test_timeout(self):
        with patch('routes.recon._http.get', side_effect=requests.exceptions.Timeout()):
            res = _rdap_info('example.com')
        assert res['status'] == 'timeout'

    def test_coexists_with_whois_in_registry(self):
        """RDAP est complémentaire de WHOIS : les deux restent enregistrés."""
        assert 'whois' in TOOLS_REGISTRY and 'rdap_info' in TOOLS_REGISTRY


# ---------------------------------------------------------------------------
# hibp_breaches
# ---------------------------------------------------------------------------


class TestArchiveHistoryUrls:
    FIRST = [["timestamp", "statuscode"], ["20050301120000", "200"]]
    LAST  = [["timestamp", "statuscode"], ["20260701120000", "200"]]
    URLS  = [["original"],
             ["http://example.com/"],
             ["http://example.com/admin"],
             ["http://example.com/admin"],          # doublon → dédupliqué
             ["http://example.com/backup.zip"]]

    def _side_effect(self, url_resp):
        def _get(url, *a, **kw):
            if 'collapse=urlkey' in url:
                return url_resp
            # `limit=-1` (raccourci CDX pour lire la fin de l'index sans scan
            # complet) remplace `reverse=true`, qui ne renvoyait pas le
            # snapshot le plus récent — voir CLAUDE.md.
            if 'limit=-1' in url:
                return _resp(200, self.LAST, text=str(self.LAST))
            if 'showNumPages' in url:
                return _resp(200, None, text='3')
            return _resp(200, self.FIRST, text=str(self.FIRST))
        return _get

    def test_historical_urls_collected_and_deduplicated(self):
        urls_resp = _resp(200, self.URLS, text=str(self.URLS))
        with patch('routes.recon._http.get', side_effect=self._side_effect(urls_resp)):
            res = _archive_history('example.com')
        assert res['status'] == 'success'
        data = res['data']
        assert data['historical_urls'] == [
            'http://example.com/',
            'http://example.com/admin',
            'http://example.com/backup.zip',
        ]
        assert data['historical_urls_count'] == 3
        assert data['historical_urls_truncated'] is False
        # Les champs préexistants ne sont pas écrasés
        assert data['first_snapshot']['date'] == '2005-03-01'
        assert data['last_snapshot']['date'] == '2026-07-01'
        assert data['wayback_url'] == 'https://web.archive.org/web/*/example.com'

    def test_cdx_url_uses_collapse_urlkey(self):
        urls_resp = _resp(200, self.URLS, text=str(self.URLS))
        calls = []

        def _get(url, *a, **kw):
            calls.append(url)
            return self._side_effect(urls_resp)(url, *a, **kw)

        with patch('routes.recon._http.get', side_effect=_get):
            _archive_history('example.com')
        cdx = [u for u in calls if 'collapse=urlkey' in u]
        assert cdx, "aucune requête CDX avec collapse=urlkey"
        assert 'fl=original' in cdx[0]
        assert 'limit=500' in cdx[0]

    def test_url_query_failure_does_not_break_tool(self):
        def _get(url, *a, **kw):
            if 'collapse=urlkey' in url:
                raise requests.exceptions.Timeout()
            return self._side_effect(None)(url, *a, **kw)

        with patch('routes.recon._http.get', side_effect=_get):
            res = _archive_history('example.com')
        assert res['status'] == 'success'
        assert res['data']['historical_urls'] == []
        assert res['data']['first_snapshot']['date'] == '2005-03-01'


# ---------------------------------------------------------------------------
# Traçabilité outil → conclusion (section « Méthodologie & Sources » du PDF)
# ---------------------------------------------------------------------------

class TestPdfTraceability:
    SCAN = {"data": {
        "domain": "example.com",
        "cache": {"hit": False, "cached_at": "2026-07-27T10:00:00", "scan_duration_s": 12.5},
        "whois": {"meta": {"tool": "WHOIS Lookup", "category": "Domain Intelligence",
                           "description": "Interroge la base WHOIS."},
                  "status": "success", "data": {"registrar": "OVH"}},
        "xposedornot_breaches": {"meta": {"tool": "XposedOrNot — Breached Domain",
                                   "category": "Réputation / Threat Intel",
                                   "description": "Fuites connues."},
                          "status": "skipped", "error": "HIBP_API_KEY non configuré",
                          "data": {"breach_count": 0}},
        "all_subdomains": {"data": [], "count": 0},          # sans meta → ignoré
    }}

    def test_collect_tools_reads_real_metadata(self):
        from utils.pdf_generator import _collect_tools
        tools = _collect_tools(self.SCAN)
        keys = {t['key'] for t in tools}
        assert keys == {'whois', 'xposedornot_breaches'}            # all_subdomains n'a pas de meta
        hibp = next(t for t in tools if t['key'] == 'xposedornot_breaches')
        assert hibp['name'] == 'XposedOrNot — Breached Domain'
        assert hibp['category'] == 'Réputation / Threat Intel'
        assert hibp['status'] == 'skipped'

    def test_tool_meta_builds_title_from_scan(self):
        from utils.pdf_generator import _tool_meta
        title, caption, keys = _tool_meta(self.SCAN['data'], 'whois', 'rdap_info')
        assert title == 'WHOIS Lookup'                        # rdap_info absent du scan
        assert caption == 'Interroge la base WHOIS.'
        assert keys == ['whois']

    def test_pdf_includes_methodology_section(self):
        from utils.pdf_generator import generate_pdf
        analysis = {
            "domain": "example.com", "risk_score": 10, "risk_level": "LOW",
            "executive_summary": "OK",
            "findings": [{
                "id": "DNS-001", "category": "DNS", "severity": "HIGH",
                "title": "DNSSEC absent", "description": "d",
                "evidence": "dnssec.enabled = false",
                "source_tool": "dnssec", "source_tools": ["dnssec", "dns_records"],
                "recommendation": "Activer DNSSEC",
            }],
            "model_used": "test", "analyzed_at": "2026-07-27T11:00:00",
        }
        pdf = generate_pdf(analysis, None, {"scan_duration_s": 12.5}, self.SCAN)
        assert pdf[:4] == b'%PDF' and len(pdf) > 5000
