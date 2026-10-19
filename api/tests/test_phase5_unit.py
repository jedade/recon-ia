# tests/test_phase5_unit.py
"""
Tests unitaires des outils de la phase 5 (collecte passive enrichie).

Aucun réseau : toutes les réponses HTTP/DNS sont simulées. La suite tourne avec
--network none.
"""
import io
import json

import pytest

from utils.passive_sources import (
    dns_mass, blocklists, threats, ranking, reputation, discovery, github_dorks, webpage,
)
from utils.passive_sources import read_bounded, read_json, ResponseTooLarge, scrub
import utils.signals_extra as signals_extra


# ---------------------------------------------------------------------------
# Fausse réponse HTTP (compatible read_bounded / read_json)
# ---------------------------------------------------------------------------
class FakeResp:
    def __init__(self, status_code=200, json_data=None, text=None, headers=None,
                 set_cookies=None):
        self.status_code = status_code
        if json_data is not None:
            self._body = json.dumps(json_data).encode()
            self.text = json.dumps(json_data)
        else:
            self.text = text or ""
            self._body = self.text.encode()
        self.headers = headers or {}
        self.cookies = []
        self._set_cookies = set_cookies or []

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    @property
    def content(self):
        return self._body

    def close(self):
        pass


class FakeRaw:
    """Simule urllib3 HTTPResponse.headers.get_all('Set-Cookie')."""
    def __init__(self, cookies):
        self.headers = self

    def get_all(self, name):
        return self._cookies if name.lower() == "set-cookie" else []


class FakeHTTP:
    """Session HTTP simulée : renvoie des réponses programmées par URL ou en file."""
    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def _pick(self, url):
        self.calls.append(url)
        for frag, resp in self.responses.items():
            if frag in url:
                return resp
        if self.default is not None:
            return self.default
        return FakeResp(404, text="")

    def get(self, url, **kw):
        return self._pick(url)

    def post(self, url, **kw):
        return self._pick(url)


# ---------------------------------------------------------------------------
# Helpers de lecture bornée
# ---------------------------------------------------------------------------
class TestBoundedReads:
    def test_read_bounded_ok(self):
        assert read_bounded(FakeResp(text="hello")) == b"hello"

    def test_read_bounded_rejects_large_body(self):
        big = FakeResp(text="x" * 100)
        with pytest.raises(ResponseTooLarge):
            read_bounded(big, max_bytes=10)

    def test_read_bounded_rejects_declared_content_length(self):
        resp = FakeResp(text="small", headers={"Content-Length": "999999999"})
        with pytest.raises(ResponseTooLarge):
            read_bounded(resp, max_bytes=1024)

    def test_read_json_rejects_bad_json(self):
        from utils.passive_sources import InvalidResponse
        with pytest.raises(InvalidResponse):
            read_json(FakeResp(text="{not json"))

    def test_scrub_removes_secret(self):
        assert "SECRETVALUE" not in scrub("error with SECRETVALUE token", "SECRETVALUE")


# ---------------------------------------------------------------------------
# dns_mass (B4)
# ---------------------------------------------------------------------------
class TestDnsMass:
    def _query(self, mapping):
        def q(name, rtype):
            key = (name, rtype)
            if name in mapping and mapping[name] == "NX":
                raise dns_mass.NXDomain(name)
            val = mapping.get(key)
            if val is None:
                raise dns_mass.NoAnswer(name)
            return val
        return q

    def test_alive_dead_and_cdn(self):
        mapping = {
            ("www.example.com", "A"): ["93.184.216.34"],
            ("www.example.com", "AAAA"): None,
            ("www.example.com", "CNAME"): ["example.map.fastly.net"],
            ("gone.example.com", "A"): None,  # -> NoAnswer -> no_address
            "dead.example.com": "NX",
            ("example.com", "A"): ["93.184.216.34"],
        }

        def q(name, rtype):
            if mapping.get(name) == "NX":
                raise dns_mass.NXDomain(name)
            val = mapping.get((name, rtype), None)
            if val is None:
                raise dns_mass.NoAnswer(name)
            return val

        res = dns_mass.resolve_subdomains(
            q, ["www.example.com", "dead.example.com", "gone.example.com", "example.com"],
            max_asn_lookups=0,
        )
        assert res["status"] == "success"
        by = {h["subdomain"]: h for h in res["data"]["hosts"]}
        assert by["www.example.com"]["status"] == "alive"
        assert by["www.example.com"]["cdn"] == "Fastly"
        assert by["dead.example.com"]["status"] == "dead"
        assert by["gone.example.com"]["status"] == "no_address"
        assert res["data"]["alive_count"] == 2

    def test_internal_ip_flagged_never_as_global(self):
        def q(name, rtype):
            if rtype == "A":
                return ["10.0.0.5"]
            raise dns_mass.NoAnswer(name)
        res = dns_mass.resolve_subdomains(q, ["intranet.example.com"], max_asn_lookups=0)
        assert "intranet.example.com" in res["data"]["internal_ip_hosts"]

    def test_asn_lookup_cymru(self):
        def q(name, rtype):
            if name == "sub.example.com" and rtype == "A":
                return ["1.2.3.4"]
            if name.endswith("origin.asn.cymru.com"):
                return ['"13335 | 1.2.3.0/24 | US | arin | 2010-01-01"']
            if name.startswith("AS13335"):
                return ['"13335 | US | arin | 2010-01-01 | CLOUDFLARENET, US"']
            raise dns_mass.NoAnswer(name)
        res = dns_mass.resolve_subdomains(q, ["sub.example.com"], max_asn_lookups=5)
        host = res["data"]["hosts"][0]
        assert host["asns"][0]["asn"] == 13335
        # ASN Cloudflare → CDN déduit même sans CNAME
        assert host["cdn"] == "Cloudflare"

    def test_truncation_bounded(self):
        def q(name, rtype):
            raise dns_mass.NoAnswer(name)
        subs = [f"h{i}.example.com" for i in range(10)]
        res = dns_mass.resolve_subdomains(q, subs, max_subdomains=3, max_asn_lookups=0)
        assert res["data"]["count"] == 3
        assert res["data"]["truncated"] == 7


# ---------------------------------------------------------------------------
# blocklists
# ---------------------------------------------------------------------------
class TestBlocklists:
    def test_blocked_by_nxdomain_vs_reference(self):
        def query_at(ns, name, rtype="A"):
            if ns == blocklists.REFERENCE_RESOLVER:
                return ["93.184.216.34"]
            if ns == "9.9.9.9":
                raise blocklists.NXDomain(name)
            return ["93.184.216.34"]
        res = blocklists.check_blocklists(
            query_at, "bad.example.com",
            resolvers=[("Quad9", "9.9.9.9"), ("OpenDNS", "208.67.222.222")],
        )
        assert res["status"] == "success"
        assert "Quad9" in res["data"]["blocked_by"]
        assert res["data"]["is_blocked"] is True

    def test_sinkhole_ip_is_block(self):
        def query_at(ns, name, rtype="A"):
            if ns == blocklists.REFERENCE_RESOLVER:
                return ["93.184.216.34"]
            return ["0.0.0.0"]
        res = blocklists.check_blocklists(
            query_at, "x.example.com", resolvers=[("AdGuard", "94.140.14.14")])
        assert res["data"]["blocked_count"] == 1

    def test_not_blocked_when_all_resolve_normally(self):
        def query_at(ns, name, rtype="A"):
            return ["93.184.216.34"]
        res = blocklists.check_blocklists(
            query_at, "ok.example.com", resolvers=[("Quad9", "9.9.9.9")])
        assert res["data"]["is_blocked"] is False


# ---------------------------------------------------------------------------
# threats (Safe Browsing + PhishTank)
# ---------------------------------------------------------------------------
class TestThreats:
    def test_safe_browsing_skipped_without_key_but_phishtank_runs(self):
        http = FakeHTTP(responses={"checkurl": FakeResp(200, {"results": {"in_database": False}})})
        res = threats.check_threats(http, "example.com", safe_browsing_key="", phishtank_key="")
        assert res["data"]["safe_browsing"]["status"] == "skipped"
        assert res["data"]["phishtank"]["status"] == "success"

    def test_flagged_when_safe_browsing_matches(self):
        http = FakeHTTP(responses={
            "threatMatches": FakeResp(200, {"matches": [{"threatType": "MALWARE",
                                                         "platformType": "ANY_PLATFORM"}]}),
            "checkurl": FakeResp(200, {"results": {"in_database": False}}),
        })
        res = threats.check_threats(http, "bad.example.com",
                                    safe_browsing_key="k", phishtank_key="")
        assert res["data"]["flagged"] is True
        assert res["data"]["risk_level"] == "high"


# ---------------------------------------------------------------------------
# ranking (Tranco + HSTS preload)
# ---------------------------------------------------------------------------
class TestRanking:
    def test_tranco_and_hsts(self):
        http = FakeHTTP(responses={
            "tranco-list": FakeResp(200, {"ranks": [{"rank": 1000}], "rank": 950}),
            "hstspreload": FakeResp(200, {"status": "preloaded"}),
        })
        res = ranking.check_ranking(http, "example.com")
        assert res["data"]["rank"] == 950
        assert res["data"]["hsts_preloaded"] is True

    def test_tranco_404_is_no_data(self):
        http = FakeHTTP(responses={
            "tranco-list": FakeResp(404),
            "hstspreload": FakeResp(200, {"status": "unknown"}),
        })
        res = ranking.check_ranking(http, "obscure.example.com")
        assert res["data"]["tranco"]["status"] == "no_data"


# ---------------------------------------------------------------------------
# reputation (VirusTotal)
# ---------------------------------------------------------------------------
class TestVirusTotal:
    def test_skipped_without_key(self):
        res = reputation.check_reputation(FakeHTTP(), "example.com", api_key="")
        assert res["status"] == "skipped"

    def test_success_parses_stats(self):
        http = FakeHTTP(responses={
            "domains/example.com/resolutions": FakeResp(200, {"data": [
                {"attributes": {"ip_address": "1.2.3.4", "date": 1600000000}}]}),
            "domains/example.com": FakeResp(200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60},
                "reputation": -5,
                "categories": {"engineX": "malware"}}}}),
        })
        res = reputation.check_reputation(http, "example.com", api_key="k")
        assert res["status"] == "success"
        assert res["data"]["domain_stats"]["malicious"] == 2
        assert res["data"]["risk_level"] == "high"
        assert res["data"]["passive_dns"][0]["ip"] == "1.2.3.4"

    def test_limited_on_401(self):
        http = FakeHTTP(responses={"domains/example.com": FakeResp(401)})
        res = reputation.check_reputation(http, "example.com", api_key="bad")
        assert res["status"] == "limited"


# ---------------------------------------------------------------------------
# discovery (DNSDumpster + GrayHatWarfare)
# ---------------------------------------------------------------------------
class TestDiscovery:
    def test_dnsdumpster_skipped_without_key(self):
        assert discovery.check_dnsdumpster(FakeHTTP(), "example.com", api_key="")["status"] == "skipped"

    def test_dnsdumpster_parses_subdomains(self):
        http = FakeHTTP(responses={"domain/example.com": FakeResp(200, {
            "a": [{"host": "www.example.com", "ips": [{"ip": "1.2.3.4"}]},
                  {"host": "api.example.com", "ips": [{"ip": "5.6.7.8"}]}],
            "mx": [{"host": "mail.example.com"}],
            "txt": ["v=spf1 include:_spf.example.com ~all"],
        })})
        res = discovery.check_dnsdumpster(http, "example.com", api_key="k")
        assert res["status"] == "success"
        assert "www.example.com" in res["data"]["subdomains"]
        assert res["data"]["count"] == 2

    def test_grayhatwarfare_skipped_without_key(self):
        assert discovery.check_grayhatwarfare(FakeHTTP(), "example.com", api_key="")["status"] == "skipped"

    def test_grayhatwarfare_parses_files(self):
        http = FakeHTTP(responses={"files": FakeResp(200, {
            "files": [{"bucket": "b", "fullPath": "secret.txt", "size": 10}], "total": 1})})
        res = discovery.check_grayhatwarfare(http, "example.com", api_key="k")
        assert res["data"]["file_count"] == 1


# ---------------------------------------------------------------------------
# github_dorks
# ---------------------------------------------------------------------------
class TestGithubDorks:
    def test_skipped_without_token(self):
        assert github_dorks.search_dorks(FakeHTTP(), "example.com", token="")["status"] == "skipped"

    def test_secret_value_never_stored(self):
        # text_match contient une vraie clé AWS : elle ne doit PAS ressortir en clair
        aws = "AKIAIOSFODNN7EXAMPLE"
        http = FakeHTTP(default=FakeResp(200, {"items": [{
            "repository": {"full_name": "acme/leak"},
            "path": "config/prod.env",
            "html_url": "https://github.com/acme/leak/blob/main/config/prod.env",
            "text_matches": [{"fragment": f"aws key = {aws}"}],
        }]}))
        res = github_dorks.search_dorks(http, "example.com", token="t", max_queries=1)
        blob = json.dumps(res)
        assert aws not in blob
        assert res["data"]["confirmed_secret_count"] >= 1
        assert "AWS Access Key" in res["data"]["secret_types"]
        assert res["data"]["findings"][0]["path"] == "config/prod.env"

    def test_403_quota_returns_limited(self):
        http = FakeHTTP(default=FakeResp(403))
        res = github_dorks.search_dorks(http, "example.com", token="t", max_queries=1)
        assert res["status"] == "limited"


# ---------------------------------------------------------------------------
# webpage (cookies / social / linked), un seul GET
# ---------------------------------------------------------------------------
class TestWebpage:
    def test_cookie_flags_parsed_without_values(self):
        resp = FakeResp(200, headers={"Content-Type": "text/html"})
        resp._set_cookies = []
        # Injecte des Set-Cookie via le repli d'en-tête fusionné
        resp.headers["Set-Cookie"] = "session=abc123secretvalue; Secure; HttpOnly; SameSite=Lax"
        out = webpage.analyze_response(resp, "example.com")
        cookie = out["data"]["cookies"][0]
        assert cookie["name"] == "session"
        assert cookie["secure"] and cookie["http_only"]
        assert cookie["same_site"] == "Lax"
        # La valeur du cookie ne doit jamais apparaître dans le résultat
        assert "abc123secretvalue" not in json.dumps(out["data"]["cookies"])

    def test_insecure_cookie_flagged(self):
        resp = FakeResp(200, headers={"Content-Type": "text/html", "Set-Cookie": "tracker=1"})
        out = webpage.analyze_response(resp, "example.com")
        assert "tracker" in out["data"]["insecure_cookies"]
        assert out["data"]["all_cookies_secure"] is False

    def test_social_tags_and_linked_domains(self):
        html = (
            '<meta property="og:title" content="Hello">'
            '<meta name="twitter:card" content="summary">'
            '<a href="https://cdn.other.com/x.js"></a>'
            '<img src="https://www.example.com/logo.png">'  # même domaine, ignoré
        )
        resp = FakeResp(200, text=html, headers={"Content-Type": "text/html"})
        out = webpage.analyze_response(resp, "example.com")
        assert out["data"]["social_tags"]["og:title"] == "Hello"
        linked = [d["domain"] for d in out["data"]["linked_domains"]]
        assert "cdn.other.com" in linked
        assert "www.example.com" not in linked


# ---------------------------------------------------------------------------
# signals_extra
# ---------------------------------------------------------------------------
class TestSignalsExtra:
    def test_empty_input_returns_full_shape(self):
        sig = signals_extra.extract_extra_signals({})
        for key in ("dns_mass", "blocklists", "threats", "virustotal", "cookies",
                    "ranking", "github_dorks", "grayhatwarfare"):
            assert key in sig
        assert sig["social_tags_present"] is False
        assert sig["linked_domains"] == []

    def test_extracts_compact_signals(self):
        raw = {
            "dns_mass": {"status": "success", "data": {
                "alive_count": 2, "dead_count": 1, "unique_ip_count": 3,
                "cdn_distribution": {"Cloudflare": 2},
                "asns": [{"asn": 13335, "as_name": "CLOUDFLARENET", "ip_count": 2}],
                "internal_ip_hosts": ["intranet.example.com"],
                "hosts": [{"subdomain": "www.example.com", "status": "alive"},
                          {"subdomain": "api.example.com", "status": "alive"},
                          {"subdomain": "old.example.com", "status": "dead"}],
            }},
            "blocklists": {"status": "success", "data": {
                "is_blocked": True, "blocked_count": 3, "blocked_by": ["Quad9", "AdGuard", "OpenDNS"]}},
            "web_metadata": {"status": "success", "data": {
                "cookie_count": 2, "all_cookies_secure": False,
                "insecure_cookies": ["tracker"],
                "social_tags": {"og:title": "x"},
                "linked_domains": [{"domain": "cdn.other.com", "references": 3}]}},
            "virustotal": {"status": "success", "data": {
                "malicious_total": 4, "risk_level": "high", "categories": {"e": "malware"}}},
            "github_dorks": {"status": "success", "data": {
                "match_count": 2, "confirmed_secret_count": 1,
                "secret_types": ["AWS Access Key"],
                "findings": [{"repository": "a/b", "path": "p", "has_secret": True}]}},
        }
        sig = signals_extra.extract_extra_signals(raw)
        assert sig["dns_mass"]["alive_count"] == 2
        assert sig["dns_mass"]["top_live_hosts"] == ["www.example.com", "api.example.com"]
        assert sig["blocklists"]["is_blocked"] is True
        assert sig["cookies"]["insecure"] == ["tracker"]
        assert sig["social_tags_present"] is True
        assert sig["linked_domains"] == ["cdn.other.com"]
        assert sig["virustotal"]["available"] is True
        assert sig["github_dorks"]["locations"] == ["a/b:p"]

    def test_skipped_tools_marked_unavailable(self):
        raw = {"virustotal": {"status": "skipped", "data": {}},
               "github_dorks": {"status": "skipped", "data": {}},
               "grayhatwarfare": {"status": "skipped", "data": {}}}
        sig = signals_extra.extract_extra_signals(raw)
        assert sig["virustotal"]["available"] is False
        assert sig["github_dorks"]["available"] is False
        assert sig["grayhatwarfare"]["available"] is False
