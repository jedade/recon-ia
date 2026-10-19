# tests/test_phase5_security.py
"""
Tests de sécurité de la phase 5 (marqueur `security`) :
  - anti-SSRF : les outils HTTP passent par la session gardée `recon._http` ;
  - masquage des secrets : clés/token jamais renvoyés, même en cas d'erreur ;
  - robustesse : réponses géantes ou malformées → statut d'erreur, jamais
    d'exception ni de fuite mémoire.

Aucun réseau (--network none) : tout est simulé.
"""
import json

import pytest

import routes.recon as recon
from utils.passive_sources import (
    reputation, discovery, github_dorks, threats, ranking, ResponseTooLarge, read_bounded,
)
from utils.passive_sources import InvalidResponse, read_json

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Réponses hostiles simulées
# ---------------------------------------------------------------------------
class GiantResp:
    """Réponse qui diffuse indéfiniment : ne doit jamais être lue en entier."""
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def iter_content(self, chunk_size=65536):
        while True:
            yield b"A" * chunk_size

    def close(self):
        pass


class MalformedResp:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    text = "{this is : not json,,,"

    def iter_content(self, chunk_size=65536):
        yield self.text.encode()

    @property
    def content(self):
        return self.text.encode()

    def close(self):
        pass


class OneResp:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        return self.resp

    def post(self, url, **kw):
        self.calls.append(url)
        return self.resp


# ---------------------------------------------------------------------------
# Robustesse : réponses géantes / malformées
# ---------------------------------------------------------------------------
class TestHostileResponses:
    def test_read_bounded_stops_on_infinite_stream(self):
        with pytest.raises(ResponseTooLarge):
            read_bounded(GiantResp(), max_bytes=1024)

    def test_virustotal_giant_response_is_error_not_crash(self):
        res = reputation.check_reputation(OneResp(GiantResp()), "example.com", api_key="k")
        assert res["status"] in ("error", "limited")

    def test_dnsdumpster_malformed_json_is_error(self):
        res = discovery.check_dnsdumpster(OneResp(MalformedResp()), "example.com", api_key="k")
        assert res["status"] == "error"

    def test_tranco_malformed_json_is_error(self):
        res = ranking.check_tranco(OneResp(MalformedResp()), "example.com")
        assert res["status"] == "error"

    def test_github_dorks_malformed_does_not_crash(self):
        res = github_dorks.search_dorks(OneResp(MalformedResp()), "example.com",
                                        token="t", max_queries=1)
        assert res["status"] in ("no_data", "success")


# ---------------------------------------------------------------------------
# Masquage des secrets
# ---------------------------------------------------------------------------
class TestSecretMasking:
    def test_github_token_never_in_result_on_error(self):
        token = "ghp_SUPERSECRETTOKEN0000000000000000000000"

        class Boom:
            def get(self, url, **kw):
                raise RuntimeError(f"connection failed using {token}")
        res = github_dorks.search_dorks(Boom(), "example.com", token=token, max_queries=1)
        assert token not in json.dumps(res)

    def test_virustotal_key_never_in_result_on_error(self):
        key = "VT_SECRET_KEY_ABCDEF"

        class Boom:
            def get(self, url, **kw):
                raise RuntimeError(f"failed with x-apikey={key}")
        res = reputation.check_reputation(Boom(), "example.com", api_key=key)
        assert key not in json.dumps(res)

    def test_dnsdumpster_key_masked_on_error(self):
        key = "DNSDUMPSTER_SECRET_123456"

        class Boom:
            def get(self, url, **kw):
                raise RuntimeError(f"boom {key}")
        res = discovery.check_dnsdumpster(Boom(), "example.com", api_key=key)
        assert key not in json.dumps(res)

    def test_github_dorks_never_stores_secret_values(self):
        aws = "AKIAIOSFODNN7EXAMPLE"

        class Resp:
            status_code = 200
            headers = {"Content-Type": "application/json"}

            def iter_content(self, chunk_size=65536):
                yield json.dumps({"items": [{
                    "repository": {"full_name": "a/b"}, "path": "p.env",
                    "html_url": "https://github.com/a/b/p.env",
                    "text_matches": [{"fragment": f"key={aws}"}],
                }]}).encode()

            def close(self):
                pass

        class HTTP:
            def get(self, url, **kw):
                return Resp()
        res = github_dorks.search_dorks(HTTP(), "example.com", token="t", max_queries=1)
        assert aws not in json.dumps(res)


# ---------------------------------------------------------------------------
# Anti-SSRF : les wrappers utilisent la session gardée partagée
# ---------------------------------------------------------------------------
class TestWrappersUseGuardedSession:
    @pytest.mark.parametrize("wrapper", [
        "_virustotal_tool", "_dnsdumpster_tool", "_grayhatwarfare_tool",
        "_github_dorks_tool", "_threats_tool", "_site_ranking_tool", "_web_metadata_tool",
    ])
    def test_wrapper_passes_shared_http(self, wrapper, monkeypatch):
        """Chaque wrapper HTTP doit transmettre recon._http (session anti-SSRF)."""
        captured = {}

        def spy(http, domain, *a, **k):
            captured["http"] = http
            return {"status": "skipped", "data": {}, "raw_output": ""}

        # Redirige la fonction du module sous-jacent vers l'espion
        mapping = {
            "_virustotal_tool": ("reputation", "check_reputation"),
            "_dnsdumpster_tool": ("discovery", "check_dnsdumpster"),
            "_grayhatwarfare_tool": ("discovery", "check_grayhatwarfare"),
            "_github_dorks_tool": ("github_dorks", "search_dorks"),
            "_threats_tool": ("threats", "check_threats"),
            "_site_ranking_tool": ("ranking", "check_ranking"),
            "_web_metadata_tool": ("webpage", "analyze_homepage"),
        }
        mod_attr, func = mapping[wrapper]
        module = getattr(recon, f"_{mod_attr}")
        monkeypatch.setattr(module, func, spy)
        getattr(recon, wrapper)("example.com")
        assert captured["http"] is recon._http

    def test_blocklists_never_queries_target_host(self, monkeypatch):
        """block-lists n'émet que des requêtes DNS vers des résolveurs, pas vers la cible."""
        seen = []

        def fake_query_at(ns, name, rtype="A"):
            seen.append((ns, name))
            return ["93.184.216.34"]
        monkeypatch.setattr(recon, "_dns_query_at", fake_query_at)
        recon._blocklists_tool("example.com")
        # Toutes les requêtes ciblent un résolveur connu, jamais une connexion à la cible
        from utils.passive_sources import blocklists as bl
        known = {bl.REFERENCE_RESOLVER} | {ip for _, ip in bl.FILTERING_RESOLVERS}
        assert all(ns in known for ns, _ in seen)
