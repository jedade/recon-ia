"""
Raccords entre les phases livrées en parallèle (3 à 8) : chaque module a ses
propres tests, ceux-ci vérifient seulement que les pièces s'emboîtent.
"""
import pytest

from routes.recon import TOOLS_REGISTRY
from utils.mitre_attack import TECHNIQUES, TOOL_TECHNIQUES, load_reference, map_tools_to_techniques
from utils.entity_graph import extract_graph

PHASE5_TOOLS = ('dns_mass', 'blocklists', 'threats_check', 'web_metadata', 'site_ranking',
                'virustotal', 'dnsdumpster', 'grayhatwarfare', 'github_dorks')


class TestPhase5ToMitre:
    @pytest.mark.parametrize('tool', PHASE5_TOOLS)
    def test_new_tool_is_mapped(self, tool):
        assert TOOL_TECHNIQUES.get(tool), f'{tool} sans technique ATT&CK'

    def test_every_mapped_technique_is_described(self):
        """Une technique absente de TECHNIQUES serait ignorée sans bruit."""
        missing = {t for ids in TOOL_TECHNIQUES.values() for t in ids if t not in TECHNIQUES}
        assert not missing

    def test_every_mapped_technique_is_in_reference(self):
        ref = load_reference()['techniques']
        missing = {t for ids in TOOL_TECHNIQUES.values() for t in ids if t not in ref}
        assert not missing

    def test_mapped_tools_exist(self):
        keys = set(TOOLS_REGISTRY)
        assert set(PHASE5_TOOLS) <= keys

    def test_new_tools_produce_techniques(self):
        out = map_tools_to_techniques([{'key': t, 'status': 'success'} for t in PHASE5_TOOLS])
        ids = {t['technique_id'] for t in out}
        assert {'T1593', 'T1596', 'T1552.001'} <= ids


@pytest.mark.integration
class TestDnsMassToGraph:
    def test_dns_mass_hosts_feed_the_graph(self):
        raw = {'dns_mass': {'status': 'success', 'data': {'hosts': [
            {'subdomain': 'www.example.com', 'status': 'alive', 'ips': ['93.184.215.14']},
            {'subdomain': 'old.example.com', 'status': 'dead', 'ips': []},
        ]}}}
        graph = extract_graph('example.com', raw)
        values = set(graph["entities"])
        assert ('subdomain', 'www.example.com') in values
        assert ('ip', '93.184.215.14') in values

    @pytest.mark.security
    def test_private_ip_from_dns_mass_not_in_graph(self):
        raw = {'dns_mass': {'status': 'success', 'data': {'hosts': [
            {'subdomain': 'intra.example.com', 'status': 'alive', 'ips': ['10.0.0.5']},
        ]}}}
        graph = extract_graph('example.com', raw)
        assert ("ip", "10.0.0.5") not in graph["entities"]


# ── Phase 3 ↔ phase 5 / phase 6 : branchements dans l'analyse ────────────────

import routes.analyze as analyze_mod
from utils.severity_rules import detect_observations
from utils.ollama_client import _build_section_data

_SCAN_PHASE5 = {
    'domain': 'example.com',
    'dns_mass': {'status': 'success', 'data': {'hosts': [
        {'subdomain': 'www.example.com', 'status': 'alive', 'ips': ['93.184.215.14']}],
        'alive_count': 1, 'dead_count': 0}},
    'github_dorks': {'status': 'success', 'data': {
        'confirmed_secret_count': 2, 'secret_types': ['aws_access_key'], 'findings': []}},
}


@pytest.mark.integration
class TestAnalysisWiring:
    def test_signals_include_phase5_block(self, app):
        with app.app_context():
            signals = analyze_mod._extract_signals(_SCAN_PHASE5)
        assert 'passive_extra' in signals
        assert signals['passive_extra']['github_dorks']['confirmed_secret_count'] == 2

    def test_stats_failure_never_breaks_signals(self, app, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError('base indisponible')
        monkeypatch.setattr(analyze_mod, 'comparative_context', boom)
        with app.app_context():
            signals = analyze_mod._extract_signals(_SCAN_PHASE5)
        assert 'comparative_context' not in signals
        assert signals['domain'] == 'example.com'

    def test_comparative_context_added_when_available(self, app, monkeypatch):
        monkeypatch.setattr(analyze_mod, 'comparative_context',
                            lambda tld, s: ['Comme ce domaine, 65 % des domaines .com…'])
        with app.app_context():
            signals = analyze_mod._extract_signals(_SCAN_PHASE5)
        assert signals['comparative_context'] == ['Comme ce domaine, 65 % des domaines .com…']

    def test_prompt_tells_model_stats_are_not_evidence(self):
        assert 'comparative_context' in analyze_mod._TRACEABILITY_RULES
        assert 'passive_extra' in analyze_mod._TRACEABILITY_RULES

    def test_github_dorks_secrets_trigger_rule(self):
        obs = detect_observations(_SCAN_PHASE5)
        assert obs['secrets_exposed']['state'] == 'observed'
        assert obs['secrets_exposed']['source_tool'] == 'github_dorks'

    @pytest.mark.security
    def test_bool_secret_count_is_not_a_secret(self):
        scan = {'github_dorks': {'status': 'success', 'data': {'confirmed_secret_count': True}}}
        assert detect_observations(scan).get('secrets_exposed', {}).get('state') != 'observed'

    def test_ollama_sections_receive_phase5_signals(self):
        signals = {'domain': 'example.com', 'passive_extra': {
            'dns_mass': {'alive_count': 3, 'dead_count': 1, 'unique_ip_count': 2},
            'cookies': {'count': 1, 'all_secure': False, 'insecure': ['sid']},
            'blocklists': {'is_blocked': False, 'blocked_count': 0, 'blocked_by': []}}}
        assert _build_section_data('subdomains', signals)['resolution']['alive_count'] == 3
        assert _build_section_data('web_tech', signals)['cookies']['insecure'] == ['sid']
        assert _build_section_data('dns_security', signals)['blocklists']['is_blocked'] is False

    def test_ollama_sections_tolerate_missing_phase5(self):
        data = _build_section_data('network_infra', {'domain': 'example.com'})
        assert data['hosting'] is None and data['virustotal'] is None


# ── Phase 8 ↔ PDF / graphe / analyse ; phase 6 ↔ takeover ────────────────────

import dns.resolver as _dnsr
import routes.recon as recon_mod
from utils.pdf_generator import generate_pdf

_PIVOTS = {'agent_pivots': {'status': 'success', 'meta': {'tool': 'Agent de pivots (IA)', 'category': 'Méthodologie'},
    'data': {
        'status': 'success', 'stop_reason': 'llm_finished',
        'backend': {'name': 'gemini', 'model': 'gemini-2.5-flash'},
        'usage': {'pivots_executed': 1, 'pivots_refused': 1},
        'budget': {'max_pivots': 15, 'max_depth': 2},
        'decisions': [
            {'seq': 1, 'tool': 'resolve_host', 'arguments': {'host': 'api.example.com', 'reason': 'sous-domaine sensible'},
             'reason': 'sous-domaine sensible & exposé', 'outcome': 'executed', 'refusal': None,
             'result_status': 'success', 'result_summary': {'ips': ['93.184.215.20']}},
            {'seq': 2, 'tool': 'resolve_host', 'arguments': {'host': 'evil.org', 'reason': 'x'},
             'reason': 'x', 'outcome': 'refused', 'refusal': {'code': 'out_of_scope'}},
        ],
        'results': [{'seq': 1, 'tool': 'resolve_host', 'registry_key': 'dns_mass', 'target': 'api.example.com',
                     'result': {'status': 'success', 'data': {'hosts': [
                         {'subdomain': 'api.example.com', 'status': 'alive', 'ips': ['93.184.215.20']}]}}}],
    }}}


@pytest.mark.integration
class TestAgentPivotsWiring:
    def test_pdf_contains_agent_journal(self):
        pdf = generate_pdf({'findings': [], 'security_score': 90}, scan_data={'domain': 'example.com', **_PIVOTS})
        assert pdf.startswith(b'%PDF')

    def test_pdf_without_pivots_still_builds(self):
        assert generate_pdf({'findings': []}, scan_data={'domain': 'example.com'}).startswith(b'%PDF')

    def test_graph_replays_pivot_results(self):
        graph = extract_graph('example.com', _PIVOTS)
        assert ('subdomain', 'api.example.com') in graph['entities']
        assert ('ip', '93.184.215.20') in graph['entities']

    @pytest.mark.security
    def test_graph_ignores_out_of_scope_pivot_hosts(self):
        bad = {'agent_pivots': {'status': 'success', 'data': {'results': [
            {'registry_key': 'dns_mass', 'result': {'status': 'success', 'data': {'hosts': [
                {'subdomain': 'www.evil.org', 'status': 'alive', 'ips': ['8.8.8.8']}]}}},
            {'registry_key': 'agent_pivots', 'result': {'status': 'success', 'data': {}}}]}}}
        graph = extract_graph('example.com', bad)
        assert not any(v.endswith('evil.org') for (_, v) in graph['entities'])

    def test_signals_get_executed_pivots_only(self, app):
        with app.app_context():
            signals = analyze_mod._extract_signals({'domain': 'example.com', **_PIVOTS})
        assert [p['tool'] for p in signals['agent_pivots']] == ['resolve_host']
        assert 'raw_output' not in str(signals['agent_pivots'])


class _Rdata:
    def __init__(self, target):
        self.target = target


class TestTakeoverFingerprints:
    def _run(self, monkeypatch, cname, target_nx=False):
        def fake_resolve(name, rtype):
            if rtype == 'CNAME':
                return [_Rdata(cname + '.')]
            if target_nx:
                raise _dnsr.NXDOMAIN()
            return ['1.2.3.4']
        monkeypatch.setattr(recon_mod._resolver, 'resolve', fake_resolve)
        return recon_mod._subdomain_takeover({'shop.example.com'}, 'example.com')['data']

    def test_not_vulnerable_service_is_ignored(self, monkeypatch):
        """Fastly est « Not vulnerable » : l'ancienne liste le signalait à tort."""
        data = self._run(monkeypatch, 'example.global.fastly.net')
        assert data['vulnerable_count'] == 0

    @pytest.mark.security
    def test_substring_lookalike_not_matched(self, monkeypatch):
        """Comparaison par suffixe DNS : « github.io.evil.com » n'est pas GitHub."""
        data = self._run(monkeypatch, 'github.io.evil.com')
        assert data['vulnerable_count'] == 0 and data['edge_cases'] == []

    def test_vulnerable_service_flagged(self, monkeypatch):
        from utils.takeover_fingerprints import load_fingerprints
        fp = next(f for f in load_fingerprints() if f['vulnerable'] and f['cname'])
        data = self._run(monkeypatch, 'x.' + fp['cname'][0])
        assert data['vulnerable_count'] == 1
        assert data['vulnerable'][0]['service'] == fp['service']
        assert data['risk_level'] == 'high'

    def test_nxdomain_service_with_dead_target_is_high_confidence(self, monkeypatch):
        from utils.takeover_fingerprints import load_fingerprints
        fp = next(f for f in load_fingerprints() if f['vulnerable'] and f['nxdomain'] and f['cname'])
        data = self._run(monkeypatch, 'x.' + fp['cname'][0], target_nx=True)
        assert data['vulnerable'][0]['confidence'] == 'high'

    def test_edge_case_listed_apart(self, monkeypatch):
        from utils.takeover_fingerprints import load_fingerprints
        fp = next(f for f in load_fingerprints() if f['status'] == 'Edge case' and f['cname'])
        data = self._run(monkeypatch, 'x.' + fp['cname'][0])
        assert data['vulnerable_count'] == 0
        assert data['edge_cases'][0]['service'] == fp['service']

    @pytest.mark.parametrize('cname,expected', [
        ('acme.github.io', 'edge'), ('acme.herokuapp.com', 'edge'),
        ('acme.readthedocs.io', 'vulnerable'), ('acme.global.fastly.net', 'ignored'),
        ('acme.zendesk.com', 'ignored'),
    ])
    def test_legacy_services_keep_source_status(self, monkeypatch, cname, expected):
        """Services sans CNAME dans la source : reconnus par le complément local,
        mais classés selon le statut de can-i-take-over-xyz."""
        data = self._run(monkeypatch, cname)
        got = 'vulnerable' if data['vulnerable_count'] else ('edge' if data['edge_cases'] else 'ignored')
        assert got == expected


# ── Correctifs trouvés sur la stack réelle (example.com, 2026-10-19) ─────────

class TestRealStackFixes:
    def test_enumerated_subdomains_leave_room_for_infrastructure(self):
        """example.com : ~5 000 sous-domaines énumérés remplissaient seuls le
        graphe (ni IP, ni ASN, ni port)."""
        from utils.entity_graph import MAX_ENUMERATED_SUBDOMAINS
        subs = [f'h{i}.example.com' for i in range(6000)]
        raw = {'all_subdomains': {'status': 'success', 'data': subs},
               'dns_records': {'status': 'success', 'data': {'A': ['93.184.215.14']}}}
        graph = extract_graph('example.com', raw)
        n_subs = sum(1 for t, _ in graph['entities'] if t == 'subdomain')
        assert n_subs == MAX_ENUMERATED_SUBDOMAINS
        assert ('ip', '93.184.215.14') in graph['entities']

    def test_ssl_info_falls_back_from_unreachable_ipv6(self, monkeypatch):
        import socket as _socket
        tried = []
        monkeypatch.setattr(recon_mod, '_resolve_ips', lambda d: ['2606:2800::1', '93.184.215.14'])

        class _Sock:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_conn(addr, timeout=None):
            tried.append(addr[0])
            if ':' in addr[0]:
                raise OSError(101, 'Network is unreachable')
            return _Sock()

        class _SSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getpeercert(self): return {'subject': ((('commonName', 'example.com'),),),
                                           'issuer': ((('organizationName', 'CA'),),),
                                           'notAfter': 'Jan  1 00:00:00 2030 GMT'}
            def cipher(self): return ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            def version(self): return 'TLSv1.3'

        class _Ctx:
            def wrap_socket(self, sock, server_hostname=None): return _SSock()

        monkeypatch.setattr(_socket, 'create_connection', fake_conn)
        monkeypatch.setattr(recon_mod.ssl, 'create_default_context', lambda: _Ctx())
        out = recon_mod._ssl_info('example.com')
        assert tried[0] == '93.184.215.14'     # IPv4 essayée en premier
        assert out['status'] == 'success'

    def test_graph_selection_is_deterministic(self):
        subs = [f'h{i}.example.com' for i in range(6000)]
        a = extract_graph('example.com', {'all_subdomains': {'status': 'success', 'data': subs}})
        b = extract_graph('example.com', {'all_subdomains': {'status': 'success', 'data': list(reversed(subs))}})
        assert set(a['entities']) == set(b['entities'])

    def test_diff_compares_full_subdomain_sets(self):
        """Mêmes 6 000 sous-domaines dans un autre ordre : aucun changement.
        Avant correction, le plafond du graphe créait de fausses disparitions."""
        from utils.scan_diff import diff_scans
        subs = [f'h{i}.example.com' for i in range(6000)]
        prev = {'domain': 'example.com', 'all_subdomains': {'status': 'success', 'data': subs}}
        cur = {'domain': 'example.com', 'all_subdomains': {'status': 'success', 'data': list(reversed(subs))}}
        diff = diff_scans(prev, cur, domain='example.com')
        assert diff['subdomains']['added_count'] == 0
        assert diff['subdomains']['removed_count'] == 0

    def test_diff_still_detects_real_removal_beyond_cap(self):
        from utils.scan_diff import diff_scans
        subs = [f'h{i}.example.com' for i in range(6000)]
        prev = {'domain': 'example.com', 'all_subdomains': {'status': 'success', 'data': subs}}
        cur = {'domain': 'example.com', 'all_subdomains': {'status': 'success', 'data': subs[:-1]}}
        diff = diff_scans(prev, cur, domain='example.com')
        assert diff['subdomains']['removed'] == ['h5999.example.com']
        assert diff['subdomains']['removed_count'] == 1


# ── Ollama : synthèse REDUCE non analysable (constaté sur la stack réelle) ───

import json as _json
from utils import ollama_client as oc

_MAP_OK = {'content': _json.dumps({'findings': [{'id': 'EMAIL-001', 'title': 'DMARC absent',
                                                 'severity': 'HIGH', 'source_tool': 'dmarc_check'}],
                                   'strengths': ['SPF présent']})}


class TestReduceFallback:
    @pytest.mark.parametrize('content,usable', [
        ('{"findings": []}', True),
        ('<think>...</think>\n```json\n{"findings": [{"id": "A"}]}\n```', True),
        ('Voici le rapport : {"findings": [], "risk_level": "LOW"} fin.', True),
        ('{"findings": [', False),
        ('{"risk_level": "LOW"}', False),
        ('', False),
    ])
    def test_reduce_output_usable(self, content, usable):
        assert oc._reduce_output_usable(content) is usable

    @pytest.mark.integration
    def test_invalid_reduce_json_falls_back_to_map_findings(self, monkeypatch):
        client = oc.OllamaClient()
        monkeypatch.setattr(client, 'agentic_chat', lambda *a, **k: (dict(_MAP_OK), []))
        monkeypatch.setattr(client, 'chat', lambda *a, **k: {'role': 'assistant', 'content': '{"findings": [ tronqué'})
        msg, _searches, _ = client.map_reduce_agentic_chat(signals={'domain': 'example.com'},
                                                           tool_handler=None, map_rounds=1)
        report = _json.loads(msg['content'])
        assert report['_reduce_degraded'] is True
        assert report['findings'] and report['findings'][0]['title'] == 'DMARC absent'

    @pytest.mark.integration
    def test_valid_reduce_is_kept(self, monkeypatch):
        client = oc.OllamaClient()
        monkeypatch.setattr(client, 'agentic_chat', lambda *a, **k: (dict(_MAP_OK), []))
        good = '{"findings": [{"id": "EMAIL-001", "title": "DMARC absent", "severity": "HIGH"}], "risk_level": "HIGH"}'
        monkeypatch.setattr(client, 'chat', lambda *a, **k: {'role': 'assistant', 'content': good})
        msg, _s, _ = client.map_reduce_agentic_chat(signals={'domain': 'example.com'}, tool_handler=None, map_rounds=1)
        assert msg['content'] == good


# ── Gemini : file de modèles lue sur l'API (gemini-2.0-flash retiré, 404) ───

import utils.gemini_client as gc


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)
    def json(self):
        return self._p


def _models(*names):
    return {'models': [{'name': f'models/{n}', 'supportedGenerationMethods': ['generateContent']} for n in names]}


class TestGeminiModelQueue:
    def test_queue_uses_only_available_models(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        monkeypatch.setattr(gc.requests, 'get', lambda *a, **k: _Resp(_models(
            'gemini-flash-latest', 'gemini-3.6-flash', 'gemini-2.5-flash-preview-tts',
            'gemini-3-pro-image', 'gemini-3.5-flash', 'gemini-3.1-pro-preview')))
        client = gc.GeminiClient()
        q = client._model_queue
        assert q[0] == 'gemini-flash-latest'
        assert 'gemini-2.0-flash' not in q
        assert not any('tts' in m or 'image' in m or 'preview' in m for m in q)
        assert q.index('gemini-3.6-flash') < q.index('gemini-3.5-flash')

    def test_retired_preferred_model_is_skipped(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        monkeypatch.setattr(gc.requests, 'get', lambda *a, **k: _Resp(_models('gemini-2.5-flash')))
        client = gc.GeminiClient(model='gemini-2.0-flash')
        assert client._model_queue == ['gemini-2.5-flash']

    def test_listing_failure_falls_back_to_defaults(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        def boom(*a, **k):
            raise ConnectionError('hors ligne')
        monkeypatch.setattr(gc.requests, 'get', boom)
        q = gc.GeminiClient()._model_queue
        assert q[0] == 'gemini-flash-latest' and 'gemini-2.0-flash' not in q

    def test_overloaded_model_switches_to_next(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        monkeypatch.setattr(gc.requests, 'get', lambda *a, **k: _Resp(_models('gemini-flash-latest', 'gemini-2.5-flash')))
        client = gc.GeminiClient()
        tried = []

        class _Msg:
            content = 'OK'

        class _Choice:
            message = _Msg()

        class _R:
            choices = [_Choice()]
            usage = None

        def create(**kw):
            tried.append(kw['model'])
            if kw['model'] == 'gemini-flash-latest':
                raise RuntimeError("Error code: 503 - This model is currently experiencing high demand")
            return _R()
        monkeypatch.setattr(client._client.chat.completions, 'create', create)
        assert client.chat([{'role': 'user', 'content': 'x'}]).content == 'OK'
        assert tried == ['gemini-flash-latest', 'gemini-2.5-flash']

    def test_newest_versions_first_and_audio_models_excluded(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        monkeypatch.setattr(gc.requests, 'get', lambda *a, **k: _Resp(_models(
            'gemini-2.5-flash', 'gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-3.5-transcribe',
            'gemini-omni-1.1-flash', 'gemini-flash-lite-latest')))
        q = gc.GeminiClient()._model_queue
        assert q == ['gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-2.5-flash', 'gemini-flash-lite-latest']

    def test_refused_models_move_to_end_for_next_analyses(self, monkeypatch):
        monkeypatch.setattr(gc, '_API_KEY', 'k')
        monkeypatch.setattr(gc, '_COOLDOWN', {})
        monkeypatch.setattr(gc.requests, 'get', lambda *a, **k: _Resp(_models('gemini-flash-latest', 'gemini-3.6-flash')))
        first = gc.GeminiClient()
        assert first._model_queue[0] == 'gemini-flash-latest'

        class _R:
            class _C:
                class message:
                    content = 'OK'
            choices = [_C()]
            usage = None

        def create(**kw):
            if kw['model'] == 'gemini-flash-latest':
                raise RuntimeError("Error code: 429 - You exceeded your current quota")
            return _R()
        monkeypatch.setattr(first._client.chat.completions, 'create', create)
        first.chat([{'role': 'user', 'content': 'x'}])
        # Analyse suivante : le modèle sans quota passe en dernier
        assert gc.GeminiClient()._model_queue == ['gemini-3.6-flash', 'gemini-flash-latest']
