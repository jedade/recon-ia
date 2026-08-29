# tests/test_parallel.py
"""
Tests de l'exécuteur parallèle résilient (phase 4).

Vérifie les deux garanties structurantes :
  - isolation  : l'échec d'un outil n'empêche jamais les autres d'aboutir
  - borne      : un outil bloqué ne peut pas immobiliser le scan
"""
import threading
import time

import pytest

from utils.parallel import (
    ToolTask,
    run_tools_parallel,
    DEFAULT_MAX_WORKERS,
)


def _ok(value):
    return {'status': 'success', 'data': value, 'raw_output': str(value)}


class TestIsolation:
    def test_all_results_returned(self):
        tasks = [ToolTask(key=f't{i}', fn=(lambda v=i: _ok(v))) for i in range(5)]
        out = run_tools_parallel(tasks)
        assert set(out) == {f't{i}' for i in range(5)}
        assert all(not o.failed for o in out.values())
        assert out['t3'].result['data'] == 3

    def test_exception_does_not_kill_the_scan(self):
        """Une exception d'un outil ne doit pas empêcher les autres d'aboutir."""
        def boom():
            raise RuntimeError('boum')

        tasks = [
            ToolTask(key='ok1', fn=lambda: _ok('a')),
            ToolTask(key='bad', fn=boom),
            ToolTask(key='ok2', fn=lambda: _ok('b')),
        ]
        out = run_tools_parallel(tasks)

        assert out['ok1'].result['data'] == 'a'
        assert out['ok2'].result['data'] == 'b'
        assert out['bad'].failed is True
        assert out['bad'].result['status'] == 'error'
        assert 'boum' in out['bad'].result['error']

    def test_error_result_keeps_tool_contract(self):
        """Un échec doit garder le format status/data/error/raw_output (phase 2)."""
        out = run_tools_parallel([
            ToolTask(key='bad', fn=lambda: (_ for _ in ()).throw(ValueError('x'))),
        ])
        res = out['bad'].result
        assert set(['status', 'data', 'error', 'raw_output']).issubset(res)
        assert res['data'] == {}

    def test_non_dict_return_is_normalised(self):
        """Un outil retournant autre chose qu'un dict ne corrompt pas scan_results."""
        out = run_tools_parallel([ToolTask(key='weird', fn=lambda: ['pas', 'un', 'dict'])])
        assert out['weird'].failed is True
        assert out['weird'].result['status'] == 'error'
        assert isinstance(out['weird'].result['data'], dict)

    def test_missing_status_is_defaulted(self):
        out = run_tools_parallel([ToolTask(key='nostatus', fn=lambda: {'data': 1})])
        assert out['nostatus'].result['status'] == 'success'
        assert out['nostatus'].failed is False

    def test_empty_task_list(self):
        assert run_tools_parallel([]) == {}

    def test_duplicate_keys_are_deduplicated(self):
        """Deux tâches de même clé produiraient un résultat non déterministe."""
        tasks = [
            ToolTask(key='dup', fn=lambda: _ok('premier')),
            ToolTask(key='dup', fn=lambda: _ok('second')),
        ]
        out = run_tools_parallel(tasks)
        assert len(out) == 1
        assert out['dup'].result['data'] == 'premier'


class TestDeadline:
    def test_slow_tool_does_not_block_scan(self):
        """Le délai global borne la durée totale malgré un outil bloqué."""
        def slow():
            time.sleep(3)
            return _ok('tardif')

        tasks = [
            ToolTask(key='fast', fn=lambda: _ok('vite')),
            ToolTask(key='slow', fn=slow),
        ]
        started = time.perf_counter()
        out = run_tools_parallel(tasks, overall_deadline_s=1.0)
        elapsed = time.perf_counter() - started

        assert elapsed < 10, f'le scan a duré {elapsed:.1f}s malgré le deadline'
        assert out['fast'].result['data'] == 'vite'
        assert out['slow'].timed_out is True
        assert out['slow'].result['status'] == 'timeout'

    def test_every_key_present_even_on_deadline(self):
        """Le format de sortie ne doit pas dépendre des aléas d'exécution."""
        def slow():
            # Retourne un dict valide (et non None) : le thread survit au
            # deadline par conception, et journaliser un « résultat inattendu »
            # après la fin du test polluerait la sortie de pytest.
            time.sleep(2)
            return _ok('tardif')

        tasks = [ToolTask(key=f's{i}', fn=slow) for i in range(4)]
        out = run_tools_parallel(tasks, overall_deadline_s=0.5)
        assert set(out) == {f's{i}' for i in range(4)}
        assert all(o.result['status'] in ('timeout', 'error') for o in out.values())


class TestParallelism:
    def test_tools_actually_run_concurrently(self):
        """
        Cœur de la phase 4 : 6 tâches de 0,3 s doivent prendre ~0,3 s au total,
        pas 1,8 s. Sinon l'exécution est restée séquentielle.
        """
        def sleeper():
            time.sleep(0.3)
            return _ok('ok')

        tasks = [ToolTask(key=f'p{i}', fn=sleeper) for i in range(6)]
        started = time.perf_counter()
        out = run_tools_parallel(tasks, max_workers=6)
        elapsed = time.perf_counter() - started

        assert len(out) == 6
        assert all(not o.failed for o in out.values())
        assert elapsed < 1.0, f'exécution probablement séquentielle ({elapsed:.2f}s)'

    def test_worker_count_is_bounded(self):
        """Ne jamais ouvrir plus de connexions simultanées que la borne fixée."""
        active = 0
        peak = 0
        lock = threading.Lock()

        def tracked():
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return _ok('ok')

        tasks = [ToolTask(key=f'w{i}', fn=tracked) for i in range(20)]
        run_tools_parallel(tasks, max_workers=4)
        assert peak <= 4, f'{peak} threads simultanés pour une borne de 4'

    def test_default_worker_cap_is_reasonable(self):
        """Garde-fou : rester discret vis-à-vis des services tiers interrogés."""
        assert 1 < DEFAULT_MAX_WORKERS <= 16


class TestHttpSession:
    """Session HTTP partagée : connexions persistantes + retries ciblés."""

    def test_shared_session_is_a_session(self):
        import requests
        import routes.recon as recon
        assert isinstance(recon._http, requests.Session)

    def test_retry_policy(self):
        import routes.recon as recon
        retry = recon._http.get_adapter('https://example.com').max_retries
        assert retry.total == 2
        assert retry.backoff_factor == 1
        assert set(retry.status_forcelist) == {429, 502, 503, 504}

    def test_only_idempotent_methods_are_retried(self):
        """Rejouer un POST non idempotent pourrait dupliquer un effet de bord."""
        import routes.recon as recon
        allowed = recon._http.get_adapter('https://example.com').max_retries.allowed_methods
        assert 'GET' in allowed
        assert 'POST' not in allowed

    def test_404_is_not_retried(self):
        """Un 404 est une réponse métier légitime (« rien trouvé »), pas une panne."""
        import routes.recon as recon
        assert 404 not in recon._http.get_adapter('https://example.com').max_retries.status_forcelist

    def test_pool_large_enough_for_parallel_wave(self):
        """Un pool trop petit sérialiserait les threads de la vague parallèle."""
        import routes.recon as recon
        adapter = recon._http.get_adapter('https://example.com')
        assert adapter._pool_maxsize >= recon._SCAN_MAX_WORKERS


class TestScanIntegration:
    """
    Vérifie le câblage réel dans POST /pass_recon, outils réseau mockés.

    Objectif : prouver que la vague parallèle préserve le contrat de sortie
    (clés, meta de la phase 2) et qu'un outil qui explose ne fait plus échouer
    le scan entier.
    """

    def _post(self, client, auth_headers, tools):
        return client.post('/pass_recon', json={
            'domain': 'example.com',
            'tools': tools,
            'force_refresh': True,
        }, headers=auth_headers)

    def test_failing_tool_does_not_break_the_scan(self, client, auth_headers, monkeypatch):
        import routes.recon as recon

        def boom(_domain):
            raise RuntimeError('outil cassé')

        monkeypatch.setattr(recon, '_dnssec', boom)
        monkeypatch.setattr(recon, '_ssl_info',
                            lambda d: {'status': 'success', 'data': {'ok': True},
                                       'raw_output': 'ssl ok'})

        resp = self._post(client, auth_headers, ['dnssec', 'ssl_info'])
        assert resp.status_code == 200
        data = resp.get_json()['data']

        # L'outil sain a bien produit son résultat malgré l'échec de l'autre
        assert data['ssl_info']['status'] == 'success'
        assert data['ssl_info']['data'] == {'ok': True}
        # L'outil en échec est présent et explicitement marqué
        assert data['dnssec']['status'] == 'error'
        assert 'outil cassé' in data['dnssec']['error']

    def test_meta_contract_preserved(self, client, auth_headers, monkeypatch):
        """La traçabilité meta.tool/meta.category (phase 2) doit survivre."""
        import routes.recon as recon
        monkeypatch.setattr(recon, '_dns_records',
                            lambda d: {'status': 'success', 'data': {'A': ['1.2.3.4']},
                                       'raw_output': 'A 1.2.3.4'})

        data = self._post(client, auth_headers, ['dns_records']).get_json()['data']
        assert 'meta' in data['dns_records']
        assert data['dns_records']['meta'].get('tool')
        assert data['dns_records']['meta'].get('category')

    def test_failing_tool_still_carries_meta(self, client, auth_headers, monkeypatch):
        """Un outil en échec doit rester traçable, sinon l'IA perd la source."""
        import routes.recon as recon
        monkeypatch.setattr(recon, '_dns_records',
                            lambda d: (_ for _ in ()).throw(RuntimeError('ko')))

        data = self._post(client, auth_headers, ['dns_records']).get_json()['data']
        assert data['dns_records']['status'] == 'error'
        assert data['dns_records']['meta'].get('tool')

    def test_discovery_wave_unions_subdomains(self, client, auth_headers, monkeypatch):
        """
        Les 5 outils de découverte tournent en parallèle ; l'union dans
        all_subs est faite après la vague par le thread principal.
        Aucun binaire CLI réel n'est requis : _run_subprocess est mocké.
        """
        import routes.recon as recon

        def fake_subprocess(cmd, timeout=60, cwd=None):
            binary = cmd[0]
            lines = {
                'subfinder':   ['a.example.com'],
                'assetfinder': ['b.example.com'],
                'amass':       ['c.example.com', 'a.example.com'],  # doublon volontaire
            }.get(binary, [])
            return {'status': 'success', 'lines': lines, 'raw': '\n'.join(lines)}

        monkeypatch.setattr(recon, '_run_subprocess', fake_subprocess)
        monkeypatch.setenv('GITHUB_TOKEN', '')   # github → skipped proprement

        data = self._post(
            client, auth_headers,
            ['subfinder', 'assetfinder', 'amass', 'github'],
        ).get_json()['data']

        assert data['subfinder']['data']['subdomains'] == ['a.example.com']
        assert data['amass']['status'] == 'success'
        assert data['github']['status'] == 'skipped'
        # Union dédupliquée des trois outils ayant produit des résultats
        assert data['all_subdomains']['data'] == [
            'a.example.com', 'b.example.com', 'c.example.com',
        ]
        assert data['all_subdomains']['count'] == 3

    def test_discovery_failure_does_not_lose_other_subdomains(
            self, client, auth_headers, monkeypatch):
        """Un outil de découverte qui explose ne doit pas vider all_subs."""
        import routes.recon as recon

        def fake_subprocess(cmd, timeout=60, cwd=None):
            if cmd[0] == 'amass':
                raise RuntimeError('amass a planté')
            return {'status': 'success', 'lines': ['ok.example.com'],
                    'raw': 'ok.example.com'}

        monkeypatch.setattr(recon, '_run_subprocess', fake_subprocess)

        data = self._post(client, auth_headers,
                          ['subfinder', 'amass']).get_json()['data']

        assert data['amass']['status'] == 'error'
        assert data['subfinder']['data']['subdomains'] == ['ok.example.com']
        assert data['all_subdomains']['data'] == ['ok.example.com']

    def test_headers_consume_subdomains_from_wave1(self, client, auth_headers, monkeypatch):
        """`headers` (vague 2) doit voir les sous-domaines produits en vague 1."""
        import routes.recon as recon

        monkeypatch.setattr(recon, '_run_subprocess',
                            lambda cmd, timeout=60, cwd=None: {
                                'status': 'success', 'lines': ['web.example.com'],
                                'raw': 'web.example.com'})
        captured = {}

        def fake_headers(subs):
            captured['subs'] = sorted(subs)
            return {'status': 'success', 'data': {}, 'raw_output': ''}

        monkeypatch.setattr(recon, '_http_headers_tool', fake_headers)

        self._post(client, auth_headers, ['subfinder', 'headers'])
        assert captured['subs'] == ['web.example.com']

    def test_shodan_reuses_ips_resolved_by_ip_info(self, client, auth_headers, monkeypatch):
        """La chaîne ip_info → shodan_internetdb doit être préservée."""
        import routes.recon as recon

        monkeypatch.setattr(recon, '_ip_info', lambda d: {
            'status': 'success',
            'data': {'ips': [{'ip': '9.9.9.9'}], 'count': 1},
            'raw_output': '',
        })
        captured = {}

        def fake_shodan(domain, ips=None):
            captured['ips'] = ips
            return {'status': 'success', 'data': {'ports': []}, 'raw_output': ''}

        monkeypatch.setattr(recon, '_shodan_internetdb', fake_shodan)

        self._post(client, auth_headers, ['ip_info', 'shodan_internetdb'])
        assert captured['ips'] == ['9.9.9.9']

    def test_result_key_order_is_deterministic(self, client, auth_headers, monkeypatch):
        """
        L'ordre des clés doit suivre la spécification, pas l'ordre aléatoire
        d'achèvement des threads — sinon le SHA-256 du jeu de données varierait
        d'un scan à l'autre et l'empreinte de reproductibilité serait inutile.
        """
        import routes.recon as recon
        import time as _t

        def slow(_d):
            _t.sleep(0.2)
            return {'status': 'success', 'data': {}, 'raw_output': ''}

        def fast(_d):
            return {'status': 'success', 'data': {}, 'raw_output': ''}

        # dns_records est déclaré AVANT ssl_info dans _parallel_specs, mais
        # termine après : l'ordre des clés ne doit pas en dépendre.
        monkeypatch.setattr(recon, '_dns_records', slow)
        monkeypatch.setattr(recon, '_ssl_info', fast)

        data = self._post(client, auth_headers, ['dns_records', 'ssl_info']).get_json()['data']
        keys = [k for k in data if k in ('dns_records', 'ssl_info')]
        assert keys == ['dns_records', 'ssl_info']
