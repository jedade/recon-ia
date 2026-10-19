# tests/test_subdomain_selection.py
"""
Sélection des sous-domaines envoyés aux outils `headers` et
`subdomain_takeover` (plan d'action, phase 0, bugs B2 et B3).

Avant : `sorted(subs)[:10]` (alphabétique pur) pour les en-têtes et
`list(set)[:50]` (ordre non déterministe) pour le takeover.
"""
from unittest.mock import patch

import dns.resolver
import pytest

from routes.recon import (
    _prioritize_subdomains,
    _subdomain_priority,
    _SENSITIVE_SUBDOMAIN_KEYWORDS,
    _subdomain_takeover,
)


NOT_SENSITIVE = len(_SENSITIVE_SUBDOMAIN_KEYWORDS)


class TestSubdomainPriority:
    @pytest.mark.parametrize("sub", [
        "admin.example.com", "vpn.example.com", "admin-panel.example.com",
        "staging.app.example.com", "dev2.example.com", "jenkins.example.com",
    ])
    def test_sensitive_labels_are_ranked(self, sub):
        assert _subdomain_priority(sub) < NOT_SENSITIVE

    @pytest.mark.parametrize("sub", [
        "a1.example.com", "www.example.com", "latest.example.com",
        "contest.example.com", "blog.example.com",
    ])
    def test_substring_is_not_a_keyword(self, sub):
        # `latest` contient `test`, `contest` aussi : ce ne sont pas des
        # environnements de test.
        assert _subdomain_priority(sub) == NOT_SENSITIVE

    def test_parent_domain_labels_are_ignored(self):
        # Le domaine parent lui-même ne doit pas rendre tout « sensible ».
        assert _subdomain_priority("www.admin.com") == NOT_SENSITIVE

    def test_earlier_keyword_wins(self):
        assert _subdomain_priority("admin.example.com") < _subdomain_priority("api.example.com")


class TestPrioritizeSubdomains:
    SUBS = {
        "a1.example.com", "api-test.example.com", "admin.example.com",
        "blog.example.com", "vpn.example.com", "www.example.com",
    }

    def test_sensitive_first(self):
        top = _prioritize_subdomains(self.SUBS, 3)
        assert top[0] == "admin.example.com"
        assert top[1] == "vpn.example.com"
        # L'ancienne sélection alphabétique aurait renvoyé a1. en premier
        assert "a1.example.com" not in top

    def test_deterministic_regardless_of_input_order(self):
        as_list = sorted(self.SUBS)
        assert _prioritize_subdomains(as_list, 6) == _prioritize_subdomains(
            list(reversed(as_list)), 6)
        assert _prioritize_subdomains(set(self.SUBS), 6) == _prioritize_subdomains(as_list, 6)

    def test_limit_respected(self):
        assert len(_prioritize_subdomains(self.SUBS, 2)) == 2
        assert len(_prioritize_subdomains(self.SUBS, 100)) == len(self.SUBS)

    def test_normalises_and_deduplicates(self):
        out = _prioritize_subdomains(["Admin.Example.com.", "admin.example.com", "", "  "], 10)
        assert out == ["admin.example.com"]

    def test_empty_input(self):
        assert _prioritize_subdomains(set(), 10) == []


class TestTakeoverSelection:
    def test_takeover_targets_are_reproducible(self):
        """Deux scans identiques doivent tester les mêmes sous-domaines."""
        subs = {f"host{i}.example.com" for i in range(80)} | {"admin.example.com"}
        calls = []

        def fake_resolve(name, rtype):
            calls.append(name)
            raise dns.resolver.NoAnswer()

        with patch("routes.recon._resolver.resolve", side_effect=fake_resolve):
            _subdomain_takeover(subs, "example.com")
            first = list(calls)
            calls.clear()
            _subdomain_takeover(set(sorted(subs, reverse=True)), "example.com")

        assert first == calls
        assert len(first) == 50
        assert first[0] == "admin.example.com"

    def test_takeover_detects_known_service(self):
        # Bitbucket est « Vulnerable » dans can-i-take-over-xyz ; Heroku y est
        # un « Edge case » : listé à part, jamais compté vulnérable.
        class _Bitbucket:
            target = "victim.bitbucket.io."

        class _Heroku:
            target = "victim.herokuapp.com."

        def fake_resolve(name, rtype):
            if rtype == "CNAME" and name == "old.example.com":
                return [_Bitbucket()]
            if rtype == "CNAME" and name == "app.example.com":
                return [_Heroku()]
            raise dns.resolver.NXDOMAIN()

        with patch("routes.recon._resolver.resolve", side_effect=fake_resolve):
            out = _subdomain_takeover({"old.example.com", "app.example.com"}, "example.com")

        assert out["data"]["vulnerable_count"] == 1
        assert out["data"]["vulnerable"][0]["service"] == "Bitbucket"
        assert [e["service"] for e in out["data"]["edge_cases"]] == ["Heroku"]
        assert out["data"]["checked_count"] == 2
