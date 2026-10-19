# tests/test_validators.py
import pytest
from utils.validators import (
    is_valid_domain,
    is_valid_host,
    is_valid_url,
    sanitize_crawl_options,
)


class TestIsValidDomain:
    def test_valid_simple(self):
        assert is_valid_domain("example.com") is True

    def test_valid_subdomain(self):
        assert is_valid_domain("sub.example.com") is True

    def test_valid_multi_level(self):
        assert is_valid_domain("a.b.example.co.uk") is True

    def test_invalid_no_tld(self):
        assert is_valid_domain("example") is False

    def test_invalid_with_scheme(self):
        assert is_valid_domain("http://example.com") is False

    def test_invalid_with_path(self):
        assert is_valid_domain("example.com/path") is False

    def test_invalid_ip_address(self):
        assert is_valid_domain("192.168.1.1") is False

    def test_invalid_empty(self):
        assert is_valid_domain("") is False

    def test_invalid_special_chars(self):
        assert is_valid_domain("ex ample.com") is False

    def test_invalid_shell_injection(self):
        assert is_valid_domain("example.com; ls -la") is False

    def test_invalid_backtick(self):
        assert is_valid_domain("`whoami`.com") is False


class TestIsValidHost:
    def test_valid_domain_only(self):
        assert is_valid_host("example.com") is True

    def test_valid_with_port(self):
        assert is_valid_host("example.com:443") is True

    def test_valid_subdomain_with_port(self):
        assert is_valid_host("sub.example.com:8443") is True

    def test_invalid_port_too_large(self):
        assert is_valid_host("example.com:99999") is False

    def test_invalid_no_tld(self):
        assert is_valid_host("localhost") is False

    def test_invalid_with_scheme(self):
        assert is_valid_host("https://example.com") is False

    def test_invalid_injection(self):
        assert is_valid_host("example.com; rm -rf /") is False


class TestIsValidUrl:
    def test_valid_https(self):
        assert is_valid_url("https://example.com") is True

    def test_valid_http(self):
        assert is_valid_url("http://example.com") is True

    def test_valid_with_path(self):
        assert is_valid_url("https://example.com/path?q=1") is True

    def test_invalid_no_scheme(self):
        assert is_valid_url("example.com") is False

    def test_invalid_ftp(self):
        assert is_valid_url("ftp://example.com") is False

    def test_invalid_empty(self):
        assert is_valid_url("") is False

    def test_invalid_javascript(self):
        assert is_valid_url("javascript:alert(1)") is False


class TestSanitizeCrawlOptions:
    def test_valid_depth_option(self):
        opts, err = sanitize_crawl_options(["--depth", "2"])
        assert err is None
        assert opts == ["--depth", "2"]

    def test_valid_multiple_options(self):
        opts, err = sanitize_crawl_options(["--depth", "3", "--threads", "5"])
        assert err is None
        assert opts == ["--depth", "3", "--threads", "5"]

    def test_empty_options(self):
        opts, err = sanitize_crawl_options([])
        assert err is None
        assert opts == []

    def test_invalid_option_rejected(self):
        opts, err = sanitize_crawl_options(["--rm", "-rf"])
        assert err is not None
        assert opts == []

    def test_injection_attempt(self):
        opts, err = sanitize_crawl_options(["--depth", "2; rm -rf /"])
        assert err is not None
        assert opts == []

    def test_unknown_flag_rejected(self):
        opts, err = sanitize_crawl_options(["--unknown-flag"])
        assert err is not None


class TestSsrfProtection:
    """
    Régression SSRF : is_safe_domain doit RÉSOUDRE le domaine.

    Avant correctif, seules les IP littérales étaient testées : un nom public
    pointant vers 169.254.169.254 passait et le scanner allait interroger les
    métadonnées cloud.
    """

    def test_literal_private_ips_rejected(self):
        from utils.validators import is_safe_domain
        for ip in ('127.0.0.1', '169.254.169.254', '10.1.2.3',
                   '192.168.1.1', '172.16.0.1', '::1'):
            ok, reason = is_safe_domain(ip)
            assert ok is False, f'{ip} aurait dû être refusé'
            assert reason

    def test_internal_service_names_rejected(self):
        from utils.validators import is_safe_domain
        for name in ('localhost', 'postgres', 'redis', 'ollama',
                     'host.docker.internal', 'svc.internal'):
            ok, _ = is_safe_domain(name)
            assert ok is False, f'{name} aurait dû être refusé'

    def test_domain_resolving_to_internal_ip_rejected(self, monkeypatch):
        """Le cœur de la faille : un nom public qui résout en interne."""
        import ipaddress
        import utils.validators as v
        monkeypatch.setattr(
            v, 'resolve_domain_ips',
            lambda d: [ipaddress.ip_address('169.254.169.254')],
        )
        ok, reason = v.is_safe_domain('metadata.attaquant.tld')
        assert ok is False
        assert '169.254.169.254' in reason

    def test_mixed_resolution_rejected_if_any_internal(self, monkeypatch):
        """Une seule adresse interne suffit à refuser."""
        import ipaddress
        import utils.validators as v
        monkeypatch.setattr(
            v, 'resolve_domain_ips',
            lambda d: [ipaddress.ip_address('93.184.216.34'),
                       ipaddress.ip_address('127.0.0.1')],
        )
        ok, _ = v.is_safe_domain('mixte.tld')
        assert ok is False

    def test_public_domain_allowed(self, monkeypatch):
        import ipaddress
        import utils.validators as v
        monkeypatch.setattr(
            v, 'resolve_domain_ips',
            lambda d: [ipaddress.ip_address('93.184.216.34')],
        )
        ok, reason = v.is_safe_domain('example.com')
        assert ok is True and reason is None

    def test_unresolvable_domain_allowed(self, monkeypatch):
        """Une panne DNS ne doit pas bloquer : la cible est de toute façon injoignable."""
        import utils.validators as v
        monkeypatch.setattr(v, 'resolve_domain_ips', lambda d: [])
        ok, _ = v.is_safe_domain('inexistant.tld')
        assert ok is True


class TestDbUrl:
    """Pilote PostgreSQL explicite (SQLAlchemy 2.1 a changé le défaut)."""

    def test_postgresql_scheme_gets_psycopg2(self):
        from db_url import with_psycopg2
        assert with_psycopg2('postgresql://u:p@h:5432/d') == 'postgresql+psycopg2://u:p@h:5432/d'
        assert with_psycopg2('postgres://u:p@h/d') == 'postgresql+psycopg2://u:p@h/d'

    def test_other_urls_untouched(self):
        from db_url import with_psycopg2
        assert with_psycopg2('sqlite:///:memory:') == 'sqlite:///:memory:'
        assert with_psycopg2('postgresql+psycopg://u@h/d') == 'postgresql+psycopg://u@h/d'
        assert with_psycopg2('') == ''
