# tests/phase8_fixtures.py
"""
Doublures partagées des tests de la phase 8 (boucle agent) : LLM scripté,
outils pivots simulés, scan brut de référence. Aucun accès réseau.
"""
import copy
import ipaddress
import json

from utils.agent_llm import build_reply
from utils.recon_agent import AgentBudget

PUBLIC_IP = "93.184.216.34"
SECOND_IP = "93.184.216.35"


def tool_call(name, args, call_id=None):
    """Tool call au format OpenAI ; `args` dict → JSON, str → tel quel."""
    return {
        "id": call_id or f"call_{name}_{abs(hash(json.dumps(args, sort_keys=True, default=str))) % 10**6}",
        "type": "function",
        "function": {"name": name,
                     "arguments": args if isinstance(args, str) else json.dumps(args)},
    }


class ScriptedBackend:
    """
    LLM factice : chaque étape du script est soit une chaîne (réponse finale
    sans tool call), soit une liste de (nom, arguments), soit un callable
    recevant l'historique et retournant l'un des deux.
    """

    def __init__(self, script, name="fake", model="fake-8b"):
        self.script = list(script)
        self.calls = []
        self._name, self._model = name, model

    def describe(self):
        return {"name": self._name, "model": self._model}

    def chat(self, messages, tools, timeout=None):
        self.calls.append({"messages": copy.deepcopy(messages), "tools": tools,
                           "timeout": timeout})
        step = self.script.pop(0) if self.script else "Plus rien à vérifier."
        if callable(step):
            step = step(messages)
        if isinstance(step, str):
            return build_reply({"role": "assistant", "content": step})
        return build_reply({"role": "assistant", "content": "",
                            "tool_calls": [tool_call(n, a) for n, a in step]})


class RepeatingBackend(ScriptedBackend):
    """LLM qui boucle : renvoie toujours la même étape."""

    def __init__(self, step):
        super().__init__([])
        self.step = step

    def chat(self, messages, tools, timeout=None):
        self.script = [self.step]
        return super().chat(messages, tools, timeout)


def raw_scan():
    """Scan brut minimal : 3 sous-domaines, 1 IP exposée, certificat, takeover."""
    return {
        "domain": "example.com",
        "all_subdomains": {"data": ["admin.example.com", "www.example.com",
                                    "dev.example.com"], "count": 3},
        "dns_records": {"status": "success", "data": {"A": [PUBLIC_IP], "AAAA": []},
                        "raw_output": ""},
        "ip_info": {"status": "success", "data": {"ips": [
            {"ip": PUBLIC_IP, "org": "AS15133 Edgecast Inc", "country": "US"}]}},
        "shodan_internetdb": {"status": "success", "data": {"ips": [{
            "ip": PUBLIC_IP, "ports": [80, 443], "vulns": ["CVE-2023-44487"],
            "cpes": ["cpe:/a:nginx:nginx"], "hostnames": ["www.example.com"]}]}},
        "ssl_info": {"status": "success", "data": {
            "subject": {"commonName": "example.com"},
            "issuer": {"organizationName": "DigiCert Inc"},
            "serial_number": "0ABC", "not_after": "Dec 31 23:59:59 2026 GMT",
            "san": ["example.com", "www.example.com"], "san_count": 2}},
        "subdomain_takeover": {"status": "success", "data": {"vulnerable": [
            {"subdomain": "dev.example.com", "cname": "x.github.io",
             "service": "GitHub Pages", "confidence": "medium"}]}},
        "tech_stack": {"status": "success", "data": {"server": "nginx"}},
    }


class FakeTools:
    """Runners simulés des 7 outils pivots ; enregistre chaque appel."""

    def __init__(self, overrides=None, on_call=None):
        self.calls = []
        self.overrides = overrides or {}
        self.on_call = on_call

    def _record(self, name, value, root):
        self.calls.append((name, value))
        if self.on_call:
            self.on_call(name, value)
        if name in self.overrides:
            out = self.overrides[name]
            return copy.deepcopy(out(value, root) if callable(out) else out)
        return copy.deepcopy(DEFAULT_RESULTS[name](value, root))

    def impls(self):
        return {name: (lambda v, root, _n=name: self._record(_n, v, root))
                for name in DEFAULT_RESULTS}


DEFAULT_RESULTS = {
    "resolve_host": lambda v, root: {"status": "success",
                                     "data": {"A": [SECOND_IP], "AAAA": [], "CNAME": [], "MX": []},
                                     "raw_output": f"{v}. IN A {SECOND_IP}"},
    "reverse_ip": lambda v, root: {"status": "success", "data": {
        "ip": v, "domains": ["shop.example.com", "other-tenant.net"], "count": 2},
        "raw_output": "shop.example.com\nother-tenant.net"},
    "internetdb": lambda v, root: {"status": "success", "data": {
        "ips": [{"ip": v}], "ports": [22, 443], "vulns": ["CVE-2021-44228"],
        "cpes": ["cpe:/a:openbsd:openssh"], "tags": ["cloud"],
        "hostnames": ["mail.example.com", "unrelated.org"]}, "raw_output": "{}"},
    "asn_lookup": lambda v, root: {"status": "success", "data": {
        "ip_queried": v, "asn": "AS15133", "asn_name": "EDGECAST", "prefix_count": 12},
        "raw_output": ""},
    "crtsh_subdomains": lambda v, root: {"status": "success", "data": {
        "subdomains": [f"api.{v}", f"staging.{v}", "foreign.com"], "count": 3},
        "raw_output": "[]"},
    "http_headers": lambda v, root: {"status": "success", "data": {v: {
        "status": "success", "scheme": "https", "http_status": 200,
        "data": {"Server": "nginx", "Strict-Transport-Security": "max-age=1"}}},
        "raw_output": ""},
    "takeover_check": lambda v, root: {"status": "success", "data": {
        "vulnerable": [], "vulnerable_count": 0, "checked_count": 1}, "raw_output": ""},
}


def budget(**overrides):
    """Budget de test : généreux par défaut, sans attente réelle."""
    base = dict(max_pivots=15, max_depth=2, deadline_s=60.0, max_rounds=8,
                max_calls_per_round=4, max_refusals=10, tool_timeout_s=5.0,
                tool_output_chars=1500, summary_max_chars=6000)
    base.update(overrides)
    return AgentBudget(**base)


DNS = {
    "example.com": [PUBLIC_IP],
    "www.example.com": [PUBLIC_IP],
    "admin.example.com": [PUBLIC_IP],
    "dev.example.com": [PUBLIC_IP],
    "evil.example.com": ["10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
}


def fake_resolve(name):
    return [ipaddress.ip_address(a) for a in DNS.get(name, [])]


def all_llm_text(backend):
    """Concatène tout ce que le LLM factice a reçu (pour les vérifications d'injection)."""
    parts = []
    for call in backend.calls:
        for msg in call["messages"]:
            parts.append(json.dumps(msg, ensure_ascii=False))
    return "\n".join(parts)
