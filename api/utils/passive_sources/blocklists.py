# utils/passive_sources/blocklists.py
"""
block-lists (repris de web-check) — le domaine est-il bloqué par des
résolveurs DNS filtrants publics ?

Principe : on pose la même question A à un résolveur NON filtrant (référence)
puis à chaque résolveur filtrant. Le domaine est considéré « bloqué » par un
résolveur quand celui-ci répond :
  - NXDOMAIN alors que la référence résout le nom ;
  - une adresse « puits » (0.0.0.0, 127.x, ::, IP de page de blocage connue).

Passif : seules des requêtes DNS vers des résolveurs publics sont émises,
jamais vers la cible. La fonction de requête est injectée (`query_at(ns, name)
-> list[str]`, lève NXDomain/NoAnswer de `dns_mass`) pour les tests.
"""
import concurrent.futures
import ipaddress

from utils.passive_sources.dns_mass import NXDomain, NoAnswer

REFERENCE_RESOLVER = "8.8.8.8"

# (nom affiché, IPv4 du résolveur)
FILTERING_RESOLVERS = [
    ("Quad9", "9.9.9.9"),
    ("Cloudflare Malware", "1.1.1.2"),
    ("Cloudflare Family", "1.1.1.3"),
    ("AdGuard", "94.140.14.14"),
    ("AdGuard Family", "94.140.14.15"),
    ("CleanBrowsing Security", "185.228.168.9"),
    ("CleanBrowsing Adult", "185.228.168.10"),
    ("CleanBrowsing Family", "185.228.168.168"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS FamilyShield", "208.67.222.123"),
    ("Comodo Secure DNS", "8.26.56.26"),
    ("UltraDNS Threat Protection", "156.154.70.2"),
    ("Yandex Safe", "77.88.8.88"),
    ("Yandex Family", "77.88.8.7"),
    ("CIRA Canadian Shield", "149.112.121.10"),
    ("Control D Malware", "76.76.2.1"),
    ("DNS0.eu", "193.110.81.0"),
]

# Adresses de pages de blocage connues
BLOCK_PAGE_IPS = {
    "146.112.61.104", "146.112.61.105", "146.112.61.106", "146.112.61.107",
    "146.112.61.108", "146.112.61.109", "146.112.61.110",       # OpenDNS
    "213.180.193.250", "93.158.134.250",                         # Yandex
    "94.140.14.33", "94.140.14.35",                              # AdGuard
    "185.228.168.10", "185.228.168.9",                           # CleanBrowsing
}


def _is_sinkhole(ip: str) -> bool:
    if ip in BLOCK_PAGE_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_unspecified or addr.is_loopback


def _ask(query_at, ns, domain):
    """Retourne (ips, état) avec état ∈ {'ok', 'nxdomain', 'noanswer', 'error'}."""
    try:
        ips = [str(x) for x in (query_at(ns, domain) or [])][:10]
        return ips, "ok"
    except NXDomain:
        return [], "nxdomain"
    except NoAnswer:
        return [], "noanswer"
    except Exception:
        return [], "error"


def check_blocklists(query_at, domain: str, *, workers: int = 6,
                     budget_s: float = 30.0, resolvers=None) -> dict:
    resolvers = list(resolvers or FILTERING_RESOLVERS)
    ref_ips, ref_state = _ask(query_at, REFERENCE_RESOLVER, domain)
    ref_resolves = ref_state == "ok" and bool(ref_ips)

    verdicts = {}
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(workers, len(resolvers))), thread_name_prefix="blocklist")
    try:
        futures = {executor.submit(_ask, query_at, ip, domain): (name, ip) for name, ip in resolvers}
        done, not_done = concurrent.futures.wait(futures, timeout=budget_s)
        for fut in done:
            name, ns = futures[fut]
            ips, state = fut.result()
            if state == "ok" and ips and all(_is_sinkhole(i) for i in ips):
                verdict, reason = "blocked", f"adresse de blocage {', '.join(ips)}"
            elif state == "nxdomain" and ref_resolves:
                verdict, reason = "blocked", "NXDOMAIN alors que la référence résout"
            elif state == "ok":
                verdict, reason = "not_blocked", None
            elif state == "error":
                verdict, reason = "error", "résolveur injoignable"
            else:
                verdict, reason = "unknown", state
            verdicts[name] = {"resolver": ns, "verdict": verdict, "answer": ips, "reason": reason}
        for fut in not_done:
            fut.cancel()
            name, ns = futures[fut]
            verdicts[name] = {"resolver": ns, "verdict": "timeout", "answer": [], "reason": None}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    ordered = [{"name": name, **verdicts[name]} for name, _ in resolvers]
    blocked = [v["name"] for v in ordered if v["verdict"] == "blocked"]
    answered = [v for v in ordered if v["verdict"] in ("blocked", "not_blocked")]
    raw = [f"Référence {REFERENCE_RESOLVER}: {ref_state} {', '.join(ref_ips)}"] + [
        f"{v['name']} ({v['resolver']}): {v['verdict']} {', '.join(v['answer'])}" for v in ordered
    ]
    if not answered:
        return {"status": "error",
                "data": {"resolvers": ordered, "blocked_by": [], "blocked_count": 0},
                "error": "Aucun résolveur filtrant n'a répondu", "raw_output": "\n".join(raw)}
    return {
        "status": "success",
        "data": {
            "reference": {"resolver": REFERENCE_RESOLVER, "state": ref_state, "answer": ref_ips},
            "resolvers": ordered,
            "checked_count": len(answered),
            "blocked_by": blocked,
            "blocked_count": len(blocked),
            "is_blocked": bool(blocked),
        },
        "raw_output": "\n".join(raw),
    }
