# utils/passive_sources/dns_mass.py
"""
B4 — Résolution DNS massive des sous-domaines découverts.

Pour chaque sous-domaine (borné, priorisé en amont) : enregistrements A, AAAA
et CNAME via des résolveurs publics → statut vivant / mort, IP, ASN (Team
Cymru, requête DNS TXT) et CDN détecté (suffixe CNAME ou ASN connu).

Passif : uniquement des requêtes DNS vers des résolveurs publics, aucune
connexion à la cible. Les IP privées/réservées publiées dans un DNS public sont
signalées (fuite d'adressage interne) mais jamais contactées.

La fonction de requête DNS est injectée (`query(name, rtype) -> list[str]`),
ce qui rend le module testable sans réseau. Elle doit lever `NXDomain` pour un
nom inexistant et `NoAnswer` pour un nom sans enregistrement du type demandé.
"""
import concurrent.futures
import ipaddress
import time

# Bornes par défaut (surchargées par les variables d'environnement côté recon.py)
DEFAULT_MAX_SUBDOMAINS = 300
DEFAULT_WORKERS = 10
DEFAULT_BUDGET_S = 60.0
DEFAULT_MAX_ASN_LOOKUPS = 50


class NXDomain(Exception):
    """Nom inexistant."""


class NoAnswer(Exception):
    """Nom existant mais sans enregistrement du type demandé."""


# Suffixes CNAME → CDN / hébergeur frontal
CDN_CNAME_SUFFIXES = {
    "cloudflare.net": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door",
    "trafficmanager.net": "Azure Traffic Manager",
    "googlehosted.com": "Google",
    "ghs.googlehosted.com": "Google",
    "cdn77.org": "CDN77",
    "b-cdn.net": "BunnyCDN",
    "stackpathdns.com": "StackPath",
    "incapdns.net": "Imperva",
    "sucuri.net": "Sucuri",
    "netlify.app": "Netlify",
    "vercel-dns.com": "Vercel",
    "github.io": "GitHub Pages",
}

# ASN → CDN / grand hébergeur
CDN_ASNS = {
    13335: "Cloudflare",
    209242: "Cloudflare",
    16509: "Amazon",
    14618: "Amazon",
    54113: "Fastly",
    20940: "Akamai",
    16625: "Akamai",
    8075: "Microsoft",
    15169: "Google",
    396982: "Google",
    19551: "Imperva",
    60068: "CDN77",
    200325: "BunnyCDN",
}


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not addr.is_global


def _cdn_from_cnames(cnames):
    for cname in cnames:
        c = cname.lower().rstrip(".")
        for suffix, name in CDN_CNAME_SUFFIXES.items():
            if c == suffix or c.endswith("." + suffix):
                return name
    return None


def _safe_query(query, name, rtype):
    """Retourne (liste, erreur) ; erreur ∈ {None, 'nxdomain', 'noanswer', 'error'}."""
    try:
        return [str(x).rstrip(".") for x in (query(name, rtype) or [])][:20], None
    except NXDomain:
        return [], "nxdomain"
    except NoAnswer:
        return [], "noanswer"
    except Exception:
        return [], "error"


def resolve_one(query, sub: str) -> dict:
    """Résout un sous-domaine (A, AAAA, CNAME)."""
    a, err_a = _safe_query(query, sub, "A")
    if err_a == "nxdomain":
        return {"subdomain": sub, "status": "dead", "reason": "NXDOMAIN",
                "ips": [], "cnames": []}
    aaaa, _ = _safe_query(query, sub, "AAAA")
    cnames, _ = _safe_query(query, sub, "CNAME")
    ips = []
    for ip in a + aaaa:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    if ips:
        status = "alive"
    elif err_a == "error":
        status = "error"
    else:
        status = "no_address"
    internal = [ip for ip in ips if _is_internal(ip)]
    return {
        "subdomain": sub,
        "status": status,
        "ips": ips,
        "cnames": cnames,
        "internal_ips": internal,
        "cdn": _cdn_from_cnames(cnames),
    }


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def lookup_asn(query, ip: str):
    """
    ASN d'une IPv4 via Team Cymru (DNS TXT, passif).

    `<ip inversée>.origin.asn.cymru.com` → "13335 | 104.16.0.0/12 | US | arin | …"
    `AS13335.asn.cymru.com`             → "13335 | US | arin | … | CLOUDFLARENET …"
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4 or not addr.is_global:
        return None
    txt, err = _safe_query(query, f"{_reverse_ipv4(ip)}.origin.asn.cymru.com", "TXT")
    if err or not txt:
        return None
    parts = [p.strip().strip('"') for p in txt[0].strip('"').split("|")]
    try:
        asn = int(parts[0].split()[0])
    except (ValueError, IndexError):
        return None
    info = {
        "asn": asn,
        "prefix": parts[1][:50] if len(parts) > 1 else None,
        "country": parts[2][:5] if len(parts) > 2 else None,
        "as_name": None,
    }
    name_txt, err = _safe_query(query, f"AS{asn}.asn.cymru.com", "TXT")
    if not err and name_txt:
        nparts = [p.strip().strip('"') for p in name_txt[0].strip('"').split("|")]
        if len(nparts) >= 5:
            info["as_name"] = nparts[4][:120]
    return info


def resolve_subdomains(query, subdomains, *, max_subdomains=DEFAULT_MAX_SUBDOMAINS,
                       workers=DEFAULT_WORKERS, budget_s=DEFAULT_BUDGET_S,
                       max_asn_lookups=DEFAULT_MAX_ASN_LOOKUPS) -> dict:
    """
    Résout en parallèle borné une liste de sous-domaines (déjà priorisée).

    Retourne un résultat au format des outils de recon.py.
    """
    started = time.monotonic()
    targets = list(dict.fromkeys(s for s in subdomains if isinstance(s, str)))
    truncated = max(0, len(targets) - max_subdomains)
    targets = targets[:max_subdomains]
    if not targets:
        return {"status": "no_data", "data": {"hosts": [], "count": 0},
                "error": "Aucun sous-domaine à résoudre", "raw_output": ""}

    results = {}
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(workers, len(targets))), thread_name_prefix="dns-mass")
    try:
        futures = {executor.submit(resolve_one, query, s): s for s in targets}
        remaining = budget_s - (time.monotonic() - started)
        done, not_done = concurrent.futures.wait(futures, timeout=max(0.0, remaining))
        for fut in done:
            sub = futures[fut]
            try:
                results[sub] = fut.result()
            except Exception:
                results[sub] = {"subdomain": sub, "status": "error", "ips": [], "cnames": []}
        for fut in not_done:
            fut.cancel()
            sub = futures[fut]
            results[sub] = {"subdomain": sub, "status": "timeout", "ips": [], "cnames": []}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    # Ordre déterministe : celui de la liste priorisée
    hosts = [results[s] for s in targets]

    # ASN des IP uniques (bornées), dans l'ordre d'apparition
    unique_ips = []
    for h in hosts:
        for ip in h.get("ips", []):
            if ip not in unique_ips:
                unique_ips.append(ip)
    asn_by_ip = {}
    for ip in unique_ips:
        if len(asn_by_ip) >= max_asn_lookups or time.monotonic() - started > budget_s:
            break
        if ":" in ip or _is_internal(ip):
            continue
        info = lookup_asn(query, ip)
        if info:
            asn_by_ip[ip] = info

    for h in hosts:
        asns = []
        for ip in h.get("ips", []):
            info = asn_by_ip.get(ip)
            if info and info["asn"] not in [a["asn"] for a in asns]:
                asns.append(info)
        h["asns"] = asns
        if not h.get("cdn"):
            h["cdn"] = next((CDN_ASNS[a["asn"]] for a in asns if a["asn"] in CDN_ASNS), None)

    alive = [h for h in hosts if h["status"] == "alive"]
    dead = [h for h in hosts if h["status"] == "dead"]
    internal_hosts = [h["subdomain"] for h in hosts if h.get("internal_ips")]
    cdn_counts = {}
    for h in alive:
        if h.get("cdn"):
            cdn_counts[h["cdn"]] = cdn_counts.get(h["cdn"], 0) + 1
    asn_summary = {}
    for info in asn_by_ip.values():
        key = info["asn"]
        entry = asn_summary.setdefault(key, {"asn": key, "as_name": info.get("as_name"), "ip_count": 0})
        entry["ip_count"] += 1

    raw_lines = [
        f"{h['subdomain']} [{h['status']}] {', '.join(h.get('ips', []))}"
        + (f" CNAME {', '.join(h['cnames'])}" if h.get("cnames") else "")
        + (f" CDN={h['cdn']}" if h.get("cdn") else "")
        for h in hosts
    ]
    return {
        "status": "success",
        "data": {
            "hosts": hosts,
            "count": len(hosts),
            "alive_count": len(alive),
            "dead_count": len(dead),
            "unique_ips": unique_ips,
            "unique_ip_count": len(unique_ips),
            "internal_ip_hosts": internal_hosts,
            "cdn_distribution": cdn_counts,
            "asns": sorted(asn_summary.values(), key=lambda x: -x["ip_count"]),
            "truncated": truncated,
        },
        "raw_output": "\n".join(raw_lines)[:20000],
    }
