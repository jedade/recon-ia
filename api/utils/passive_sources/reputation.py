# utils/passive_sources/reputation.py
"""
Réputation via VirusTotal v3 (réputation domaine + passive DNS + réputation des
IP résolues). Clé gratuite VIRUSTOTAL_API_KEY (4 req/min) ; sans elle l'outil
est `skipped`.

Toutes les requêtes passent par la session HTTP anti-SSRF fournie en argument.
Les hôtes VirusTotal sont fixes (www.virustotal.com) ; la cible n'est jamais
contactée. La clé n'apparaît jamais dans les résultats ni dans raw_output
(scrub).
"""
from utils.passive_sources import (
    InvalidResponse, ResponseTooLarge, as_int, as_str, excerpt, read_json, scrub, skipped,
)

VT_BASE = "https://www.virustotal.com/api/v3"
_ENV = "VIRUSTOTAL_API_KEY"
_SIGNUP = "https://www.virustotal.com/gui/join-us"
MAX_IPS = 4
MAX_PASSIVE_DNS = 40


def _get(http, path, api_key, timeout=12):
    return http.get(f"{VT_BASE}/{path}", headers={"x-apikey": api_key},
                    timeout=timeout, stream=True)


def _last_analysis(stats):
    if not isinstance(stats, dict):
        return {}
    return {k: as_int(stats.get(k)) or 0 for k in ("malicious", "suspicious", "harmless", "undetected")}


def check_reputation(http, domain, ips=None, *, api_key=None):
    api_key = (api_key or "").strip()
    if not api_key:
        return skipped(_ENV, _SIGNUP)

    raw_parts = []
    data = {"domain": domain, "domain_stats": {}, "reputation": None,
            "categories": {}, "passive_dns": [], "ip_reputation": []}
    try:
        resp = _get(http, f"domains/{domain}", api_key)
        raw_parts.append(f"=== VT domains/{domain} (HTTP {resp.status_code}) ===")
        if resp.status_code in (401, 403):
            return {"status": "limited", "data": {},
                    "error": "VirusTotal a refusé la clé (401/403)", "raw_output": "\n".join(raw_parts)}
        if resp.status_code == 429:
            return {"status": "limited", "data": {},
                    "error": "Quota VirusTotal atteint (429)", "raw_output": "\n".join(raw_parts)}
        if resp.status_code == 404:
            return {"status": "no_data", "data": data,
                    "error": "Domaine inconnu de VirusTotal", "raw_output": "\n".join(raw_parts)}
        if resp.status_code != 200:
            return {"status": "error", "data": {},
                    "error": f"HTTP {resp.status_code}", "raw_output": "\n".join(raw_parts)}
        attrs = (read_json(resp).get("data") or {}).get("attributes") or {}
        data["domain_stats"] = _last_analysis(attrs.get("last_analysis_stats"))
        data["reputation"] = as_int(attrs.get("reputation"))
        cats = attrs.get("categories")
        if isinstance(cats, dict):
            data["categories"] = {as_str(k, 60): as_str(v, 120) for k, v in list(cats.items())[:20]}
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key),
                "raw_output": "\n".join(raw_parts)}
    except Exception as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key),
                "raw_output": "\n".join(raw_parts)}

    # Passive DNS (résolutions historiques)
    try:
        resp = _get(http, f"domains/{domain}/resolutions?limit={MAX_PASSIVE_DNS}", api_key)
        raw_parts.append(f"=== VT resolutions (HTTP {resp.status_code}) ===")
        if resp.status_code == 200:
            for item in (read_json(resp).get("data") or [])[:MAX_PASSIVE_DNS]:
                a = item.get("attributes") or {}
                data["passive_dns"].append({
                    "ip": as_str(a.get("ip_address"), 45),
                    "date": as_int(a.get("date")),
                })
    except Exception as e:
        raw_parts.append(f"resolutions: {scrub(e, api_key)}")

    # Réputation des IP résolues (bornée)
    for ip in [i for i in (ips or []) if isinstance(i, str) and ":" not in i][:MAX_IPS]:
        try:
            resp = _get(http, f"ip_addresses/{ip}", api_key)
            raw_parts.append(f"=== VT ip/{ip} (HTTP {resp.status_code}) ===")
            if resp.status_code == 200:
                a = (read_json(resp).get("data") or {}).get("attributes") or {}
                data["ip_reputation"].append({
                    "ip": ip,
                    "stats": _last_analysis(a.get("last_analysis_stats")),
                    "as_owner": as_str(a.get("as_owner"), 120),
                    "reputation": as_int(a.get("reputation")),
                })
        except Exception as e:
            raw_parts.append(f"ip/{ip}: {scrub(e, api_key)}")

    malicious = (data["domain_stats"].get("malicious") or 0) + (data["domain_stats"].get("suspicious") or 0)
    ip_mal = sum((r["stats"].get("malicious") or 0) for r in data["ip_reputation"])
    data["malicious_total"] = malicious + ip_mal
    data["risk_level"] = "high" if malicious + ip_mal >= 3 else ("medium" if malicious + ip_mal else "clean")
    return {"status": "success", "data": data,
            "raw_output": excerpt("\n".join(raw_parts))}
