# utils/signals_extra.py
"""
Signaux compacts des outils de la phase 5 (collecte passive enrichie).

`extract_extra_signals(raw_results)` prend le dictionnaire complet des résultats
de scan (tel que produit par `routes/recon.py::run_recon`, c.-à-d. {clé_outil:
{status, data, meta, raw_output}}) et en extrait une structure COMPACTE,
destinée à être fusionnée dans `_extract_signals` de `routes/analyze.py` pour
l'analyse LLM. Objectif : donner au modèle les faits saillants sans lui envoyer
les résultats bruts volumineux.

Garanties :
  - purement défensif : tout champ manquant ou mal typé est ignoré, jamais
    d'exception ;
  - aucune donnée sensible : les secrets GitHub sont déjà masqués en amont
    (seuls type + emplacement sont repris), aucune clé d'API n'est lue ici ;
  - borné : les listes sont tronquées.

Structure retournée (toutes les clés sont toujours présentes) :
{
  "dns_mass": {
      "alive_count": int,          # sous-domaines vivants
      "dead_count": int,
      "unique_ip_count": int,
      "cdn_distribution": {str: int},   # CDN → nb d'hôtes
      "asns": [{"asn": int, "as_name": str|None, "ip_count": int}],  # ≤ 10
      "internal_ip_hosts": [str],  # ≤ 20, fuite d'adressage interne
      "top_live_hosts": [str],     # ≤ 30 sous-domaines vivants
  },
  "blocklists": {
      "is_blocked": bool,
      "blocked_count": int,
      "blocked_by": [str],         # ≤ 20 résolveurs
  },
  "threats": {
      "flagged": bool,
      "safe_browsing_types": [str],
      "phishtank_listed": bool,
  },
  "virustotal": {
      "available": bool,           # False si clé absente / skipped
      "malicious_total": int,
      "risk_level": str,           # clean|medium|high
      "categories": [str],         # ≤ 10
  },
  "cookies": {
      "count": int,
      "all_secure": bool,
      "insecure": [str],           # ≤ 20 noms de cookies non sécurisés
  },
  "social_tags_present": bool,
  "linked_domains": [str],         # ≤ 30 domaines tiers liés
  "ranking": {
      "tranco_rank": int|None,
      "hsts_preloaded": bool,
  },
  "dnsdumpster_subdomains": int,   # nb de sous-domaines rapportés
  "grayhatwarfare": {
      "available": bool,
      "file_count": int,
  },
  "github_dorks": {
      "available": bool,
      "match_count": int,
      "confirmed_secret_count": int,
      "secret_types": [str],       # ≤ 15, types masqués (jamais la valeur)
      "locations": [str],          # ≤ 15 "repo:path" avec secret
  },
}
"""
from typing import Any, Dict


def _tool(raw_results: dict, key: str) -> Dict[str, Any]:
    entry = (raw_results or {}).get(key)
    if not isinstance(entry, dict):
        return {}
    return entry


def _data(raw_results: dict, key: str) -> Dict[str, Any]:
    data = _tool(raw_results, key).get("data")
    return data if isinstance(data, dict) else {}


def _int(value, default=0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    return default


def _str_list(value, limit: int) -> list:
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, str):
            out.append(item[:253])
        if len(out) >= limit:
            break
    return out


def extract_extra_signals(raw_results: dict) -> dict:
    """Produit les signaux compacts de la phase 5. Ne lève jamais."""
    try:
        return _extract(raw_results or {})
    except Exception:
        # Un signal défaillant ne doit jamais bloquer l'analyse.
        return _empty()


def _empty() -> dict:
    return {
        "dns_mass": {"alive_count": 0, "dead_count": 0, "unique_ip_count": 0,
                     "cdn_distribution": {}, "asns": [], "internal_ip_hosts": [],
                     "top_live_hosts": []},
        "blocklists": {"is_blocked": False, "blocked_count": 0, "blocked_by": []},
        "threats": {"flagged": False, "safe_browsing_types": [], "phishtank_listed": False},
        "virustotal": {"available": False, "malicious_total": 0, "risk_level": "clean",
                       "categories": []},
        "cookies": {"count": 0, "all_secure": False, "insecure": []},
        "social_tags_present": False,
        "linked_domains": [],
        "ranking": {"tranco_rank": None, "hsts_preloaded": False},
        "dnsdumpster_subdomains": 0,
        "grayhatwarfare": {"available": False, "file_count": 0},
        "github_dorks": {"available": False, "match_count": 0, "confirmed_secret_count": 0,
                         "secret_types": [], "locations": []},
    }


def _extract(raw_results: dict) -> dict:
    out = _empty()

    # dns_mass (B4)
    dm = _data(raw_results, "dns_mass")
    if dm:
        hosts = dm.get("hosts") if isinstance(dm.get("hosts"), list) else []
        live = [h.get("subdomain") for h in hosts
                if isinstance(h, dict) and h.get("status") == "alive" and isinstance(h.get("subdomain"), str)]
        cdn = dm.get("cdn_distribution")
        asns = dm.get("asns") if isinstance(dm.get("asns"), list) else []
        out["dns_mass"] = {
            "alive_count": _int(dm.get("alive_count")),
            "dead_count": _int(dm.get("dead_count")),
            "unique_ip_count": _int(dm.get("unique_ip_count")),
            "cdn_distribution": {str(k)[:40]: _int(v) for k, v in cdn.items()} if isinstance(cdn, dict) else {},
            "asns": [
                {"asn": _int(a.get("asn")), "as_name": (a.get("as_name") or None),
                 "ip_count": _int(a.get("ip_count"))}
                for a in asns[:10] if isinstance(a, dict)
            ],
            "internal_ip_hosts": _str_list(dm.get("internal_ip_hosts"), 20),
            "top_live_hosts": live[:30],
        }

    # blocklists
    bl = _data(raw_results, "blocklists")
    if bl:
        out["blocklists"] = {
            "is_blocked": bool(bl.get("is_blocked")),
            "blocked_count": _int(bl.get("blocked_count")),
            "blocked_by": _str_list(bl.get("blocked_by"), 20),
        }

    # threats (Safe Browsing + PhishTank)
    th = _data(raw_results, "threats_check")
    if th:
        sb = th.get("safe_browsing") if isinstance(th.get("safe_browsing"), dict) else {}
        pt = th.get("phishtank") if isinstance(th.get("phishtank"), dict) else {}
        sb_types = [m.get("threat_type") for m in (sb.get("matches") or [])
                    if isinstance(m, dict) and isinstance(m.get("threat_type"), str)]
        out["threats"] = {
            "flagged": bool(th.get("flagged")),
            "safe_browsing_types": sb_types[:10],
            "phishtank_listed": bool(pt.get("is_phish")),
        }

    # virustotal
    vt_tool = _tool(raw_results, "virustotal")
    vt = vt_tool.get("data") if isinstance(vt_tool.get("data"), dict) else {}
    available = vt_tool.get("status") not in (None, "skipped", "limited")
    cats = vt.get("categories")
    out["virustotal"] = {
        "available": bool(available and vt),
        "malicious_total": _int(vt.get("malicious_total")),
        "risk_level": vt.get("risk_level") if isinstance(vt.get("risk_level"), str) else "clean",
        "categories": sorted({str(v)[:60] for v in cats.values()})[:10] if isinstance(cats, dict) else [],
    }

    # cookies / social / linked (web_metadata)
    wm = _data(raw_results, "web_metadata")
    if wm:
        out["cookies"] = {
            "count": _int(wm.get("cookie_count")),
            "all_secure": bool(wm.get("all_cookies_secure")),
            "insecure": _str_list(wm.get("insecure_cookies"), 20),
        }
        social = wm.get("social_tags")
        out["social_tags_present"] = bool(isinstance(social, dict) and social)
        linked = wm.get("linked_domains")
        if isinstance(linked, list):
            out["linked_domains"] = [
                d.get("domain") for d in linked[:30]
                if isinstance(d, dict) and isinstance(d.get("domain"), str)
            ]

    # ranking (Tranco + HSTS preload)
    sr = _data(raw_results, "site_ranking")
    if sr:
        rank = sr.get("rank")
        out["ranking"] = {
            "tranco_rank": rank if isinstance(rank, int) and not isinstance(rank, bool) else None,
            "hsts_preloaded": bool(sr.get("hsts_preloaded")),
        }

    # dnsdumpster
    dd = _data(raw_results, "dnsdumpster")
    if dd:
        out["dnsdumpster_subdomains"] = _int(dd.get("count"))

    # grayhatwarfare
    ghw_tool = _tool(raw_results, "grayhatwarfare")
    ghw = ghw_tool.get("data") if isinstance(ghw_tool.get("data"), dict) else {}
    out["grayhatwarfare"] = {
        "available": ghw_tool.get("status") not in (None, "skipped"),
        "file_count": _int(ghw.get("file_count")),
    }

    # github_dorks (valeurs de secrets déjà masquées en amont)
    gd_tool = _tool(raw_results, "github_dorks")
    gd = gd_tool.get("data") if isinstance(gd_tool.get("data"), dict) else {}
    findings = gd.get("findings") if isinstance(gd.get("findings"), list) else []
    locations = [
        f"{f.get('repository')}:{f.get('path')}"
        for f in findings
        if isinstance(f, dict) and f.get("has_secret") and f.get("repository")
    ]
    out["github_dorks"] = {
        "available": gd_tool.get("status") not in (None, "skipped"),
        "match_count": _int(gd.get("match_count")),
        "confirmed_secret_count": _int(gd.get("confirmed_secret_count")),
        "secret_types": _str_list(gd.get("secret_types"), 15),
        "locations": locations[:15],
    }

    return out
