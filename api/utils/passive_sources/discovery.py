# utils/passive_sources/discovery.py
"""
DNSDumpster (API officielle) + GrayHatWarfare (buckets cloud exposés).

- DNSDumpster : DNSDUMPSTER_API_KEY (gratuite). Renvoie sous-domaines, MX, TXT,
  enregistrements A historiques.
- GrayHatWarfare : GRAYHATWARFARE_API_KEY (priorité basse). Recherche de fichiers
  exposés dans des buckets publics liés au nom de domaine.

Sans clé → `skipped`. Hôtes fixes (api.dnsdumpster.com, api.grayhatwarfare.com),
jamais la cible. Session anti-SSRF fournie. Les clés ne figurent jamais dans
les résultats (scrub des messages d'erreur).
"""
from utils.passive_sources import (
    InvalidResponse, ResponseTooLarge, as_int, as_str, excerpt, read_json, scrub, skipped,
)

DNSDUMPSTER_URL = "https://api.dnsdumpster.com/domain/"
DNSDUMPSTER_ENV = "DNSDUMPSTER_API_KEY"
DNSDUMPSTER_SIGNUP = "https://dnsdumpster.com/"
GHW_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
GHW_ENV = "GRAYHATWARFARE_API_KEY"
GHW_SIGNUP = "https://grayhatwarfare.com/"
MAX_RECORDS = 200


def check_dnsdumpster(http, domain, *, api_key=None):
    api_key = (api_key or "").strip()
    if not api_key:
        return skipped(DNSDUMPSTER_ENV, DNSDUMPSTER_SIGNUP)
    try:
        resp = http.get(f"{DNSDUMPSTER_URL}{domain}", headers={"X-API-Key": api_key},
                        timeout=15, stream=True)
        if resp.status_code in (401, 403):
            return {"status": "limited", "data": {},
                    "error": "DNSDumpster a refusé la clé (401/403)", "raw_output": ""}
        if resp.status_code == 429:
            return {"status": "limited", "data": {},
                    "error": "Quota DNSDumpster atteint (429)", "raw_output": ""}
        if resp.status_code != 200:
            return {"status": "error", "data": {}, "error": f"HTTP {resp.status_code}", "raw_output": ""}
        payload = read_json(resp)
        subs, ips = [], []
        for rec in (payload.get("a") or [])[:MAX_RECORDS]:
            host = as_str(rec.get("host"), 253)
            if host:
                subs.append(host)
            for ipr in (rec.get("ips") or [])[:5]:
                ip = as_str(ipr.get("ip"), 45)
                if ip:
                    ips.append(ip)
        mx = [as_str((r or {}).get("host"), 253) for r in (payload.get("mx") or [])[:20]]
        txt = [as_str(t, 400) for t in (payload.get("txt") or [])[:20] if isinstance(t, str)]
        subs = list(dict.fromkeys(s for s in subs if s))
        return {
            "status": "success",
            "data": {
                "subdomains": subs,
                "count": len(subs),
                "ips": list(dict.fromkeys(ips)),
                "mx": [m for m in mx if m],
                "txt": [t for t in txt if t],
            },
            "raw_output": excerpt("\n".join(subs)),
        }
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key), "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key), "raw_output": ""}


def check_grayhatwarfare(http, domain, *, api_key=None, limit=40):
    api_key = (api_key or "").strip()
    if not api_key:
        return skipped(GHW_ENV, GHW_SIGNUP)
    # Mot-clé de recherche : le label principal du domaine
    keyword = domain.split(".")[0]
    try:
        resp = http.get(GHW_URL, params={"keywords": keyword, "limit": min(limit, 100)},
                        headers={"Authorization": f"Bearer {api_key}"}, timeout=15, stream=True)
        if resp.status_code in (401, 403):
            return {"status": "limited", "data": {},
                    "error": "GrayHatWarfare a refusé la clé (401/403)", "raw_output": ""}
        if resp.status_code == 429:
            return {"status": "limited", "data": {},
                    "error": "Quota GrayHatWarfare atteint (429)", "raw_output": ""}
        if resp.status_code != 200:
            return {"status": "error", "data": {}, "error": f"HTTP {resp.status_code}", "raw_output": ""}
        payload = read_json(resp)
        files = []
        for f in (payload.get("files") or [])[:limit]:
            files.append({
                "bucket": as_str(f.get("bucket"), 200),
                "filename": as_str(f.get("fullPath") or f.get("filename"), 300),
                "size": as_int(f.get("size")),
            })
        total = as_int(payload.get("total"))
        return {
            "status": "success" if files else "no_data",
            "data": {
                "keyword": keyword,
                "files": files,
                "file_count": len(files),
                "total_matches": total,
            },
            "raw_output": excerpt("\n".join(f["filename"] or "" for f in files)),
        }
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key), "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": scrub(e, api_key), "raw_output": ""}
