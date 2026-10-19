# utils/passive_sources/ranking.py
"""
rank (Tranco) + HSTS preload (repris de web-check).

- Tranco : classement de popularité du domaine via l'API publique
  (https://tranco-list.eu/api/ranks/domain/<domaine>), sans clé. Sert à
  pondérer l'exposition (un domaine très classé = surface d'attaque critique).
- HSTS preload : éligibilité/état sur la liste de préchargement des navigateurs
  via l'API publique hstspreload.org (sans clé).

Hôtes fixes, jamais la cible. Session anti-SSRF fournie en argument.
"""
from utils.passive_sources import (
    InvalidResponse, ResponseTooLarge, as_int, as_str, excerpt, read_json, scrub,
)

TRANCO_URL = "https://tranco-list.eu/api/ranks/domain/"
HSTS_URL = "https://hstspreload.org/api/v2/status"


def check_tranco(http, domain):
    try:
        resp = http.get(f"{TRANCO_URL}{domain}", timeout=10, stream=True)
        if resp.status_code == 404:
            return {"status": "no_data", "ranked": False,
                    "note": "Domaine absent du classement Tranco"}
        if resp.status_code != 200:
            return {"status": "error", "error": f"HTTP {resp.status_code}"}
        payload = read_json(resp)
        ranks = payload.get("ranks") or []
        latest = as_int(payload.get("rank"))
        if latest is None and ranks:
            latest = as_int((ranks[-1] or {}).get("rank"))
        return {"status": "success", "ranked": latest is not None,
                "rank": latest, "history_points": len(ranks)}
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "error": str(e)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_hsts_preload(http, domain):
    try:
        resp = http.get(HSTS_URL, params={"domain": domain}, timeout=10, stream=True)
        if resp.status_code != 200:
            return {"status": "error", "error": f"HTTP {resp.status_code}"}
        payload = read_json(resp)
        status = as_str(payload.get("status"), 40) or "unknown"
        return {"status": "success", "preload_status": status,
                "is_preloaded": status == "preloaded",
                "bulk_1_year": bool(payload.get("bulk_1_year"))}
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "error": str(e)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_ranking(http, domain):
    tranco = check_tranco(http, domain)
    hsts = check_hsts_preload(http, domain)
    status = "success" if "success" in (tranco.get("status"), hsts.get("status")) else "error"
    return {
        "status": status,
        "data": {
            "tranco": tranco,
            "hsts_preload": hsts,
            "rank": tranco.get("rank"),
            "hsts_preloaded": hsts.get("is_preloaded", False),
        },
        "raw_output": excerpt(f"Tranco: {tranco}\nHSTS preload: {hsts}"),
    }
