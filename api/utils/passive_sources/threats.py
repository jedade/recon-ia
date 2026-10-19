# utils/passive_sources/threats.py
"""
threats (repris de web-check) — Google Safe Browsing + PhishTank.

- Safe Browsing : POST threatMatches:find (clé GOOGLE_SAFE_BROWSING_API_KEY,
  gratuite). Sans clé → partie `skipped`.
- PhishTank : consultation publique `checkurl` (sans clé ; un PHISHTANK_API_KEY
  optionnel améliore le quota). Gratuit.

URLhaus est déjà couvert par l'outil `abusech_check` existant, donc non repris
ici. La cible n'est jamais contactée : seules les API fixes de Google et
PhishTank le sont, via la session anti-SSRF fournie.
"""
from utils.passive_sources import (
    InvalidResponse, ResponseTooLarge, as_str, excerpt, read_json, scrub,
)

SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PT_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
SB_ENV = "GOOGLE_SAFE_BROWSING_API_KEY"
SB_SIGNUP = "https://developers.google.com/safe-browsing/v4/get-started"


def _safe_browsing(http, domain, api_key):
    if not api_key:
        return {"status": "skipped",
                "error": f"{SB_ENV} non configuré — clé gratuite sur {SB_SIGNUP}",
                "matches": []}
    body = {
        "client": {"clientId": "recon-ia", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}/"}, {"url": f"https://{domain}/"}],
        },
    }
    try:
        resp = http.post(SB_ENDPOINT, params={"key": api_key}, json=body, timeout=12, stream=True)
        if resp.status_code in (400, 401, 403):
            return {"status": "limited", "error": f"Safe Browsing a refusé la requête ({resp.status_code})",
                    "matches": []}
        if resp.status_code != 200:
            return {"status": "error", "error": f"HTTP {resp.status_code}", "matches": []}
        payload = read_json(resp)
        matches = []
        for m in (payload.get("matches") or [])[:20]:
            matches.append({"threat_type": as_str(m.get("threatType"), 60),
                            "platform": as_str(m.get("platformType"), 60)})
        return {"status": "success", "matches": matches, "flagged": bool(matches)}
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "error": scrub(e, api_key), "matches": []}
    except Exception as e:
        return {"status": "error", "error": scrub(e, api_key), "matches": []}


def _phishtank(http, domain, api_key):
    data = {"url": f"http://{domain}/", "format": "json"}
    if api_key:
        data["app_key"] = api_key
    try:
        resp = http.post(PT_ENDPOINT, data=data,
                         headers={"User-Agent": "phishtank/recon-ia"}, timeout=12, stream=True)
        if resp.status_code == 509:
            return {"status": "limited", "error": "PhishTank : quota atteint (509)"}
        if resp.status_code != 200:
            return {"status": "error", "error": f"HTTP {resp.status_code}"}
        results = (read_json(resp).get("results") or {})
        in_db = bool(results.get("in_database"))
        return {"status": "success", "in_database": in_db,
                "is_phish": bool(results.get("valid")) if in_db else False,
                "phish_detail_page": as_str(results.get("phish_detail_page"), 200)}
    except (ResponseTooLarge, InvalidResponse) as e:
        return {"status": "error", "error": scrub(e, api_key)}
    except Exception as e:
        return {"status": "error", "error": scrub(e, api_key)}


def check_threats(http, domain, *, safe_browsing_key=None, phishtank_key=None):
    sb = _safe_browsing(http, domain, (safe_browsing_key or "").strip())
    pt = _phishtank(http, domain, (phishtank_key or "").strip())
    flagged = bool(sb.get("flagged")) or bool(pt.get("is_phish"))
    # Statut global : skipped seulement si les DEUX sources sont inutilisables
    usable = {sb.get("status"), pt.get("status")} & {"success"}
    status = "success" if usable else (sb.get("status") or "error")
    return {
        "status": status,
        "data": {
            "safe_browsing": sb,
            "phishtank": pt,
            "flagged": flagged,
            "risk_level": "high" if flagged else "clean",
        },
        "raw_output": excerpt(f"SafeBrowsing: {sb}\nPhishTank: {pt}"),
    }
