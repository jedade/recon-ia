# utils/passive_sources/github_dorks.py
"""
GitHub secret dorks — extension de l'outil `github` existant.

Recherche de code public GitHub mentionnant le domaine, croisée avec des motifs
de secrets courants (clés AWS, tokens, clés privées…). Clé GITHUB_TOKEN
requise (sinon `skipped`).

RÈGLE DE SÉCURITÉ ABSOLUE : on ne stocke JAMAIS la valeur d'un secret. On ne
conserve que :
  - l'emplacement (dépôt + chemin de fichier + URL) ;
  - le TYPE de secret détecté (ex. "AWS Access Key") ;
  - un fragment MASQUÉ servant de preuve non exploitable (ex. "AKIA…XZ").
Aucun fragment de code brut n'est renvoyé.

La session anti-SSRF est fournie en argument. Seul api.github.com est contacté
(fixe) ; la cible n'est jamais touchée. Le token n'apparaît jamais dans les
résultats (scrub).
"""
import re

from utils.passive_sources import (
    InvalidResponse, ResponseTooLarge, as_str, excerpt, read_json, scrub, skipped,
)

GITHUB_SEARCH = "https://api.github.com/search/code"
_ENV = "GITHUB_TOKEN"
_SIGNUP = "https://github.com/settings/tokens"

# Motifs de secrets : (type lisible, regex). Volontairement conservateurs pour
# limiter les faux positifs. Les captures ne sont JAMAIS stockées en clair.
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Generic API Key", re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Stripe Key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("Private IP in config", re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9.]+")),
]

# Qualificatifs de recherche croisant le domaine avec des indices de secret
DORK_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" BEGIN PRIVATE KEY',
    '"{domain}" aws_access_key_id',
]


def _mask(value: str) -> str:
    """Masque une valeur de secret : ne garde que le début et la fin."""
    value = value.strip().strip("'\"")
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-2:]}"


def _classify(text: str):
    """Retourne la liste des (type, fragment masqué) trouvés dans un extrait."""
    found = []
    seen = set()
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text or ""):
            key = (label, m.group(0)[:6])
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": label, "masked": _mask(m.group(0))})
            if len(found) >= 10:
                return found
    return found


def search_dorks(http, domain, *, token=None, max_queries=5, per_page=10):
    token = (token or "").strip()
    if not token:
        return skipped(_ENV, _SIGNUP)

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.text-match+json",
        "User-Agent": "recon-ia",
    }
    findings = []
    seen_locations = set()
    raw_parts = []
    queries = [q.format(domain=domain) for q in DORK_QUERIES][:max_queries]

    for q in queries:
        try:
            resp = http.get(GITHUB_SEARCH, params={"q": q, "per_page": per_page},
                            headers=headers, timeout=15, stream=True)
            raw_parts.append(f"=== q={q} (HTTP {resp.status_code}) ===")
            if resp.status_code in (401, 403):
                # 403 = quota de recherche atteint ; on s'arrête proprement
                if not findings:
                    return {"status": "limited", "data": {"findings": []},
                            "error": "GitHub a refusé la requête (401/403, quota de recherche)",
                            "raw_output": "\n".join(raw_parts)}
                break
            if resp.status_code == 422:
                continue  # requête rejetée par GitHub, on passe à la suivante
            if resp.status_code != 200:
                continue
            payload = read_json(resp)
            for item in (payload.get("items") or [])[:per_page]:
                repo = as_str((item.get("repository") or {}).get("full_name"), 200)
                path = as_str(item.get("path"), 300)
                url = as_str(item.get("html_url"), 400)
                location = f"{repo}:{path}"
                if location in seen_locations:
                    continue
                # On ne concatène que les fragments de correspondance (text_matches)
                # pour la classification, et on ne les conserve JAMAIS tels quels.
                fragments = " ".join(
                    as_str(tm.get("fragment"), 500) or ""
                    for tm in (item.get("text_matches") or [])
                )
                secrets = _classify(fragments)
                seen_locations.add(location)
                findings.append({
                    "repository": repo,
                    "path": path,
                    "url": url,
                    "query": q,
                    "secret_types": [s["type"] for s in secrets],
                    "masked_samples": [s["masked"] for s in secrets],
                    "has_secret": bool(secrets),
                })
        except (ResponseTooLarge, InvalidResponse) as e:
            raw_parts.append(f"{q}: {scrub(e, token)}")
        except Exception as e:
            raw_parts.append(f"{q}: {scrub(e, token)}")

    confirmed = [f for f in findings if f["has_secret"]]
    return {
        "status": "success" if findings else "no_data",
        "data": {
            "findings": findings,
            "match_count": len(findings),
            "confirmed_secret_count": len(confirmed),
            "secret_types": sorted({t for f in confirmed for t in f["secret_types"]}),
        },
        "raw_output": excerpt("\n".join(raw_parts)),
    }
