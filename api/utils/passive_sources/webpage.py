# utils/passive_sources/webpage.py
"""
cookies / social-tags / linked-pages (repris de web-check).

Les trois lectures se font sur UNE SEULE réponse HTTP de la page d'accueil
(le seul GET autorisé vers la cible, déjà pratiqué par le projet). Aucune
requête supplémentaire n'est émise : `analyze_homepage` reçoit une réponse
`requests` déjà obtenue via la session anti-SSRF, ou la récupère en un unique
GET quand on lui passe la session.

- B11 cookies : drapeaux Secure, HttpOnly, SameSite de chaque Set-Cookie
  (valeurs des cookies jamais conservées, seulement les noms et drapeaux).
- social-tags : balises meta Open Graph (og:) et Twitter Card.
- linked-pages : domaines tiers liés depuis le HTML (href/src externes).
"""
import re
from urllib.parse import urlparse

from utils.passive_sources import as_str, excerpt

MAX_HTML_BYTES = 1_000_000
SAMESITE_RE = re.compile(r";\s*samesite\s*=\s*([^;]+)", re.IGNORECASE)


def _parse_set_cookies(raw_headers):
    """
    Analyse les en-têtes Set-Cookie. `raw_headers` est une liste de chaînes
    (un cookie par entrée). Ne conserve jamais la valeur du cookie.
    """
    cookies = []
    for line in raw_headers or []:
        if not isinstance(line, str) or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        low = line.lower()
        samesite = SAMESITE_RE.search(line)
        cookies.append({
            "name": as_str(name, 120),
            "secure": "; secure" in low or low.endswith("secure") or ";secure" in low,
            "http_only": "httponly" in low,
            "same_site": as_str(samesite.group(1).strip(), 20) if samesite else None,
        })
    return cookies


def _extract_set_cookie_headers(resp):
    """Récupère chaque Set-Cookie séparément (requests fusionne sinon)."""
    raw = getattr(resp, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "get_all"):
        try:
            got = headers.get_all("Set-Cookie")
            if got:
                return list(got)
        except Exception:
            pass
    # Replis : cookies de l'objet réponse, ou en-tête fusionné
    jar = getattr(resp, "cookies", None)
    if jar:
        try:
            return [f"{c.name}={c.value or ''}" + ("; Secure" if getattr(c, 'secure', False) else "")
                    + ("; HttpOnly" if c.has_nonstandard_attr('HttpOnly') else "")
                    for c in jar]
        except Exception:
            pass
    merged = (getattr(resp, "headers", None) or {}).get("Set-Cookie")
    return [merged] if merged else []


def _extract_social_tags(html):
    tags = {}
    for m in re.finditer(
        r'<meta\s+(?:property|name)=["\']([^"\']+)["\']\s+content=["\']([^"\']*)["\']',
        html, re.IGNORECASE,
    ):
        prop, content = m.group(1).lower(), m.group(2)
        if prop.startswith("og:") or prop.startswith("twitter:"):
            tags[prop[:60]] = content[:300]
        if len(tags) >= 40:
            break
    return tags


def _registrable(host):
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _extract_linked_domains(html, domain):
    own = _registrable(domain)
    domains = {}
    for m in re.finditer(r'(?:href|src)=["\'](https?://[^"\'>\s]+)["\']', html, re.IGNORECASE):
        host = (urlparse(m.group(1)).hostname or "").lower()
        if not host or host == domain or host.endswith("." + domain):
            continue
        if _registrable(host) == own:
            continue
        domains[host] = domains.get(host, 0) + 1
        if len(domains) >= 200:
            break
    return [{"domain": h, "references": n} for h, n in sorted(domains.items(), key=lambda x: -x[1])]


def analyze_response(resp, domain):
    """Extrait cookies/social/linked d'une réponse `requests` déjà obtenue."""
    set_cookies = _extract_set_cookie_headers(resp)
    cookies = _parse_set_cookies(set_cookies)
    content_type = (getattr(resp, "headers", None) or {}).get("Content-Type", "")
    html = ""
    if "html" in content_type.lower() or not content_type:
        text = getattr(resp, "text", "") or ""
        html = text[:MAX_HTML_BYTES]
    social = _extract_social_tags(html)
    linked = _extract_linked_domains(html, domain)
    insecure = [c["name"] for c in cookies if not (c["secure"] and c["http_only"])]
    return {
        "status": "success",
        "data": {
            "cookies": cookies,
            "cookie_count": len(cookies),
            "insecure_cookies": insecure,
            "all_cookies_secure": bool(cookies) and not insecure,
            "social_tags": social,
            "social_tag_count": len(social),
            "linked_domains": linked,
            "linked_domain_count": len(linked),
        },
        "raw_output": excerpt(
            "Set-Cookie:\n" + "\n".join(c["name"] for c in cookies)
            + "\n\nSocial:\n" + "\n".join(f"{k}={v}" for k, v in social.items())
            + "\n\nLinked:\n" + "\n".join(d["domain"] for d in linked)
        ),
    }


def analyze_homepage(http, domain):
    """Récupère la page d'accueil (un seul GET) puis délègue à analyze_response."""
    last_err = None
    for scheme in ("https", "http"):
        try:
            resp = http.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"})
            return analyze_response(resp, domain)
        except Exception as e:
            last_err = e
            continue
    return {"status": "unreachable", "data": {}, "error": str(last_err) if last_err else "injoignable",
            "raw_output": ""}
