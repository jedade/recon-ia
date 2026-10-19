# utils/takeover_fingerprints.py
"""
Empreintes de prise de contrôle de sous-domaine (consultation directe, hors RAG).

Source : projet communautaire can-i-take-over-xyz (EdOverflow,
https://github.com/EdOverflow/can-i-take-over-xyz, licence CC BY 4.0 —
attribution conservée dans le fichier JSON). Copie locale :
`api/data/takeover_fingerprints.json`, régénérée manuellement par
`data/script_takeover_fingerprints.py` (aucun appel réseau à l'exécution).

Intérêt par rapport à la liste codée en dur de routes/recon.py
(`_subdomain_takeover.TAKEOVER_SERVICES`, 18 services) : ~80 services, et
surtout le STATUT communautaire de chacun (« Vulnerable », « Not
vulnerable », « Edge case ») et l'indication NXDOMAIN — certains services de
la liste actuelle (ex. Fastly, Shopify selon les époques) sont signalés « Not
vulnerable » ou « Edge case », source de faux positifs. Intégration dans
recon.py laissée à la phase 5 (propriétaire du fichier) :

    from utils.takeover_fingerprints import match_cname
    fp = match_cname(cname_target)
    if fp and fp["vulnerable"]: ...

La correspondance se fait sur le SUFFIXE DNS exact (« x.github.io » correspond
à « github.io », « evilgithub.io » non), contrairement au `in` de recon.py.
"""
import json
import os
from functools import lru_cache
from typing import Dict, List, Optional

FINGERPRINTS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "data", "takeover_fingerprints.json")

# can-i-take-over-xyz ne renseigne pas le champ CNAME de certains services
# (dont des « Vulnerable »). Suffixes de leur domaine d'hébergement, repris de
# l'ancienne liste de recon.py : ils servent seulement à RECONNAÎTRE le
# service, le statut (vulnérable, cas limite, non vulnérable) reste celui de
# la source.
_CNAME_SUPPLEMENT = {
    "Github": ["github.io"],
    "Heroku": ["herokuapp.com", "herokudns.com"],
    "Shopify": ["myshopify.com"],
    "Netlify": ["netlify.app", "netlify.com"],
    "Readthedocs": ["readthedocs.io"],
    "Pantheon": ["pantheonsite.io"],
    "Cargo Collective": ["cargo.site", "cargocollective.com"],
    "Fly.io": ["fly.dev"],
    "Fastly": ["fastly.net"],
    "Zendesk": ["zendesk.com"],
}


@lru_cache(maxsize=4)
def load_fingerprints(path: str = FINGERPRINTS_PATH) -> List[Dict]:
    """Liste des empreintes ({service, cname[], status, vulnerable, nxdomain, fingerprint})."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return []
    items = doc.get("fingerprints", []) if isinstance(doc, dict) else []
    out = []
    for it in items:
        if not isinstance(it, dict) or not isinstance(it.get("service"), str):
            continue
        cnames = [c.strip().lower().rstrip(".") for c in it.get("cname") or []
                  if isinstance(c, str) and c.strip()]
        if not cnames:
            cnames = list(_CNAME_SUPPLEMENT.get(it["service"], []))
        out.append({
            "service": it["service"][:120],
            "cname": cnames,
            "status": str(it.get("status") or "")[:40],
            "vulnerable": bool(it.get("vulnerable")),
            "nxdomain": bool(it.get("nxdomain")),
            "fingerprint": str(it.get("fingerprint") or "")[:300],
        })
    return out


def _suffix_match(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def match_cname(cname_target: str, path: str = FINGERPRINTS_PATH) -> Optional[Dict]:
    """
    Empreinte correspondant à la cible CNAME, ou None. En cas de plusieurs
    correspondances, la plus spécifique (suffixe le plus long) l'emporte.
    """
    if not isinstance(cname_target, str) or not cname_target.strip():
        return None
    host = cname_target.strip().lower().rstrip(".")
    best, best_len = None, -1
    for fp in load_fingerprints(path):
        for suffix in fp["cname"]:
            if _suffix_match(host, suffix) and len(suffix) > best_len:
                best, best_len = fp, len(suffix)
    return dict(best) if best else None
