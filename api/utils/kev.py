# utils/kev.py
"""
Catalogue CISA KEV (Known Exploited Vulnerabilities) — phase 3 du plan.

Rôle : savoir si une CVE observée passivement (Shodan InternetDB, champ
`vulns` / `vulns_enriched`) figure dans la liste officielle des
vulnérabilités EXPLOITÉES dans la nature, tenue par la CISA. Une CVE
présente dans KEV passe en sévérité CRITICAL (utils/severity_rules.py,
règle `cve_kev`) : c'est la seule source de ce projet qui distingue « une
version vulnérable est annoncée » de « cette faille est réellement utilisée
par des attaquants ».

Cycle de vie :
  - Le JSON officiel (~1,5 Mo) est téléchargé AU PLUS une fois par période
    `KEV_REFRESH_HOURS` (défaut 24 h), puis mis en cache sur disque
    (`KEV_CACHE_PATH`, défaut <tmp>/recon-ia-kev.json) ET en mémoire.
  - Plusieurs workers gunicorn partagent le même fichier : écriture
    atomique (fichier temporaire + os.replace), un téléchargement simultané
    par deux workers est sans effet de bord (le dernier gagne, contenu
    identique).
  - Rafraîchi par le watchdog (utils/stale_scan_watchdog.py) et, en
    secours, à la première consultation si le cache est absent ou périmé.

Échec non bloquant (exigence du plan) : réseau coupé, HTTP ≠ 200, JSON
invalide, fichier illisible → aucune CVE n'est considérée KEV, l'analyse
continue, l'échec est journalisé. Après un échec, aucune nouvelle tentative
avant `KEV_RETRY_MINUTES` (défaut 60) pour ne pas ajouter un délai réseau à
chaque analyse.

Sécurité :
  - URL forcée en https (une valeur `KEV_URL` en http est refusée).
  - Taille de réponse bornée (`_MAX_BYTES`), lecture en flux.
  - Seuls les identifiants au format strict `CVE-AAAA-NNNN+` sont retenus,
    les champs texte associés sont tronqués : rien du flux distant n'est
    réinjecté tel quel dans un prompt ou un rapport.
"""
import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional

import requests

logger = logging.getLogger(__name__)

_DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_URL = os.getenv("KEV_URL", _DEFAULT_URL).strip() or _DEFAULT_URL
_ENABLED = os.getenv("KEV_ENABLED", "true").strip().lower() not in ("0", "false", "no", "non")
_CACHE_PATH = os.getenv("KEV_CACHE_PATH", "").strip() or os.path.join(
    tempfile.gettempdir(), "recon-ia-kev.json"
)
_REFRESH_S = max(1, int(os.getenv("KEV_REFRESH_HOURS", "24"))) * 3600
_RETRY_S = max(1, int(os.getenv("KEV_RETRY_MINUTES", "60"))) * 60
_TIMEOUT_S = int(os.getenv("KEV_TIMEOUT_S", "20"))
_MAX_BYTES = 20 * 1024 * 1024     # le flux réel fait ~1,5 Mo ; marge large mais bornée

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

_lock = threading.Lock()
_mem: Dict = {"cves": None, "fetched_at": 0.0, "last_failure": 0.0}


def _now() -> float:
    return time.time()


def _parse_catalog(payload) -> Optional[Dict[str, Dict]]:
    """Extrait {cve_id: {date_added, ransomware, name}} du JSON CISA, ou None si invalide."""
    if not isinstance(payload, dict):
        return None
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return None
    out: Dict[str, Dict] = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not CVE_RE.match(cve):
            continue
        out[cve] = {
            "date_added": str(v.get("dateAdded") or "")[:10],
            "ransomware": str(v.get("knownRansomwareCampaignUse") or "")[:20],
            "name":       str(v.get("vulnerabilityName") or "")[:200],
        }
    return out


def _load_file() -> Optional[Dict]:
    """Lit le cache disque ; None s'il est absent ou illisible."""
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        cves = data.get("cves")
        fetched_at = float(data.get("fetched_at_ts") or 0)
        if not isinstance(cves, dict):
            return None
        # Revalidation : le fichier vit sur un disque partagé, on ne lui fait
        # pas plus confiance qu'au flux distant.
        cves = {k: v for k, v in cves.items() if isinstance(k, str) and CVE_RE.match(k)}
        return {"cves": cves, "fetched_at": fetched_at}
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning("[kev] Cache disque illisible (%s) — ignoré", e)
        return None


def _write_file(cves: Dict[str, Dict], fetched_at: float) -> None:
    directory = os.path.dirname(_CACHE_PATH) or "."
    try:
        fd, tmp = tempfile.mkstemp(prefix=".kev-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({
                "fetched_at":    datetime.fromtimestamp(fetched_at, tz=timezone.utc).isoformat(),
                "fetched_at_ts": fetched_at,
                "source":        _URL,
                "cves":          cves,
            }, fh)
        os.replace(tmp, _CACHE_PATH)
    except Exception as e:
        logger.warning("[kev] Écriture du cache disque impossible (%s) — cache mémoire seul", e)


def _download() -> Optional[Dict[str, Dict]]:
    if not _URL.lower().startswith("https://"):
        logger.error("[kev] KEV_URL doit être en https — téléchargement refusé")
        return None
    try:
        with requests.get(_URL, timeout=_TIMEOUT_S, stream=True,
                          headers={"User-Agent": "Recon-IA/1.0 (+KEV)"}) as resp:
            if resp.status_code != 200:
                logger.warning("[kev] HTTP %s sur le flux CISA KEV", resp.status_code)
                return None
            chunks, size = [], 0
            for chunk in resp.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > _MAX_BYTES:
                    logger.warning("[kev] Réponse trop volumineuse (> %d octets) — ignorée", _MAX_BYTES)
                    return None
                chunks.append(chunk)
        catalog = _parse_catalog(json.loads(b"".join(chunks).decode("utf-8")))
        if not catalog:
            logger.warning("[kev] Flux CISA KEV invalide ou vide — ignoré")
            return None
        return catalog
    except Exception as e:
        logger.warning("[kev] Téléchargement CISA KEV impossible (%s) — analyse sans KEV", e)
        return None


def refresh(force: bool = False) -> bool:
    """
    Met à jour le catalogue si le cache (mémoire puis disque) a plus de
    KEV_REFRESH_HOURS. Retourne True si un catalogue utilisable est chargé.
    Ne lève jamais.
    """
    if not _ENABLED:
        return False
    with _lock:
        now = _now()
        if not force and _mem["cves"] is not None and now - _mem["fetched_at"] < _REFRESH_S:
            return True

        disk = _load_file()
        if disk and not force and now - disk["fetched_at"] < _REFRESH_S:
            _mem.update(cves=disk["cves"], fetched_at=disk["fetched_at"])
            return True

        if not force and now - _mem["last_failure"] < _RETRY_S:
            # Échec récent : on garde l'éventuel cache périmé plutôt que de
            # retenter le réseau à chaque analyse.
            if _mem["cves"] is None and disk:
                _mem.update(cves=disk["cves"], fetched_at=disk["fetched_at"])
            return _mem["cves"] is not None

        catalog = _download()
        if catalog is None:
            _mem["last_failure"] = now
            # Un cache périmé vaut mieux que rien : la liste KEV ne fait que grossir.
            if _mem["cves"] is None and disk:
                _mem.update(cves=disk["cves"], fetched_at=disk["fetched_at"])
                logger.info("[kev] Cache périmé conservé (%d CVE)", len(disk["cves"]))
            return _mem["cves"] is not None

        _mem.update(cves=catalog, fetched_at=now, last_failure=0.0)
        _write_file(catalog, now)
        logger.info("[kev] Catalogue CISA KEV chargé — %d CVE", len(catalog))
        return True


def kev_entries(cve_ids: Iterable[str], allow_fetch: bool = True) -> Dict[str, Dict]:
    """
    Sous-ensemble de `cve_ids` présent dans KEV → métadonnées KEV.
    Dictionnaire vide si KEV indisponible (jamais d'exception).
    """
    ids = {str(c).strip().upper() for c in (cve_ids or []) if isinstance(c, str)}
    ids = {c for c in ids if CVE_RE.match(c)}
    if not ids or not _ENABLED:
        return {}
    if allow_fetch:
        refresh()
    else:
        with _lock:
            if _mem["cves"] is None:
                disk = _load_file()
                if disk:
                    _mem.update(cves=disk["cves"], fetched_at=disk["fetched_at"])
    catalog = _mem["cves"] or {}
    return {c: catalog[c] for c in ids if c in catalog}


def status() -> Dict:
    """État du cache, pour les rapports et la mesure (aucun appel réseau)."""
    cves = _mem["cves"]
    return {
        "enabled":    _ENABLED,
        "loaded":     cves is not None,
        "count":      len(cves) if cves else 0,
        "fetched_at": (
            datetime.fromtimestamp(_mem["fetched_at"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if cves is not None and _mem["fetched_at"] else None
        ),
    }


def _reset_for_tests() -> None:
    with _lock:
        _mem.update(cves=None, fetched_at=0.0, last_failure=0.0)
