# utils/scan_stats.py
"""
Statistiques agrégées et ANONYMISÉES des scans passés (phase 6).

But : donner au LLM d'analyse un contexte comparatif court, du type
« Comme ce domaine, 70 % des domaines .bj déjà analysés par Recon-IA n'ont
pas d'enregistrement DMARC », sans indexer les scans bruts dans le RAG et
sans jamais exposer un nom de domaine.

Source des données
------------------
`pass_recon_cache` (models/pass_recon_cache.py) : c'est la seule table où
les résultats bruts de scan restent en clair (les résultats de `recon` sont
chiffrés par le coffre — décision D3 — et donc illisibles ici, ce qui est
voulu). Une ligne par (domaine, jeu d'outils) : on ne garde que le scan le
plus récent de chaque domaine, sur une fenêtre glissante
(`SCAN_STATS_WINDOW_DAYS`, 365 j par défaut) et au plus
`SCAN_STATS_MAX_ROWS` domaines (500).

Garanties d'anonymat
--------------------
- **k-anonymat** : une statistique n'est produite que si son dénominateur
  (domaines du périmètre pour lesquels le contrôle a pu être évalué) compte
  au moins `SCAN_STATS_MIN_SAMPLE` domaines (10 par défaut, plancher
  absolu 5 même si la variable est plus basse).
- **Domaine courant exclu** : le domaine en cours d'analyse ne participe
  jamais à la statistique qu'on lui compare.
- **Aucun nom de domaine en sortie** : les domaines ne servent qu'au
  dédoublonnage, en mémoire, sous forme d'empreinte SHA-256 ; les phrases
  sont construites à partir de gabarits fixes et du seul TLD, validé par
  expression régulière (pas de texte issu des scans dans la sortie).
- **Pourcentages arrondis** au multiple de 5 le plus proche, pour limiter
  les attaques par différence (comparer la statistique avant/après un scan).

Performance
-----------
Les `result_json` font jusqu'à quelques Mo. Les caractéristiques de chaque
ligne sont calculées une seule fois puis mises en cache en mémoire, clé
(id, updated_at) : seules les lignes nouvelles ou rescannées sont relues.
Les requêtes passent par l'ORM SQLAlchemy (paramétrées).

Usage (intégration prévue dans routes/analyze.py, phase 3) :

    from utils.scan_stats import comparative_context, tld_of
    signals["comparative_context"] = comparative_context(tld_of(domain), signals)

`comparative_context` ne lève jamais : liste vide si la base est
indisponible, l'échantillon trop petit ou les signaux inexploitables.
"""
import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paramètres
# ---------------------------------------------------------------------------

_ABSOLUTE_MIN_SAMPLE = 5


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def min_sample() -> int:
    """Seuil k-anonymat effectif (jamais sous le plancher absolu)."""
    return max(_ABSOLUTE_MIN_SAMPLE, _env_int("SCAN_STATS_MIN_SAMPLE", 10))


MAX_ROWS = _env_int("SCAN_STATS_MAX_ROWS", 500)
WINDOW_DAYS = _env_int("SCAN_STATS_WINDOW_DAYS", 365)
MAX_SENTENCES = _env_int("SCAN_STATS_MAX_SENTENCES", 6)
# Une « bonne pratique » du domaine courant n'est signalée que si au moins
# ce pourcentage du périmètre ne la respecte pas (sinon : sans intérêt).
NOTABLE_STRENGTH_PCT = 50

_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# Ports d'administration / de données qui ne devraient pas être exposés.
ADMIN_PORTS = frozenset({21, 22, 23, 445, 1433, 1521, 2375, 3306, 3389, 5432,
                         5900, 6379, 9200, 11211, 27017})

# Statuts d'outil qui rendent un contrôle « non évaluable » (None).
_UNUSABLE_STATUS = {"error", "timeout", "skipped", "unavailable", "disabled", "rate_limited"}

# ---------------------------------------------------------------------------
# Caractéristiques : (clé, libellé « ont / n'ont pas … » au pluriel)
# Une valeur True = faiblesse présente, False = bonne pratique, None = non évaluable.
# ---------------------------------------------------------------------------

FEATURES = (
    ("dmarc_absent",        "n'ont pas d'enregistrement DMARC"),
    ("dmarc_policy_none",   "ont une politique DMARC en p=none (surveillance seule, aucune protection)"),
    ("spf_absent",          "n'ont pas d'enregistrement SPF"),
    ("spf_permissive",      "ont un SPF permissif (+all ou ?all)"),
    ("dkim_absent",         "n'exposent aucune clé DKIM sur les sélecteurs courants"),
    ("mta_sts_absent",      "n'ont pas de politique MTA-STS"),
    ("dnssec_absent",       "n'ont pas activé DNSSEC"),
    ("caa_absent",          "n'ont pas d'enregistrement CAA"),
    ("hsts_absent",         "n'envoient pas l'en-tête HSTS"),
    ("csp_absent",          "n'envoient pas d'en-tête Content-Security-Policy"),
    ("tls_legacy",          "acceptent encore TLS 1.0/1.1 ou SSL"),
    ("cert_problem",        "ont un certificat TLS expiré ou proche de l'expiration"),
    ("security_txt_absent", "ne publient pas de fichier security.txt"),
    ("admin_ports_exposed", "exposent des ports d'administration ou de base de données (observés par Shodan)"),
    ("takeover_candidate",  "ont au moins un sous-domaine candidat à une prise de contrôle"),
    ("dnsbl_listed",        "ont une adresse IP présente sur une liste de blocage DNS"),
    ("breaches_found",      "ont des adresses génériques présentes dans des fuites de données publiques"),
)
FEATURE_KEYS = tuple(k for k, _ in FEATURES)
_LABELS = dict(FEATURES)


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def tld_of(domain: str) -> Optional[str]:
    """TLD (dernier label, minuscules) d'un domaine, ou None s'il est invalide."""
    if not isinstance(domain, str):
        return None
    label = domain.strip().rstrip(".").lower().rsplit(".", 1)[-1]
    return label if _TLD_RE.match(label) else None


def _norm_tld(tld: Any) -> Optional[str]:
    if not isinstance(tld, str):
        return None
    t = tld.strip().lstrip(".").lower()
    return t if _TLD_RE.match(t) else None


def _domain_hash(domain: str) -> str:
    return hashlib.sha256((domain or "").strip().rstrip(".").lower().encode("utf-8")).hexdigest()


def _round5(pct: float) -> int:
    return int(5 * round(pct / 5.0))


def _get(d: Any, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return default if d is None else d


# ---------------------------------------------------------------------------
# Vue normalisée : même calcul pour un scan brut (cache) et pour les signaux
# compacts de routes/analyze.py::_extract_signals.
# ---------------------------------------------------------------------------

def _tool_data(d: dict, tool: str) -> Optional[dict]:
    """`data` d'un outil du scan brut, ou None si absent / en erreur."""
    t = d.get(tool)
    if not isinstance(t, dict):
        return None
    if str(t.get("status", "")).lower() in _UNUSABLE_STATUS:
        return None
    data = t.get("data")
    return data if isinstance(data, dict) else ({} if t.get("status") else None)


def _view_from_raw(result: dict) -> dict:
    d = result
    if isinstance(d, dict) and "domain" not in d and isinstance(d.get("data"), dict):
        d = d["data"]
    if not isinstance(d, dict):
        return {}
    sec_txt = d.get("security_txt")
    sec_txt_status = sec_txt.get("status") if isinstance(sec_txt, dict) else None
    breaches = d.get("xposedornot_breaches")
    return {
        "dmarc":        _tool_data(d, "dmarc_check"),
        "email_config": _tool_data(d, "email_config"),
        "spf":          _tool_data(d, "spf_analysis"),
        "dkim":         _tool_data(d, "dkim_check"),
        "mta_sts":      _tool_data(d, "mta_sts_check"),
        "dnssec":       _tool_data(d, "dnssec"),
        "caa":          _tool_data(d, "caa_check"),
        "sec_headers":  _tool_data(d, "security_headers"),
        "tls":          _tool_data(d, "tls_config"),
        "ssl":          _tool_data(d, "ssl_info"),
        "security_txt_status": sec_txt_status,
        "shodan":       _tool_data(d, "shodan_internetdb"),
        "takeover":     _tool_data(d, "subdomain_takeover"),
        "dnsbl":        _tool_data(d, "dnsbl_check"),
        "breaches":     _tool_data(d, "xposedornot_breaches"),
        "breaches_status": breaches.get("status") if isinstance(breaches, dict) else None,
    }


def _view_from_signals(signals: dict) -> dict:
    s = signals if isinstance(signals, dict) else {}
    email = _get(s, "email", default={})
    shodan = _get(s, "network", "shodan_internetdb", default=None)
    if isinstance(shodan, dict) and str(shodan.get("status", "")).lower() in _UNUSABLE_STATUS:
        shodan = None
    dnsbl = _get(s, "network", "dnsbl", default=None)
    if isinstance(dnsbl, dict) and dnsbl.get("clean") is None and dnsbl.get("listed") is None:
        dnsbl = None
    breaches = _get(s, "breaches", default=None)
    return {
        "dmarc":        email.get("dmarc") if isinstance(email, dict) else None,
        "email_config": email.get("config") if isinstance(email, dict) else None,
        "spf":          email.get("spf_analysis") if isinstance(email, dict) else None,
        "dkim":         email.get("dkim") if isinstance(email, dict) else None,
        "mta_sts":      email.get("mta_sts") if isinstance(email, dict) else None,
        "dnssec":       _get(s, "dns", "dnssec"),
        "caa":          _get(s, "ssl_tls", "caa"),
        "sec_headers":  _get(s, "web", "security_headers"),
        "tls":          _get(s, "ssl_tls", "tls_config"),
        "ssl":          _get(s, "ssl_tls", "certificate"),
        "security_txt_status": _get(s, "web", "security_txt_status"),
        "shodan":       shodan,
        "takeover":     _get(s, "subdomains", "takeover"),
        "dnsbl":        ({"clean": dnsbl.get("clean"), "listed": dnsbl.get("listed")}
                         if isinstance(dnsbl, dict) else None),
        "breaches":     breaches if isinstance(breaches, dict) else None,
        "breaches_status": breaches.get("status") if isinstance(breaches, dict) else None,
    }


_SPF_ALL_RE = re.compile(r"(?:^|\s)([+?~-]?)all(?:\s|$)", re.IGNORECASE)


def _spf_record(view: dict) -> Optional[str]:
    cfg = view.get("email_config")
    if isinstance(cfg, dict):
        rec = cfg.get("spf")
        if isinstance(rec, str) and rec.lower().startswith("v=spf1"):
            return rec
        if cfg.get("spf_status") == "not_found":
            return ""
    spf = view.get("spf")
    if isinstance(spf, dict) and isinstance(spf.get("mechanisms"), list):
        mechs = [m.get("mechanism", "") for m in spf["mechanisms"] if isinstance(m, dict)]
        if mechs:
            return "v=spf1 " + " ".join(str(m) for m in mechs)
    return None


def _header_present(sec: dict, name: str) -> Optional[bool]:
    headers = sec.get("headers") if isinstance(sec, dict) else None
    if isinstance(headers, dict) and isinstance(headers.get(name), dict):
        return bool(headers[name].get("present"))
    missing = sec.get("missing_headers") if isinstance(sec, dict) else None
    if isinstance(missing, list):
        short = {"strict-transport-security": "HSTS", "content-security-policy": "CSP"}[name]
        return short not in missing
    return None


def extract_features(view: dict) -> Dict[str, Optional[bool]]:
    """Calcule les caractéristiques booléennes d'un scan (vue normalisée)."""
    f: Dict[str, Optional[bool]] = {k: None for k in FEATURE_KEYS}
    if not isinstance(view, dict):
        return f

    # DMARC
    dmarc = view.get("dmarc")
    cfg = view.get("email_config") if isinstance(view.get("email_config"), dict) else {}
    present = dmarc.get("present") if isinstance(dmarc, dict) else None
    if present is None and cfg.get("dmarc_status") in ("found", "not_found"):
        present = cfg["dmarc_status"] == "found"
    if present is not None:
        f["dmarc_absent"] = not present
        if present:
            policy = (dmarc or {}).get("policy") or cfg.get("dmarc_policy")
            if isinstance(policy, str) and policy:
                f["dmarc_policy_none"] = policy.strip().lower() == "none"

    # SPF
    rec = _spf_record(view)
    if rec is not None:
        f["spf_absent"] = rec == ""
        if rec:
            m = _SPF_ALL_RE.search(rec)
            f["spf_permissive"] = bool(m and m.group(1) in ("", "+", "?"))

    # DKIM
    dkim = view.get("dkim")
    if isinstance(dkim, dict) and isinstance(dkim.get("found"), list):
        f["dkim_absent"] = not any(isinstance(x, dict) and x.get("has_key") for x in dkim["found"])

    # MTA-STS
    mta = view.get("mta_sts")
    if isinstance(mta, dict) and mta.get("present") is not None:
        f["mta_sts_absent"] = not mta["present"]

    # DNSSEC
    dnssec = view.get("dnssec")
    if isinstance(dnssec, dict) and dnssec.get("enabled") is not None:
        f["dnssec_absent"] = not dnssec["enabled"]

    # CAA
    caa = view.get("caa")
    if isinstance(caa, dict) and caa.get("present") is not None:
        f["caa_absent"] = not caa["present"]

    # En-têtes HTTP
    sec = view.get("sec_headers")
    if isinstance(sec, dict) and sec:
        hsts = _header_present(sec, "strict-transport-security")
        csp = _header_present(sec, "content-security-policy")
        f["hsts_absent"] = None if hsts is None else not hsts
        f["csp_absent"] = None if csp is None else not csp

    # TLS
    tls = view.get("tls")
    protocols = tls.get("protocols") if isinstance(tls, dict) else None
    if isinstance(protocols, dict) and protocols:
        f["tls_legacy"] = any(bool(protocols.get(p)) for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"))

    # Certificat
    ssl = view.get("ssl")
    if isinstance(ssl, dict) and ("expired" in ssl or "expiry_warning" in ssl):
        f["cert_problem"] = bool(ssl.get("expired") or ssl.get("expiry_warning"))

    # security.txt
    st = view.get("security_txt_status")
    if isinstance(st, str):
        if st.lower() in ("success", "found"):
            f["security_txt_absent"] = False
        elif st.lower() in ("not_found", "no_data"):
            f["security_txt_absent"] = True

    # Ports exposés
    shodan = view.get("shodan")
    if isinstance(shodan, dict) and isinstance(shodan.get("ports"), list):
        ports = set()
        for p in shodan["ports"]:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
        f["admin_ports_exposed"] = bool(ports & ADMIN_PORTS)

    # Takeover
    tk = view.get("takeover")
    if isinstance(tk, dict):
        if isinstance(tk.get("vulnerable_count"), int):
            f["takeover_candidate"] = tk["vulnerable_count"] > 0
        elif isinstance(tk.get("vulnerable"), list):
            f["takeover_candidate"] = bool(tk["vulnerable"])

    # Listes de blocage
    bl = view.get("dnsbl")
    if isinstance(bl, dict):
        if isinstance(bl.get("listed_count"), int):
            f["dnsbl_listed"] = bl["listed_count"] > 0
        elif bl.get("clean") is not None:
            f["dnsbl_listed"] = not bl["clean"]
        elif isinstance(bl.get("listed"), list):
            f["dnsbl_listed"] = bool(bl["listed"])

    # Fuites
    br = view.get("breaches")
    if isinstance(br, dict) and str(view.get("breaches_status") or "success").lower() not in _UNUSABLE_STATUS:
        if isinstance(br.get("breach_count"), int):
            f["breaches_found"] = br["breach_count"] > 0
        elif isinstance(br.get("breaches"), list):
            f["breaches_found"] = bool(br["breaches"])

    return f


def features_from_scan(result: dict) -> Dict[str, Optional[bool]]:
    """Caractéristiques d'un scan brut (`pass_recon_cache.result_json` décodé)."""
    return extract_features(_view_from_raw(result))


def features_from_signals(signals: dict) -> Dict[str, Optional[bool]]:
    """Caractéristiques des signaux compacts de routes/analyze.py::_extract_signals."""
    return extract_features(_view_from_signals(signals))


# ---------------------------------------------------------------------------
# Cache mémoire des caractéristiques par ligne
# ---------------------------------------------------------------------------

_lock = threading.Lock()
# id de ligne → (updated_at, domain_hash, tld, features)
_row_cache: Dict[int, tuple] = {}


def reset_cache() -> None:
    """Vide le cache (tests, ou après une purge de pass_recon_cache)."""
    with _lock:
        _row_cache.clear()


def _load_rows(now: datetime = None) -> List[tuple]:
    """
    Retourne [(domain_hash, tld, features)] — un élément par domaine (scan le
    plus récent), sur la fenêtre et dans la limite configurées.
    """
    from database import db
    from models.pass_recon_cache import PassReconCache

    now = now or datetime.utcnow()
    since = now - timedelta(days=WINDOW_DAYS)
    meta = (
        db.session.query(PassReconCache.id, PassReconCache.domain, PassReconCache.updated_at)
        .filter(PassReconCache.updated_at >= since)
        .order_by(PassReconCache.updated_at.desc(), PassReconCache.id.desc())
        .limit(MAX_ROWS * 3)   # plusieurs jeux d'outils par domaine possibles
        .all()
    )

    # Dédoublonnage par domaine : on garde la ligne la plus récente.
    latest: Dict[str, tuple] = {}
    for row_id, domain, updated_at in meta:
        h = _domain_hash(domain)
        if h not in latest:
            latest[h] = (row_id, updated_at, tld_of(domain))
        if len(latest) >= MAX_ROWS:
            break

    with _lock:
        missing = [rid for rid, upd, _ in latest.values()
                   if rid not in _row_cache or _row_cache[rid][0] != upd]

    for i in range(0, len(missing), 25):
        batch = missing[i:i + 25]
        rows = (db.session.query(PassReconCache.id, PassReconCache.result_json)
                .filter(PassReconCache.id.in_(batch)).all())
        computed = {}
        for rid, result_json in rows:
            try:
                feats = features_from_scan(json.loads(result_json or "{}"))
            except Exception:
                feats = {k: None for k in FEATURE_KEYS}
            computed[rid] = feats
        with _lock:
            for h, (rid, upd, tld) in latest.items():
                if rid in computed:
                    _row_cache[rid] = (upd, h, tld, computed[rid])

    out = []
    with _lock:
        live_ids = {rid for rid, _, _ in latest.values()}
        for rid in list(_row_cache):
            if rid not in live_ids:
                del _row_cache[rid]   # ligne purgée, rescannée ou hors fenêtre
        for h, (rid, upd, tld) in latest.items():
            entry = _row_cache.get(rid)
            if entry:
                out.append((h, tld, entry[3]))
    return out


# ---------------------------------------------------------------------------
# Agrégation
# ---------------------------------------------------------------------------

def _aggregate(rows: List[tuple], tld: Optional[str], exclude_hash: Optional[str], k: int) -> dict:
    scoped = [feats for h, t, feats in rows
              if h != exclude_hash and (tld is None or t == tld)]
    features = {}
    for key in FEATURE_KEYS:
        values = [fe.get(key) for fe in scoped if fe.get(key) is not None]
        n = len(values)
        if n < k:
            continue  # k-anonymat : pas de statistique sur un petit échantillon
        positives = sum(1 for v in values if v)
        features[key] = {"n": n, "pct": _round5(100.0 * positives / n)}
    return {
        "scope": f".{tld}" if tld else "tous TLD",
        "sample_size": len(scoped) if len(scoped) >= k else None,
        "min_sample": k,
        "features": features,
    }


def compute_stats(tld: Optional[str] = None, exclude_domain: Optional[str] = None,
                  now: datetime = None) -> dict:
    """
    Statistiques agrégées d'un périmètre (`tld` ou tous TLD si None).

    Sortie (aucun nom de domaine) :
        {"scope": ".bj", "sample_size": 23 | None, "min_sample": 10,
         "features": {"dmarc_absent": {"n": 23, "pct": 70}, ...}}
    `sample_size` vaut None et `features` est vide sous le seuil k.
    """
    t = _norm_tld(tld) if tld is not None else None
    if tld is not None and t is None:
        return {"scope": None, "sample_size": None, "min_sample": min_sample(), "features": {}}
    rows = _load_rows(now)
    excl = _domain_hash(exclude_domain) if exclude_domain else None
    return _aggregate(rows, t, excl, min_sample())


def _scope_phrase(tld: Optional[str]) -> str:
    return f"des domaines .{tld}" if tld else "des domaines (tous TLD confondus)"


def comparative_context(tld: str, signals: dict) -> List[str]:
    """
    Phrases courtes (français) comparant le domaine analysé aux scans passés,
    à injecter telles quelles dans le prompt d'analyse.

    - `tld` : TLD du domaine analysé (« bj » ou « .bj ») ; invalide → seules
      les statistiques tous TLD sont utilisées.
    - `signals` : sortie de routes/analyze.py::_extract_signals (la clé
      `domain` sert uniquement à exclure ce domaine de l'échantillon).

    Pour chaque contrôle évaluable chez le domaine courant, on prend la
    statistique du TLD si elle atteint le seuil k, sinon celle de tous les
    TLD, sinon rien. Jamais d'exception, jamais de nom de domaine ;
    au plus `SCAN_STATS_MAX_SENTENCES` phrases (faiblesses d'abord).
    """
    try:
        current = features_from_signals(signals)
        if all(v is None for v in current.values()):
            return []
        domain = signals.get("domain") if isinstance(signals, dict) else None
        excl = _domain_hash(domain) if isinstance(domain, str) and domain else None
        t = _norm_tld(tld)
        k = min_sample()
        rows = _load_rows()
        by_scope = []
        if t:
            by_scope.append((t, _aggregate(rows, t, excl, k)["features"]))
        by_scope.append((None, _aggregate(rows, None, excl, k)["features"]))

        weaknesses, strengths = [], []
        for key in FEATURE_KEYS:
            mine = current.get(key)
            if mine is None:
                continue
            for scope_tld, feats in by_scope:
                stat = feats.get(key)
                if not stat:
                    continue
                scope = _scope_phrase(scope_tld)
                label = _LABELS[key]
                if mine:
                    weaknesses.append(
                        f"Comme ce domaine, {stat['pct']} % {scope} déjà analysés par "
                        f"Recon-IA (échantillon : {stat['n']}) {label}."
                    )
                elif stat["pct"] >= NOTABLE_STRENGTH_PCT:
                    strengths.append(
                        f"Ce domaine fait mieux que la moyenne : {stat['pct']} % {scope} "
                        f"déjà analysés par Recon-IA (échantillon : {stat['n']}) {label}."
                    )
                break  # une seule portée par contrôle (TLD prioritaire)
        return (weaknesses + strengths)[:max(0, MAX_SENTENCES)]
    except Exception as e:  # la statistique est un bonus : ne jamais casser l'analyse
        logger.warning("[scan_stats] contexte comparatif indisponible (%s)", type(e).__name__)
        return []
