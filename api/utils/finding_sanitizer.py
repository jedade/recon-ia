# utils/finding_sanitizer.py
"""
Nettoyage déterministe des findings produits par le LLM, avant scoring.

Ne réinterprète JAMAIS le contenu sémantique (pas de second appel LLM) —
corrige uniquement des défauts de FORMAT mécaniquement détectables, tous
constatés sur des rapports réellement produits (2026-07-29, fallback
Map-Reduce Ollama / qwen3:1.7b) :

  - `category` doit être une valeur EXACTE de l'énumération demandée dans le
    prompt (DNS|SSL|Email|Web|Infrastructure|Subdomain|Reputation|Cloud).
    Un petit modèle local a été vu recopier l'énumération ENTIÈRE comme
    valeur littérale au lieu d'en choisir une (ex: "DNS|SSL|Email|Web|
    Infrastructure|Subdomain|Reputation|Cloud" comme `category`) — corrigé
    en dérivant la catégorie depuis la catégorie RÉELLE de `source_tool`
    dans `TOOLS_REGISTRY` (source de vérité déterministe), jamais depuis le
    texte généré par le LLM.
  - `id` doit être unique par rapport ; des doublons stricts ("DNS-001"
    répété sur les 6 findings d'un même rapport, y compris entre sections
    différentes) ont été constatés — renumérotés de façon déterministe en
    cas de collision.
  - `references`/`web_sources` contenant des marqueurs de gabarit non
    complétés ("CVE-2025-XXXX", "CWE-2025", "https://example.com/...") sont
    une hallucination quasi certaine : le modèle a recopié le PATTERN
    d'exemple du prompt sans le remplacer par une vraie valeur — retirés
    plutôt que présentés comme des références/sources réelles.

Phase 3 (2026-10-19) — le module devient la frontière de validation de
TOUT ce qui sort du LLM pour un finding :

  - Liste blanche de champs : seuls les champs du schéma sont repris
    (`id`, `category`, `severity`, `title`, `description`, `evidence`,
    `source_tool`, `source_tools`, `recommendation`, `references`,
    `web_sources`, `confidence`). Un champ calculé par le serveur
    (`severity_rule`, `grounding`, `attack_enabled`, `observed_at`…) fourni
    par le modèle est IGNORÉ : il ne peut pas se faire passer pour un
    résultat de contrôle.
  - Typage et bornes : chaînes tronquées, caractères de contrôle retirés,
    listes plafonnées, clés d'outil au format strict, URLs http(s)
    uniquement, nombre de findings plafonné.
  - **B6** : toute CVE citée (titre, description, evidence, recommandation,
    références, sources web) doit figurer dans les CVE réellement observées
    par le scan (Shodan InternetDB `vulns`/`vulns_enriched`, voir
    `severity_rules.observed_cves`). Sinon elle est retirée ; le finding
    entier est retiré s'il ne repose que sur elle (titre centré sur la CVE
    sans autre CVE vérifiée, ou evidence vide une fois la CVE ôtée). Échec
    fermé : sans liste de CVE observées, aucune CVE n'est acceptée.
    Constaté : « CVE-2023-12345 », plausible mais inventée, passait le
    filtre gabarit `XXXX`.
  - `references` devient une liste d'objets `{"collection", "source"}`
    (schéma cible §9.3 du plan) : les références textuelles du modèle sont
    validées par motif (CVE, CWE, CAPEC, RFC, ATT&CK, OWASP, ASVS, ANSSI…)
    et rangées sous `collection: "llm"` ; les références RAG sont ajoutées
    ensuite par utils/rag_retrieval.py.
  - `observed_at` est l'horodatage du SCAN (ISO 8601 UTC), posé par le
    serveur — jamais la valeur du modèle.

Ce que ce module NE fait PAS : juger la sévérité — c'est le rôle de
utils/severity_rules.py, appliqué juste après.
"""
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_VALID_CATEGORIES = {
    "DNS", "SSL", "Email", "Web", "Infrastructure", "Subdomain", "Reputation", "Cloud",
}

# Catégorie TOOLS_REGISTRY (routes/recon.py) → catégorie du schéma de finding.
# Mapping approximatif pour les catégories sans équivalent 1:1 direct — reste
# toujours une meilleure valeur que le texte brut potentiellement invalide du LLM.
_REGISTRY_TO_FINDING_CATEGORY = {
    "Domain Intelligence":        "Infrastructure",
    "DNS / Réseau":               "DNS",
    "DNS / Sécurité":              "DNS",
    "Subdomain Discovery":        "Subdomain",
    "SSL / TLS":                  "SSL",
    "Email / Messagerie":         "Email",
    "Web / HTTP":                 "Web",
    "Web / Sécurité":              "Web",
    "Web / OSINT":                "Web",
    "Web / Fingerprinting":       "Web",
    "Réseau / Infrastructure":    "Infrastructure",
    "Infrastructure / Sécurité":   "Infrastructure",
    "Réputation / Threat Intel":  "Reputation",
    "OSINT Externe":              "Reputation",
    "Vulnérabilités / OSINT":     "Subdomain",
}

_DEFAULT_CATEGORY = "Infrastructure"

# "CVE-2025-XXXX", "CWE-2025", "example.com" (avec ou sans sous-domaine) —
# tous des gabarits d'exemple copiés depuis le prompt sans être complétés.
_PLACEHOLDER_RE = re.compile(r"(XXXX|example\.com)", re.IGNORECASE)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TOOL_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,63}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,31}$")
_URL_RE = re.compile(r"^https?://[^\s<>\"'`]{3,500}$", re.IGNORECASE)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Références acceptées : familles de référentiels reconnus uniquement.
_REF_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,7}|CWE-\d{1,5}|CAPEC-\d{1,5}|RFC ?\d{3,5}(\s*§\s*[\d.]+)?|BCP ?\d{1,3}"
    r"|T\d{4}(\.\d{3})?|TA\d{4}|M\d{4}"
    r"|(OWASP|ASVS|WSTG|NIST|ANSSI|CIS|CERT-FR|ENISA|MITRE|PCI[ -]?DSS|ISO(/IEC)?)\b[^\n]{0,100})$",
    re.IGNORECASE,
)

_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL", "CRITIQUE": "CRITICAL",
    "HIGH": "HIGH", "ELEVE": "HIGH", "ELEVEE": "HIGH", "HAUTE": "HIGH", "HAUT": "HIGH",
    "MEDIUM": "MEDIUM", "MOYEN": "MEDIUM", "MOYENNE": "MEDIUM", "MODERE": "MEDIUM", "MODEREE": "MEDIUM",
    "LOW": "LOW", "FAIBLE": "LOW", "BASSE": "LOW", "BAS": "LOW",
    "INFO": "INFO", "INFORMATIONAL": "INFO", "INFORMATION": "INFO", "INFORMATIF": "INFO", "NONE": "INFO",
}
_CONFIDENCE_ALIASES = {
    "high": "high", "haute": "high", "elevee": "high", "forte": "high",
    "medium": "medium", "moyenne": "medium", "moyen": "medium",
    "low": "low", "faible": "low", "basse": "low",
}

# Bornes (caractères / éléments)
MAX_FINDINGS = 60
_LIMITS = {"title": 200, "description": 4000, "evidence": 2000, "recommendation": 3000}
_MAX_REFS = 15
_MAX_REF_LEN = 120
_MAX_WEB_SOURCES = 10
_MAX_SOURCE_TOOLS = 10


def _strip_accents(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


def clean_text(value: Any, limit: int) -> str:
    """Chaîne bornée, sans caractères de contrôle ; non-chaîne → ""."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return ""
    value = _CTRL_RE.sub("", value).strip()
    return value[:limit]


def normalize_severity(value: Any) -> str:
    key = _strip_accents(str(value or "")).strip().upper()
    return _SEVERITY_ALIASES.get(key, "INFO")


def normalize_confidence(value: Any) -> Optional[str]:
    key = _strip_accents(str(value or "")).strip().lower()
    return _CONFIDENCE_ALIASES.get(key)


def to_iso_utc(value: Any) -> Optional[str]:
    """ISO 8601 UTC « 2026-10-19T10:42:00Z » depuis datetime/chaîne ISO ; None si illisible."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)   # les horodatages du projet sont en utcnow()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_tool_key(key: str) -> str:
    """
    Réduit une clé d'outil à sa "racine" en retirant les suffixes génériques
    courants (_check, _analysis, _info, _records, _lookup) — permet de
    rapprocher une clé plausible mais inexacte citée par le LLM (constaté :
    "dnsbl_analysis" au lieu de la vraie clé "dnsbl_check") de la bonne
    entrée de TOOLS_REGISTRY, sans dépendre d'une correspondance parfaite.
    """
    key = key.lower().strip()
    for suffix in ("_check", "_analysis", "_info", "_records", "_lookup", "_detection", "_config"):
        if key.endswith(suffix):
            return key[: -len(suffix)]
    return key


def _resolve_tool_key(source_tool: Optional[str], tool_registry: Dict[str, Dict]) -> Optional[str]:
    """Retourne la vraie clé TOOLS_REGISTRY correspondant à `source_tool`,
    par correspondance exacte puis par racine normalisée (repli)."""
    if not source_tool or not isinstance(source_tool, str):
        return None
    if source_tool in tool_registry:
        return source_tool
    normalized = _normalize_tool_key(source_tool)
    for key in tool_registry:
        if _normalize_tool_key(key) == normalized:
            return key
    return None


def _clean_tool_key(value: Any, tool_registry: Dict[str, Dict]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    if not _TOOL_KEY_RE.match(key):
        return None
    return _resolve_tool_key(key, tool_registry) or key


def _clean_reference(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("source")
    ref = clean_text(value, _MAX_REF_LEN)
    if not ref or _PLACEHOLDER_RE.search(ref) or not _REF_RE.match(ref):
        return None
    return ref


def _strip_cves(text: str, bad: set) -> str:
    if not text or not bad:
        return text
    out = _CVE_RE.sub(lambda m: "" if m.group(0).upper() in bad else m.group(0), text)
    out = re.sub(r"\(\s*[,;]?\s*\)", "", out)
    out = re.sub(r"\s*[,;]\s*([,;])", r"\1", out)
    return re.sub(r"[ \t]{2,}", " ", out).strip(" ,;:")


def _validate_cves(f: Dict[str, Any], observed: set, stats: Dict[str, Any]) -> bool:
    """B6 — retire les CVE non observées ; False si le finding doit être retiré."""
    fields = ("title", "description", "evidence", "recommendation")
    cited = set()
    for k in fields:
        cited |= {c.upper() for c in _CVE_RE.findall(f.get(k) or "")}
    for r in f.get("references") or []:
        cited |= {c.upper() for c in _CVE_RE.findall(r)}
    for u in f.get("web_sources") or []:
        cited |= {c.upper() for c in _CVE_RE.findall(u)}
    bad = cited - observed
    if not bad:
        return True
    stats["cves_removed"] = sorted(set(stats.get("cves_removed", [])) | bad)[:100]
    verified_left = cited & observed
    title_bad = {c.upper() for c in _CVE_RE.findall(f.get("title") or "")} & bad
    evidence_left = _strip_cves(f.get("evidence") or "", bad)
    if not verified_left and (title_bad or len(evidence_left.split()) < 3):
        return False
    for k in fields:
        f[k] = _strip_cves(f.get(k) or "", bad)
    f["references"] = [r for r in f.get("references") or [] if not ({c.upper() for c in _CVE_RE.findall(r)} & bad)]
    f["web_sources"] = [u for u in f.get("web_sources") or [] if not ({c.upper() for c in _CVE_RE.findall(u)} & bad)]
    return True


def sanitize_findings(
    findings: List[Dict],
    tool_registry: Dict[str, Dict],
    observed_cves: Optional[set] = None,
    observed_at: Optional[str] = None,
    stats: Optional[Dict[str, Any]] = None,
    check_cves: bool = True,
) -> List[Dict]:
    """
    Retourne la liste des findings validés (nouveaux dicts, champs en liste
    blanche, typés et bornés). Les findings retirés (non-dict, B6) sont
    comptés dans `stats` s'il est fourni.

    `tool_registry` : TOOLS_REGISTRY tel quel (routes/recon.py), passé par
    l'appelant pour ne pas créer de dépendance de utils/ vers routes/.
    `observed_cves` : CVE réellement observées par le scan (B6). None ou
    vide = aucune CVE acceptée (échec fermé).
    `observed_at` : horodatage du scan, ISO 8601 UTC.
    """
    stats = stats if stats is not None else {}
    stats.setdefault("dropped_invalid", 0)
    stats.setdefault("dropped_unverified_cve", 0)
    if not isinstance(findings, list):
        return []
    observed = {str(c).upper() for c in (observed_cves or set())}
    tool_registry = tool_registry if isinstance(tool_registry, dict) else {}

    out: List[Dict] = []
    seen_ids = set()
    for raw in findings:
        if len(out) >= MAX_FINDINGS:
            stats["truncated"] = True
            break
        if not isinstance(raw, dict):
            stats["dropped_invalid"] += 1
            continue

        f: Dict[str, Any] = {k: clean_text(raw.get(k), n) for k, n in _LIMITS.items()}
        if not (f["title"] or f["description"] or f["evidence"]):
            stats["dropped_invalid"] += 1
            continue
        f["severity"] = normalize_severity(raw.get("severity"))
        f["source_tool"] = _clean_tool_key(raw.get("source_tool"), tool_registry)
        tools = raw.get("source_tools") if isinstance(raw.get("source_tools"), list) else []
        f["source_tools"] = list(dict.fromkeys(
            t for t in (_clean_tool_key(x, tool_registry) for x in tools[:_MAX_SOURCE_TOOLS * 2]) if t
        ))[:_MAX_SOURCE_TOOLS]
        if not f["source_tool"] and f["source_tools"]:
            f["source_tool"] = f["source_tools"][0]

        refs = raw.get("references") if isinstance(raw.get("references"), list) else []
        f["references"] = list(dict.fromkeys(
            r for r in (_clean_reference(x) for x in refs[:_MAX_REFS * 2]) if r
        ))[:_MAX_REFS]
        srcs = raw.get("web_sources") if isinstance(raw.get("web_sources"), list) else []
        f["web_sources"] = list(dict.fromkeys(
            # Une URL trop longue est rejetée, pas tronquée (tronquée, elle serait fausse).
            u for u in (clean_text(x, 501) for x in srcs[:_MAX_WEB_SOURCES * 2])
            if u and len(u) <= 500 and _URL_RE.match(u) and not _PLACEHOLDER_RE.search(u)
        ))[:_MAX_WEB_SOURCES]

        # ── B6 : CVE citées ⊂ CVE observées ──────────────────────────────────
        if check_cves and not _validate_cves(f, observed, stats):
            stats["dropped_unverified_cve"] += 1
            continue

        # ── Catégorie ──────────────────────────────────────────────────────
        cat = raw.get("category")
        if cat in _VALID_CATEGORIES:
            f["category"] = cat
        else:
            resolved_key = _resolve_tool_key(f.get("source_tool"), tool_registry)
            tool_meta = tool_registry.get(resolved_key) if resolved_key else None
            registry_cat = tool_meta.get("category") if isinstance(tool_meta, dict) else None
            f["category"] = _REGISTRY_TO_FINDING_CATEGORY.get(registry_cat, _DEFAULT_CATEGORY)

        # ── ID unique ──────────────────────────────────────────────────────
        fid = raw.get("id") if isinstance(raw.get("id"), str) and _ID_RE.match(raw.get("id").strip()) else None
        fid = fid.strip() if fid else None
        if not fid or fid in seen_ids:
            cat_prefix = str(f.get("category") or "GEN")[:3].upper()
            n = len(out) + 1
            fid = f"{cat_prefix}-{n:03d}"
            while fid in seen_ids:
                n += 1
                fid = f"{cat_prefix}-{n:03d}"
        f["id"] = fid
        seen_ids.add(fid)

        # Références textuelles du modèle → schéma {collection, source}
        f["references"] = [{"collection": "llm", "source": r} for r in f["references"]]

        llm_conf = normalize_confidence(raw.get("confidence"))
        if llm_conf:
            f["_llm_confidence"] = llm_conf
        f["observed_at"] = observed_at
        out.append(f)

    return out


def ensure_unique_ids(findings: List[Dict]) -> None:
    """Attribue un id unique aux findings ajoutés après coup (règles déterministes)."""
    seen = {f.get("id") for f in findings if isinstance(f, dict) and f.get("id")}
    for f in findings:
        if not isinstance(f, dict) or f.get("id"):
            continue
        prefix = str(f.get("category") or "GEN")[:3].upper()
        n = 1
        while f"{prefix}-R{n:02d}" in seen:
            n += 1
        f["id"] = f"{prefix}-R{n:02d}"
        seen.add(f["id"])


def sanitize_strengths(strengths: Any, limit: int = 40) -> List[str]:
    """Bonnes pratiques : chaînes bornées, dédupliquées (ordre préservé)."""
    if not isinstance(strengths, list):
        return []
    out: List[str] = []
    for s in strengths:
        t = clean_text(s, 300) if isinstance(s, str) else ""
        if t and t not in out:
            out.append(t)
        if len(out) >= limit:
            break
    return out
