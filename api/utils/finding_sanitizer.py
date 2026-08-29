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

Ce que ce module NE fait PAS : juger si un finding est sémantiquement
correct, contradictoire ou mal classé en sévérité (ex: un finding au
contenu positif étiqueté CRITICAL) — cela nécessiterait un jugement
sémantique, hors de portée d'un contrôle déterministe. Voir CLAUDE.md pour
le suivi de ce point.
"""
import re
from typing import Dict, List, Optional

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
    if not source_tool:
        return None
    if source_tool in tool_registry:
        return source_tool
    normalized = _normalize_tool_key(source_tool)
    for key in tool_registry:
        if _normalize_tool_key(key) == normalized:
            return key
    return None


def sanitize_findings(findings: List[Dict], tool_registry: Dict[str, Dict]) -> List[Dict]:
    """
    Nettoie `findings` en place (et retourne la même liste, cohérent avec le
    style additif de grounding_check.py/coverage_check.py).

    `tool_registry` : TOOLS_REGISTRY tel quel (routes/recon.py), passé par
    l'appelant pour ne pas créer de dépendance de utils/ vers routes/.
    """
    if not isinstance(findings, list):
        return findings

    seen_ids = set()
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue

        # ── Catégorie ──────────────────────────────────────────────────────
        if f.get("category") not in _VALID_CATEGORIES:
            resolved_key = _resolve_tool_key(f.get("source_tool"), tool_registry)
            tool_meta = tool_registry.get(resolved_key) if resolved_key else None
            registry_cat = tool_meta.get("category") if isinstance(tool_meta, dict) else None
            f["category"] = _REGISTRY_TO_FINDING_CATEGORY.get(registry_cat, _DEFAULT_CATEGORY)

        # ── ID unique ──────────────────────────────────────────────────────
        fid = f.get("id")
        if not fid or fid in seen_ids:
            cat_prefix = str(f.get("category") or "GEN")[:3].upper()
            fid = f"{cat_prefix}-{i + 1:03d}"
            f["id"] = fid
        seen_ids.add(fid)

        # ── Références / sources placeholder ────────────────────────────────
        refs = f.get("references")
        if isinstance(refs, list):
            f["references"] = [r for r in refs if not _PLACEHOLDER_RE.search(str(r))]
        sources = f.get("web_sources")
        if isinstance(sources, list):
            f["web_sources"] = [s for s in sources if not _PLACEHOLDER_RE.search(str(s))]

    return findings
