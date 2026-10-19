# utils/analysis_merger.py
"""
Fusion de deux rapports d'analyse IA (Groq + OpenRouter).

Stratégie :
  - findings     : union dédupliquée par (category, title normalisé)
                   En cas de doublon → prend la description la plus longue
  - risk_score   : max(groq_score, openrouter_score) — conservatif
  - risk_level   : recalculé depuis risk_score fusionné
  - strengths    : union dédupliquée (insensible à la casse)
  - immediate_actions : union dédupliquée par texte normalisé, triée par priorité
  - attack_surface    : fusion des listes technologies / exposed_services / cloud_providers
  - executive_summary : combine les deux résumés
  - searches_performed: union des deux logs de recherche
  - model_used   : "groq+openrouter (merged)"
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Normalisation ──────────────────────────────────────────────────────────────

def _norm(s: Any) -> str:
    """Normalise une chaîne pour comparaison : minuscule, sans ponctuation, espaces simples."""
    if not isinstance(s, str):
        return ""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", s.lower())).strip()


def _dedup_strings(lists: List[List[str]]) -> List[str]:
    """Fusionne plusieurs listes de strings, déduplique par texte normalisé."""
    seen: set = set()
    result: List[str] = []
    for lst in lists:
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, str):
                continue
            key = _norm(item)
            if key and key not in seen:
                seen.add(key)
                result.append(item)
    return result


# ── Fusion des findings ────────────────────────────────────────────────────────

def _merge_findings(findings_a: List[Dict], findings_b: List[Dict]) -> List[Dict]:
    """
    Fusionne deux listes de findings.
    Clé de déduplication : (category, title normalisé).
    En cas de doublon :
      - severity la plus haute (CRITICAL > HIGH > MEDIUM > LOW > INFO)
      - description la plus longue
      - union des references et web_sources
    """
    _SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def _sev_rank(s: Any) -> int:
        return _SEV_ORDER.get(str(s).upper(), 0)

    merged: Dict[str, Dict] = {}

    for finding in (findings_a or []) + (findings_b or []):
        if not isinstance(finding, dict):
            continue

        category = str(finding.get("category", "")).strip()
        title    = str(finding.get("title", "")).strip()
        key      = f"{_norm(category)}|{_norm(title)}"

        if not key or key == "|":
            continue

        if key not in merged:
            merged[key] = dict(finding)
            # Ensure list fields exist
            merged[key].setdefault("references", [])
            merged[key].setdefault("web_sources", [])
        else:
            existing = merged[key]

            # Prend la sévérité la plus haute
            if _sev_rank(finding.get("severity")) > _sev_rank(existing.get("severity")):
                existing["severity"] = finding["severity"]

            # Prend la description la plus longue
            new_desc = finding.get("description", "")
            old_desc = existing.get("description", "")
            if isinstance(new_desc, str) and len(new_desc) > len(old_desc or ""):
                existing["description"] = new_desc

            # Prend la recommandation la plus longue
            new_rec = finding.get("recommendation", "")
            old_rec = existing.get("recommendation", "")
            if isinstance(new_rec, str) and len(new_rec) > len(old_rec or ""):
                existing["recommendation"] = new_rec

            # Prend l'evidence la plus longue
            new_ev = finding.get("evidence", "")
            old_ev = existing.get("evidence", "")
            if isinstance(new_ev, str) and len(new_ev) > len(old_ev or ""):
                existing["evidence"] = new_ev

            # Union references et web_sources. Depuis la phase 3, `references`
            # est une liste d'objets {collection, source} (schéma §9.3) : clé
            # de déduplication = collection + source normalisée.
            def _ref_key(x: Any) -> str:
                if isinstance(x, dict):
                    return f"{_norm(x.get('collection'))}|{_norm(x.get('source'))}"
                return _norm(x) if isinstance(x, str) else ""

            for field in ("references", "web_sources"):
                existing_list = existing.get(field) or []
                new_list      = finding.get(field) or []
                if isinstance(new_list, list):
                    seen_norm = {_ref_key(x) for x in existing_list}
                    for item in new_list:
                        k = _ref_key(item)
                        if k and k not in seen_norm:
                            existing_list.append(item)
                            seen_norm.add(k)
                existing[field] = existing_list

    # Trier : CRITICAL → HIGH → MEDIUM → LOW → INFO
    result = list(merged.values())
    result.sort(key=lambda f: -_sev_rank(f.get("severity", "INFO")))
    return result


# ── Fusion de l'attack_surface ─────────────────────────────────────────────────

def _merge_attack_surface(a: Optional[Dict], b: Optional[Dict]) -> Dict:
    if not a and not b:
        return {}
    a = a or {}
    b = b or {}

    # total_subdomains : max
    sub_a = a.get("total_subdomains")
    sub_b = b.get("total_subdomains")
    total_sub = max(
        int(sub_a) if isinstance(sub_a, (int, float)) else 0,
        int(sub_b) if isinstance(sub_b, (int, float)) else 0,
    ) or None

    # exposed_services : union par (host, service_type)
    def _svc_key(s: Dict) -> str:
        return f"{_norm(s.get('host',''))}|{_norm(s.get('service_type',''))}"

    seen_svcs: set = set()
    exposed: List[Dict] = []
    for svc in (a.get("exposed_services") or []) + (b.get("exposed_services") or []):
        if not isinstance(svc, dict):
            continue
        k = _svc_key(svc)
        if k not in seen_svcs:
            seen_svcs.add(k)
            exposed.append(svc)

    # technologies : union
    technologies = _dedup_strings([
        a.get("technologies") or [],
        b.get("technologies") or [],
    ])

    # cloud_providers : union
    cloud_providers = _dedup_strings([
        a.get("cloud_providers") or [],
        b.get("cloud_providers") or [],
    ])

    result: Dict[str, Any] = {}
    if total_sub is not None:
        result["total_subdomains"] = total_sub
    if exposed:
        result["exposed_services"] = exposed
    if technologies:
        result["technologies"] = technologies
    if cloud_providers:
        result["cloud_providers"] = cloud_providers

    return result


# ── Fusion des immediate_actions ───────────────────────────────────────────────

def _merge_actions(actions_a: List[Dict], actions_b: List[Dict]) -> List[Dict]:
    seen: set = set()
    result: List[Dict] = []

    for action in (actions_a or []) + (actions_b or []):
        if not isinstance(action, dict):
            continue
        key = _norm(action.get("action", ""))
        if key and key not in seen:
            seen.add(key)
            result.append(action)

    # Tri par priorité (1 = urgent)
    result.sort(key=lambda a: int(a.get("priority", 9)) if str(a.get("priority", "9")).isdigit() else 9)
    return result


# ── Score de sécurité global (inverse du risque + breakdown par catégorie) ─────

_SEV_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    8,
    "LOW":       3,
    "INFO":      0,
}

_GRADE_TABLE = [
    (95, "A+"),
    (90, "A"),
    (85, "B+"),
    (80, "B"),
    (75, "C+"),
    (70, "C"),
    (60, "D+"),
    (50, "D"),
    (35, "E"),
    (0,  "F"),
]

_POSTURE_TABLE = [
    (90, "Excellent — infrastructure bien sécurisée, bonnes pratiques en place"),
    (75, "Bon — quelques améliorations mineures recommandées"),
    (60, "Moyen — plusieurs points de sécurité à corriger"),
    (40, "Faible — des vulnérabilités significatives nécessitent une attention rapide"),
    (20, "Critique — infrastructure fortement exposée, action immédiate requise"),
    (0,  "Très critique — risques majeurs, intervention urgente indispensable"),
]

_KNOWN_CATEGORIES = [
    "DNS", "SSL", "Email", "Web",
    "Infrastructure", "Subdomain", "Reputation", "Cloud",
]


def _score_to_grade(score: int) -> str:
    for threshold, grade in _GRADE_TABLE:
        if score >= threshold:
            return grade
    return "F"


def _score_to_posture(score: int) -> str:
    for threshold, text in _POSTURE_TABLE:
        if score >= threshold:
            return text
    return _POSTURE_TABLE[-1][1]


def compute_security_score(report: Dict) -> Dict[str, Any]:
    """
    Calcule le score de sécurité global (0-100, 100 = parfait) et le breakdown
    par catégorie à partir des findings et des strengths du rapport.

    Formule :
      score_brut = 100
                   − Σ(poids_sévérité × findings)
                   + min(nb_strengths × 2, 10)   [bonus bonnes pratiques, max +10]
      clamped à [0, 100]

    Poids sévérité : CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3, INFO 0

    Retourne :
      {
        "security_score":     integer 0-100,
        "security_grade":     string  (A+ … F),
        "security_posture":   string  (résumé qualitatif),
        "security_breakdown": {
            "DNS":   { "score": int, "grade": str, "findings_count": int,
                       "critical": int, "high": int },
            ...
        },
        "findings_summary": {
            "total": int, "critical": int, "high": int,
            "medium": int, "low": int, "info": int,
        },
      }
    """
    findings  = report.get("findings") or []
    strengths = report.get("strengths") or []

    # ── Score global ──────────────────────────────────────────────────────────
    base = 100
    for f in findings:
        sev    = str(f.get("severity", "")).upper()
        base  -= _SEV_WEIGHTS.get(sev, 0)

    strength_bonus = min(len(strengths) * 2, 10)
    global_score   = max(0, min(100, base + strength_bonus))

    # ── Findings summary ──────────────────────────────────────────────────────
    sev_counts: Dict[str, int] = {k: 0 for k in _SEV_WEIGHTS}
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    findings_summary = {
        "total":    len(findings),
        "critical": sev_counts["CRITICAL"],
        "high":     sev_counts["HIGH"],
        "medium":   sev_counts["MEDIUM"],
        "low":      sev_counts["LOW"],
        "info":     sev_counts["INFO"],
    }

    # ── Breakdown par catégorie ───────────────────────────────────────────────
    # Collecte les catégories présentes dans les findings (+ les connues)
    cats_present = set(_KNOWN_CATEGORIES)
    for f in findings:
        cat = str(f.get("category", "")).strip()
        if cat:
            cats_present.add(cat)

    breakdown: Dict[str, Any] = {}
    for cat in sorted(cats_present):
        cat_findings = [
            f for f in findings
            if str(f.get("category", "")).strip().upper() == cat.upper()
        ]
        if not cat_findings:
            # Catégorie sans finding = parfaite pour cette catégorie
            breakdown[cat] = {
                "score":          100,
                "grade":          "A+",
                "findings_count": 0,
                "critical":       0,
                "high":           0,
            }
            continue

        cat_base = 100
        for f in cat_findings:
            sev      = str(f.get("severity", "")).upper()
            cat_base -= _SEV_WEIGHTS.get(sev, 0)
        cat_score = max(0, min(100, cat_base))

        breakdown[cat] = {
            "score":          cat_score,
            "grade":          _score_to_grade(cat_score),
            "findings_count": len(cat_findings),
            "critical":       sum(1 for f in cat_findings if str(f.get("severity","")).upper() == "CRITICAL"),
            "high":           sum(1 for f in cat_findings if str(f.get("severity","")).upper() == "HIGH"),
        }

    return {
        "security_score":     global_score,
        "security_grade":     _score_to_grade(global_score),
        "security_posture":   _score_to_posture(global_score),
        "security_breakdown": breakdown,
        "findings_summary":   findings_summary,
    }


# ── Calcul du risk_level ───────────────────────────────────────────────────────

def _score_to_level(score: Any) -> str:
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    if s >= 75:
        return "CRITICAL"
    if s >= 50:
        return "HIGH"
    if s >= 25:
        return "MEDIUM"
    return "LOW"


# ── Fusion executive_summary ───────────────────────────────────────────────────

def _merge_summaries(summary_a: Optional[str], summary_b: Optional[str]) -> str:
    a = (summary_a or "").strip()
    b = (summary_b or "").strip()

    if a and b and _norm(a) != _norm(b):
        # Déduplique si les deux résumés sont presque identiques
        if len(a) >= len(b):
            return a
        return b
    return a or b


# ── Fonction principale ────────────────────────────────────────────────────────

def merge_analyses(report_a: Dict, report_b: Dict) -> Dict:
    """
    Fusionne deux rapports JSON produits par les clients IA.

    Args:
        report_a : rapport Groq (analyste menaces techniques)
        report_b : rapport OpenRouter (auditeur complet)

    Returns:
        Rapport fusionné avec findings dédupliqués, score conservatif,
        et couverture maximale des deux analyses.
    """
    if not report_a and not report_b:
        return {}
    if not report_a:
        logger.warning("[merger] report_a vide — retour report_b seul")
        return dict(report_b)
    if not report_b:
        logger.warning("[merger] report_b vide — retour report_a seul")
        return dict(report_a)

    # ── Scores ────────────────────────────────────────────────────────────────
    score_a   = report_a.get("risk_score", 0)
    score_b   = report_b.get("risk_score", 0)
    try:
        score_a = int(score_a)
    except (TypeError, ValueError):
        score_a = 0
    try:
        score_b = int(score_b)
    except (TypeError, ValueError):
        score_b = 0

    merged_score = max(score_a, score_b)
    merged_level = _score_to_level(merged_score)

    # ── Findings ─────────────────────────────────────────────────────────────
    merged_findings = _merge_findings(
        report_a.get("findings") or [],
        report_b.get("findings") or [],
    )

    # ── Attack surface ────────────────────────────────────────────────────────
    merged_surface = _merge_attack_surface(
        report_a.get("attack_surface"),
        report_b.get("attack_surface"),
    )

    # ── Strengths ─────────────────────────────────────────────────────────────
    merged_strengths = _dedup_strings([
        report_a.get("strengths") or [],
        report_b.get("strengths") or [],
    ])

    # ── Immediate actions ─────────────────────────────────────────────────────
    merged_actions = _merge_actions(
        report_a.get("immediate_actions") or [],
        report_b.get("immediate_actions") or [],
    )

    # ── Searches log ──────────────────────────────────────────────────────────
    searches_a = report_a.get("searches_performed") or []
    searches_b = report_b.get("searches_performed") or []
    all_searches = (
        [{"source": "groq",        **s} for s in searches_a if isinstance(s, dict)] +
        [{"source": "openrouter",  **s} for s in searches_b if isinstance(s, dict)]
    )

    # ── Executive summary ─────────────────────────────────────────────────────
    merged_summary = _merge_summaries(
        report_a.get("executive_summary"),
        report_b.get("executive_summary"),
    )

    # ── Résultat final ────────────────────────────────────────────────────────
    merged: Dict[str, Any] = {
        "domain":            report_a.get("domain") or report_b.get("domain", ""),
        "risk_score":        merged_score,
        "risk_level":        merged_level,
        "executive_summary": merged_summary,
        "findings":          merged_findings,
        "attack_surface":    merged_surface,
        "strengths":         merged_strengths,
        "immediate_actions": merged_actions,
        "searches_performed": all_searches,
        "model_used":        "groq+openrouter (merged)",
        "analyzed_at":       report_a.get("analyzed_at") or report_b.get("analyzed_at", ""),
        "_merge_details": {
            "groq_score":        score_a,
            "openrouter_score":  score_b,
            "groq_findings":     len(report_a.get("findings") or []),
            "openrouter_findings": len(report_b.get("findings") or []),
            "merged_findings":   len(merged_findings),
            "groq_searches":     len(searches_a),
            "openrouter_searches": len(searches_b),
        },
    }

    # ── Score de sécurité global ──────────────────────────────────────────────
    sec = compute_security_score(merged)
    merged["security_score"]     = sec["security_score"]
    merged["security_grade"]     = sec["security_grade"]
    merged["security_posture"]   = sec["security_posture"]
    merged["security_breakdown"] = sec["security_breakdown"]
    merged["findings_summary"]   = sec["findings_summary"]

    logger.info(
        "[merger] Fusion terminée — risk=%d (%s) | security=%d (%s) | findings=%d | searches=%d",
        merged_score, merged_level,
        sec["security_score"], sec["security_grade"],
        len(merged_findings),
        len(all_searches),
    )

    return merged
