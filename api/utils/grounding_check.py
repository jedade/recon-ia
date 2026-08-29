# utils/grounding_check.py
"""
Contrôle d'ancrage (grounding check) des findings produits par l'analyse IA.

Objectif : réduire — jamais éliminer — le risque d'hallucination en vérifiant
PROGRAMMATIQUEMENT ce que le prompt (voir `_TRACEABILITY_RULES` dans
routes/analyze.py) exige déjà du LLM par instruction : que chaque finding cite
un `source_tool` réel et que son `evidence` soit effectivement présente dans
la donnée brute de cet outil.

Ce que ce module PROUVE :
  - `source_tool` désigne un outil réellement exécuté (pas un nom inventé).
  - Cet outil a réellement produit une donnée exploitable (status "success").
  - Le texte `evidence` chevauche significativement la donnée brute de cet
    outil (raw_output + data sérialisés) — l'affirmation n'est pas fabriquée
    de toutes pièces.

Ce que ce module NE PROUVE PAS :
  - Que l'interprétation du LLM est sémantiquement correcte (il peut citer un
    extrait réel tout en tirant une conclusion erronée de cet extrait).
  - Que la sévérité, la recommandation ou les références (CVE/CWE/OWASP) sont
    exactes — seule la correspondance evidence ↔ donnée brute est vérifiée.

C'est un filet de sécurité déterministe et vérifiable, pas une preuve
d'exactitude à 100 %. Le statut de chaque finding doit être lu comme tel.
"""
import re
import unicodedata
from typing import Any, Dict, List, Optional

# Longueur minimale du plus long chevauchement de mots consécutifs entre
# `evidence` et la donnée brute pour considérer le finding comme ancré.
# Volontairement bas (3 mots) : `evidence` est souvent une reformulation
# courte ("Server: Apache/2.4.41"), pas une citation mot pour mot.
_MIN_OVERLAP_WORDS = 3


def _normalize(text: str) -> str:
    """
    Minuscules, accents retirés, ponctuation réduite à des espaces —
    conserve `. - /` (significatifs dans domaines/IP/versions/CVE, ex.
    "93.184.216.34", "Apache/2.4.41", "CVE-2024-1234") mais traite `:`, `'`,
    `{`, `}`, `,` comme des séparateurs : sans ça, une donnée brute issue de
    `str(dict)` (ex. "'days_remaining': 3") ne matcherait jamais une
    reformulation en prose de l'IA (ex. "days_remaining 3").
    """
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower()
    text = re.sub(r"[^a-z0-9._/-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _tool_haystack(tool_entry: Dict) -> str:
    """Concatène raw_output + data sérialisée d'un outil en texte normalisé."""
    parts = []
    raw = tool_entry.get("raw_output")
    if isinstance(raw, str):
        parts.append(raw)
    data = tool_entry.get("data")
    if data is not None:
        parts.append(str(data))
    return _normalize(" ".join(parts))


def _longest_word_overlap(evidence_norm: str, haystack_norm: str) -> int:
    """
    Longueur (en mots) de la plus longue sous-séquence de mots de `evidence`
    retrouvée telle quelle dans `haystack`. Heuristique volontairement simple
    (substring sur des fenêtres glissantes de mots) — pas de NLP, pas de LLM,
    donc pas de risque d'halluciner la vérification elle-même.
    """
    ev_words = evidence_norm.split()
    if not ev_words:
        return 0
    best = 0
    n = len(ev_words)
    for start in range(n):
        for length in range(n - start, 0, -1):
            if length <= best:
                break
            window = " ".join(ev_words[start:start + length])
            if window and window in haystack_norm:
                best = length
                break
    return best


def _check_finding(finding: Dict, scan_results: Dict) -> Dict[str, Any]:
    source_tool  = finding.get("source_tool")
    source_tools = finding.get("source_tools") or []
    tool_keys = [k for k in ([source_tool] + list(source_tools)) if k]
    tool_keys = list(dict.fromkeys(tool_keys))  # dédupliqué, ordre préservé

    if not tool_keys:
        return {
            "status": "no_source_cited",
            "checked_tools": [],
            "detail": "Aucun `source_tool` fourni par l'analyse IA pour ce finding.",
        }

    evidence = str(finding.get("evidence") or "").strip()
    evidence_norm = _normalize(evidence) if evidence else ""

    per_tool: List[Dict[str, Any]] = []
    any_verified = False
    any_unknown  = False
    any_failed   = False

    for key in tool_keys:
        entry = scan_results.get(key)
        if not isinstance(entry, dict) or not isinstance(entry.get("meta"), dict):
            per_tool.append({"tool": key, "result": "unknown_tool"})
            any_unknown = True
            continue

        status = entry.get("status")
        if status != "success":
            per_tool.append({"tool": key, "result": "tool_not_successful", "tool_status": status})
            any_failed = True
            continue

        if not evidence_norm:
            per_tool.append({"tool": key, "result": "no_evidence_text"})
            continue

        haystack = _tool_haystack(entry)
        overlap = _longest_word_overlap(evidence_norm, haystack)
        if overlap >= min(_MIN_OVERLAP_WORDS, len(evidence_norm.split())):
            per_tool.append({"tool": key, "result": "evidence_matched", "overlap_words": overlap})
            any_verified = True
        else:
            per_tool.append({"tool": key, "result": "evidence_not_found", "overlap_words": overlap})

    if any_verified:
        overall = "verified"
    elif any_unknown and not any_failed:
        overall = "unknown_tool"
    elif any_failed and not any_unknown:
        overall = "tool_not_successful"
    elif not evidence_norm:
        overall = "no_evidence_text"
    else:
        overall = "evidence_not_found"

    return {"status": overall, "checked_tools": per_tool}


def compute_grounding_check(report: Dict, scan_results: Optional[Dict]) -> Dict[str, Any]:
    """
    Annote `report["findings"]` (in place, champ additif `grounding`) et
    retourne un résumé agrégé à assigner à `report["grounding_check"]`.

    N'écrase, ne supprime ni ne modifie aucun champ existant du rapport —
    ajoute uniquement `finding["grounding"]` par finding et le résumé retourné.
    """
    findings = report.get("findings") or []
    scan_results = scan_results if isinstance(scan_results, dict) else {}

    counts = {
        "verified": 0, "evidence_not_found": 0, "tool_not_successful": 0,
        "unknown_tool": 0, "no_source_cited": 0, "no_evidence_text": 0,
    }

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        result = _check_finding(finding, scan_results)
        finding["grounding"] = result
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    total = len(findings)
    verified = counts["verified"]
    return {
        "total_findings":       total,
        "verified":             verified,
        "verified_pct":         round(100 * verified / total, 1) if total else None,
        "evidence_not_found":   counts["evidence_not_found"],
        "tool_not_successful":  counts["tool_not_successful"],
        "unknown_tool":         counts["unknown_tool"],
        "no_source_cited":      counts["no_source_cited"],
        "no_evidence_text":     counts["no_evidence_text"],
        "method": (
            "Chevauchement textuel déterministe entre `evidence` et la donnée "
            "brute (raw_output/data) de l'outil cité en `source_tool` — vérifie "
            "l'ancrage factuel, pas l'exactitude sémantique de l'interprétation."
        ),
    }
