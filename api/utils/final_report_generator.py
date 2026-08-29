# utils/final_report_generator.py
"""
Génère un rapport final narratif IA en condensant :
  - scan_results  : JSON OSINT brut de la reconnaissance passive
  - analysis_result : JSON analyse IA (findings, risk_score, security_score…)

Sortie : dict JSON structuré stocké dans recon.final_report

Modèle utilisé : Groq par défaut (rapide, pas besoin de tool use ici),
                 OpenRouter en fallback si Groq indisponible.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constantes ─────────────────────────────────────────────────────────────────

# Taille max du JSON OSINT injecté dans le prompt (pour rester dans les limites TPM)
_MAX_SCAN_CHARS     = int(os.getenv("FINAL_REPORT_MAX_SCAN_CHARS",     "8000"))
_MAX_ANALYSIS_CHARS = int(os.getenv("FINAL_REPORT_MAX_ANALYSIS_CHARS", "6000"))

_SYSTEM_PROMPT = """\
Tu es un expert en cybersécurité, spécialisé dans la rédaction de rapports OSINT \
professionnels pour des responsables sécurité (CISO, DSI, auditeurs).

Tu reçois :
1. Un extrait des données OSINT brutes de reconnaissance passive (scan_results)
2. L'analyse IA des risques détectés (findings, score, recommandations)

Ta mission : produire un rapport narratif condensé, structuré et professionnel, \
destiné à être converti en PDF et transmis au demandeur.

RÈGLES ABSOLUES :
- Réponds UNIQUEMENT avec un objet JSON valide (UTF-8), sans markdown, \
  sans balise, sans texte avant ou après.
- Ne fabrique aucune donnée : base-toi exclusivement sur les informations fournies.
- Sois précis, professionnel, et adapté à un public non-technique pour le résumé \
  exécutif, mais technique pour les recommandations.
- Si `mitre_attack` est présent dans l'analyse fournie, mentionne les techniques \
  MITRE ATT&CK correspondantes (ex: "T1596.001") dans `risk_assessment` et \
  `prioritized_recommendations` sans en inventer d'autres.
- Langue : français.

SCHÉMA JSON ATTENDU (respecte EXACTEMENT les clés) :
{
  "executive_summary": "string — résumé exécutif en 3-5 paragraphes (pour un CISO)",
  "infrastructure_overview": "string — description de l'infrastructure cible découverte",
  "key_findings_narrative": "string — narration structurée des problèmes critiques/hauts",
  "risk_assessment": "string — évaluation du niveau de risque global et impact business",
  "prioritized_recommendations": [
    "string — recommandation prioritaire 1 (la plus urgente)",
    "string — recommandation 2",
    "..."
  ],
  "positive_points": [
    "string — bonne pratique ou point positif détecté 1",
    "..."
  ],
  "conclusion": "string — conclusion avec prochaines étapes concrètes"
}
"""


# ── Helpers de synthèse ────────────────────────────────────────────────────────

def _extract_scan_summary(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrait les informations clés du JSON OSINT pour le prompt.
    On ne garde que l'essentiel pour rester dans les limites TPM.
    """
    summary: Dict[str, Any] = {}

    # Informations de base
    for key in ("domain", "ip", "asn", "country", "hosting_provider",
                "cms", "server", "ssl_valid", "ssl_expiry", "https_redirect"):
        if key in scan:
            summary[key] = scan[key]

    # DNS
    if "dns" in scan:
        dns = scan["dns"]
        summary["dns"] = {
            k: dns[k] for k in ("A", "MX", "TXT", "NS", "DMARC", "DKIM", "SPF",
                                 "CAA", "DNSSEC")
            if k in dns
        }

    # SSL
    if "ssl" in scan:
        ssl = scan["ssl"]
        summary["ssl"] = {
            k: ssl[k] for k in ("valid", "expiry_date", "issuer", "grade",
                                 "protocols", "vulnerabilities")
            if k in ssl
        }

    # Sous-domaines (max 20)
    for key in ("subdomains", "subdomain_list"):
        if key in scan:
            subs = scan[key]
            summary["subdomains_count"] = len(subs) if isinstance(subs, list) else 0
            summary["subdomains_sample"] = subs[:20] if isinstance(subs, list) else []
            break

    # Technologies / headers
    for key in ("technologies", "tech_stack", "headers", "waf", "cdn"):
        if key in scan:
            summary[key] = scan[key]

    # Email security
    for key in ("spf", "dmarc", "dkim", "mail_servers"):
        if key in scan and key not in summary.get("dns", {}):
            summary[key] = scan[key]

    # Ports / services ouverts
    for key in ("open_ports", "services", "exposed_ports"):
        if key in scan:
            summary[key] = scan[key]

    # Réputation
    for key in ("blacklisted", "reputation", "threat_intel", "virustotal"):
        if key in scan:
            summary[key] = scan[key]

    return summary


def _extract_analysis_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Extrait les parties les plus importantes de l'analyse IA."""
    summary: Dict[str, Any] = {
        "domain":           analysis.get("domain"),
        "risk_score":       analysis.get("risk_score"),
        "risk_level":       analysis.get("risk_level"),
        "security_score":   analysis.get("security_score"),
        "security_grade":   analysis.get("security_grade"),
        "security_posture": analysis.get("security_posture"),
        "executive_summary": analysis.get("executive_summary"),
        "findings_summary": analysis.get("findings_summary"),
        "security_breakdown": analysis.get("security_breakdown"),
        "mitre_attack": analysis.get("mitre_attack"),
    }

    # Findings : on garde tout (limité par _MAX_ANALYSIS_CHARS ensuite)
    findings = analysis.get("findings", [])
    summary["findings"] = [
        {
            "id":             f.get("id"),
            "category":       f.get("category"),
            "severity":       f.get("severity"),
            "title":          f.get("title"),
            "description":    f.get("description"),
            "recommendation": f.get("recommendation"),
            "references":     f.get("references", []),
        }
        for f in findings
    ]

    # Strengths / recommandations
    summary["strengths"] = analysis.get("strengths", [])
    summary["prioritized_actions"] = analysis.get("prioritized_actions", [])

    return summary


def _truncate_json(obj: Any, max_chars: int) -> str:
    """Sérialise obj en JSON puis tronque si nécessaire."""
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n…[tronqué pour respecter la limite de contexte]"
    return text


def _parse_json_response(content: str) -> Optional[Dict]:
    """Extrait et parse le JSON depuis la réponse du modèle."""
    content = content.strip()
    # Supprimer éventuelles balises markdown
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    # Trouver le premier { et le dernier }
    start = content.find("{")
    end   = content.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(content[start:end + 1])
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error in final report: %s", e)
        return None


def _fallback_report(domain: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Rapport de secours minimal si le modèle échoue."""
    findings = analysis.get("findings", [])
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high     = [f for f in findings if f.get("severity") == "HIGH"]

    recs = [
        f.get("recommendation", "") for f in (critical + high)[:5]
        if f.get("recommendation")
    ]

    return {
        "executive_summary": (
            f"L'analyse OSINT du domaine {domain} a révélé "
            f"{len(critical)} finding(s) critiques et {len(high)} finding(s) élevés. "
            f"Le score de sécurité global est de {analysis.get('security_score', 'N/A')}/100 "
            f"(grade {analysis.get('security_grade', 'N/A')}). "
            "Une revue approfondie est recommandée."
        ),
        "infrastructure_overview": "Voir les détails dans la section findings.",
        "key_findings_narrative": (
            "Les problèmes les plus critiques sont : "
            + "; ".join(f.get("title", "") for f in (critical + high)[:5])
        ),
        "risk_assessment": (
            f"Niveau de risque : {analysis.get('risk_level', 'N/A')} "
            f"(score : {analysis.get('risk_score', 'N/A')}/100)."
        ),
        "prioritized_recommendations": recs or ["Effectuer un audit complet de sécurité."],
        "positive_points": analysis.get("strengths", []),
        "conclusion": (
            "Ce rapport doit être transmis à l'équipe sécurité pour traitement "
            "des findings critiques dans les plus brefs délais."
        ),
    }


# ── Sélection du client IA ────────────────────────────────────────────────────

def _get_client():
    """Retourne une instance Groq (préféré), OpenRouter, ou Ollama (repli local)."""
    groq_key = os.getenv("GROQ_API_KEY", "")
    openrouter_key = os.getenv("OPENROUTER_API_KEY", "")

    if groq_key:
        try:
            from utils.groq_client import GroqClient
            client = GroqClient()
            if client.is_available():
                logger.info("[final_report] Client sélectionné : Groq")
                return client, "groq"
        except Exception as e:
            logger.warning("[final_report] Groq indisponible : %s", e)

    if openrouter_key:
        try:
            from utils.openrouter_client import OpenRouterClient
            client = OpenRouterClient()
            if client.is_available():
                logger.info("[final_report] Client sélectionné : OpenRouter")
                return client, "openrouter"
        except Exception as e:
            logger.warning("[final_report] OpenRouter indisponible : %s", e)

    # Repli local — corrigé (2026-07-29) : sans ce repli, cette étape échouait
    # intégralement dès que Groq ET OpenRouter étaient indisponibles (clé
    # absente, quota épuisé), même si pass_recon et l'analyse avaient réussi
    # via Ollama — tout le flux cassait à la dernière étape narrative pour une
    # raison purement liée aux quotas cloud, sans rapport avec la qualité de
    # l'analyse déjà produite.
    try:
        from utils.ollama_client import OllamaClient
        client = OllamaClient()
        if client.is_available() and client.model_loaded():
            logger.info("[final_report] Client sélectionné : Ollama (repli local)")
            return client, "ollama"
    except Exception as e:
        logger.warning("[final_report] Ollama indisponible : %s", e)

    raise RuntimeError(
        "Aucun backend IA disponible (GROQ_API_KEY, OPENROUTER_API_KEY ou Ollama requis)."
    )


# ── Fonction principale ───────────────────────────────────────────────────────

def generate_final_report(
    scan_results: Dict[str, Any],
    analysis_result: Dict[str, Any],
    domain: str,
    client=None,
) -> Dict[str, Any]:
    """
    Génère le rapport final narratif condensé via IA.

    Args:
        scan_results:    JSON OSINT brut (recon.scan_results désérialisé)
        analysis_result: JSON analyse IA (recon.analysis_result désérialisé)
        domain:          Domaine analysé
        client:          Instance GroqClient/OpenRouterClient (auto-sélection si None)

    Returns:
        Dict structuré prêt à être stocké dans recon.final_report (JSON.dumps)
    """
    client_name = "provided"
    if client is None:
        client, client_name = _get_client()

    # Résumer les données pour rester dans les limites TPM
    scan_summary     = _extract_scan_summary(scan_results)
    analysis_summary = _extract_analysis_summary(analysis_result)

    scan_text     = _truncate_json(scan_summary,     _MAX_SCAN_CHARS)
    analysis_text = _truncate_json(analysis_summary, _MAX_ANALYSIS_CHARS)

    user_content = (
        f"Domaine analysé : **{domain}**\n\n"
        f"## Données OSINT (scan_results)\n{scan_text}\n\n"
        f"## Analyse IA des risques (analysis_result)\n{analysis_text}\n\n"
        "Génère maintenant le rapport final JSON en respectant exactement le schéma demandé."
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]

    logger.info("[final_report] Génération via %s pour domaine=%s", client_name, domain)

    # Appel direct (pas agentique — toutes les données sont déjà là)
    _chat_kwargs = {"messages": messages, "tools": None, "temperature": 0.1}
    if client_name == "ollama":
        # Ollama seul n'a pas de budget de sortie dédié pour cette étape (les
        # autres clients cloud n'ont pas ce paramètre) — même principe que
        # OLLAMA_MAP_OUTPUT_TOKENS/OLLAMA_REDUCE_OUTPUT_TOKENS.
        _chat_kwargs["num_predict"] = int(os.getenv("OLLAMA_FINAL_REPORT_OUTPUT_TOKENS", "1400"))

    # Verrou Ollama (utils/ollama_lock.py) uniquement si ce backend est utilisé
    # — même CPU unique partagé que l'analyse Map-Reduce, ne doivent pas
    # tourner en même temps sans quoi ils se ralentiraient mutuellement.
    import contextlib
    if client_name == "ollama":
        from utils.ollama_lock import ollama_slot
        _lock_ctx = ollama_slot()
    else:
        _lock_ctx = contextlib.nullcontext()

    content = ""
    with _lock_ctx:
        for attempt in range(3):
            try:
                msg = client.chat(**_chat_kwargs)
                content = msg.content if hasattr(msg, "content") else msg.get("content", "")
                if content:
                    break
            except Exception as e:
                err = str(e)
                logger.warning("[final_report] Tentative %d échouée : %s", attempt + 1, err)
                if "429" in err:
                    import time
                    time.sleep(15)
                elif attempt >= 2:
                    logger.error("[final_report] Abandon après %d tentatives", attempt + 1)
                    return _enrich(domain, analysis_result, _fallback_report(domain, analysis_result))

    parsed = _parse_json_response(content)
    if not parsed:
        logger.warning("[final_report] Impossible de parser la réponse, fallback utilisé")
        parsed = _fallback_report(domain, analysis_result)

    return _enrich(domain, analysis_result, parsed)


def _enrich(domain: str, analysis: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
    """Ajoute les métadonnées communes au rapport."""
    report["domain"]           = domain
    report["generated_at"]     = datetime.utcnow().isoformat()
    report["security_score"]   = analysis.get("security_score")
    report["security_grade"]   = analysis.get("security_grade")
    report["security_posture"] = analysis.get("security_posture")
    report["risk_score"]       = analysis.get("risk_score")
    report["risk_level"]       = analysis.get("risk_level")
    report["findings_count"]   = len(analysis.get("findings", []))
    report["security_breakdown"] = analysis.get("security_breakdown")
    report["findings_summary"]   = analysis.get("findings_summary")
    report["mitre_attack"]       = analysis.get("mitre_attack")
    return report
