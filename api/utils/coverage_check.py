# utils/coverage_check.py
"""
Contrôle de couverture de l'analyse IA — complète `utils/grounding_check.py`.

`grounding_check.py` vérifie que les findings PRODUITS sont ancrés dans des
données réelles (pas d'hallucination). Il ne répond PAS à une question
différente et tout aussi importante : est-ce que TOUTES les données
collectées ont été effectivement examinées, ou est-ce qu'un outil ayant
retourné des données exploitables a été silencieusement ignoré par le LLM
(aucun finding, aucune mention en `strengths`) ? Un score de sécurité
calculé uniquement à partir des findings PRODUITS est trompeur si des
signaux réels n'ont jamais été transformés en finding — le score paraît bon
non pas parce que le domaine est sûr, mais parce qu'une partie des données
n'a jamais été interprétée.

Ce module répond à trois questions distinctes, chacune avec une preuve
vérifiable et déterministe (pas de nouvel appel LLM — même philosophie que
grounding_check.py : un filet vérifiable, pas une preuve d'exactitude
sémantique) :

  1. Couverture : quelle proportion des outils ayant retourné des données
     exploitables (`status: success` + `data` non vide) est référencée par
     au moins un finding (`source_tool`/`source_tools`) ? Les outils non
     référencés sont listés explicitement — ce sont les angles morts.
  2. RAG : le prompt (instruction #7 de `_build_messages`) demande de CITER
     la source (ex: "cf. OWASP ASVS"), pas de recopier l'extrait — on vérifie
     donc si le nom de la source d'un extrait injecté apparaît dans au moins
     une `recommendation`, plutôt qu'un chevauchement textuel sur le contenu
     (qui sous-détecterait un RAG reformulé plutôt que cité mot pour mot).
  3. Recherche web : combien de recherches ont été effectuées et quelle
     proportion des findings cite au moins une source web (`web_sources`).

Phase 3 (B7) : le RAG interroge désormais une requête par constat, et les
extraits portent `topic`/`collection`. La mesure `rag_snippets_used` reste
la même (citation du nom de la source dans une recommandation) ; les
compteurs `rag_queries`, `rag_filtered_by_collection` et
`findings_with_rag_references` sont ajoutés par routes/analyze.py.
Les findings ajoutés par une règle déterministe (`generated_by: "rule"`)
ne sont pas comptés comme « couverture par le modèle » — sinon le contrôle
mesurerait le serveur, plus le LLM.

`strengths` n'a pas de champ `source_tool` structuré dans le schéma — le
prompt (instruction #2) demande donc au modèle de citer la clé de l'outil
entre parenthèses dans le texte (ex: "SPF correctement configuré
(spf_analysis)"), et ce module vérifie cette convention par recherche de
sous-chaîne. Si le modèle ne suit pas cette convention, un outil aux données
propres peut être compté à tort comme « non référencé » — `coverage_pct`
doit donc être lu comme un plancher (couverture réelle ≥ valeur rapportée),
jamais une mesure exacte à la baisse.
"""
from typing import Any, Dict, List, Optional


def _tools_with_exploitable_data(scan_results: Dict) -> set:
    """Clés des outils status='success' avec une donnée non vide."""
    tools = set()
    for key, entry in (scan_results or {}).items():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "success":
            continue
        data = entry.get("data")
        if data in (None, {}, [], ""):
            continue
        tools.add(key)
    return tools


def _tools_referenced(findings: List[Dict], strengths: List, candidate_tools: set) -> set:
    referenced = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        st = f.get("source_tool")
        if st:
            referenced.add(st)
        for st2 in (f.get("source_tools") or []):
            if st2:
                referenced.add(st2)

    # Convention demandée au modèle (voir docstring du module) : citer la clé
    # outil entre parenthèses dans `strengths` — recherche de sous-chaîne
    # simple sur le texte concaténé, uniquement parmi les outils candidats
    # (ceux ayant réellement des données) pour éviter tout faux positif sur
    # un mot du texte qui ressemblerait par hasard à une clé d'outil.
    strengths_text = " ".join(str(s) for s in (strengths or []) if isinstance(s, str))
    if strengths_text:
        for tool_key in candidate_tools:
            if tool_key in strengths_text:
                referenced.add(tool_key)

    return referenced


def _rag_source_cited(source_slug: str, text: str) -> bool:
    """
    Le prompt d'analyse (instruction #7 de `_build_messages`) demande
    explicitement de citer la SOURCE (ex: "cf. OWASP ASVS"), pas de recopier
    l'extrait mot pour mot — un chevauchement textuel sur le CONTENU (comme
    dans grounding_check.py) sous-détecterait donc systématiquement un RAG
    réellement utilisé mais reformulé. Vérifier la citation du nom de la
    source est à la fois plus fiable et correspond exactement à ce que le
    prompt demande au modèle.
    """
    if not source_slug or not text:
        return False
    text_l, slug_l = text.lower(), source_slug.lower()
    return slug_l in text_l or slug_l.replace('_', ' ') in text_l


def _rag_snippets_used(findings: List[Dict], rag_context: List[Dict]) -> int:
    if not rag_context:
        return 0
    recommendations = [
        str(f.get("recommendation") or "") for f in findings if isinstance(f, dict)
    ]
    recommendations = [r for r in recommendations if r]
    if not recommendations:
        return 0

    used = 0
    for extract in rag_context:
        source = extract.get("source") if isinstance(extract, dict) else None
        if not source:
            continue
        if any(_rag_source_cited(source, rec) for rec in recommendations):
            used += 1
    return used


def compute_coverage_check(
    report: Dict,
    scan_results: Optional[Dict],
    signals: Optional[Dict] = None,
    rule_examined: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Calcule le résumé de couverture à assigner à `report["coverage_check"]`.
    N'écrase ni ne modifie aucun champ existant du rapport — additif comme
    `grounding_check.py::compute_grounding_check`.
    """
    findings = report.get("findings") or []
    # Findings du modèle uniquement (voir docstring : les ajouts par règle
    # déterministe ne mesurent pas la couverture du LLM).
    findings = [f for f in findings if isinstance(f, dict) and f.get("generated_by") != "rule"]
    scan_results = scan_results if isinstance(scan_results, dict) else {}
    signals = signals if isinstance(signals, dict) else {}

    strengths = report.get("strengths") or []
    tools_with_data = _tools_with_exploitable_data(scan_results)
    tools_referenced = _tools_referenced(findings, strengths, tools_with_data)
    # Avis par outil demandés au modèle (tool_reviews) : un outil examiné sans
    # rien révéler compte comme examiné (verdict « ras »).
    for review in report.get("tool_reviews") or []:
        if isinstance(review, dict) and review.get("tool"):
            tools_referenced.add(str(review["tool"]))
    by_model = tools_with_data & tools_referenced
    # Outils dont une règle déterministe a lu les données (severity_rules)
    by_rules = tools_with_data & set(rule_examined or [])
    tools_covered = by_model | by_rules
    tools_unreferenced = sorted(tools_with_data - tools_covered)

    def pct(part):
        return round(100 * len(part) / len(tools_with_data), 1) if tools_with_data else None
    coverage_pct = pct(tools_covered)

    rag_context = signals.get("rag_context") or []
    rag_available = len(rag_context) if isinstance(rag_context, list) else 0
    rag_used = _rag_snippets_used(findings, rag_context) if isinstance(rag_context, list) else 0

    searches_performed = report.get("searches_performed") or []
    findings_with_web_source = sum(
        1 for f in findings if f.get("web_sources")
    )

    return {
        "tools_with_data_count":    len(tools_with_data),
        "tools_covered_count":      len(tools_covered),
        "tools_covered_by_model":   len(by_model),
        "tools_covered_by_rules":   len(by_rules),
        "model_coverage_pct":       pct(by_model),
        "tools_reviewed_count":     sum(1 for r in (report.get("tool_reviews") or []) if isinstance(r, dict)),
        "tools_unreferenced":       tools_unreferenced,
        "coverage_pct":             coverage_pct,
        "rag_snippets_available":   rag_available,
        "rag_snippets_used":        rag_used,
        "web_searches_performed":   len(searches_performed),
        "findings_total":           len(findings),
        "findings_citing_web_source": findings_with_web_source,
        "method": (
            "Couverture = proportion des outils status=success avec données "
            "non vides EXAMINÉS : cités en source_tool/source_tools d'un "
            "finding, cités par leur clé dans `strengths`, ayant un avis dans "
            "`tool_reviews` (un par outil, demandé au modèle), ou lus par une "
            "règle de sévérité déterministe. La part du modèle seul est "
            "donnée dans model_coverage_pct. "
            "RAG mesuré par citation du nom de la source dans une "
            "recommandation (le prompt demande de citer, pas de recopier) ; "
            "recherche web mesurée par présence de `web_sources` par finding."
        ),
    }
