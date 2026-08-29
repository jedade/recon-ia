# utils/attack_surface.py
"""
Reconstruit `report["attack_surface"]` de façon déterministe depuis les
signaux OSINT, jamais depuis le texte du LLM.

Constaté sur des rapports réels produits par DeepSeek (2026-07-30,
recon.id=9 et 10) : `attack_surface` totalement absent du JSON (`None`, pas
même `{}`) malgré une narration qui cite pourtant explicitement "25
sous-domaines" et des technologies précises — les tuiles de résumé du PDF
(Sous-domaines, Services exposés, Technologies) affichaient donc 0 alors que
les données existaient réellement dans `signals`. Même classe de bug que
celle déjà corrigée pour le repli dégradé d'Ollama (`_reduce_degraded`),
généralisée ici à TOUS les backends : aucun ne doit être une source de
vérité pour ce champ, ses valeurs sont entièrement dérivables des signaux
déjà collectés — même principe que `report["mitre_attack"]`
(utils/mitre_attack.py), calculé déterministiquement plutôt que demandé au
modèle.
"""
from typing import Dict, List


def build_attack_surface(signals: dict) -> dict:
    tech_stack = (signals.get("web") or {}).get("tech_stack") or {}
    technologies: List[str] = []
    if isinstance(tech_stack, dict):
        for key in ("server", "powered_by"):
            val = tech_stack.get(key)
            if val:
                technologies.append(str(val))
        for key in ("cms", "javascript_frameworks", "cdn"):
            items = tech_stack.get(key)
            if isinstance(items, list):
                technologies.extend(str(i) for i in items)

    shodan = signals.get("shodan_internetdb") or {}
    ports = shodan.get("ports") if isinstance(shodan, dict) else None
    exposed_services = [
        {"host": signals.get("domain", ""), "service_type": f"port {p}", "risk": "LOW"}
        for p in (ports or [])
    ] if isinstance(ports, list) else []

    waf = (signals.get("web") or {}).get("waf") or {}
    cloud_providers = []
    if isinstance(waf, dict):
        for entry in (waf.get("detected") or []):
            name = entry.get("name") if isinstance(entry, dict) else entry
            if name:
                cloud_providers.append(str(name))

    return {
        "total_subdomains": (signals.get("subdomains") or {}).get("count") or 0,
        "exposed_services": exposed_services,
        "technologies":     technologies,
        "cloud_providers":  cloud_providers,
    }
