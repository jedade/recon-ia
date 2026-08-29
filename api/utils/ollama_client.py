# utils/ollama_client.py
"""
Client HTTP pour l'API Ollama locale.

Fonctionnalités :
  - Appel simple /api/chat
  - Boucle agentique avec tool use (function calling)
  - Analyse Map-Reduce : découpage sémantique en 6 sections + synthèse finale
  - Gestion automatique des tool_calls retournés par le modèle
  - Timeout et retry configurables

Modèles recommandés supportant le tool use :
  - qwen3:1.7b   (~1.4 GB) — recommandé par défaut : seul modèle testé sur ce
    poste qui supporte réellement `tools` ET génère assez vite pour rester
    sous OLLAMA_CHAT_TIMEOUT (I/O bind mount Docker Desktop lente, pas de GPU).
    phi3:mini répond mais rejette toute requête avec `tools` (400 "does not
    support tools" — vérifié). qwen3:8b/gemma2:2b/deepseek-r1:8b se sont
    révélés corrompus sur ce poste (téléchargement interrompu, tenseurs
    tronqués) — un modèle plus petit réduit aussi ce risque (fenêtre
    d'exposition au téléchargement plus courte).
  - qwen3:8b     (8 GB RAM)   — meilleure qualité si le poste est assez rapide
  - qwen2.5:7b   (8 GB RAM)   — alternative stable
  - qwen2.5:14b  (16 GB RAM)
"""

import json
import logging
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests as _req

from utils.attack_surface import build_attack_surface

logger = logging.getLogger(__name__)

# ── Config depuis .env ────────────────────────────────────────────────────────
_OLLAMA_URL           = os.getenv("OLLAMA_URL",    "http://ollama:11434")
# OLLAMA_MODEL dédié (PAS ANALYSIS_MODEL) : ce dernier est un nom de modèle
# Groq (ex. "llama-3.3-70b-versatile"), qui n'existe pas dans Ollama — le
# réutiliser ici faisait échouer silencieusement le fallback local (slot 5 de
# la cascade), `model_loaded()` retournant toujours False. Constaté en
# conditions réelles : les 4 backends cloud ont échoué (quota/404) et Ollama
# n'a même pas été tenté, faute de log dédié sur ce cas.
_DEFAULT_MODEL        = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
_MAX_ROUNDS           = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_CHAT_TIMEOUT         = int(os.getenv("OLLAMA_CHAT_TIMEOUT", "360"))   # secondes
_MAP_ROUNDS           = int(os.getenv("OLLAMA_MAP_ROUNDS", "3"))        # rounds web_search par section MAP
_MAX_SECTION_TOKENS   = int(os.getenv("OLLAMA_MAX_SECTION_TOKENS", "1000"))  # tokens max par section (INPUT)
# Tokens max en SORTIE — avant ce correctif, num_predict était figé à 4096
# dans chat() quel que soit l'appelant : sur un modèle lent (~2-3 tok/s en
# I/O bind-mount Docker Desktop sans GPU), générer 4096 tokens dépasse
# largement OLLAMA_CHAT_TIMEOUT et fait échouer CHAQUE appel (constaté avec
# phi3:mini : 300s+ pour un rapport de section jamais terminé). Deux budgets
# séparés : MAP (findings d'une seule section) a besoin de peu de tokens,
# REDUCE (synthèse de toutes les sections) un peu plus.
_MAP_OUTPUT_TOKENS    = int(os.getenv("OLLAMA_MAP_OUTPUT_TOKENS", "700"))
_REDUCE_OUTPUT_TOKENS = int(os.getenv("OLLAMA_REDUCE_OUTPUT_TOKENS", "1400"))
# Timeout DÉDIÉ à l'appel REDUCE, distinct de _CHAT_TIMEOUT (qui reste le
# timeout des appels MAP et des autres usages de chat()). Mesuré en
# conditions réelles (2026-07-29) : l'appel REDUCE échoue quasi
# systématiquement à _CHAT_TIMEOUT (360s) sans jamais produire de synthèse
# narrative, avant de tomber sur le repli dégradé (_reduce_degraded) — qui
# préserve déjà intégralement les findings/strengths de la phase MAP (voir
# plus haut). Attendre 360s pour ce même résultat dégradé n'apporte donc
# rien : ce timeout plus court fait tomber sur le même repli, fiable, ~3-4
# min plus tôt — contribution directe au budget de 30 min bout-en-bout.
_REDUCE_TIMEOUT_S     = int(os.getenv("OLLAMA_REDUCE_TIMEOUT_S", "150"))


# ── Définition de l'outil web_search exposé au modèle ────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  Helpers Map-Reduce — token counting & section splitting
# ══════════════════════════════════════════════════════════════════════════════

# Sections sémantiques de l'analyse OSINT (id, label lisible)
_MAP_SECTIONS: List[Tuple[str, str]] = [
    ("dns_security",  "DNS, DNSSEC et réputation réseau (DNSBL)"),
    ("network_infra", "Infrastructure réseau, ASN et WHOIS"),
    ("ssl_tls",       "SSL/TLS — certificats, versions, cipher suites"),
    ("email",         "Sécurité email — SPF, DKIM, DMARC"),
    ("web_tech",      "Technologies web, en-têtes HTTP, WAF, méthodes HTTP"),
    ("subdomains",    "Sous-domaines et surface externe"),
]

# Schéma de sortie attendu de la phase REDUCE
_REDUCE_OUTPUT_SCHEMA = {
    "domain":            "string — domaine analysé",
    "risk_score":        "integer 0-100  (0=parfait, 100=critique)",
    "risk_level":        "CRITICAL | HIGH | MEDIUM | LOW",
    "executive_summary": "string — résumé 3-5 phrases pour un CISO",
    "findings": [
        {
            "id":             "string — ex: DNS-001, WEB-002",
            "category":       "DNS | SSL | Email | Web | Infrastructure | Subdomain | Reputation | Cloud",
            "severity":       "CRITICAL | HIGH | MEDIUM | LOW | INFO",
            "title":          "string",
            "description":    "string",
            "evidence":       "string — donnée OSINT exacte",
            "source_tool":    "string OBLIGATOIRE — clé exacte de l'outil (reprise du champ source_tool du finding partiel correspondant, jamais vide)",
            "recommendation": "string",
            "references":     ["string — CVE-XXXX, CWE-XXX, RFC XXXX"],
            "web_sources":    ["string — URL"],
        }
    ],
    "attack_surface": {
        "total_subdomains": "integer",
        "exposed_services": [{"host": "string", "service_type": "string", "risk": "CRITICAL|HIGH|MEDIUM|LOW"}],
        "technologies":     ["string"],
        "cloud_providers":  ["string"],
    },
    "strengths":        ["string — bonnes pratiques déjà en place"],
    "immediate_actions": [{"priority": "integer 1-3", "action": "string"}],
    "searches_performed": [{"query": "string", "results_count": "integer"}],
    "model_used":        "string",
    "analyzed_at":       "string ISO 8601",
}

# Prompt système pour la phase MAP (une section à la fois)
_MAP_SYSTEM_PROMPT = (
    "Tu es un analyste cybersécurité OSINT expert (OSCP, GPEN).\n\n"
    "MISSION : Analyser la section \"{section_label}\" pour le domaine \"{domain}\".\n\n"
    "═══ RÈGLE ABSOLUE — ZÉRO HALLUCINATION ═══\n"
    "• Tout finding DOIT être ancré dans les données fournies\n"
    "• Ne JAMAIS inventer de CVE, version ou configuration absente des données\n"
    "• Si une info est absente → indique \"Non détecté\" plutôt que de supposer\n\n"
    "═══ CONTEXTE GLOBAL (pour corrélations inter-sections) ═══\n"
    "{global_context}\n\n"
    "═══ DONNÉES À ANALYSER ═══\n"
    "{section_data}\n\n"
    "═══ INSTRUCTIONS ═══\n"
    "1. Effectue des recherches web ciblées sur les éléments détectés (CVE, risques, best practices)\n"
    "2. Identifie tous les problèmes de sécurité dans cette section\n"
    "3. COUVERTURE OBLIGATOIRE : pour CHAQUE outil ci-dessus ayant retourné des données, produis "
    "soit un finding qui le cite (`source_tool`), soit une entrée dans `strengths` citant sa clé "
    "entre parenthèses si les données sont propres (ex: \"SPF correctement configuré (spf_analysis)\") "
    "— ne jamais ignorer silencieusement un outil ayant des données\n"
    "4. TRAÇABILITÉ OBLIGATOIRE : chaque finding DOIT porter un champ `source_tool` NON VIDE — la clé "
    "EXACTE (entre crochets ci-dessus, ex: dnssec, ssl_info, spf_analysis) de l'outil d'où vient la "
    "preuve. Un finding SANS `source_tool` est INVALIDE et sera rejeté\n"
    "5. Produis UNIQUEMENT ce JSON valide (sans texte avant ou après) :\n\n"
    "{{\n"
    "  \"findings\": [\n"
    "    {{\n"
    "      \"id\": \"DNS-001\",\n"
    "      \"category\": \"DNS|SSL|Email|Web|Infrastructure|Subdomain|Reputation|Cloud\",\n"
    "      \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW|INFO\",\n"
    "      \"title\": \"titre court\",\n"
    "      \"description\": \"explication détaillée\",\n"
    "      \"evidence\": \"donnée OSINT exacte\",\n"
    "      \"source_tool\": \"clé exacte de l'outil, ex: dnssec\",\n"
    "      \"recommendation\": \"action corrective concrète\",\n"
    "      \"references\": [\"CVE-XXXX-XXXX\", \"CWE-XXX\"],\n"
    "      \"web_sources\": [\"url1\"]\n"
    "    }}\n"
    "  ],\n"
    "  \"strengths\": [\"bonne pratique constatée (clé_outil)\"],\n"
    "  \"searches_performed\": [{{\"query\": \"...\", \"results_count\": 5}}]\n"
    "}}"
)

# Prompt système pour la phase REDUCE (synthèse finale)
_REDUCE_SYSTEM_PROMPT = (
    "Tu es un analyste cybersécurité senior (OSCP, GPEN, CEH) chargé de synthétiser "
    "une analyse OSINT complète du domaine \"{domain}\".\n\n"
    "SECTIONS ANALYSÉES : DNS/Réseau, SSL/TLS, Email, Web, Sous-domaines, Infrastructure\n\n"
    "═══ TA MISSION ═══\n"
    "1. FUSIONNER et DÉDUPLIQUER les findings (éliminer les doublons entre sections)\n"
    "2. CORRÉLER les findings (ex: même CVE affecte plusieurs composants)\n"
    "3. CALCULER le risk_score global (0-100) basé sur la criticité réelle de l'ensemble\n"
    "4. ÉCRIRE executive_summary pour un CISO (3-5 phrases synthétiques et actionnables)\n"
    "5. CONSTRUIRE attack_surface (services exposés, technologies, cloud)\n"
    "6. LISTER immediate_actions par priorité (1=urgent, 2=cette semaine, 3=ce mois)\n"
    "7. CONSOLIDER les strengths déjà remontées par chaque section (ci-dessous) — "
    "ne PAS en inventer de nouvelles, ne PAS en perdre au passage, conserver la "
    "citation de clé d'outil entre parenthèses telle quelle\n"
    "8. CONSERVER le champ `source_tool` de chaque finding partiel TEL QUEL en le "
    "fusionnant dans le rapport final — ne jamais le vider ni l'omettre, même en "
    "fusionnant/dédupliquant plusieurs findings entre eux\n\n"
    "═══ FINDINGS PARTIELS PAR SECTION ═══\n"
    "{all_findings}\n\n"
    "═══ IMPORTANT ═══\n"
    "• Les recherches web ont déjà été effectuées dans les sections — ne fais AUCUNE nouvelle recherche\n"
    "• Consolide les searches_performed de toutes les sections dans le rapport final\n"
    "• Chaque section fournie ci-dessus liste ses propres `strengths` — reprends-les "
    "TOUTES dans le rapport final, ne garde pas seulement les findings\n\n"
    "Produis UNIQUEMENT le rapport JSON final (sans texte avant ou après) en respectant ce schéma :\n\n"
    "{output_schema}"
)


def _estimate_tokens(text: str) -> int:
    """Approximation rapide : 1 token ≈ 4 caractères."""
    return max(1, len(text) // 4)


def _truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Tronque le texte à max_tokens (approximatif)."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [tronqué — limite de contexte atteinte]"


def _build_section_data(section_id: str, signals: dict) -> dict:
    """Extrait les données pertinentes pour une section OSINT donnée."""
    domain = signals.get("domain", "")

    if section_id == "dns_security":
        return {
            "domain":  domain,
            "dns":     signals.get("dns", {}),
            "dnsbl":   (signals.get("network") or {}).get("dnsbl"),
        }
    if section_id == "network_infra":
        net = signals.get("network") or {}
        return {
            "domain":     domain,
            "ips":        net.get("ips"),
            "asn":        net.get("asn"),
            "ptr":        net.get("ptr"),
            "reverse_ip": net.get("reverse_ip"),
            "whois":      signals.get("whois"),
        }
    if section_id == "ssl_tls":
        return {"domain": domain, "ssl_tls": signals.get("ssl_tls", {})}
    if section_id == "email":
        return {"domain": domain, "email": signals.get("email", {})}
    if section_id == "web_tech":
        return {"domain": domain, "web": signals.get("web", {})}
    if section_id == "subdomains":
        return {
            "domain":     domain,
            "subdomains": signals.get("subdomains", {}),
        }
    return {"domain": domain}


def _build_global_context(signals: dict) -> str:
    """Résumé minimal des signaux clés pour les corrélations cross-section."""
    tech = signals.get("web", {}).get("tech_stack") or {}
    techs: List[str] = []
    if isinstance(tech, dict):
        for cat, items in tech.items():
            if isinstance(items, list):
                techs.extend(str(i) for i in items[:2])
            elif isinstance(items, str):
                techs.append(items)

    ssl    = (signals.get("ssl_tls") or {}).get("certificate") or {}
    tls_v  = ssl.get("protocol", "") if isinstance(ssl, dict) else ""

    sub_count = (signals.get("subdomains") or {}).get("count", 0)
    spf       = ((signals.get("email") or {}).get("config") or {}).get("spf", "")
    dnsbl_ok  = ((signals.get("network") or {}).get("dnsbl") or {}).get("clean")

    # Extraits RAG (OWASP Cheat Sheets/ASVS/WSTG) — seulement les 2 premiers et
    # tronqués : ce contexte se répète dans CHAQUE prompt de section MAP (6x),
    # contrairement au prompt unique des autres backends (_build_messages) qui
    # peut se permettre les 6 extraits complets.
    rag_ctx = signals.get("rag_context") or []
    rag_lines = "\n".join(
        f"  [{r.get('source', '?')}] {r.get('content', '')[:200]}"
        for r in rag_ctx[:2]
    ) or "  (aucun — RAG indisponible ou vide)"

    return (
        f"Technologies détectées : {', '.join(techs[:6]) or 'inconnues'}\n"
        f"Version TLS             : {tls_v or 'inconnue'}\n"
        f"Nombre de sous-domaines : {sub_count or 'inconnu'}\n"
        f"SPF                     : {spf or 'non configuré'}\n"
        f"DNSBL propre            : {dnsbl_ok}\n"
        f"Guidance OWASP/ASVS/WSTG pertinente (citer la source si utilisée) :\n{rag_lines}"
    )


def _parse_partial_findings(content: str) -> Optional[Dict]:
    """Parse le JSON partiel retourné par la phase MAP (findings + searches_performed)."""
    if not content:
        return None
    text = content.strip()
    # Extraire le bloc entre ``` si présent
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if m:
        text = m.group(1).strip()
    # Trouver le premier {
    start = text.find("{")
    if start >= 0:
        text = text[start:]
    # Trouver le dernier } correspondant
    depth, end = 0, -1
    for i, ch in enumerate(text):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end >= 0:
        text = text[: end + 1]
    try:
        return json.loads(text)
    except Exception:
        return None


# ── Outil web_search exposé au modèle ────────────────────────────────────────

WEB_SEARCH_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Effectue une recherche web en temps réel pour trouver :\n"
            "- Des CVE et vulnérabilités connues pour les technologies/versions détectées\n"
            "- Les meilleures pratiques de sécurité actualisées\n"
            "- Des références CWE, OWASP, RFC pour les problèmes identifiés\n"
            "- Des informations sur les configurations à risque"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Requête de recherche précise. "
                        "Exemples : 'WordPress 6.9 CVE 2025 vulnerabilities', "
                        "'DNSSEC configuration best practices 2024', "
                        "'nginx 1.24 security issues'"
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Nombre de résultats à retourner (1-10, défaut: 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  Client Ollama
# ══════════════════════════════════════════════════════════════════════════════

class OllamaClient:
    """Client pour l'API Ollama avec support du tool use agentique."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = (base_url or _OLLAMA_URL).rstrip("/")
        self.model    = model or _DEFAULT_MODEL
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    # ── Disponibilité ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Vérifie qu'Ollama répond."""
        try:
            resp = _req.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """Retourne la liste des modèles installés."""
        try:
            resp = _req.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []

    def model_loaded(self) -> bool:
        """Vérifie si le modèle configuré est disponible localement."""
        models = self.list_models()
        base = self.model.split(":")[0]
        return any(m.startswith(base) for m in models)

    # ── Appel chat unique ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.1,
        timeout: int = _CHAT_TIMEOUT,
        num_predict: int = _MAP_OUTPUT_TOKENS,
    ) -> Dict:
        """
        Appel POST /api/chat.
        Retourne le dict `message` de la réponse Ollama.
        """
        payload: Dict[str, Any] = {
            "model":    self.model,
            "messages": messages,
            "stream":   False,
            "think":    False,          # top-level : désactive le thinking de qwen3/deepseek-r1
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
            },
        }
        if tools:
            payload["tools"] = tools

        logger.debug("Ollama chat — model=%s, messages=%d", self.model, len(messages))

        resp = _req.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        # Ollama expose les compteurs de tokens en natif (pas de champ `usage`
        # façon OpenAI) — prompt_eval_count/eval_count, sommés sur tous les
        # appels (MAP + REDUCE) puisque `self` persiste sur tout le Map-Reduce.
        p = data.get("prompt_eval_count", 0) or 0
        c = data.get("eval_count", 0) or 0
        self.usage["prompt_tokens"]     += p
        self.usage["completion_tokens"] += c
        self.usage["total_tokens"]      += p + c
        return data.get("message", {"role": "assistant", "content": ""})

    # ── Boucle agentique ─────────────────────────────────────────────────────

    def agentic_chat(
        self,
        messages: List[Dict],
        tool_handler: Callable[[str, Dict], str],
        max_rounds: int = _MAX_ROUNDS,
        temperature: float = 0.1,
    ) -> Tuple[Dict, List[Dict]]:
        """
        Lance une boucle agentique :
          1. Envoie les messages avec l'outil web_search disponible
          2. Si le modèle appelle web_search → exécute la recherche, injecte le résultat
          3. Répète jusqu'à ce que le modèle produise sa réponse finale (sans tool_call)
          4. Si max_rounds atteint → demande explicitement la réponse finale

        Returns:
            (message_final, searches_log)
            - message_final : dict {"role": "assistant", "content": "..."}
            - searches_log  : liste des recherches effectuées
        """
        msgs = list(messages)
        searches_log: List[Dict] = []
        consecutive_errors = 0

        for round_num in range(max_rounds):
            logger.info("[agentique] Tour %d/%d", round_num + 1, max_rounds)

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[agentique] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning("[agentique] %d erreurs consécutives — abandon", consecutive_errors)
                    break
                continue

            tool_calls = msg.get("tool_calls") or []

            # ── Pas de tool_call → réponse finale ─────────────────────────
            if not tool_calls:
                logger.info(
                    "[agentique] Réponse finale au tour %d (%d caractères)",
                    round_num + 1, len(msg.get("content", "")),
                )
                return msg, searches_log

            # ── Exécution des tool_calls ───────────────────────────────────
            msgs.append(msg)  # ajouter l'assistant qui a fait les tool_calls

            for tc in tool_calls:
                fn        = tc.get("function", {})
                tool_name = fn.get("name", "")
                tool_args = fn.get("arguments", {})

                # Certains modèles encodent les arguments en JSON string
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except Exception:
                        tool_args = {}

                logger.info("[agentique] Tool call: %s(%s)", tool_name, tool_args)

                # Exécuter l'outil via le handler fourni par le caller
                try:
                    result_str = tool_handler(tool_name, tool_args)
                except Exception as e:
                    result_str = json.dumps({"error": str(e)})

                # Logger la recherche
                if tool_name == "web_search":
                    try:
                        n = len(json.loads(result_str)) if result_str.startswith("[") else 0
                    except Exception:
                        n = 0
                    searches_log.append({
                        "query":         tool_args.get("query", ""),
                        "results_count": n,
                    })

                # Injecter le résultat de l'outil dans la conversation
                msgs.append({
                    "role":    "tool",
                    "content": result_str,
                })

        # ── Max rounds atteint ─────────────────────────────────────────────
        logger.info("[agentique] Max rounds (%d) atteint — demande rapport final", max_rounds)

        msgs.append({
            "role": "user",
            "content": (
                "Tu as maintenant collecté suffisamment d'informations. "
                "Produis maintenant le rapport JSON final en respectant exactement "
                "le schéma demandé. "
                "Réponds UNIQUEMENT avec le JSON valide, sans texte avant ou après."
            ),
        })

        try:
            msg = self.chat(msgs, tools=None, temperature=0.0)
            return msg, searches_log
        except Exception as e:
            logger.error("[agentique] Erreur rapport final: %s", e)
            return {"role": "assistant", "content": "{}"}, searches_log

    # ── Analyse Map-Reduce ────────────────────────────────────────────────────

    def map_reduce_agentic_chat(
        self,
        signals: dict,
        tool_handler: Callable[[str, Dict], str],
        map_rounds: int = _MAP_ROUNDS,
    ) -> Tuple[Dict, List[Dict], List]:
        """
        Analyse OSINT par découpage sémantique Map-Reduce.

        Phase MAP  : analyse chaque section OSINT indépendamment (6 sections),
                     avec outil web_search (max map_rounds tours par section).
        Phase REDUCE : synthèse finale de tous les findings partiels (sans web_search).

        Budget tokens / appel MAP  : ~2 700 tokens (fenêtre 32K de qwen3:8b)
        Budget tokens pour REDUCE  : ~6 500 tokens

        Returns:
            (final_msg_dict, all_searches_log, [])
            Même convention que agentic_chat() pour faciliter l'intégration.
        """
        domain         = signals.get("domain", "unknown")
        global_context = _build_global_context(signals)

        all_partial: List[Dict] = []   # findings consolidés par section
        all_searches: List[Dict] = []  # toutes les recherches web cumulées

        # ══════════════════════════════════════════════════════════════════════
        #  Phase MAP — analyse section par section
        # ══════════════════════════════════════════════════════════════════════
        for section_id, section_label in _MAP_SECTIONS:
            section_data = _build_section_data(section_id, signals)
            section_json = json.dumps(section_data, ensure_ascii=False, indent=2)

            # Ignorer les sections vides (moins de 20 tokens → pas de données utiles)
            if _estimate_tokens(section_json) < 20:
                logger.info("[map-reduce][%s] Section vide — ignorée", section_id)
                continue

            section_json_trunc = _truncate_to_tokens(section_json, _MAX_SECTION_TOKENS)

            logger.info(
                "[map-reduce][%s] Début — ~%d tokens",
                section_id, _estimate_tokens(section_json_trunc),
            )

            system_content = _MAP_SYSTEM_PROMPT.format(
                section_label=section_label,
                domain=domain,
                global_context=global_context,
                section_data=section_json_trunc,
            )

            messages = [
                {"role": "system", "content": system_content},
                {
                    "role": "user",
                    "content": (
                        f"Analyse la section « {section_label} » pour {domain} "
                        f"et produis le JSON partiel demandé."
                    ),
                },
            ]

            try:
                final_msg, section_searches = self.agentic_chat(
                    messages=messages,
                    tool_handler=tool_handler,
                    max_rounds=map_rounds,
                    temperature=0.1,
                )

                partial = _parse_partial_findings(final_msg.get("content", ""))

                # `or partial.get("strengths")` : une section aux données propres
                # peut légitimement n'avoir AUCUN finding — sans ce cas, elle était
                # silencieusement absente de `all_partial`, perdant même la
                # reconnaissance des bonnes pratiques (voir instruction #3 du
                # prompt MAP, qui demande justement de ne rien ignorer).
                if partial and (partial.get("findings") or partial.get("strengths")):
                    all_partial.append({
                        "section":   section_label,
                        "findings":  partial.get("findings") or [],
                        "strengths": partial.get("strengths") or [],
                    })
                    # Préférer les searches extraites du message final (plus fiable)
                    embedded_searches = partial.get("searches_performed") or []
                    all_searches.extend(section_searches if section_searches else embedded_searches)
                    logger.info(
                        "[map-reduce][%s] OK — %d findings, %d strengths, %d recherches",
                        section_id, len(partial.get("findings") or []),
                        len(partial.get("strengths") or []), len(section_searches),
                    )
                else:
                    logger.warning("[map-reduce][%s] Aucun finding/strength parseable", section_id)

            except Exception as exc:
                logger.error("[map-reduce][%s] Erreur: %s — section ignorée", section_id, exc)
                continue

        if not all_partial:
            logger.error("[map-reduce] Aucune section n'a produit de findings — abandon")
            return {"role": "assistant", "content": "{}"}, all_searches, []

        # ══════════════════════════════════════════════════════════════════════
        #  Phase REDUCE — synthèse finale
        # ══════════════════════════════════════════════════════════════════════
        total_findings = sum(len(s["findings"]) for s in all_partial)
        logger.info(
            "[map-reduce][reduce] Synthèse — %d sections, %d findings",
            len(all_partial), total_findings,
        )

        all_findings_json = _truncate_to_tokens(
            json.dumps(all_partial, ensure_ascii=False, indent=2), 4000
        )
        output_schema_json = json.dumps(_REDUCE_OUTPUT_SCHEMA, ensure_ascii=False, indent=2)

        reduce_content = _REDUCE_SYSTEM_PROMPT.format(
            domain=domain,
            all_findings=all_findings_json,
            output_schema=output_schema_json,
        )

        reduce_messages = [
            {"role": "system", "content": reduce_content},
            {
                "role": "user",
                "content": (
                    f"Synthétise tous les findings et produis le rapport JSON final "
                    f"pour {domain}. Réponds UNIQUEMENT avec le JSON valide."
                ),
            },
        ]

        try:
            final_msg = self.chat(
                reduce_messages, tools=None, temperature=0.0,
                num_predict=_REDUCE_OUTPUT_TOKENS, timeout=_REDUCE_TIMEOUT_S,
            )
            logger.info(
                "[map-reduce][reduce] Rapport généré — %d caractères",
                len(final_msg.get("content", "")),
            )
            return final_msg, all_searches, []
        except Exception as exc:
            # La synthèse (déduplication inter-sections, risk_score global,
            # executive_summary) a échoué, mais les findings de la phase MAP sont
            # réels et déjà validés section par section — les jeter ici (ancien
            # comportement : content="{}") faisait tomber `findings` à 0, et
            # compute_security_score() traduisait ça en score 100/A+ « parfait »
            # alors que des problèmes réels avaient été identifiés. On replie donc
            # sur un rapport construit directement depuis `all_partial`, sans
            # narratif ni déduplication, plutôt que de perdre ces findings.
            logger.error(
                "[map-reduce][reduce] Erreur synthèse: %s — repli sur les %d "
                "findings bruts de la phase MAP (sans narratif/déduplication)",
                exc, total_findings,
            )
            flat_findings  = [f for s in all_partial for f in s["findings"]]
            # Dédupliqué (ordre préservé) : plusieurs sections MAP peuvent
            # légitimement remarquer la même bonne pratique indépendamment
            # (ex. SPF correct constaté par la section email ET reconnu à
            # nouveau ailleurs) — sans le repli normal de REDUCE pour fusionner,
            # ces doublons remontaient tels quels (constaté : 5 occurrences
            # identiques de « SPF correctement configuré » dans un même rapport).
            _seen_strengths, flat_strengths = set(), []
            for s in all_partial:
                for t in s.get("strengths", []):
                    if t not in _seen_strengths:
                        _seen_strengths.add(t)
                        flat_strengths.append(t)
            _sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            severities = {str(f.get("severity", "")).upper() for f in flat_findings}
            risk_level = next((s for s in _sev_order if s in severities), None)
            fallback_report = {
                "domain": domain,
                "risk_level": risk_level,
                "findings": flat_findings,
                "strengths": flat_strengths,
                "executive_summary": (
                    "Synthèse narrative indisponible (erreur technique lors de la "
                    "phase de fusion Map-Reduce) — les findings ci-dessous sont les "
                    "résultats bruts de l'analyse par section, non dédupliqués ni "
                    "corrélés entre eux."
                ),
                "attack_surface": build_attack_surface(signals),
                "immediate_actions": [],
                "searches_performed": all_searches,
                "_reduce_degraded": True,
            }
            fallback_content = json.dumps(fallback_report, ensure_ascii=False)
            return {"role": "assistant", "content": fallback_content}, all_searches, []
