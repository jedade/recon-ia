# utils/groq_client.py
"""
Client Groq pour l'analyse IA agentique.

Stratégie de fiabilité :
  1. Au démarrage → découverte dynamique des modèles disponibles via l'API Groq
  2. File de priorité : modèle configuré + modèles capables détectés automatiquement
  3. 429 TPM (tokens/min)  → attente courte + retry même modèle
  4. 429 TPD (tokens/day)  → switch immédiat vers le modèle suivant dans la file
  5. Tous les modèles épuisés → exception propagée (OpenRouter prend le relai)
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from groq import Groq

logger = logging.getLogger(__name__)

_DEFAULT_MODEL            = os.getenv("ANALYSIS_MODEL", "llama-3.3-70b-versatile")
_MAX_ROUNDS               = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS    = int(os.getenv("GROQ_MAX_TOOL_RESULT_CHARS", "2000"))
_MAX_TOOL_CALLS_PER_ROUND = int(os.getenv("GROQ_MAX_TOOL_CALLS_PER_ROUND", "3"))
_TPM_SLEEP                = float(os.getenv("GROQ_TPM_SLEEP", "15"))

# Modèles Groq connus pour supporter le tool use — ordre de préférence
# Mis à jour dynamiquement au démarrage via l'API
_KNOWN_TOOL_MODELS_PRIORITY = [
    "llama-3.3-70b-versatile",
    "moonshotai/kimi-k2-instruct",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen/qwen3-32b",
    "llama-3.1-8b-instant",
    "groq/compound",
    "groq/compound-mini",
]

# Modèles à exclure (audio, vision, modération, guard)
_EXCLUDE_PATTERNS = [
    "whisper", "guard", "vision", "embed", "tts", "rerank",
    "prompt-guard", "allam", "orpheus", "gpt-oss-safeguard",
]

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
                    "description": "Requête de recherche précise.",
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


def _is_usable_model(model_id: str) -> bool:
    """True si le modèle est utilisable pour du text/chat (pas audio, guard, embed…)."""
    mid = model_id.lower()
    return not any(pat in mid for pat in _EXCLUDE_PATTERNS)


def _is_tpd_error(err_str: str) -> bool:
    return any(k in err_str for k in ("per day", "tokens per day", "TPD", "tokens_per_day"))


def _is_payload_too_large(err_str: str) -> bool:
    """413 ou contexte dépassé → le payload dépasse la limite du modèle."""
    lower = err_str.lower()
    return (
        "413" in err_str
        or "request too large" in lower
        or "request entity too large" in lower
        or "payload too large" in lower
        or "context_length_exceeded" in lower
        or "maximum context length" in lower
    )


def _trim_msgs_for_final_report(msgs: List[Any]) -> List[Any]:
    """
    Réduit la conversation avant le rapport final pour éviter le 413.
    Garde : système + premier message utilisateur (données OSINT) + dernières paires outil.
    """
    if len(msgs) <= 5:
        return msgs

    # Tête : messages initiaux avant les tool calls (system + user context)
    head: List[Any] = []
    for m in msgs:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", "")
        has_tc  = bool(m.get("tool_calls") if isinstance(m, dict) else getattr(m, "tool_calls", None))
        has_tid = bool(m.get("tool_call_id") if isinstance(m, dict) else getattr(m, "tool_call_id", None))
        if role in ("system", "user") and not has_tc and not has_tid:
            head.append(m)
        else:
            break

    rest = msgs[len(head):]
    if not rest:
        return msgs

    # Garde les 8 derniers messages d'échanges outil (≈ 2 paires complètes)
    tail = rest[-8:] if len(rest) > 8 else rest
    result = head + tail
    logger.info(
        "[groq] Conversation tronquée avant rapport final : %d → %d msgs",
        len(msgs), len(result),
    )
    return result


def _build_model_queue(api_client: Groq, preferred: str) -> List[str]:
    """
    Construit la file de modèles en interrogeant l'API Groq.
    Ordre : preferred → modèles prioritaires connus → reste des modèles disponibles.
    """
    try:
        available = {m.id for m in api_client.models.list().data if _is_usable_model(m.id)}
    except Exception as e:
        logger.warning("[groq] Impossible de récupérer la liste des modèles: %s", e)
        available = set(_KNOWN_TOOL_MODELS_PRIORITY)

    queue: List[str] = []

    # 1. Modèle préféré en tête
    if preferred in available:
        queue.append(preferred)

    # 2. Modèles prioritaires connus (dans l'ordre défini)
    for m in _KNOWN_TOOL_MODELS_PRIORITY:
        if m in available and m not in queue:
            queue.append(m)

    # 3. Tous les autres modèles disponibles (par ordre alphabétique)
    for m in sorted(available):
        if m not in queue:
            queue.append(m)

    logger.info("[groq] File de modèles (%d): %s", len(queue), queue)
    return queue


class GroqClient:
    """Client Groq avec boucle agentique (tool use) et rotation automatique de modèles."""

    def __init__(self, model: Optional[str] = None):
        self.model   = model or _DEFAULT_MODEL
        # max_retries=0 : on gère nous-mêmes les retries pour contrôler
        # le switch de modèle sur TPD. Sans ça, le SDK Groq attend 42s avant
        # de propager l'exception, rendant notre logique de fallback inefficace.
        self._client = Groq(api_key=os.getenv("GROQ_API_KEY"), max_retries=0)
        self._model_queue: List[str] = _build_model_queue(self._client, self.model)
        self._model_idx = 0
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _accumulate_usage(self, resp: Any) -> None:
        """Cumule les tokens consommés (mesure de coût/usage, voir CLAUDE.md)."""
        u = getattr(resp, "usage", None)
        if u is None:
            return
        self.usage["prompt_tokens"]     += getattr(u, "prompt_tokens", 0) or 0
        self.usage["completion_tokens"] += getattr(u, "completion_tokens", 0) or 0
        self.usage["total_tokens"]      += getattr(u, "total_tokens", 0) or 0

    def _current_model(self) -> str:
        if self._model_idx < len(self._model_queue):
            return self._model_queue[self._model_idx]
        return self.model

    def _switch_to_next_model(self) -> bool:
        """Passe au modèle suivant. Retourne True si un nouveau modèle est disponible."""
        self._model_idx += 1
        if self._model_idx < len(self._model_queue):
            logger.warning(
                "[groq] Quota TPD épuisé → switch [%d/%d]: %s",
                self._model_idx + 1, len(self._model_queue), self._current_model(),
            )
            return True
        logger.error("[groq] Tous les modèles Groq ont leur quota TPD épuisé (%d modèles tentés).",
                     len(self._model_queue))
        return False

    # ── Disponibilité ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        try:
            self._client.models.list()
            return True
        except Exception:
            return False

    def list_models(self) -> List[str]:
        return list(self._model_queue)

    def model_loaded(self) -> bool:
        return self.model in self._model_queue

    # ── Appel chat unique ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.1,
    ) -> Any:
        """
        Appel à l'API Groq avec gestion automatique des 429.
        - TPM → attente + retry même modèle (1 fois)
        - TPD → switch vers modèle suivant dans la file
        """
        while True:
            current = self._current_model()
            kwargs: Dict[str, Any] = {
                "model":       current,
                "messages":    messages,
                "temperature": temperature,
                "max_tokens":  4096 if not tools else 2048,
            }
            if tools:
                kwargs["tools"]       = tools
                kwargs["tool_choice"] = "auto"

            try:
                resp = self._client.chat.completions.create(**kwargs)
                self._accumulate_usage(resp)
                return resp.choices[0].message

            except Exception as e:
                err_str = str(e)

                if _is_payload_too_large(err_str):
                    # Payload trop grand → switch modèle (un autre peut avoir plus de contexte)
                    logger.warning("[groq] Payload trop grand sur %s — switch modèle", current)
                    if not self._switch_to_next_model():
                        raise RuntimeError("[groq] Tous les modèles dépassés (payload trop grand)") from e
                    # loop → retry avec nouveau modèle
                elif "429" not in err_str:
                    raise
                elif _is_tpd_error(err_str):
                    if not self._switch_to_next_model():
                        raise RuntimeError("[groq] Tous les modèles TPD épuisés") from e
                    # loop → retry avec nouveau modèle
                else:
                    # TPM : attente courte + un retry
                    logger.warning("[groq] TPM 429 sur %s — attente %.0fs", current, _TPM_SLEEP)
                    time.sleep(_TPM_SLEEP)
                    try:
                        resp = self._client.chat.completions.create(**kwargs)
                        self._accumulate_usage(resp)
                        return resp.choices[0].message
                    except Exception as e2:
                        err2 = str(e2)
                        if "429" in err2 and _is_tpd_error(err2):
                            if not self._switch_to_next_model():
                                raise RuntimeError("[groq] Tous les modèles TPD épuisés") from e2
                        else:
                            raise

    # ── Boucle agentique ─────────────────────────────────────────────────────

    def agentic_chat(
        self,
        messages: List[Dict],
        tool_handler: Callable[[str, Dict], str],
        max_rounds: int = _MAX_ROUNDS,
        temperature: float = 0.1,
    ) -> Tuple[Dict, List[Dict], List]:
        """
        Boucle agentique avec rotation automatique de modèles sur quota épuisé.

        Retourne : (message_final, searches_log, msgs_accumulés)
          - msgs_accumulés : conversation complète incluant tous les tool results
            → transmissible au backend suivant pour continuer sans perte
        """
        msgs: List[Any] = list(messages)
        searches_log: List[Dict] = []
        consecutive_errors = 0

        for round_num in range(max_rounds):
            logger.info("[groq] Tour %d/%d — modèle: %s", round_num + 1, max_rounds, self._current_model())

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[groq] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning("[groq] %d erreurs consécutives — abandon (conversation préservée: %d msgs)",
                                   consecutive_errors, len(msgs))
                    break
                continue

            tool_calls = msg.tool_calls or []

            if not tool_calls:
                logger.info("[groq] Réponse finale tour %d (%d chars)", round_num + 1, len(msg.content or ""))
                msgs.append({"role": "assistant", "content": msg.content or ""})
                return {"role": "assistant", "content": msg.content or ""}, searches_log, msgs

            if len(tool_calls) > _MAX_TOOL_CALLS_PER_ROUND:
                tool_calls = tool_calls[:_MAX_TOOL_CALLS_PER_ROUND]

            msgs.append({
                "role":       "assistant",
                "content":    msg.content or "",
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ],
            })

            for tc in tool_calls:
                tool_name = tc.function.name
                try:
                    tool_args = json.loads(tc.function.arguments)
                except Exception:
                    tool_args = {}

                logger.info("[groq] Tool call: %s(%s)", tool_name, tool_args)
                try:
                    result_str = tool_handler(tool_name, tool_args)
                except Exception as e:
                    result_str = json.dumps({"error": str(e)})

                if tool_name == "web_search":
                    try:
                        n = len(json.loads(result_str)) if result_str.startswith("[") else 0
                    except Exception:
                        n = 0
                    searches_log.append({"query": tool_args.get("query", ""), "results_count": n})

                if len(result_str) > _MAX_TOOL_RESULT_CHARS:
                    result_str = result_str[:_MAX_TOOL_RESULT_CHARS] + "…[tronqué]"

                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": result_str})

        # Max rounds atteint — demande rapport final
        logger.info("[groq] Max rounds atteint — rapport final (modèle: %s, %d recherches effectuées)",
                    self._current_model(), len(searches_log))

        # Tronquer la conversation avant le rapport final pour éviter les 413
        msgs_for_report = _trim_msgs_for_final_report(msgs)

        msgs_for_report.append({
            "role": "user",
            "content": (
                "Tu as collecté suffisamment d'informations. "
                "Produis maintenant le rapport JSON final en respectant exactement "
                "le schéma demandé. "
                "Réponds UNIQUEMENT avec le JSON valide, sans texte avant ou après."
            ),
        })
        try:
            msg = self.chat(msgs_for_report, tools=None, temperature=0.0)
            content = msg.content or ""
            msgs.append({"role": "assistant", "content": content})
            return {"role": "assistant", "content": content}, searches_log, msgs
        except Exception as e:
            logger.error(
                "[groq] Erreur rapport final: %s — conversation préservée (%d msgs, tronquée: %d)",
                e, len(msgs), len(msgs_for_report),
            )
            return {"role": "assistant", "content": ""}, searches_log, msgs
