# utils/gemini_client.py
"""
Client Google Gemini pour l'analyse IA agentique.

Gemini expose une interface compatible OpenAI (via Google AI Studio).
Base URL : https://generativelanguage.googleapis.com/v1beta/openai/

Avantages :
  - Fenêtre de contexte très large (1 M tokens sur Gemini 1.5 Pro)
  - Quota généreux sur le plan gratuit (1 500 req/jour sur Flash)
  - Excellent support du tool use (function calling natif)
  - Modèles : gemini-2.5-pro, gemini-2.0-flash, gemini-1.5-flash

Stratégie de fiabilité :
  1. File de modèles avec rotation automatique sur 429 / quota
  2. 429 transitoire → attente courte + retry même modèle (1 fois)
  3. Quota épuisé (RESOURCE_EXHAUSTED) → switch modèle suivant
  4. Payload trop grand → switch modèle suivant
  5. Tous les modèles épuisés → exception propagée (backend suivant prend le relai)
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import openai

logger = logging.getLogger(__name__)

_API_KEY               = os.getenv("GEMINI_API_KEY", "")
_BASE_URL              = "https://generativelanguage.googleapis.com/v1beta/openai/"
_DEFAULT_MODEL         = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
_MAX_ROUNDS            = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS = int(os.getenv("GEMINI_MAX_TOOL_RESULT_CHARS", "3000"))
_MAX_TOOL_CALLS_PER_ROUND = int(os.getenv("GEMINI_MAX_TOOL_CALLS_PER_ROUND", "3"))
_TPM_SLEEP             = float(os.getenv("GEMINI_TPM_SLEEP", "15"))

# Modèles Gemini disponibles — ordre de préférence
# Tous supportent le function calling (tool use)
_MODEL_PRIORITY = [
    "gemini-2.5-pro-preview-05-06",  # Meilleur raisonnement, contexte 1M
    "gemini-2.0-flash",              # Rapide, 1 500 req/jour gratuit
    "gemini-1.5-pro",                # Contexte 1M tokens, bon raisonnement
    "gemini-1.5-flash",              # Fallback léger
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


def _is_rate_limit(err_str: str) -> bool:
    lower = err_str.lower()
    return (
        "429" in err_str
        or "rate_limit" in lower
        or "rate limit" in lower
        or "resource_exhausted" in lower
        or "quota_exceeded" in lower
    )


def _is_quota_exhausted(err_str: str) -> bool:
    """Quota journalier épuisé ou crédit insuffisant."""
    lower = err_str.lower()
    return any(k in lower for k in (
        "resource_exhausted", "quota_exceeded", "quota", "per day",
        "daily limit", "insufficient_quota", "billing",
    ))


def _is_payload_too_large(err_str: str) -> bool:
    lower = err_str.lower()
    return (
        "413" in err_str
        or "request too large" in lower
        or "context_length_exceeded" in lower
        or "maximum context" in lower
        or "too many tokens" in lower
        or "input_too_long" in lower
    )


def _is_model_unavailable(err_str: str) -> bool:
    """Modèle renommé/déprécié/inaccessible côté fournisseur (dérive d'API,
    pas un problème de notre config) — doit déclencher un switch de modèle
    plutôt que d'abandonner tout le backend Gemini."""
    lower = err_str.lower()
    return (
        "404" in err_str
        or "not_found" in lower
        or "not found" in lower
        or "does not exist" in lower
        or "not supported for" in lower
    )


def _trim_msgs_for_final_report(msgs: List[Any]) -> List[Any]:
    """Réduit la conversation avant le rapport final pour éviter les erreurs de contexte."""
    if len(msgs) <= 5:
        return msgs
    head: List[Any] = []
    for m in msgs:
        role   = m.get("role") if isinstance(m, dict) else getattr(m, "role", "")
        has_tc = bool(m.get("tool_calls") if isinstance(m, dict) else getattr(m, "tool_calls", None))
        has_tid = bool(m.get("tool_call_id") if isinstance(m, dict) else getattr(m, "tool_call_id", None))
        if role in ("system", "user") and not has_tc and not has_tid:
            head.append(m)
        else:
            break
    rest = msgs[len(head):]
    tail = rest[-8:] if len(rest) > 8 else rest
    result = head + tail
    logger.info("[gemini] Conversation tronquée avant rapport final : %d → %d msgs", len(msgs), len(result))
    return result


class GeminiClient:
    """
    Client Google Gemini avec boucle agentique (tool use) et rotation automatique de modèles.
    Interface identique aux autres clients (CerebrasClient, GroqClient, OpenRouterClient).
    """

    def __init__(self, model: Optional[str] = None):
        self.model = model or _DEFAULT_MODEL
        self._client = openai.OpenAI(
            api_key=_API_KEY,
            base_url=_BASE_URL,
        )
        self._model_queue = self._build_model_queue(self.model)
        self._model_idx   = 0
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _accumulate_usage(self, resp: Any) -> None:
        """Cumule les tokens consommés (mesure de coût/usage, voir CLAUDE.md)."""
        u = getattr(resp, "usage", None)
        if u is None:
            return
        self.usage["prompt_tokens"]     += getattr(u, "prompt_tokens", 0) or 0
        self.usage["completion_tokens"] += getattr(u, "completion_tokens", 0) or 0
        self.usage["total_tokens"]      += getattr(u, "total_tokens", 0) or 0

    def _build_model_queue(self, preferred: str) -> List[str]:
        queue: List[str] = []
        if preferred not in _MODEL_PRIORITY:
            queue.append(preferred)
        for m in _MODEL_PRIORITY:
            if m not in queue:
                queue.append(m)
        logger.info("[gemini] File de modèles (%d): %s", len(queue), queue)
        return queue

    def _current_model(self) -> str:
        if self._model_idx < len(self._model_queue):
            return self._model_queue[self._model_idx]
        return self.model

    def _switch_to_next_model(self) -> bool:
        self._model_idx += 1
        if self._model_idx < len(self._model_queue):
            logger.warning(
                "[gemini] Quota/erreur → switch [%d/%d]: %s",
                self._model_idx + 1, len(self._model_queue), self._current_model(),
            )
            return True
        logger.error("[gemini] Tous les modèles Gemini épuisés (%d tentés).", len(self._model_queue))
        return False

    # ── Disponibilité ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        return bool(_API_KEY)

    def list_models(self) -> List[str]:
        return list(self._model_queue)

    def model_loaded(self) -> bool:
        return bool(self._model_queue)

    # ── Appel chat unique ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.1,
    ) -> Any:
        """
        Appel à l'API Gemini avec gestion automatique des erreurs.
        - 429 / RESOURCE_EXHAUSTED → switch modèle
        - Payload trop grand → switch modèle
        - Rate limit transitoire → attente + retry (1 fois)
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
                    logger.warning("[gemini] Payload trop grand sur %s — switch modèle", current)
                    if not self._switch_to_next_model():
                        raise RuntimeError("[gemini] Tous les modèles dépassés (payload)") from e

                elif _is_rate_limit(err_str):
                    if _is_quota_exhausted(err_str):
                        if not self._switch_to_next_model():
                            raise RuntimeError("[gemini] Tous les modèles quota épuisés") from e
                    else:
                        # Rate limit transitoire → attente courte + un retry
                        logger.warning("[gemini] Rate limit sur %s — attente %.0fs", current, _TPM_SLEEP)
                        time.sleep(_TPM_SLEEP)
                        try:
                            resp = self._client.chat.completions.create(**kwargs)
                            self._accumulate_usage(resp)
                            return resp.choices[0].message
                        except Exception as e2:
                            err2 = str(e2)
                            if _is_rate_limit(err2):
                                if not self._switch_to_next_model():
                                    raise RuntimeError("[gemini] Tous les modèles quota épuisés") from e2
                            else:
                                raise

                elif _is_model_unavailable(err_str):
                    logger.warning("[gemini] Modèle %s indisponible (404/renommé) — switch modèle", current)
                    if not self._switch_to_next_model():
                        raise RuntimeError("[gemini] Tous les modèles indisponibles") from e

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
          - msgs_accumulés : conversation complète transmissible au backend suivant
        """
        msgs: List[Any] = list(messages)
        searches_log: List[Dict] = []
        consecutive_errors = 0

        for round_num in range(max_rounds):
            logger.info("[gemini] Tour %d/%d — modèle: %s",
                        round_num + 1, max_rounds, self._current_model())

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[gemini] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning(
                        "[gemini] %d erreurs consécutives — abandon (conversation préservée: %d msgs)",
                        consecutive_errors, len(msgs),
                    )
                    break
                continue

            tool_calls = getattr(msg, "tool_calls", None) or []

            if not tool_calls:
                content = getattr(msg, "content", "") or ""
                logger.info("[gemini] Réponse finale tour %d (%d chars)", round_num + 1, len(content))
                msgs.append({"role": "assistant", "content": content})
                return {"role": "assistant", "content": content}, searches_log, msgs

            if len(tool_calls) > _MAX_TOOL_CALLS_PER_ROUND:
                tool_calls = tool_calls[:_MAX_TOOL_CALLS_PER_ROUND]

            msgs.append({
                "role":       "assistant",
                "content":    getattr(msg, "content", "") or "",
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

                logger.info("[gemini] Tool call: %s(%s)", tool_name, tool_args)
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

        # Max rounds atteint — rapport final
        logger.info("[gemini] Max rounds atteint — rapport final (modèle: %s, %d recherches)",
                    self._current_model(), len(searches_log))

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
            content = getattr(msg, "content", "") or ""
            msgs.append({"role": "assistant", "content": content})
            return {"role": "assistant", "content": content}, searches_log, msgs
        except Exception as e:
            logger.error(
                "[gemini] Erreur rapport final: %s — conversation préservée (%d msgs)",
                e, len(msgs),
            )
            return {"role": "assistant", "content": ""}, searches_log, msgs
