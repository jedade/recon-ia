# utils/deepseek_client.py
"""
Client DeepSeek pour l'analyse IA agentique.

DeepSeek expose une API compatible OpenAI (base_url différente), comme
Cerebras/OpenRouter/Gemini — même SDK `openai` réutilisé. Contrairement aux
autres backends cloud du projet, DeepSeek est **payant à l'usage** (pas de
quota gratuit journalier) : ajouté en slot 1 (avant Gemini) à la demande
explicite de l'utilisateur, pour test, pas parce qu'il serait gratuit comme
les autres.

Seul `deepseek-chat` (DeepSeek-V3) supporte le function calling (`tools`)
qu'exige l'architecture agentique de ce projet (web_search) — `deepseek-reasoner`
(R1, mode réflexion) ne le supporte pas et n'est donc pas dans la file de
modèles par défaut.

Stratégie de fiabilité : identique à CerebrasClient (interface interchangeable
avec les autres clients, aucune modification de analyze.py nécessaire au-delà
du branchement du nouveau slot).
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import openai

logger = logging.getLogger(__name__)

# Plafond de sortie : la réponse JSON contient findings ET tool_reviews.
_MAX_OUT       = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "8192"))
_MAX_OUT_TOOLS = int(os.getenv("LLM_MAX_OUTPUT_TOKENS_WITH_TOOLS", "4096"))

_API_KEY               = os.getenv("DEEPSEEK_API_KEY", "")
_BASE_URL              = "https://api.deepseek.com"
_DEFAULT_MODEL         = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
_MAX_ROUNDS            = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS = int(os.getenv("DEEPSEEK_MAX_TOOL_RESULT_CHARS", "2500"))
_MAX_TOOL_CALLS_PER_ROUND = int(os.getenv("DEEPSEEK_MAX_TOOL_CALLS_PER_ROUND", "3"))
_TPM_SLEEP             = float(os.getenv("DEEPSEEK_TPM_SLEEP", "10"))

# Un seul modèle par défaut : deepseek-reasoner ne supporte pas `tools`.
_MODEL_PRIORITY = [
    "deepseek-chat",
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
    return "429" in err_str or "rate_limit" in err_str.lower() or "rate limit" in err_str.lower()


def _is_quota_exhausted(err_str: str) -> bool:
    """Quota épuisé ou crédit insuffisant (compte payant à sec)."""
    return any(k in err_str.lower() for k in (
        "insufficient_quota", "insufficient balance", "quota", "exceeded",
    ))


def _is_model_unavailable(err_str: str) -> bool:
    """Modèle renommé/déprécié/inaccessible côté fournisseur — doit déclencher
    un switch de modèle plutôt que d'abandonner tout le backend DeepSeek."""
    lower = err_str.lower()
    return (
        "404" in err_str
        or "not_found" in lower
        or "not found" in lower
        or "does not exist" in lower
        or "do not have access" in lower
    )


class DeepSeekClient:
    """
    Client DeepSeek avec boucle agentique (tool use).
    Interface identique à CerebrasClient/GroqClient pour permettre l'échange
    sans modifier analyze.py.
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
        logger.info("[deepseek] File de modèles (%d): %s", len(queue), queue)
        return queue

    def _current_model(self) -> str:
        if self._model_idx < len(self._model_queue):
            return self._model_queue[self._model_idx]
        return self.model

    def _switch_to_next_model(self) -> bool:
        self._model_idx += 1
        if self._model_idx < len(self._model_queue):
            logger.warning(
                "[deepseek] Quota épuisé → switch [%d/%d]: %s",
                self._model_idx + 1, len(self._model_queue), self._current_model(),
            )
            return True
        logger.error("[deepseek] Tous les modèles DeepSeek ont leur quota épuisé (%d tentés).",
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
        return bool(self._model_queue)

    # ── Appel chat unique ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.1,
    ) -> Any:
        while True:
            current = self._current_model()
            kwargs: Dict[str, Any] = {
                "model":       current,
                "messages":    messages,
                "temperature": temperature,
                # Réponse finale : findings + tool_reviews (un avis par outil, ~40 outils)
                "max_tokens":  _MAX_OUT if not tools else _MAX_OUT_TOOLS,
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
                if not _is_rate_limit(err_str):
                    if _is_model_unavailable(err_str):
                        logger.warning("[deepseek] Modèle %s indisponible (404/renommé) — switch modèle", current)
                        if not self._switch_to_next_model():
                            raise RuntimeError("[deepseek] Tous les modèles indisponibles") from e
                        continue
                    raise

                if _is_quota_exhausted(err_str):
                    if not self._switch_to_next_model():
                        raise RuntimeError("[deepseek] Tous les modèles quota épuisés") from e
                else:
                    logger.warning("[deepseek] Rate limit sur %s — attente %.0fs", current, _TPM_SLEEP)
                    time.sleep(_TPM_SLEEP)
                    try:
                        resp = self._client.chat.completions.create(**kwargs)
                        self._accumulate_usage(resp)
                        return resp.choices[0].message
                    except Exception as e2:
                        err2 = str(e2)
                        if _is_rate_limit(err2) and _is_quota_exhausted(err2):
                            if not self._switch_to_next_model():
                                raise RuntimeError("[deepseek] Tous les modèles quota épuisés") from e2
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
        msgs: List[Any] = list(messages)
        searches_log: List[Dict] = []
        consecutive_errors = 0

        for round_num in range(max_rounds):
            logger.info("[deepseek] Tour %d/%d — modèle: %s",
                        round_num + 1, max_rounds, self._current_model())

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[deepseek] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning(
                        "[deepseek] %d erreurs consécutives — abandon (conversation préservée: %d msgs)",
                        consecutive_errors, len(msgs),
                    )
                    break
                continue

            tool_calls = getattr(msg, "tool_calls", None) or []

            if not tool_calls:
                content = getattr(msg, "content", "") or ""
                logger.info("[deepseek] Réponse finale tour %d (%d chars)",
                            round_num + 1, len(content))
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

                logger.info("[deepseek] Tool call: %s(%s)", tool_name, tool_args)
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

        logger.info("[deepseek] Max rounds atteint — rapport final (modèle: %s, %d recherches)",
                    self._current_model(), len(searches_log))
        msgs.append({
            "role": "user",
            "content": (
                "Tu as collecté suffisamment d'informations. "
                "Produis maintenant le rapport JSON final en respectant exactement "
                "le schéma demandé. "
                "Réponds UNIQUEMENT avec le JSON valide, sans texte avant ou après."
            ),
        })
        try:
            msg = self.chat(msgs, tools=None, temperature=0.0)
            content = getattr(msg, "content", "") or ""
            msgs.append({"role": "assistant", "content": content})
            return {"role": "assistant", "content": content}, searches_log, msgs
        except Exception as e:
            logger.error("[deepseek] Erreur rapport final: %s — conversation préservée (%d msgs)",
                         e, len(msgs))
            return {"role": "assistant", "content": ""}, searches_log, msgs
