# utils/openrouter_client.py
"""
Client OpenRouter pour l'analyse IA agentique.

Stratégie de fiabilité :
  1. Au démarrage → découverte dynamique de TOUS les modèles :free disponibles via l'API
  2. File de priorité : modèles capables et connus en tête, reste en queue
  3. 429 sur un modèle → attente courte, puis switch vers le suivant après N tentatives
  4. Tous les modèles épuisés → exception propagée
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import openai

logger = logging.getLogger(__name__)

_DEFAULT_MODEL         = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
_API_KEY               = os.getenv("OPENROUTER_API_KEY", "")
_BASE_URL              = "https://openrouter.ai/api/v1"
_MAX_ROUNDS            = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS = int(os.getenv("OPENROUTER_MAX_TOOL_RESULT_CHARS", "2500"))
_RATE_LIMIT_SLEEP      = float(os.getenv("OPENROUTER_RATE_LIMIT_SLEEP", "10"))
_MAX_429_BEFORE_SWITCH = int(os.getenv("OPENROUTER_MAX_429_BEFORE_SWITCH", "3"))

# Modèles free connus — ordre de préférence (qualité décroissante)
# Note : gemma (pas de tool use) et gpt-oss (restrictions privacy) exclus
_PRIORITY_FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nousresearch/hermes-3-llama-3.1-405b:free",
    "qwen/qwen3-coder:free",
    "moonshotai/kimi-k2-instruct",          # Groq aussi, mais dispo sur OR
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "minimax/minimax-m2.5:free",
    "z-ai/glm-4.5-air:free",
    "arcee-ai/trinity-large-preview:free",
]

# Modèles à exclure (trop petits, spécialisés vision/audio, ou sans tool use)
_EXCLUDE_PATTERNS = [
    "vision", "embed", "tts", "rerank", "guard", "whisper",
    "1.2b", "0.5b", "e2b",       # trop petits
    "nemotron",                   # modèle thinking → réponse de 3+ minutes
    "thinking", "reasoner",       # modèles de raisonnement lents
    "gemma",                      # Google Gemma : function calling désactivé sur OpenRouter
    "gpt-oss",                    # OpenAI gpt-oss : restrictions guardrail OpenRouter
]

WEB_SEARCH_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Recherche web en temps réel pour :\n"
            "- Vérifier les bonnes pratiques de sécurité actuelles\n"
            "- Confirmer CVE et vulnérabilités pour les technologies détectées\n"
            "- Valider les configurations (SPF, DKIM, DNSSEC, TLS, headers HTTP)\n"
            "- Rechercher des standards de référence (OWASP, RFC, CIS Benchmarks)"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Requête de recherche ciblée et précise",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Nombre de résultats (1-10, défaut: 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
    },
}


def _is_usable_model(model_id: str) -> bool:
    mid = model_id.lower()
    return not any(pat in mid for pat in _EXCLUDE_PATTERNS)


def _build_model_queue(client: openai.OpenAI, preferred: str) -> List[str]:
    """
    Construit la file de modèles :free disponibles via l'API OpenRouter.
    Ordre : preferred → priorités connues → reste des modèles free découverts.
    """
    available_free: set = set()
    try:
        resp = client.models.list()
        for m in resp.data:
            mid = m.id
            if ":free" in mid and _is_usable_model(mid):
                available_free.add(mid)
        logger.info("[openrouter] %d modèles :free découverts via API", len(available_free))
    except Exception as e:
        logger.warning("[openrouter] Impossible de récupérer la liste des modèles: %s", e)
        available_free = {m for m in _PRIORITY_FREE_MODELS if ":free" in m}

    queue: List[str] = []

    # 1. Modèle préféré en tête s'il est free et disponible
    if preferred in available_free:
        queue.append(preferred)
    elif preferred and ":free" not in preferred:
        # Modèle payant configuré → on le garde quand même en tête
        queue.append(preferred)

    # 2. Modèles prioritaires connus (dans l'ordre)
    for m in _PRIORITY_FREE_MODELS:
        if m in available_free and m not in queue:
            queue.append(m)

    # 3. Tous les autres modèles free découverts (ordre alphabétique)
    for m in sorted(available_free):
        if m not in queue:
            queue.append(m)

    logger.info("[openrouter] File de modèles (%d): %s", len(queue), queue[:5])
    return queue


class OpenRouterClient:
    """Client OpenRouter avec boucle agentique (tool use) et rotation automatique de modèles :free."""

    def __init__(self, model: Optional[str] = None):
        self.model = model or _DEFAULT_MODEL
        # max_retries=0 : on gère nous-mêmes les retries pour contrôler
        # le switch de modèle sur 429. Sans ça, le SDK OpenAI retente 2x
        # (~0.5s, ~1s) avant de propager, masquant le 429 à notre code.
        self._client = openai.OpenAI(api_key=_API_KEY, base_url=_BASE_URL, max_retries=0)
        self._model_queue: List[str] = _build_model_queue(self._client, self.model)
        self._model_idx  = 0
        self._429_streak = 0
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
        """Passe au modèle suivant. Retourne True si disponible."""
        self._model_idx  += 1
        self._429_streak  = 0
        if self._model_idx < len(self._model_queue):
            logger.warning(
                "[openrouter] Trop de 429 → switch [%d/%d]: %s",
                self._model_idx + 1, len(self._model_queue), self._current_model(),
            )
            return True
        logger.error("[openrouter] Tous les %d modèles sont rate-limités.", len(self._model_queue))
        return False

    # ── Disponibilité ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        return bool(_API_KEY) and len(self._model_queue) > 0

    def list_models(self) -> List[str]:
        return list(self._model_queue)

    def model_loaded(self) -> bool:
        return bool(_API_KEY)

    # ── Appel chat unique avec rotation ──────────────────────────────────────

    def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.1,
    ) -> Any:
        """
        Appel à l'API OpenRouter avec gestion automatique des 429.
        Après _MAX_429_BEFORE_SWITCH tentatives → switch vers modèle suivant.
        """
        while True:
            current = self._current_model()
            kwargs: Dict[str, Any] = {
                "model":       current,
                "messages":    messages,
                "temperature": temperature,
                "max_tokens":  int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "8192")),
            }
            if tools:
                kwargs["tools"]       = tools
                kwargs["tool_choice"] = "auto"

            try:
                resp = self._client.chat.completions.create(**kwargs)
                self._429_streak = 0
                self._accumulate_usage(resp)
                return resp.choices[0].message

            except Exception as e:
                err_str = str(e)

                # Erreurs qui nécessitent un switch immédiat (sans retry)
                _switch_immediately = (
                    "function calling" in err_str.lower()
                    or "tool" in err_str.lower() and "not" in err_str.lower()
                    or "no endpoints available" in err_str.lower()
                    or "guardrail" in err_str.lower()
                )
                if _switch_immediately:
                    logger.warning(
                        "[openrouter] Modèle %s incompatible (tool use / guardrail) — switch immédiat",
                        current,
                    )
                    if not self._switch_to_next_model():
                        raise RuntimeError("[openrouter] Tous les modèles sont incompatibles") from e
                    # loop → réessaie avec nouveau modèle
                elif "429" not in err_str:
                    raise
                else:
                    self._429_streak += 1
                    logger.warning(
                        "[openrouter] 429 sur %-45s (tentative %d/%d) — attente %.0fs",
                        current, self._429_streak, _MAX_429_BEFORE_SWITCH, _RATE_LIMIT_SLEEP,
                    )
                    time.sleep(_RATE_LIMIT_SLEEP)

                    if self._429_streak >= _MAX_429_BEFORE_SWITCH:
                        if not self._switch_to_next_model():
                            raise RuntimeError(
                                "[openrouter] Tous les modèles free sont épuisés"
                            ) from e
                        # loop → réessaie avec nouveau modèle

    # ── Boucle agentique ─────────────────────────────────────────────────────

    def agentic_chat(
        self,
        messages: List[Dict],
        tool_handler: Callable[[str, Dict], str],
        max_rounds: int = _MAX_ROUNDS,
        temperature: float = 0.1,
    ) -> Tuple[Dict, List[Dict], List]:
        """
        Boucle agentique avec rotation automatique de modèles sur 429.

        Retourne : (message_final, searches_log, msgs_accumulés)
          - msgs_accumulés : conversation complète, transmissible au backend suivant
        """
        msgs: List[Any] = list(messages)
        searches_log: List[Dict] = []
        consecutive_errors = 0

        for round_num in range(max_rounds):
            logger.info("[openrouter] Tour %d/%d — modèle: %s",
                        round_num + 1, max_rounds, self._current_model())

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[openrouter] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning("[openrouter] %d erreurs consécutives — abandon (conversation préservée: %d msgs)",
                                   consecutive_errors, len(msgs))
                    break
                continue

            tool_calls = msg.tool_calls or []

            if not tool_calls:
                logger.info("[openrouter] Réponse finale tour %d (%d chars)",
                            round_num + 1, len(msg.content or ""))
                msgs.append({"role": "assistant", "content": msg.content or ""})
                return {"role": "assistant", "content": msg.content or ""}, searches_log, msgs

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

                logger.info("[openrouter] Tool call: %s(%s)", tool_name, tool_args)
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

        # Max rounds atteint
        logger.info("[openrouter] Max rounds atteint — rapport final (modèle: %s, %d recherches)",
                    self._current_model(), len(searches_log))
        msgs.append({
            "role": "user",
            "content": (
                "/no_think\n\n"
                "Tu as collecté suffisamment d'informations. "
                "Produis maintenant le rapport JSON final en respectant exactement "
                "le schéma demandé. "
                "Réponds UNIQUEMENT avec le JSON valide, sans texte avant ou après."
            ),
        })
        try:
            msg = self.chat(msgs, tools=None, temperature=0.0)
            content = msg.content or ""
            msgs.append({"role": "assistant", "content": content})
            return {"role": "assistant", "content": content}, searches_log, msgs
        except Exception as e:
            logger.error("[openrouter] Erreur rapport final: %s — conversation préservée (%d msgs)", e, len(msgs))
            return {"role": "assistant", "content": ""}, searches_log, msgs
