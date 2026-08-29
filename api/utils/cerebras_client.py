# utils/cerebras_client.py
"""
Client Cerebras pour l'analyse IA agentique.

Cerebras est compatible avec l'interface OpenAI (base_url différente).
Avantages vs Groq :
  - Débit TPM très élevé (inférence sur wafers silicium dédié)
  - Quota TPD généreux (pas de problème de "per day" comme Groq)
  - Modèles : llama-3.3-70b, llama3.1-70b, llama3.1-8b, qwen-3-32b

Stratégie de fiabilité :
  1. File de modèles avec rotation automatique sur 429 / erreur
  2. 429 TPM → attente courte + retry même modèle
  3. 429 TPD ou quota → switch vers modèle suivant
  4. Tous les modèles épuisés → exception propagée (Groq prend le relai)
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import openai

logger = logging.getLogger(__name__)

_API_KEY               = os.getenv("CEREBRAS_API_KEY", "")
_BASE_URL              = "https://api.cerebras.ai/v1"
_DEFAULT_MODEL         = os.getenv("CEREBRAS_MODEL", "llama3.3-70b")
_MAX_ROUNDS            = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS = int(os.getenv("CEREBRAS_MAX_TOOL_RESULT_CHARS", "2500"))
_MAX_TOOL_CALLS_PER_ROUND = int(os.getenv("CEREBRAS_MAX_TOOL_CALLS_PER_ROUND", "3"))
_TPM_SLEEP             = float(os.getenv("CEREBRAS_TPM_SLEEP", "10"))

# Modèles Cerebras disponibles — ordre de préférence (IDs exacts de l'API Cerebras)
_MODEL_PRIORITY = [
    "llama3.3-70b",   # Meilleur — raisonnement + tool use
    "llama3.1-70b",   # Alternative stable
    "llama3.1-8b",    # Rapide, moins précis
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
    """Quota journalier épuisé (TPD) ou crédit insuffisant."""
    return any(k in err_str.lower() for k in (
        "per day", "tokens per day", "tpd", "tokens_per_day",
        "quota", "insufficient_quota", "exceeded",
    ))


def _is_model_unavailable(err_str: str) -> bool:
    """Modèle renommé/déprécié/inaccessible côté fournisseur (dérive d'API,
    pas un problème de notre config) — doit déclencher un switch de modèle
    plutôt que d'abandonner tout le backend Cerebras."""
    lower = err_str.lower()
    return (
        "404" in err_str
        or "not_found" in lower
        or "not found" in lower
        or "does not exist" in lower
        or "do not have access" in lower
    )


class CerebrasClient:
    """
    Client Cerebras avec boucle agentique (tool use) et rotation automatique de modèles.
    Interface identique à GroqClient pour permettre l'échange sans modifier analyze.py.
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
        """Construit la file : modèle préféré en tête, puis les autres."""
        queue: List[str] = []
        if preferred not in _MODEL_PRIORITY:
            queue.append(preferred)
        for m in _MODEL_PRIORITY:
            if m not in queue:
                queue.append(m)
        logger.info("[cerebras] File de modèles (%d): %s", len(queue), queue)
        return queue

    def _current_model(self) -> str:
        if self._model_idx < len(self._model_queue):
            return self._model_queue[self._model_idx]
        return self.model

    def _switch_to_next_model(self) -> bool:
        """Passe au modèle suivant. Retourne True si un nouveau modèle est disponible."""
        self._model_idx += 1
        if self._model_idx < len(self._model_queue):
            logger.warning(
                "[cerebras] Quota épuisé → switch [%d/%d]: %s",
                self._model_idx + 1, len(self._model_queue), self._current_model(),
            )
            return True
        logger.error("[cerebras] Tous les modèles Cerebras ont leur quota épuisé (%d tentés).",
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
        """
        Appel à l'API Cerebras avec gestion automatique des 429.
        - 429 TPM → attente + retry même modèle (1 fois)
        - 429 TPD / quota → switch vers modèle suivant
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
                if not _is_rate_limit(err_str):
                    if _is_model_unavailable(err_str):
                        logger.warning("[cerebras] Modèle %s indisponible (404/renommé) — switch modèle", current)
                        if not self._switch_to_next_model():
                            raise RuntimeError("[cerebras] Tous les modèles indisponibles") from e
                        continue
                    raise

                if _is_quota_exhausted(err_str):
                    if not self._switch_to_next_model():
                        raise RuntimeError("[cerebras] Tous les modèles quota épuisés") from e
                    # loop → retry avec nouveau modèle
                else:
                    # TPM / rate limit transitoire : attente courte + un retry
                    logger.warning("[cerebras] Rate limit sur %s — attente %.0fs", current, _TPM_SLEEP)
                    time.sleep(_TPM_SLEEP)
                    try:
                        resp = self._client.chat.completions.create(**kwargs)
                        self._accumulate_usage(resp)
                        return resp.choices[0].message
                    except Exception as e2:
                        err2 = str(e2)
                        if _is_rate_limit(err2) and _is_quota_exhausted(err2):
                            if not self._switch_to_next_model():
                                raise RuntimeError("[cerebras] Tous les modèles quota épuisés") from e2
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
            logger.info("[cerebras] Tour %d/%d — modèle: %s",
                        round_num + 1, max_rounds, self._current_model())

            try:
                msg = self.chat(msgs, tools=[WEB_SEARCH_TOOL], temperature=temperature)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                logger.error("[cerebras] Erreur tour %d: %s", round_num + 1, e)
                if consecutive_errors >= 2:
                    logger.warning(
                        "[cerebras] %d erreurs consécutives — abandon (conversation préservée: %d msgs)",
                        consecutive_errors, len(msgs),
                    )
                    break
                continue

            tool_calls = getattr(msg, "tool_calls", None) or []

            if not tool_calls:
                content = getattr(msg, "content", "") or ""
                logger.info("[cerebras] Réponse finale tour %d (%d chars)",
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

                logger.info("[cerebras] Tool call: %s(%s)", tool_name, tool_args)
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

        # Max rounds atteint — demande rapport final sans tool use
        logger.info("[cerebras] Max rounds atteint — rapport final (modèle: %s, %d recherches)",
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
            logger.error("[cerebras] Erreur rapport final: %s — conversation préservée (%d msgs)",
                         e, len(msgs))
            return {"role": "assistant", "content": ""}, searches_log, msgs
