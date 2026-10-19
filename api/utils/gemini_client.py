# utils/gemini_client.py
"""
Client Google Gemini pour l'analyse IA agentique.

Gemini expose une interface compatible OpenAI (via Google AI Studio).
Base URL : https://generativelanguage.googleapis.com/v1beta/openai/

Avantages :
  - Fenêtre de contexte très large (1 M tokens sur Gemini 1.5 Pro)
  - Quota généreux sur le plan gratuit (1 500 req/jour sur Flash)
  - Excellent support du tool use (function calling natif)
  - Modèles : liste lue au démarrage sur l'API (ceux que la clé propose
    réellement), alias « gemini-flash-latest » par défaut. Google retire
    régulièrement des versions (gemini-2.0-flash : 404 en 2026) : une liste
    figée finit toujours par ne plus contenir aucun modèle valide.

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
import requests

logger = logging.getLogger(__name__)

# Plafond de sortie : la réponse JSON contient findings ET tool_reviews.
_MAX_OUT       = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "8192"))
_MAX_OUT_TOOLS = int(os.getenv("LLM_MAX_OUTPUT_TOKENS_WITH_TOOLS", "4096"))

_API_KEY               = os.getenv("GEMINI_API_KEY", "")
_BASE_URL              = "https://generativelanguage.googleapis.com/v1beta/openai/"
# Alias tenu à jour par Google : survit au retrait des versions numérotées
_DEFAULT_MODEL         = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
_MAX_ROUNDS            = int(os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", "6"))
_MAX_TOOL_RESULT_CHARS = int(os.getenv("GEMINI_MAX_TOOL_RESULT_CHARS", "3000"))
_MAX_TOOL_CALLS_PER_ROUND = int(os.getenv("GEMINI_MAX_TOOL_CALLS_PER_ROUND", "3"))
_TPM_SLEEP             = float(os.getenv("GEMINI_TPM_SLEEP", "15"))

# Modèles Gemini disponibles — ordre de préférence
# Tous supportent le function calling (tool use)
# Ordre de préférence parmi les modèles réellement proposés par l'API ;
# sert aussi de repli si la liste ne peut pas être lue.
_MODEL_PRIORITY = [
    "gemini-flash-latest",           # Alias Flash courant (rapide, quota gratuit généreux)
    "gemini-pro-latest",             # Alias Pro courant (meilleur raisonnement)
]
# Repli léger, placé après les versions numérotées
_LAST_RESORT = ["gemini-flash-lite-latest"]
# Utilisé seulement si la liste de l'API est illisible
_OFFLINE_QUEUE = _MODEL_PRIORITY + ["gemini-2.5-flash", "gemini-2.5-pro"] + _LAST_RESORT
# Modèles sans intérêt pour l'analyse texte + function calling
_EXCLUDE_MODEL_PATTERNS = ("tts", "image", "embedding", "aqa", "live", "audio",
                           "vision", "banana", "imagen", "veo", "gemma", "robotics",
                           "computer-use", "customtools", "learnlm", "transcribe", "omni")
_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def _available_models() -> List[str]:
    """
    Modèles texte proposés par la clé (generateContent), ou [] si la liste
    est illisible (réseau, clé invalide) — l'appelant se rabat alors sur
    _MODEL_PRIORITY.
    """
    if not _API_KEY:
        return []
    try:
        r = requests.get(_MODELS_URL, headers={"x-goog-api-key": _API_KEY},
                         params={"pageSize": 200}, timeout=10)
        r.raise_for_status()
        out = []
        for m in r.json().get("models", []):
            name = str(m.get("name", "")).split("/")[-1]
            if ("generateContent" in (m.get("supportedGenerationMethods") or [])
                    and name.startswith("gemini")
                    and not any(p in name for p in _EXCLUDE_MODEL_PATTERNS)):
                out.append(name)
        return out
    except Exception as e:
        logger.warning("[gemini] Liste des modèles indisponible (%s) — file par défaut", e)
        return []

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


def _is_overloaded(err_str: str) -> bool:
    """Modèle saturé côté Google (503 UNAVAILABLE, « high demand »), constaté
    sur gemini-flash-latest : passer au modèle suivant plutôt que d'abandonner
    Gemini — un autre modèle de la file répond en général."""
    lower = err_str.lower()
    return "503" in err_str or "unavailable" in lower or "high demand" in lower or "overloaded" in lower


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


# Modèles écartés temporairement (partagé entre analyses, par processus) :
# un modèle refusé n'est pas réessayé en tête de file à chaque analyse.
_COOLDOWN: Dict[str, float] = {}
_COOLDOWN_S = {"missing": 24 * 3600, "quota": 3600, "overloaded": 300}


def _penalize(model: str, reason: str) -> None:
    _COOLDOWN[model] = time.time() + _COOLDOWN_S.get(reason, 300)


def _cooled_last(queue: List[str]) -> List[str]:
    """Modèles en période d'écart renvoyés en fin de file (ordre conservé)."""
    now = time.time()
    fresh = [m for m in queue if _COOLDOWN.get(m, 0) <= now]
    return fresh + [m for m in queue if m not in fresh]


def _version_key(name: str):
    """Clé de tri : gemini-3.6-flash > gemini-3.5-flash > gemini-2.5-pro…"""
    import re as _re
    nums = [int(x) for x in _re.findall(r"\d+", name)[:2]]
    return (nums + [0, 0])[:2] + [0 if "lite" in name else 1]


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
        """
        File : modèle préféré (s'il existe), préférences connues disponibles,
        puis les autres Flash/Pro stables, versions récentes d'abord.
        """
        available = _available_models()
        if not available:
            queue = [preferred] + [m for m in _OFFLINE_QUEUE if m != preferred]
            logger.info("[gemini] File de modèles (repli, %d): %s", len(queue), queue)
            return queue
        queue: List[str] = []
        if preferred in available:
            queue.append(preferred)
        elif preferred:
            logger.warning("[gemini] Modèle %s non proposé par l'API — ignoré", preferred)
        for m in _MODEL_PRIORITY:
            if m in available and m not in queue:
                queue.append(m)
        # Autres modèles stables (hors preview), plus récents d'abord
        extras = sorted((m for m in available if m not in queue and m not in _LAST_RESORT
                         and "preview" not in m and "latest" not in m),
                        key=_version_key, reverse=True)
        queue.extend(extras[:6])
        queue.extend(m for m in _LAST_RESORT if m in available and m not in queue)
        queue = _cooled_last(queue)
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

                if _is_payload_too_large(err_str):
                    pass   # dépend de la requête, pas du modèle : pas d'écart
                    logger.warning("[gemini] Payload trop grand sur %s — switch modèle", current)
                    if not self._switch_to_next_model():
                        raise RuntimeError("[gemini] Tous les modèles dépassés (payload)") from e

                elif _is_rate_limit(err_str):
                    if _is_quota_exhausted(err_str):
                        _penalize(current, "quota")
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
                    _penalize(current, "missing")
                    if not self._switch_to_next_model():
                        raise RuntimeError("[gemini] Tous les modèles indisponibles") from e

                elif _is_overloaded(err_str):
                    logger.warning("[gemini] Modèle %s saturé (503) — switch modèle", current)
                    _penalize(current, "overloaded")
                    if not self._switch_to_next_model():
                        raise RuntimeError("[gemini] Tous les modèles saturés") from e

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
