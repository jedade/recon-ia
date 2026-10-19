# utils/agent_llm.py
"""
Adaptateur LLM minimal et autonome pour la boucle agent (phase 8).

Seul besoin de la boucle : un appel « chat + function calling » au format
OpenAI (`/chat/completions` avec `tools`). Les trois backends retenus parlent
ce format :

  gemini    https://generativelanguage.googleapis.com/v1beta/openai/
  deepseek  https://api.deepseek.com
  ollama    {OLLAMA_URL}/v1   (uniquement un modèle ≥ 7B déclaré)

Ce module ne réutilise PAS les clients d'analyse (`utils/*_client.py`) : ils
portent une logique propre à l'analyse (rotation de modèles, web_search,
rapport final) et appartiennent à un autre périmètre. On ne lit que les mêmes
variables d'environnement qu'eux (GEMINI_API_KEY, GEMINI_MODEL,
DEEPSEEK_API_KEY, DEEPSEEK_CONFIRM_EXTERNAL_SHARING, DEEPSEEK_MODEL,
OLLAMA_URL), au moment de l'appel — jamais figées à l'import, pour que les
tests puissent les faire varier.

Pourquoi pas qwen3:1.7b : un modèle de cette taille ne suit pas un protocole
de tool calls de façon fiable (arguments inventés, boucles). Ollama n'est donc
accepté que si AGENT_OLLAMA_MODEL désigne explicitement un modèle dont la
taille, lue dans son tag (« qwen2.5:7b », « llama3.1:8b-instruct »), atteint
AGENT_OLLAMA_MIN_PARAMS_B (7 par défaut). Sans backend capable, la boucle est
désactivée (statut `skipped`) et le flux classique continue.

Sécurité : les URL des backends sont fixes ou viennent de la configuration de
l'opérateur, jamais d'une donnée de scan. Les clés ne sont jamais journalisées
ni recopiées dans un message d'erreur (`_scrub`).
"""
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

# Taille maximale acceptée d'une réponse de backend (protège la mémoire)
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
# Nombre maximal de tool calls lus dans UNE réponse (le reste est ignoré)
MAX_TOOL_CALLS_PARSED = 16
# Taille maximale de la chaîne d'arguments d'un tool call
MAX_ARGUMENTS_CHARS = 4000

_SIZE_RE = re.compile(r'(?<![0-9.])(\d+(?:\.\d+)?)\s*b(?![a-z])', re.IGNORECASE)


class AgentLLMError(Exception):
    """Échec d'un appel au backend (réseau, HTTP, réponse invalide)."""


@dataclass
class ToolCall:
    """Un tool call demandé par le LLM, arguments déjà décodés si possible."""
    id: str
    name: str
    arguments: Optional[dict]          # None si le JSON est invalide
    raw_arguments: str = ""
    parse_error: Optional[str] = None


@dataclass
class AgentReply:
    content: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    # Message assistant à réinjecter tel quel dans l'historique (format OpenAI)
    assistant_message: Dict[str, Any] = field(default_factory=dict)


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on", "oui")


def _scrub(text: str, secrets: List[str]) -> str:
    """Retire toute clé d'API d'un message (erreur HTTP, exception)."""
    text = str(text or "")
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")
    return text[:300]


# ── Parsing des tool calls ────────────────────────────────────────────────────

def parse_tool_calls(message: Any) -> List[ToolCall]:
    """
    Extrait les tool calls d'un message assistant au format OpenAI.

    Tolérant : un élément malformé est ignoré, des arguments JSON invalides
    donnent `arguments=None` + `parse_error` (la boucle journalise un refus).
    Ne lève jamais.
    """
    if not isinstance(message, dict):
        return []
    raw_calls = message.get("tool_calls")
    if not isinstance(raw_calls, list):
        return []
    calls: List[ToolCall] = []
    for index, item in enumerate(raw_calls[:MAX_TOOL_CALLS_PARSED]):
        if not isinstance(item, dict):
            continue
        fn = item.get("function")
        if not isinstance(fn, dict):
            continue
        name = fn.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        call_id = item.get("id")
        if not isinstance(call_id, str) or not call_id:
            call_id = f"call_{index}"
        raw_args = fn.get("arguments")
        arguments: Optional[dict] = None
        parse_error = None
        if isinstance(raw_args, dict):
            arguments = raw_args
            raw_text = json.dumps(raw_args, ensure_ascii=False)[:MAX_ARGUMENTS_CHARS]
        elif isinstance(raw_args, str):
            raw_text = raw_args[:MAX_ARGUMENTS_CHARS]
            if len(raw_args) > MAX_ARGUMENTS_CHARS:
                parse_error = "arguments trop longs"
            else:
                try:
                    decoded = json.loads(raw_args) if raw_args.strip() else {}
                    if isinstance(decoded, dict):
                        arguments = decoded
                    else:
                        parse_error = "arguments non objet JSON"
                except (ValueError, TypeError):
                    parse_error = "arguments JSON invalides"
        elif raw_args is None:
            arguments, raw_text = {}, ""
        else:
            raw_text, parse_error = "", "arguments de type inattendu"
        # Nom conservé tel quel (pas de strip ni de casse) : la liste blanche
        # exige une correspondance exacte.
        calls.append(ToolCall(id=call_id[:64], name=name[:64], arguments=arguments,
                              raw_arguments=raw_text, parse_error=parse_error))
    return calls


# ── Backend OpenAI-compatible ─────────────────────────────────────────────────

class OpenAICompatBackend:
    """Appel `/chat/completions` avec tools, via `requests` (aucun SDK)."""

    def __init__(self, name: str, base_url: str, model: str, api_key: str = "",
                 timeout: float = 60.0, session: Optional[requests.Session] = None):
        self.name = name
        self.base_url = base_url.rstrip("/") + "/"
        self.model = model
        self._api_key = api_key
        self.timeout = timeout
        self._session = session or requests.Session()

    def describe(self) -> dict:
        return {"name": self.name, "model": self.model}

    def chat(self, messages: List[dict], tools: List[dict],
             timeout: Optional[float] = None) -> AgentReply:
        url = self.base_url + "chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.1,
        }
        call_timeout = max(1.0, min(self.timeout, timeout or self.timeout))
        try:
            resp = self._session.post(url, json=payload, headers=headers,
                                      timeout=call_timeout, allow_redirects=False)
        except requests.exceptions.RequestException as exc:
            raise AgentLLMError(f"{self.name} injoignable : "
                                f"{_scrub(exc, [self._api_key])}") from None
        if resp.status_code != 200:
            raise AgentLLMError(f"{self.name} HTTP {resp.status_code} : "
                                f"{_scrub(resp.text, [self._api_key])}")
        if len(resp.content or b"") > _MAX_RESPONSE_BYTES:
            raise AgentLLMError(f"{self.name} : réponse trop volumineuse")
        try:
            body = resp.json()
            message = body["choices"][0]["message"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AgentLLMError(f"{self.name} : réponse invalide") from None
        if not isinstance(message, dict):
            raise AgentLLMError(f"{self.name} : message invalide")
        return build_reply(message)


def build_reply(message: dict) -> AgentReply:
    """Construit un AgentReply depuis un message assistant OpenAI (testable)."""
    content = message.get("content")
    content = content if isinstance(content, str) else ""
    calls = parse_tool_calls(message)
    assistant = {"role": "assistant", "content": content}
    if calls:
        # Historique reconstruit à partir des appels PARSÉS (bornés), jamais
        # le message brut du backend.
        assistant["tool_calls"] = [{
            "id": c.id, "type": "function",
            "function": {"name": c.name, "arguments": c.raw_arguments or "{}"},
        } for c in calls]
    return AgentReply(content=content[:4000], tool_calls=calls, assistant_message=assistant)


# ── Sélection du backend ──────────────────────────────────────────────────────

def ollama_model_size_b(model: str) -> Optional[float]:
    """
    Taille (milliards de paramètres) lue dans le nom/tag d'un modèle Ollama :
    « qwen2.5:7b » → 7, « llama3.1:8b-instruct-q4 » → 8, « qwen3:1.7b » → 1.7,
    « mixtral:8x7b » → 56. None si illisible (le modèle est alors refusé).
    """
    if not isinstance(model, str) or not model.strip():
        return None
    name = model.strip().lower()
    moe = re.search(r'(\d+)x(\d+(?:\.\d+)?)b(?![a-z])', name)
    if moe:
        return float(moe.group(1)) * float(moe.group(2))
    tag = name.split(":", 1)[1] if ":" in name else name
    for candidate in (tag, name):
        match = _SIZE_RE.search(candidate)
        if match:
            return float(match.group(1))
    return None


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _gemini_backend() -> Tuple[Optional[OpenAICompatBackend], str]:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        return None, "GEMINI_API_KEY absente"
    model = (os.getenv("AGENT_GEMINI_MODEL") or os.getenv("GEMINI_MODEL") or "gemini-2.0-flash").strip()
    return OpenAICompatBackend("gemini", GEMINI_BASE_URL, model, key,
                               timeout=_env_float("AGENT_LLM_TIMEOUT_SECONDS", 60.0)), ""


def _deepseek_backend() -> Tuple[Optional[OpenAICompatBackend], str]:
    key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not key:
        return None, "DEEPSEEK_API_KEY absente"
    # Même garde-fou que l'analyse : prestataire payant, partage confirmé exigé
    if not _truthy(os.getenv("DEEPSEEK_CONFIRM_EXTERNAL_SHARING")):
        return None, "DEEPSEEK_CONFIRM_EXTERNAL_SHARING non confirmé"
    model = (os.getenv("AGENT_DEEPSEEK_MODEL") or os.getenv("DEEPSEEK_MODEL") or "deepseek-chat").strip()
    return OpenAICompatBackend("deepseek", DEEPSEEK_BASE_URL, model, key,
                               timeout=_env_float("AGENT_LLM_TIMEOUT_SECONDS", 60.0)), ""


def _ollama_backend() -> Tuple[Optional[OpenAICompatBackend], str]:
    model = os.getenv("AGENT_OLLAMA_MODEL", "").strip()
    if not model:
        return None, "AGENT_OLLAMA_MODEL non défini (qwen3:1.7b ne pilote pas la boucle)"
    size = ollama_model_size_b(model)
    minimum = _env_float("AGENT_OLLAMA_MIN_PARAMS_B", 7.0)
    if size is None:
        return None, f"taille du modèle Ollama « {model[:60]} » illisible dans son tag"
    if size < minimum:
        return None, f"modèle Ollama trop petit ({size:g}B < {minimum:g}B)"
    base = os.getenv("OLLAMA_URL", "http://ollama:11434").strip().rstrip("/") + "/v1"
    return OpenAICompatBackend("ollama", base, model,
                               timeout=_env_float("AGENT_OLLAMA_TIMEOUT_SECONDS", 180.0)), ""


_FACTORIES = {"gemini": _gemini_backend, "deepseek": _deepseek_backend, "ollama": _ollama_backend}
DEFAULT_ORDER = ("gemini", "deepseek", "ollama")


def select_backend() -> Tuple[Optional[OpenAICompatBackend], str]:
    """
    Premier backend capable de function calling, selon AGENT_BACKEND
    (`auto` = gemini → deepseek → ollama, ou un nom précis).
    Retourne (backend, "") ou (None, raison lisible).
    """
    choice = os.getenv("AGENT_BACKEND", "auto").strip().lower() or "auto"
    if choice != "auto" and choice not in _FACTORIES:
        return None, f"AGENT_BACKEND inconnu : {choice[:30]}"
    order = DEFAULT_ORDER if choice == "auto" else (choice,)
    reasons = []
    for name in order:
        backend, reason = _FACTORIES[name]()
        if backend is not None:
            return backend, ""
        reasons.append(f"{name} : {reason}")
    return None, "aucun backend capable de function calling — " + " ; ".join(reasons)
