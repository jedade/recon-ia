# utils/explanations.py
"""
Textes pédagogiques par contrôle (collection RAG `explications`, phase 6).

Source de vérité : un fichier JSON par contrôle dans `api/data/explanations/`
(dmarc.json, spf.json, hsts.json…). Le même contenu sert deux usages :

  1. le RAG : `data/script_explications.py` appelle `render_markdown()` pour
     produire `data/combined_explications.md`, ingéré par n8n dans la
     collection `explications` (cf. utils/rag_collections.py) ;
  2. l'interface : les modales « Pourquoi c'est important ? » du dashboard ou
     de la page résultat peuvent lire directement `load_all()` / `get()`
     (texte brut, jamais de HTML : à insérer avec textContent).

Schéma d'un fichier (vérifié par `validate()` et par
tests/test_phase6_explanations.py) :

  id                str   identifiant = nom du fichier sans .json ([a-z0-9_]+)
  titre             str
  categorie         str   Messagerie | Web | TLS | DNS | Réseau | Réputation | Contexte
  outils            [str] clés d'outils Recon-IA concernés (source_tool)
  pourquoi          str   pourquoi c'est important
  risque            str   ce que risque le propriétaire du domaine
  comment_corriger  [str] étapes de correction
  exemple           str   (optionnel) exemple de configuration, texte brut
  references        [{titre, url}]  url en https://
  credits           str   attribution (inspiration web-check, licence MIT)

Inspiration : page « About » de web-check (Alicia Sykes,
https://github.com/Lissy93/web-check, licence MIT) — seule la structure
(« ce que c'est / pourquoi c'est important / liens ») est reprise ; les
textes sont rédigés en français pour Recon-IA.
"""
import json
import os
import re
from functools import lru_cache
from typing import Dict, List

EXPLANATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "data", "explanations")

REQUIRED_STR = ("id", "titre", "categorie", "pourquoi", "risque", "credits")
REQUIRED_LIST = ("outils", "comment_corriger", "references")
OPTIONAL_STR = ("exemple",)
ALLOWED_KEYS = set(REQUIRED_STR) | set(REQUIRED_LIST) | set(OPTIONAL_STR)
CATEGORIES = ("Messagerie", "Web", "TLS", "DNS", "Réseau", "Réputation", "Contexte")

_ID_RE = re.compile(r"^[a-z0-9_]{2,40}$")
_HTML_RE = re.compile(r"<\s*/?\s*[a-zA-Z!][^>]*>|&[a-zA-Z]+;|&#\d+;")
_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?:/[^\s<>\"']*)?$")


def _iter_strings(entry: dict):
    for k in REQUIRED_STR + OPTIONAL_STR:
        if isinstance(entry.get(k), str):
            yield k, entry[k]
    for k in ("outils", "comment_corriger"):
        for s in entry.get(k) or []:
            yield k, s
    for ref in entry.get("references") or []:
        if isinstance(ref, dict):
            for kk in ("titre", "url"):
                if isinstance(ref.get(kk), str):
                    yield f"references.{kk}", ref[kk]


def validate(entry: dict, expected_id: str = None) -> List[str]:
    """Liste des erreurs de schéma (vide = valide)."""
    errors = []
    if not isinstance(entry, dict):
        return ["l'entrée n'est pas un objet JSON"]
    for k in entry:
        if k not in ALLOWED_KEYS:
            errors.append(f"clé inconnue : {k}")
    for k in REQUIRED_STR:
        if not isinstance(entry.get(k), str) or not entry[k].strip():
            errors.append(f"champ texte manquant ou vide : {k}")
    for k in OPTIONAL_STR:
        if k in entry and (not isinstance(entry[k], str) or not entry[k].strip()):
            errors.append(f"champ optionnel invalide : {k}")
    for k in REQUIRED_LIST:
        v = entry.get(k)
        if not isinstance(v, list) or not v:
            errors.append(f"liste manquante ou vide : {k}")
    if isinstance(entry.get("id"), str) and not _ID_RE.match(entry["id"]):
        errors.append("id invalide (attendu [a-z0-9_]+)")
    if expected_id and entry.get("id") != expected_id:
        errors.append(f"id {entry.get('id')!r} différent du nom de fichier {expected_id!r}")
    if entry.get("categorie") not in CATEGORIES:
        errors.append(f"catégorie inconnue : {entry.get('categorie')!r}")
    for k in ("outils", "comment_corriger"):
        for s in entry.get(k) or []:
            if not isinstance(s, str) or not s.strip():
                errors.append(f"élément vide ou non textuel dans {k}")
    for ref in entry.get("references") or []:
        if not isinstance(ref, dict) or set(ref) != {"titre", "url"}:
            errors.append("référence invalide (attendu {titre, url})")
            continue
        if not isinstance(ref["url"], str) or not _URL_RE.match(ref["url"]):
            errors.append(f"URL de référence non https ou invalide : {ref.get('url')!r}")
    for k, s in _iter_strings(entry):
        if _HTML_RE.search(s):
            errors.append(f"HTML interdit dans {k}")
        if any(ord(c) < 32 and c != "\n" for c in s):
            errors.append(f"caractère de contrôle dans {k}")
    return errors


@lru_cache(maxsize=1)
def _load_cached(directory: str) -> Dict[str, dict]:
    out = {}
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as f:
            entry = json.load(f)
        expected = name[:-5]
        errs = validate(entry, expected)
        if errs:
            raise ValueError(f"explication {name} invalide : {'; '.join(errs)}")
        out[expected] = entry
    return out


def load_all(directory: str = None) -> Dict[str, dict]:
    """Toutes les explications, indexées par id. Lève ValueError si un fichier est invalide."""
    return dict(_load_cached(directory or EXPLANATIONS_DIR))


def get(control_id: str, directory: str = None):
    """Explication d'un contrôle, ou None."""
    if not isinstance(control_id, str) or not _ID_RE.match(control_id):
        return None
    return load_all(directory).get(control_id)


def for_tool(tool_key: str, directory: str = None) -> List[dict]:
    """Explications qui citent l'outil `tool_key` (ex. 'dmarc_check')."""
    return [e for e in load_all(directory).values() if tool_key in e.get("outils", [])]


def render_markdown(entry: dict) -> str:
    """Rendu markdown d'une explication, pour le corpus RAG (un titre = un document)."""
    lines = [
        f"# Explication — {entry['titre']}",
        "",
        f"Contrôle : {entry['id']} · Catégorie : {entry['categorie']} · "
        f"Outils Recon-IA : {', '.join(entry['outils'])}",
        "",
        "## Pourquoi c'est important",
        "",
        entry["pourquoi"],
        "",
        "## Risque",
        "",
        entry["risque"],
        "",
        "## Comment corriger",
        "",
    ]
    lines += [f"{i}. {step}" for i, step in enumerate(entry["comment_corriger"], 1)]
    if entry.get("exemple"):
        lines += ["", "## Exemple", "", "```", entry["exemple"], "```"]
    lines += ["", "## Références", ""]
    lines += [f"- {r['titre']} : {r['url']}" for r in entry["references"]]
    lines += ["", f"_{entry['credits']}_", ""]
    return "\n".join(lines)


def render_corpus(directory: str = None) -> str:
    """Corpus complet `combined_explications.md`."""
    entries = load_all(directory)
    parts = [render_markdown(entries[k]) for k in sorted(entries)]
    return "\n---\n\n".join(parts)
