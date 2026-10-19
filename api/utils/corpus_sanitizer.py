# utils/corpus_sanitizer.py
"""
Nettoyage des contenus tiers destinés au corpus RAG (phase 6).

Tout texte téléchargé par un script `data/script_*.py` (avis CISA en HTML,
XML CWE/CAPEC, JSON Mozilla…) est une DONNÉE NON FIABLE : il finira, découpé
en extraits de 500 caractères, dans le prompt du LLM d'analyse
(`utils/rag_retrieval.py` → `signals["rag_context"]`). Un avis piégé, un
miroir compromis ou un simple commentaire HTML pourrait y glisser des
« instructions » adressées au modèle (injection de prompt indirecte).

Ce module, sans dépendance réseau ni Flask (importable depuis les scripts
`data/` via `sys.path`), applique donc systématiquement :

  1. HTML → texte brut (BeautifulSoup si disponible, sinon expression
     régulière) en supprimant `script`, `style`, `iframe`, `noscript`,
     `object`, `embed`, `form`, `svg` et les commentaires HTML ;
  2. suppression des caractères de contrôle et des caractères invisibles
     (zero-width, marques bidirectionnelles) qui servent à cacher du texte ;
  3. neutralisation des motifs typiques d'injection de prompt (« ignore
     previous instructions », balises de rôle `<|im_start|>`, `[INST]`,
     « system prompt », etc.) remplacés par un marqueur explicite ;
  4. neutralisation des liens `javascript:` / `data:` ;
  5. normalisation des blancs et troncature à une longueur maximale.

Ce n'est pas une garantie absolue (aucun filtre ne l'est) : c'est une couche
de défense en profondeur, en plus de la consigne du prompt d'analyse qui
traite le contexte RAG comme une référence et non comme des ordres.
"""
import html as _html
import re
import unicodedata

NEUTRALIZED = "[contenu neutralisé]"

_DANGEROUS_TAGS = ("script", "style", "iframe", "noscript", "object",
                   "embed", "form", "svg", "template", "head")
_BLOCK_TAGS = ["p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table",
               "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
               "blockquote", "pre", "dd", "dt", "hr"]

# Motifs d'injection de prompt courants (FR + EN). Volontairement larges :
# un faux positif ne coûte qu'une phrase d'un avis de sécurité.
_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|messages?|rules?)",
    r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)",
    r"forget\s+(?:all\s+)?(?:your|the|previous)\s+(?:instructions?|rules?)",
    r"ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|consignes?|règles?)\s+(?:précédentes?|ci-dessus|antérieures?)",
    r"oublie[rz]?\s+(?:toutes?\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions?|consignes?)",
    r"you\s+are\s+now\s+(?:a|an|the)\b",
    r"tu\s+es\s+désormais\b",
    r"new\s+instructions?\s*:",
    r"nouvelles?\s+instructions?\s*:",
    r"system\s+prompt",
    r"prompt\s+système",
    r"<\|[a-z_]+\|>",            # <|im_start|>, <|system|>…
    r"\[/?INST\]",
    r"<</?SYS>>",
    r"^\s*(?:system|assistant)\s*:",  # faux tours de dialogue en début de ligne
]
_INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in _INJECTION_PATTERNS),
                           re.IGNORECASE | re.MULTILINE)

_DANGEROUS_URL_RE = re.compile(r"\b(?:javascript|vbscript|data)\s*:[^\s)\]]*", re.IGNORECASE)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]{0,2000}>")
_LOOKS_HTML_RE = re.compile(r"<\s*/?\s*[a-zA-Z][a-zA-Z0-9]*(?:\s[^>]*)?>")

# Caractères invisibles / bidi utilisés pour masquer du texte.
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "­",
}


def html_to_text(raw: str) -> str:
    """Convertit du HTML en texte brut, sans aucun contenu actif."""
    if not raw:
        return ""
    raw = _HTML_COMMENT_RE.sub(" ", raw)
    try:
        import warnings
        from bs4 import BeautifulSoup  # présent dans requirements.txt
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # avertissements « ressemble à du XML/une URL »
            soup = BeautifulSoup(raw, "html.parser")
        for tag in soup(list(_DANGEROUS_TAGS)):
            tag.decompose()
        # Les blocs (paragraphes, cellules, titres…) deviennent des lignes
        # distinctes ; le texte en ligne (<b>, <a>…) reste dans sa phrase.
        for tag in soup.find_all(_BLOCK_TAGS):
            tag.insert_before("\n")
            tag.insert_after("\n")
        text = soup.get_text("")
    except Exception:
        for tag in _DANGEROUS_TAGS:
            raw = re.sub(rf"<{tag}\b.*?</{tag}\s*>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
        text = _TAG_RE.sub(" ", raw)
    # Entités résiduelles (&nbsp; doublement échappé dans les flux RSS)
    text = _html.unescape(text)
    # Toute balise qui aurait survécu (ex. texte « &lt;script&gt; » déséchappé)
    text = _TAG_RE.sub(" ", text)
    return text


def strip_invisible(text: str) -> str:
    """Retire caractères de contrôle (hors \\n et \\t) et caractères invisibles."""
    out = []
    for ch in text:
        if ch in ("\n", "\t"):
            out.append(ch)
            continue
        if ch in _INVISIBLE:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co"):
            continue
        out.append(ch)
    return "".join(out)


def neutralize_injections(text: str) -> str:
    """Remplace les motifs d'injection de prompt par un marqueur explicite."""
    text = _INJECTION_RE.sub(NEUTRALIZED, text)
    return _DANGEROUS_URL_RE.sub(NEUTRALIZED, text)


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    text = re.sub(r"[  ]{2,}", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def clean_text(raw: str, *, max_len: int = 20000, is_html=None) -> str:
    """
    Chaîne complète de nettoyage d'un contenu tiers.

    `is_html=None` détecte automatiquement la présence de balises.
    Le résultat ne contient ni balise HTML, ni caractère invisible, ni motif
    d'injection connu, et fait au plus `max_len` caractères.
    """
    if raw is None:
        return ""
    text = str(raw)
    if is_html or (is_html is None and _LOOKS_HTML_RE.search(text)):
        text = html_to_text(text)
    else:
        text = _HTML_COMMENT_RE.sub(" ", text)
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = neutralize_injections(text)
    text = normalize_whitespace(text)
    # Une ligne commençant par « # » ouvrirait un faux titre markdown et
    # casserait la structure « un document = un titre » du corpus.
    text = re.sub(r"^#+\s*", "", text, flags=re.MULTILINE)
    if max_len and len(text) > max_len:
        text = text[:max_len].rstrip() + " […]"
    return text


def clean_title(raw: str, max_len: int = 200, is_html=None) -> str:
    """Titre sur une seule ligne, nettoyé."""
    return clean_text(raw, max_len=max_len, is_html=is_html).replace("\n", " ").strip()
