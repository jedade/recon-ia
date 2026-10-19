# data/script_cisa_advisories.py
"""
Avis conjoints CISA « AA » (collection RAG `menaces`).

Source : flux RSS https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml
(le champ description contient le texte intégral de l'avis en HTML). Seuls
les avis conjoints de cybersécurité (identifiant AAyy-nnnX, URL
/news-events/cybersecurity-advisories/aa...) sont retenus : ils décrivent
les campagnes, techniques ATT&CK et mesures d'atténuation des acteurs de la
menace ; les avis ICS (ICSA) et alertes produits sont hors sujet pour une
recon passive de domaine.

Licence : œuvre du gouvernement fédéral américain — domaine public aux
États-Unis (17 U.S.C. §105). CISA demande de ne pas laisser entendre un
soutien de sa part ; certains avis co-signés peuvent contenir des contenus
tiers marqués comme tels. https://www.cisa.gov/privacy-policy (section
« Copyright »).

Sécurité : le HTML est une donnée NON FIABLE (flux tiers, possiblement
détourné) : conversion en texte brut sans script/style/iframe, retrait des
caractères invisibles, neutralisation des motifs d'injection de prompt
(utils/corpus_sanitizer.py), troncature par avis.

Sortie : data/combined_cisa_advisories.md (à copier dans n8n_ressource/).

Usage (manuel, réseau requis) :
    python data/script_cisa_advisories.py [nombre_max_d_avis] [flux_telecharge.xml]
"""
import os
import re
import sys

import requests
from lxml import etree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.corpus_sanitizer import clean_text, clean_title  # noqa: E402

FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
OUTPUT_FILE = os.path.join(ROOT, "data", "combined_cisa_advisories.md")
MAX_ADVISORIES = 40
MAX_CHARS_PER_ADVISORY = 12000

_AA_RE = re.compile(r"/cybersecurity-advisories/(aa\d{2}-\d{3}[a-z])\b", re.IGNORECASE)
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True,
                          remove_comments=True, remove_pis=True)


def parse_feed(xml_bytes: bytes, max_items: int = MAX_ADVISORIES) -> list:
    """[(identifiant, titre, date, lien, texte nettoyé)] des avis AA du flux."""
    root = etree.fromstring(xml_bytes, _PARSER)
    out, seen = [], set()
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        m = _AA_RE.search(link)
        if not m or not link.startswith("https://www.cisa.gov/"):
            continue
        aa_id = m.group(1).upper()
        if aa_id in seen:
            continue
        seen.add(aa_id)
        title = clean_title(item.findtext("title") or aa_id)
        date = clean_title(item.findtext("pubDate") or "", 60)
        body = clean_text(item.findtext("description") or "", max_len=MAX_CHARS_PER_ADVISORY, is_html=True)
        out.append((aa_id, title, date, link, body))
        if len(out) >= max_items:
            break
    return out


def render(advisories: list) -> str:
    parts = []
    for aa_id, title, date, link, body in advisories:
        parts.append(
            f"# CISA {aa_id} — {title}\n\n"
            f"Source : CISA, avis de cybersécurité {aa_id} ({date}) — {link} — "
            f"domaine public (œuvre du gouvernement fédéral américain). "
            f"Contenu tiers rapporté à titre documentaire.\n\n{body}\n"
        )
    return "\n---\n\n".join(parts)


def main():
    # Arguments : [nombre_max] et/ou [chemin d'un flux RSS déjà téléchargé].
    # Le CDN de cisa.gov refuse parfois (403) le client `requests` alors qu'il
    # accepte curl : dans ce cas, télécharger le flux à la main
    #   curl -o cisa.xml https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml
    # puis : python data/script_cisa_advisories.py cisa.xml
    limit, local_file = MAX_ADVISORIES, None
    for arg in sys.argv[1:]:
        if arg.isdigit():
            limit = int(arg)
        else:
            local_file = arg
    if local_file:
        with open(local_file, "rb") as f:
            content = f.read()
    else:
        resp = requests.get(FEED_URL, timeout=60,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; Recon-IA corpus builder)"})
        resp.raise_for_status()
        content = resp.content
    advisories = parse_feed(content, limit)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(render(advisories))
    print(f"--- {len(advisories)} avis CISA écrits dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
