# data/script_anssi_guides.py
"""
Guides de l'ANSSI (messagerie, TLS, DNS / noms de domaine, sites web) pour la
collection RAG `normes`.

Contrainte constatée le 2026-10-19 : cyber.gouv.fr est protégé par un pare-feu
applicatif (Incapsula) qui refuse les téléchargements automatisés, et les
guides sont des PDF (pas d'extracteur PDF dans requirements.txt). Le script
produit donc par défaut le corpus à partir d'une SYNTHÈSE rédigée pour
Recon-IA (`data/sources/anssi_guides_resume.md`), qui cite chaque guide
(titre, référence, URL) sans en reproduire le texte.

Option : si vous avez téléchargé les PDF à la main, passez le dossier en
argument ; leur texte est alors extrait (bibliothèque `pypdf` requise,
`pip install pypdf`), nettoyé et ajouté après la synthèse :

    python data/script_anssi_guides.py                 # synthèse seule
    python data/script_anssi_guides.py ~/guides-anssi  # + texte intégral des PDF

Licence : les publications de l'ANSSI sont diffusées sous Licence Ouverte /
Open Licence version 2.0 (Etalab) sauf mention contraire — réutilisation libre
avec mention de la paternité (« ANSSI »), de la date et du lien. Vérifier la
mention de chaque PDF avant d'en ingérer le texte intégral.

Sortie : data/combined_anssi_guides.md (à copier dans n8n_ressource/).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.corpus_sanitizer import clean_text, clean_title  # noqa: E402

SUMMARY_FILE = os.path.join(ROOT, "data", "sources", "anssi_guides_resume.md")
OUTPUT_FILE = os.path.join(ROOT, "data", "combined_anssi_guides.md")
MAX_CHARS_PER_PDF = 200000


def extract_pdfs(directory: str) -> list:
    try:
        from pypdf import PdfReader
    except ImportError:
        print("pypdf absent : `pip install pypdf` pour extraire les PDF — synthèse seule.")
        return []
    docs = []
    for name in sorted(os.listdir(directory)):
        if not name.lower().endswith(".pdf"):
            continue
        reader = PdfReader(os.path.join(directory, name))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        body = clean_text(text, max_len=MAX_CHARS_PER_PDF, is_html=False)
        title = clean_title(os.path.splitext(name)[0].replace("_", " "))
        docs.append(f"# ANSSI — {title} (texte intégral)\n\n"
                    f"Source : ANSSI, fichier {clean_title(name)} — Licence Ouverte Etalab 2.0 "
                    f"(sauf mention contraire du document).\n\n{body}\n")
        print(f"Contenu ajouté pour : {name}")
    return docs


def main():
    with open(SUMMARY_FILE, encoding="utf-8") as f:
        parts = [f.read().strip() + "\n"]
    if len(sys.argv) > 1:
        parts += extract_pdfs(sys.argv[1])
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n---\n\n".join(parts))
    print(f"--- {len(parts)} bloc(s) ANSSI écrits dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
