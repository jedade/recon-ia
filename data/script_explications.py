# data/script_explications.py
"""
Génère le corpus RAG de la collection `explications` à partir des fichiers
JSON par contrôle de `api/data/explanations/` (source de vérité partagée
avec les modales de l'interface — voir api/utils/explanations.py).

Aucun réseau : contenu rédigé pour Recon-IA (structure inspirée de la page
« About » de web-check, Alicia Sykes, licence MIT).

Sortie : data/combined_explications.md (à copier dans n8n_ressource/).

Usage :
    python data/script_explications.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.explanations import load_all, render_corpus  # noqa: E402

OUTPUT_FILE = os.path.join(ROOT, "data", "combined_explications.md")


def main():
    md = render_corpus()  # lève ValueError si un JSON ne respecte pas le schéma
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"--- {len(load_all())} explications écrites dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
