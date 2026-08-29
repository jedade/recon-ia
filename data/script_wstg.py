# data/script_wstg.py
"""
Agrège l'OWASP Web Security Testing Guide (WSTG) depuis
github.com/OWASP/wstg en un seul fichier markdown, pour enrichir le RAG n8n
(au même titre que combined_owasp_cheatsheets.md).

Licence source : CC BY-SA 4.0 (OWASP WSTG).
"""
from github_md_aggregator import aggregate_markdown

if __name__ == "__main__":
    aggregate_markdown(
        owner="OWASP",
        repo="wstg",
        path="document",
        ref="master",
        output_file="combined_owasp_wstg.md",
        header_prefix="WSTG — ",
    )
