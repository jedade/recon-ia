# data/script_asvs.py
"""
Agrège l'OWASP Application Security Verification Standard (ASVS) v5.0
depuis github.com/OWASP/ASVS en un seul fichier markdown, pour enrichir le
RAG n8n (au même titre que combined_owasp_cheatsheets.md).

Licence source : CC BY-SA 4.0 (OWASP ASVS).
"""
from github_md_aggregator import aggregate_markdown

if __name__ == "__main__":
    aggregate_markdown(
        owner="OWASP",
        repo="ASVS",
        path="5.0/en",
        ref="master",
        output_file="combined_owasp_asvs.md",
        header_prefix="ASVS — ",
    )
