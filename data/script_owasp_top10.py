# data/script_owasp_top10.py
"""
Agrège l'OWASP Top 10:2021 depuis github.com/OWASP/Top10 en un seul fichier
markdown, pour enrichir le RAG n8n (au même titre que combined_owasp_cheatsheets.md).

Pourquoi cette source, en complément des CVE déjà enrichies en LIVE
(routes/recon.py::_enrich_cves, CVSS+résumé CIRCL / EPSS FIRST par CVE
détectée) : une CVE ponctuelle est une instance précise, datée, qui change
chaque jour (200 000+ CVE, embarquer un instantané statique serait obsolète
immédiatement) — le Top 10 est au contraire la classification STABLE des
CATÉGORIES de vulnérabilité auxquelles la quasi-totalité des CVE se
rattachent (chaque catégorie liste ses CWE constitutifs). Combine les deux :
la CVE live donne le « quoi, précisément, sur cette cible », le Top 10 (RAG)
donne le « dans quelle famille de risque, avec quelle remédiation générale
reconnue ». Referme aussi l'écart documenté dans CLAUDE.md (§8) : « CWE et
CAPEC n'ont volontairement pas de script — URLs non vérifiées » — le Top 10
sert cette même fonction (classification par famille de vulnérabilité) sans
avoir à parser le XML CWE complet de MITRE (~900 entrées, hors périmètre).

Licence source : CC BY-SA 4.0 (OWASP Top 10).
"""
from github_md_aggregator import aggregate_markdown

if __name__ == "__main__":
    aggregate_markdown(
        owner="OWASP",
        repo="Top10",
        path="2021/docs/en",
        ref="master",
        output_file="combined_owasp_top10.md",
        header_prefix="OWASP Top 10:2021 — ",
    )
