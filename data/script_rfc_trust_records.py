# data/script_rfc_trust_records.py
"""
Agrège en un seul fichier markdown les RFC IETF officiels derrière les
enregistrements DNS de confiance et protocoles vérifiés passivement par ce
projet (SPF, DKIM, DMARC, DANE, MTA-STS, TLS-RPT, BIMI, CAA, security.txt),
pour enrichir le RAG n8n au même titre que les cheat sheets/ASVS/WSTG/MITRE.

Pourquoi ces RFC précisément : chacun correspond exactement à un outil déjà
implémenté (spf_analysis, dkim_check, dmarc_check, dane_check, mta_sts_check,
tlsrpt_check, bimi_check, caa_check, security_txt — cf. TOOLS_REGISTRY dans
routes/recon.py) — le texte de la norme officielle permet à l'IA de citer la
source exacte (« RFC 7208 §3.1 ») au lieu de reformuler une bonne pratique
de mémoire, avec le même niveau de précision que le corpus ASVS/WSTG pour le
reste de l'analyse.

Source : IETF RFC Editor (rfc-editor.org), domaine public / libre de droits
pour republication avec attribution (cf. licence IETF Trust).
"""
import requests

RFCS = [
    (7208, "SPF — Sender Policy Framework"),
    (6376, "DKIM — DomainKeys Identified Mail Signatures"),
    (7489, "DMARC — Domain-based Message Authentication, Reporting & Conformance"),
    (6698, "DANE — TLSA (base)"),
    (7671, "DANE — TLSA (opérationnel)"),
    (8461, "MTA-STS — SMTP MTA Strict Transport Security"),
    (8460, "TLS-RPT — SMTP TLS Reporting"),
    (6844, "CAA — Certification Authority Authorization (base)"),
    (8659, "CAA — Certification Authority Authorization (révision)"),
    (9116, "security.txt — A File Format to Aid in Security Vulnerability Disclosure"),
]

OUTPUT_FILE = "combined_rfc_trust_records.md"


def main():
    combined = ""
    count = 0
    for number, label in RFCS:
        url = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            print(f"Erreur lors de la récupération de RFC {number} ({resp.status_code})")
            continue
        combined += f"# RFC {number} — {label}\n\n```\n{resp.text}\n```\n\n---\n\n"
        count += 1
        print(f"Contenu ajouté pour : RFC {number} — {label}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(combined)
    print(f"\n--- {count} RFC agrégées dans {OUTPUT_FILE} ---\n")


if __name__ == "__main__":
    main()
