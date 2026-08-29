# data/script_mitre_attack.py
"""
Agrège les techniques MITRE ATT&CK Enterprise des tactiques Reconnaissance
(TA0043) et Resource Development (TA0042) depuis le bundle STIX officiel
(github.com/mitre/cti) en un seul fichier markdown, pour enrichir le RAG n8n
au même titre que les cheat sheets/ASVS/WSTG.

Pourquoi ces deux tactiques seulement (pas les 14 de la matrice Enterprise) :
`utils/mitre_attack.py` corrèle déjà déterministiquement chaque outil OSINT
exécuté à des techniques de CES DEUX tactiques précisément (reconnaissance
passive + préparation d'infrastructure par l'attaquant) — ce sont les seules
pertinentes pour un outil de recon passive. Ingérer les 14 tactiques (dont
Exécution, Mouvement latéral, Exfiltration...) n'aurait aucun rapport avec
ce que ce projet peut réellement observer, et diluerait le corpus RAG.

Licence source : CC BY-SA 4.0 (MITRE ATT&CK).
"""
import json
import requests

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
TARGET_TACTICS = {"reconnaissance", "resource-development"}
OUTPUT_FILE = "combined_mitre_attack_recon.md"


def main():
    print(f"Téléchargement du bundle STIX ATT&CK Enterprise depuis {STIX_URL} ...")
    resp = requests.get(STIX_URL, timeout=120)
    resp.raise_for_status()
    bundle = resp.json()
    objects = bundle.get("objects", [])
    print(f"{len(objects)} objets STIX chargés.")

    combined = ""
    count = 0
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        phases = {p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"}
        if not (phases & TARGET_TACTICS):
            continue

        external_id = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            "T????",
        )
        name = obj.get("name", "")
        description = obj.get("description", "").strip()
        detection = obj.get("x_mitre_detection", "").strip()

        combined += f"# {external_id} — {name}\n\n"
        combined += f"**Tactique(s)** : {', '.join(sorted(phases))}\n\n"
        combined += f"## Description\n\n{description}\n\n"
        if detection:
            combined += f"## Détection\n\n{detection}\n\n"
        combined += "\n---\n\n"
        count += 1
        print(f"Contenu ajouté pour : {external_id} — {name}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(combined)
    print(f"\n--- {count} techniques agrégées dans {OUTPUT_FILE} ---\n")


if __name__ == "__main__":
    main()
