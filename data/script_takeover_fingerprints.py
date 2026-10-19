# data/script_takeover_fingerprints.py
"""
Met à jour la copie locale des empreintes de prise de contrôle de
sous-domaine (`api/data/takeover_fingerprints.json`), consultée directement
par `api/utils/takeover_fingerprints.py` — HORS RAG (donnée structurée,
interrogée par suffixe DNS, pas par similarité).

Source : https://github.com/EdOverflow/can-i-take-over-xyz (fingerprints.json)
Licence : Creative Commons Attribution 4.0 International (CC BY 4.0) —
l'attribution est écrite dans le fichier produit.

Le contenu téléchargé est traité comme non fiable : seuls les champs
attendus sont conservés, typés et tronqués ; le texte est nettoyé
(utils/corpus_sanitizer.py).

Usage (manuel, réseau requis) :
    python data/script_takeover_fingerprints.py
"""
import json
import os
import sys
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.corpus_sanitizer import clean_title  # noqa: E402

URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
OUTPUT_FILE = os.path.join(ROOT, "api", "data", "takeover_fingerprints.json")


def normalize(items):
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict) or not isinstance(it.get("service"), str):
            continue
        cnames = [c.strip().lower().rstrip(".") for c in it.get("cname") or []
                  if isinstance(c, str) and 0 < len(c.strip()) <= 253
                  and all(ch.isalnum() or ch in ".-_" for ch in c.strip())]
        out.append({
            "service": clean_title(it["service"], 120),
            "cname": cnames,
            "status": clean_title(str(it.get("status") or ""), 40),
            "vulnerable": bool(it.get("vulnerable")),
            "nxdomain": bool(it.get("nxdomain")),
            "fingerprint": clean_title(str(it.get("fingerprint") or ""), 300, is_html=False),
        })
    return sorted(out, key=lambda x: x["service"].lower())


def main():
    resp = requests.get(URL, timeout=30)
    resp.raise_for_status()
    fingerprints = normalize(resp.json())
    doc = {
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "licence": "CC BY 4.0 — © EdOverflow et contributeurs de can-i-take-over-xyz",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(fingerprints),
        "fingerprints": fingerprints,
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"--- {len(fingerprints)} empreintes écrites dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
