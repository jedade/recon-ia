# data/script_mozilla_tls.py
"""
Recommandations TLS de Mozilla (collection RAG `normes`).

Source : https://ssl-config.mozilla.org/guidelines/latest.json — données du
générateur de configuration SSL de Mozilla (dépôt mozilla/ssl-config-generator,
licence Mozilla Public License 2.0). Seules les données structurées du JSON
sont reprises (versions TLS, suites, courbes, tailles de clé, HSTS, clients
les plus anciens supportés) ; les textes explicatifs en français sont
rédigés pour Recon-IA (pas de reprise du wiki « Server Side TLS », sous
licence CC BY-SA).

Sortie : data/combined_mozilla_tls.md (à copier dans n8n_ressource/).

Usage (manuel, réseau requis) :
    python data/script_mozilla_tls.py
"""
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.corpus_sanitizer import clean_title  # noqa: E402

URL = "https://ssl-config.mozilla.org/guidelines/latest.json"
OUTPUT_FILE = os.path.join(ROOT, "data", "combined_mozilla_tls.md")

PROFILES = {
    "modern": "Profil « modern » : TLS 1.3 uniquement. À réserver aux services dont "
              "tous les clients sont récents (navigateurs à jour, API entre serveurs modernes).",
    "intermediate": "Profil « intermediate » : recommandé par défaut pour un site public. "
                    "TLS 1.2 et 1.3, suites ECDHE avec chiffrement authentifié (AEAD) uniquement.",
    "old": "Profil « old » : compatibilité avec des clients très anciens. Accepte des "
           "protocoles et suites obsolètes ; à n'utiliser qu'en dernier recours, et à "
           "considérer comme une faiblesse lors d'un audit.",
}


def _fmt(value):
    if isinstance(value, list):
        return ", ".join(clean_title(str(v), 120) for v in value) or "—"
    if isinstance(value, dict):
        return "; ".join(f"{clean_title(str(k), 60)} {clean_title(str(v), 60)}" for k, v in value.items())
    return clean_title(str(value), 300)


def render(doc: dict) -> str:
    version = clean_title(str(doc.get("version", "?")), 20)
    parts = [
        f"# Mozilla — recommandations de configuration TLS (guidelines v{version})",
        "",
        "Source : Mozilla SSL Configuration Generator (ssl-config.mozilla.org, licence MPL 2.0). "
        "Mozilla publie trois profils de configuration serveur. Un audit passif compare les "
        "protocoles et suites observés (outil tls_config / sslscan) à ces profils : un serveur "
        "qui accepte des éléments absents du profil « intermediate » présente un écart.",
        "",
        "---",
        "",
    ]
    for name, cfg in (doc.get("configurations") or {}).items():
        if not isinstance(cfg, dict):
            continue
        name = clean_title(str(name), 40)
        parts += [f"# Mozilla TLS — profil {name}", "", PROFILES.get(name, ""), ""]
        fields = [
            ("Versions TLS", "tls_versions"),
            ("Suites TLS 1.3", "ciphersuites"),
            ("Suites TLS 1.2 et antérieures (OpenSSL)", ("ciphers", "openssl")),
            ("Courbes TLS", "tls_curves"),
            ("Types de certificat", "certificate_types"),
            ("Courbes de certificat", "certificate_curves"),
            ("Signatures de certificat", "certificate_signatures"),
            ("Taille minimale de clé RSA", "rsa_key_size"),
            ("Taille des paramètres DH", "dh_param_size"),
            ("Taille ECDH", "ecdh_param_size"),
            ("Durée HSTS minimale (secondes)", "hsts_min_age"),
            ("Durée de vie recommandée du certificat (jours)", "recommended_certificate_lifespan"),
            ("Ordre des suites imposé par le serveur", "server_preferred_order"),
            ("Clients les plus anciens supportés", "oldest_clients"),
        ]
        for label, key in fields:
            if isinstance(key, tuple):
                value = (cfg.get(key[0]) or {}).get(key[1])
            else:
                value = cfg.get(key)
            if value in (None, "", []):
                continue
            parts.append(f"- {label} : {_fmt(value)}")
        parts += ["", "---", ""]
    return "\n".join(parts)


def main():
    resp = requests.get(URL, timeout=30)
    resp.raise_for_status()
    md = render(resp.json())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"--- recommandations Mozilla écrites dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
