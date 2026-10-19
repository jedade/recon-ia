# data/script_cwe_capec.py
"""
CWE et CAPEC des findings courants de Recon-IA (collection RAG `normes`).

Plutôt que d'ingérer les ~950 CWE et ~560 CAPEC (bruit pour la recherche
vectorielle), on extrait des catalogues XML officiels de MITRE la seule
liste d'entrées correspondant aux constats que produit une recon passive :
messagerie usurpable, transport en clair, TLS faible, certificats, en-têtes
HTTP, cookies, exposition de services, DNS, typosquatting, fuites…

Sources :
  - CWE   https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  - CAPEC https://capec.mitre.org/data/xml/capec_latest.xml
Licence : CWE™ et CAPEC™ Terms of Use (MITRE) — usage, reproduction et
redistribution libres, y compris commerciaux, à condition de conserver la
mention de copyright « © The MITRE Corporation » (reprise dans le fichier
produit). https://cwe.mitre.org/about/termsofuse.html

Sécurité : XML analysé sans résolution d'entités ni accès réseau
(lxml resolve_entities=False, no_network=True) ; texte nettoyé par
utils/corpus_sanitizer.py.

Sortie : data/combined_cwe_capec.md (à copier dans n8n_ressource/).

Usage (manuel, réseau requis) :
    python data/script_cwe_capec.py
"""
import io
import os
import sys
import zipfile

import requests
from lxml import etree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
from utils.corpus_sanitizer import clean_text, clean_title  # noqa: E402

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
OUTPUT_FILE = os.path.join(ROOT, "data", "combined_cwe_capec.md")

# CWE liés aux constats d'une recon passive (outil Recon-IA entre parenthèses)
CWE_IDS = [
    16,    # Configuration (catégorie historique, en-têtes/config)
    79,    # XSS (CSP absente)
    200,   # Exposition d'informations (bannières, robots.txt, sitemap)
    284,   # Contrôle d'accès incorrect
    290,   # Contournement par usurpation (SPF/DKIM/DMARC)
    295,   # Validation de certificat incorrecte
    298,   # Expiration de certificat
    306,   # Fonction critique sans authentification (ports exposés)
    319,   # Transmission en clair (HSTS, MTA-STS)
    326,   # Force de chiffrement insuffisante (TLS)
    327,   # Algorithme cassé ou risqué (TLS)
    345,   # Vérification insuffisante d'authenticité (e-mail, DNS)
    346,   # Erreur de validation d'origine
    350,   # Dépendance à la résolution DNS inverse
    523,   # Transport non protégé des identifiants
    538,   # Fichiers/répertoires accessibles (gau, archives)
    548,   # Listing de répertoire
    601,   # Redirection ouverte (redirect_chain)
    614,   # Cookie sensible sans Secure
    668,   # Ressource exposée à la mauvaise sphère
    693,   # Défaillance d'un mécanisme de protection (en-têtes)
    757,   # Négociation d'algorithme moins sûr (downgrade)
    798,   # Identifiants codés en dur (github, js_endpoints)
    942,   # Politique cross-domain permissive (CORS)
    1004,  # Cookie sensible sans HttpOnly
    1021,  # Clickjacking (X-Frame-Options)
    1104,  # Composants tiers non maintenus (tech_stack)
    1275,  # Cookie sensible avec SameSite incorrect
    1395,  # Dépendance à un composant tiers vulnérable (CVE Shodan)
]

# CAPEC (schémas d'attaque) correspondants
CAPEC_IDS = [
    89,    # Pharming
    94,    # Adversary in the Middle
    98,    # Phishing
    103,   # Clickjacking
    141,   # Cache Poisoning
    142,   # DNS Cache Poisoning
    157,   # Sniffing Attacks
    163,   # Spear Phishing
    169,   # Footprinting
    194,   # Fake the Source of Data
    217,   # Exploiting Incorrectly Configured SSL/TLS
    300,   # Port Scanning
    459,   # Creating a Rogue Certification Authority Certificate
    543,   # Counterfeit Websites
    600,   # Credential Stuffing
    620,   # Drop Encryption Level
    630,   # TypoSquatting
    631,   # SoundSquatting
    632,   # Homograph Attack via Homoglyphs
]

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True,
                          remove_comments=True, remove_pis=True)


def _local(tag) -> str:
    return tag.split("}", 1)[-1] if isinstance(tag, str) else ""


def _child(el, name):
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _children(el, name):
    return [c for c in el if _local(c.tag) == name] if el is not None else []


def _text(el, max_len=1500) -> str:
    if el is None:
        return ""
    return clean_text(" ".join(t.strip() for t in el.itertext() if t and t.strip()),
                      max_len=max_len, is_html=False)


def render_cwe(root) -> list:
    wanted = set(CWE_IDS)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("Weakness", "Category"):
            continue
        try:
            wid = int(el.get("ID"))
        except (TypeError, ValueError):
            continue
        if wid not in wanted:
            continue
        name = clean_title(el.get("Name", ""))
        lines = [f"# CWE-{wid} — {name}", "",
                 f"Source : MITRE CWE (https://cwe.mitre.org/data/definitions/{wid}.html)", ""]
        desc = _text(_child(el, "Description")) or _text(_child(el, "Summary"))
        if desc:
            lines += ["## Description", "", desc, ""]
        ext = _text(_child(el, "Extended_Description"), 2000)
        if ext:
            lines += [ext, ""]
        cons = _children(_child(el, "Common_Consequences"), "Consequence")
        if cons:
            lines += ["## Conséquences", ""]
            for c in cons[:6]:
                scopes = ", ".join(_text(s, 80) for s in _children(c, "Scope"))
                impacts = ", ".join(_text(s, 120) for s in _children(c, "Impact"))
                note = _text(_child(c, "Note"), 400)
                lines.append(f"- {scopes} : {impacts}" + (f" — {note}" if note else ""))
            lines.append("")
        mits = _children(_child(el, "Potential_Mitigations"), "Mitigation")
        if mits:
            lines += ["## Mesures d'atténuation", ""]
            for m in mits[:6]:
                phase = ", ".join(_text(p, 60) for p in _children(m, "Phase"))
                lines.append(f"- [{phase or 'Général'}] {_text(_child(m, 'Description'), 800)}")
            lines.append("")
        out.append((wid, "\n".join(lines)))
    return [md for _, md in sorted(out)]


def render_capec(root) -> list:
    wanted = set(CAPEC_IDS)
    out = []
    for el in root.iter():
        if _local(el.tag) != "Attack_Pattern":
            continue
        try:
            pid = int(el.get("ID"))
        except (TypeError, ValueError):
            continue
        if pid not in wanted:
            continue
        name = clean_title(el.get("Name", ""))
        lines = [f"# CAPEC-{pid} — {name}", "",
                 f"Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/{pid}.html)", ""]
        for label, tag in (("Probabilité d'attaque", "Likelihood_Of_Attack"),
                           ("Sévérité typique", "Typical_Severity")):
            v = _text(_child(el, tag), 40)
            if v:
                lines.append(f"- {label} : {v}")
        lines.append("")
        desc = _text(_child(el, "Description"), 2000)
        if desc:
            lines += ["## Description", "", desc, ""]
        prereq = _children(_child(el, "Prerequisites"), "Prerequisite")
        if prereq:
            lines += ["## Prérequis", ""] + [f"- {_text(p, 500)}" for p in prereq[:5]] + [""]
        mits = _children(_child(el, "Mitigations"), "Mitigation")
        if mits:
            lines += ["## Mesures d'atténuation", ""] + [f"- {_text(m, 600)}" for m in mits[:6]] + [""]
        rel = [w.get("CWE_ID") for w in _children(_child(el, "Related_Weaknesses"), "Related_Weakness")]
        rel = [f"CWE-{r}" for r in rel if r and r.isdigit()]
        if rel:
            lines += [f"Faiblesses liées : {', '.join(rel[:12])}", ""]
        out.append((pid, "\n".join(lines)))
    return [md for _, md in sorted(out)]


def main():
    r = requests.get(CWE_URL, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        xml_name = next(n for n in z.namelist() if n.endswith(".xml"))
        cwe_root = etree.fromstring(z.read(xml_name), _PARSER)
    r = requests.get(CAPEC_URL, timeout=120)
    r.raise_for_status()
    capec_root = etree.fromstring(r.content, _PARSER)

    cwe_docs = render_cwe(cwe_root)
    capec_docs = render_capec(capec_root)
    header = ("# CWE et CAPEC — sélection Recon-IA\n\n"
              "Sélection des faiblesses (CWE) et schémas d'attaque (CAPEC) correspondant aux "
              "constats d'une reconnaissance passive. © The MITRE Corporation — CWE™ et CAPEC™, "
              "reproduits selon leurs conditions d'utilisation (https://cwe.mitre.org/about/termsofuse.html).\n")
    md = "\n---\n\n".join([header] + cwe_docs + capec_docs) + "\n"
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"--- {len(cwe_docs)} CWE et {len(capec_docs)} CAPEC écrits dans {OUTPUT_FILE} ---")


if __name__ == "__main__":
    main()
