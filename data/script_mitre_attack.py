# data/script_mitre_attack.py
"""
Extrait du bundle STIX officiel MITRE ATT&CK Enterprise (github.com/mitre/cti,
`enterprise-attack/enterprise-attack.json`, dernière version) deux sorties :

1. `combined_mitre_attack_recon.md` (corpus RAG, collection `attack`) :
   - toutes les techniques des tactiques Reconnaissance (TA0043) et
     Resource Development (TA0042) — celles que `utils/mitre_attack.py`
     corrèle aux outils OSINT exécutés ;
   - (phase 4) les techniques « rendues possibles » par les constats
     (`utils/attack_enablement.py` : T1566, T1190, T1133, T1078, T1110.004,
     T1552, T1552.001…) ;
   - (phase 4) les mitigations officielles (relations `mitigates`) de ces
     techniques.

2. `api/data/attack_reference.json` (référentiel runtime, versionné dans le
   dépôt) : pour chaque technique de `REFERENCE_TECHNIQUES`, son nom complet,
   ses tactiques, ses mitigations (ID → nom) et, à titre de CONTEXTE
   seulement, le nombre de groupes connus qui l'utilisent (relations `uses`)
   avec un échantillon de 5 noms. Le runtime ne lit QUE ce fichier : aucun
   appel réseau pendant une analyse.

Pourquoi pas les 14 tactiques entières : ce projet ne fait que de la
reconnaissance passive ; seules les techniques que l'on peut relier à un
constat observé ont leur place dans le rapport (et dans le RAG).

Usage (Python dans un conteneur, jamais sur l'hôte) :
    python -I data/script_mitre_attack.py                      # dernière release mitre/cti
    python -I data/script_mitre_attack.py --bundle chemin.json --version 20.0  # bundle local
Options : --out-md, --out-json (chemins de sortie).

Régénérer après chaque nouvelle version d'ATT&CK (deux par an) ou après
l'ajout d'une technique dans `utils/attack_enablement.py` /
`utils/mitre_attack.py` — `tests/test_phase4_attack_reference.py` échoue si
une technique utilisée manque du référentiel.

Licence source : MITRE ATT&CK® — conditions d'utilisation
https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
STIX_URL_AT_TAG = "https://raw.githubusercontent.com/mitre/cti/{tag}/enterprise-attack/enterprise-attack.json"
RELEASES_API = "https://api.github.com/repos/mitre/cti/releases/latest"
TARGET_TACTICS = {"reconnaissance", "resource-development"}

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_MD = os.path.join(HERE, "combined_mitre_attack_recon.md")
OUTPUT_JSON = os.path.join(HERE, "..", "api", "data", "attack_reference.json")

# Techniques du référentiel runtime : celles de utils/mitre_attack.py
# (outil → technique) + celles de la table constat → technique
# (utils/attack_enablement.py). Tenir à jour avec ces deux modules.
REFERENCE_TECHNIQUES = sorted({
    # Reconnaissance / Resource Development (mitre_attack.TECHNIQUES)
    "T1589.002", "T1590.001", "T1590.002", "T1590.004", "T1590.005",
    "T1592.002", "T1593", "T1593.001", "T1593.002", "T1593.003", "T1594",
    "T1596", "T1596.001", "T1596.003", "T1596.005",
    "T1583.001", "T1584.001",
    # Techniques rendues possibles (attack_enablement.RULES)
    "T1566", "T1190", "T1133", "T1078", "T1110.004", "T1552", "T1552.001",
})
# Techniques ajoutées au corpus RAG en plus des deux tactiques entières
EXTRA_MD_TECHNIQUES = {"T1566", "T1190", "T1133", "T1078", "T1110.004", "T1552", "T1552.001"}

_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MIT_RE = re.compile(r"^M\d{4}$")
_TACTIC_RE = re.compile(r"^TA\d{4}$")
_GROUP_RE = re.compile(r"^G\d{4}$")


def _external_id(obj):
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _active(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def latest_release():
    """
    Tag de la dernière version publiée de mitre/cti (« ATT&CK-v20.0 »). Le
    bundle de mitre/cti ne contient pas d'objet x-mitre-collection : la
    version ne se lit que sur la release GitHub.
    """
    import requests  # import tardif : inutile avec --bundle --version
    resp = requests.get(RELEASES_API, timeout=30, headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    tag = resp.json().get("tag_name") or ""
    match = re.match(r"^ATT&CK-v(\d+\.\d+)$", tag)
    if not match:
        raise SystemExit(f"Tag de release inattendu : {tag!r}")
    return tag, match.group(1)


def load_bundle(path=None, tag=None):
    """Bundle local (--bundle) ou téléchargé au tag de release (contenu figé, version connue)."""
    if path:
        print(f"Lecture du bundle local {path} ...")
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    import requests
    url = STIX_URL_AT_TAG.format(tag=quote(tag, safe="")) if tag else STIX_URL
    print(f"Téléchargement du bundle STIX ATT&CK Enterprise depuis {url} ...")
    resp = requests.get(url, timeout=900)
    resp.raise_for_status()
    return resp.json(), url


def index_bundle(bundle):
    """Indexe les objets utiles du bundle (actifs uniquement)."""
    objects = bundle.get("objects", [])
    techniques, mitigations, groups, tactics = {}, {}, {}, {}
    by_stix_id = {}
    version = None
    for obj in objects:
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            version = obj.get("x_mitre_version") or version
            continue
        if not _active(obj):
            continue
        ext = _external_id(obj)
        if kind == "attack-pattern" and ext and _TECH_RE.match(ext):
            techniques[ext] = obj
            by_stix_id[obj["id"]] = ("technique", ext)
        elif kind == "course-of-action" and ext and _MIT_RE.match(ext):
            mitigations[ext] = obj
            by_stix_id[obj["id"]] = ("mitigation", ext)
        elif kind == "intrusion-set" and ext and _GROUP_RE.match(ext):
            groups[ext] = obj
            by_stix_id[obj["id"]] = ("group", ext)
        elif kind == "x-mitre-tactic" and ext and _TACTIC_RE.match(ext):
            tactics[ext] = obj

    mitigates, uses = {}, {}
    for obj in objects:
        if obj.get("type") != "relationship" or not _active(obj):
            continue
        src = by_stix_id.get(obj.get("source_ref"))
        dst = by_stix_id.get(obj.get("target_ref"))
        if not src or not dst or dst[0] != "technique":
            continue
        if obj.get("relationship_type") == "mitigates" and src[0] == "mitigation":
            mitigates.setdefault(dst[1], set()).add(src[1])
        elif obj.get("relationship_type") == "uses" and src[0] == "group":
            uses.setdefault(dst[1], set()).add(src[1])
    return {
        "version": version, "techniques": techniques, "mitigations": mitigations,
        "groups": groups, "tactics": tactics, "mitigates": mitigates, "uses": uses,
    }


def _phases(obj):
    return sorted({p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")})


def full_name(idx, tid):
    """« Parent: Sous-technique » pour une sous-technique, comme attack.mitre.org."""
    obj = idx["techniques"][tid]
    if "." in tid:
        parent = idx["techniques"].get(tid.split(".")[0])
        if parent:
            return f"{parent.get('name', '')}: {obj.get('name', '')}"
    return obj.get("name", "")


def build_reference(idx, version=None, source=None):
    missing = [t for t in REFERENCE_TECHNIQUES if t not in idx["techniques"]]
    if missing:
        raise SystemExit(f"Techniques absentes (révoquées ?) du bundle : {missing} — mettre à jour les tables.")

    techniques, used_mitigations, used_tactics = {}, set(), set()
    for tid in REFERENCE_TECHNIQUES:
        obj = idx["techniques"][tid]
        mits = sorted(idx["mitigates"].get(tid, set()))
        group_ids = idx["uses"].get(tid, set())
        group_names = sorted(idx["groups"][g].get("name", "") for g in group_ids)
        techniques[tid] = {
            "name":          full_name(idx, tid),
            "tactics":       _phases(obj),
            "mitigations":   mits,
            "groups_count":  len(group_ids),
            "groups_sample": group_names[:5],
        }
        used_mitigations.update(mits)
        used_tactics.update(_phases(obj))

    tactics = {}
    for ta_id, obj in sorted(idx["tactics"].items()):
        short = obj.get("x_mitre_shortname")
        if short in used_tactics:
            tactics[ta_id] = {"name": obj.get("name", ""), "shortname": short}

    return {
        "attack_version": version or idx["version"] or "inconnue",
        "domain":         "enterprise-attack",
        "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source":         source or STIX_URL,
        "note":           "Généré par data/script_mitre_attack.py — ne pas modifier à la main. "
                          "groups_* : contexte seulement (relations `uses`), jamais une menace avérée.",
        "tactics":        tactics,
        "techniques":     techniques,
        "mitigations":    {m: {"name": idx["mitigations"][m].get("name", "")}
                           for m in sorted(used_mitigations)},
    }


def build_markdown(idx):
    out, count = [], 0
    selected = []
    for tid, obj in idx["techniques"].items():
        if (set(_phases(obj)) & TARGET_TACTICS) or tid in EXTRA_MD_TECHNIQUES:
            selected.append(tid)
    for tid in sorted(selected):
        obj = idx["techniques"][tid]
        out.append(f"# {tid} — {full_name(idx, tid)}\n\n")
        out.append(f"**Tactique(s)** : {', '.join(_phases(obj))}\n\n")
        out.append(f"## Description\n\n{(obj.get('description') or '').strip()}\n\n")
        detection = (obj.get("x_mitre_detection") or "").strip()
        if detection:
            out.append(f"## Détection\n\n{detection}\n\n")
        mits = sorted(idx["mitigates"].get(tid, set()))
        if mits:
            out.append("## Mitigations\n\n")
            for m in mits:
                out.append(f"- {m} — {idx['mitigations'][m].get('name', '')}\n")
            out.append("\n")
        out.append("\n---\n\n")
        count += 1

    # Mitigations des techniques du référentiel, décrites une fois chacune
    mit_ids = sorted({m for t in REFERENCE_TECHNIQUES for m in idx["mitigates"].get(t, set())})
    for m in mit_ids:
        obj = idx["mitigations"][m]
        out.append(f"# {m} — {obj.get('name', '')} (mitigation ATT&CK)\n\n")
        out.append(f"{(obj.get('description') or '').strip()}\n\n\n---\n\n")
    return "".join(out), count, len(mit_ids)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--bundle", help="bundle STIX enterprise-attack.json déjà téléchargé")
    parser.add_argument("--out-md", default=OUTPUT_MD)
    parser.add_argument("--out-json", default=OUTPUT_JSON)
    parser.add_argument("--version", help="version ATT&CK du bundle local (ex. 20.0) ; "
                                          "sans --bundle, lue sur la dernière release mitre/cti")
    args = parser.parse_args(argv)

    version, tag, source = args.version, None, None
    if args.version and not re.match(r"^\d+\.\d+$", args.version):
        raise SystemExit("--version attend la forme 20.0")
    if not args.bundle and not version:
        tag, version = latest_release()
    elif not args.bundle:
        tag = f"ATT&CK-v{version}"
    bundle, url = load_bundle(args.bundle, tag)
    source = url or (STIX_URL_AT_TAG.format(tag=quote(f"ATT&CK-v{version}", safe="")) if version else STIX_URL)
    idx = index_bundle(bundle)
    print(f"ATT&CK Enterprise v{version or idx['version']} — {len(idx['techniques'])} techniques, "
          f"{len(idx['mitigations'])} mitigations, {len(idx['groups'])} groupes actifs.")

    reference = build_reference(idx, version, source)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as fh:
        json.dump(reference, fh, ensure_ascii=False, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"Référentiel : {len(reference['techniques'])} techniques, "
          f"{len(reference['mitigations'])} mitigations → {args.out_json}")

    markdown, n_tech, n_mit = build_markdown(idx)
    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    print(f"Corpus RAG : {n_tech} techniques + {n_mit} mitigations → {args.out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
