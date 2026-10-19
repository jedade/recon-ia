# utils/mitre_attack.py
"""
Corrélation déterministe outils OSINT → techniques MITRE ATT&CK (tactiques
Reconnaissance TA0043 et Resource Development TA0042, framework Enterprise —
version renvoyée par `attack_version()`, lue dans le référentiel local
`api/data/attack_reference.json`).

Référentiel local (phase 4 du plan) : `data/script_mitre_attack.py` extrait
du bundle STIX officiel `mitre/cti` (enterprise-attack.json, ~50 Mo) un
fichier JSON compact versionné dans le dépôt — noms des techniques, tactiques,
mitigations (relations `mitigates`) et, à titre de contexte, nombre de
groupes connus (relations `uses`). Le runtime ne lit QUE ce fichier : aucun
appel réseau. `load_reference()` le charge une fois (cache mémoire) et
revalide chaque identifiant (regex) : un fichier altéré ne peut pas injecter
d'ID arbitraire dans un rapport.

Ce module ne fait AUCUN appel réseau ni au framework ATT&CK complet (le
bundle STIX complet fait ~50 Mo et ne se justifie pas pour ~47 outils) : il
s'agit d'un sous-ensemble curé et vérifié à la main, couvrant l'essentiel des
outils de `routes/recon.py::ALL_TOOLS`. La correspondance outil → technique
est un fait déterministe (documenté ci-dessous avec sa source), jamais
laissée à l'appréciation du LLM — ça évite les IDs de technique hallucinés
dans le rapport final.

La quasi-totalité des mitigations officielles ATT&CK pour la tactique
Reconnaissance renvoient à une mitigation générique unique, M1056
(Pre-compromise) : « réduire l'exposition d'information est difficile à
garantir mais augmente le coût d'une attaque ». Le champ `advice` ci-dessous
traduit ça en recommandation concrète et actionnable pour CE projet, plutôt
que de répéter le texte générique ATT&CK.

Référence : https://attack.mitre.org/tactics/TA0043/
"""
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Identifiants ATT&CK au format strict (technique, sous-technique, mitigation,
# tactique, groupe). Tout ID qui ne correspond pas est rejeté, d'où qu'il vienne.
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MITIGATION_ID_RE = re.compile(r"^M\d{4}$")
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
GROUP_ID_RE = re.compile(r"^G\d{4}$")

REFERENCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "attack_reference.json"
)

_ref_lock = threading.Lock()
_ref_cache: Dict[str, Any] = {}


def _clean_text(value: Any, limit: int = 200) -> str:
    """Texte court du référentiel : caractères de contrôle retirés, longueur bornée."""
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    return text[:limit]


def _validate_reference(raw: Any) -> Optional[Dict[str, Any]]:
    """
    Revalide le référentiel chargé : seules les entrées dont l'ID respecte le
    format ATT&CK sont conservées, les textes sont bornés. Retourne None si la
    structure est inutilisable.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("techniques"), dict):
        return None
    mitigations = {}
    for mid, meta in (raw.get("mitigations") or {}).items():
        if isinstance(mid, str) and MITIGATION_ID_RE.match(mid) and isinstance(meta, dict):
            mitigations[mid] = {"name": _clean_text(meta.get("name"), 120)}
    tactics = {}
    for tid, meta in (raw.get("tactics") or {}).items():
        if isinstance(tid, str) and TACTIC_ID_RE.match(tid) and isinstance(meta, dict):
            short = _clean_text(meta.get("shortname"), 40)
            if re.match(r"^[a-z-]+$", short):
                tactics[tid] = {"name": _clean_text(meta.get("name"), 60), "shortname": short}
    shortnames = {t["shortname"] for t in tactics.values()}
    techniques = {}
    for tid, meta in raw["techniques"].items():
        if not (isinstance(tid, str) and TECHNIQUE_ID_RE.match(tid) and isinstance(meta, dict)):
            continue
        techniques[tid] = {
            "name":        _clean_text(meta.get("name"), 160),
            "tactics":     [t for t in (meta.get("tactics") or []) if t in shortnames],
            "mitigations": [m for m in (meta.get("mitigations") or []) if m in mitigations],
            "groups_count": meta["groups_count"] if isinstance(meta.get("groups_count"), int) and meta["groups_count"] > 0 else 0,
            "groups_sample": [_clean_text(g, 60) for g in (meta.get("groups_sample") or [])[:5]],
        }
    return {
        "attack_version": _clean_text(raw.get("attack_version"), 20) or "inconnue",
        "domain":         _clean_text(raw.get("domain"), 40) or "enterprise-attack",
        "generated_at":   _clean_text(raw.get("generated_at"), 40),
        "source":         _clean_text(raw.get("source"), 200),
        "tactics":        tactics,
        "techniques":     techniques,
        "mitigations":    mitigations,
    }


def load_reference(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Référentiel ATT&CK local (voir docstring du module), chargé une fois.
    En cas d'absence ou de corruption du fichier : référentiel VIDE (aucune
    technique reconnue — fail closed, jamais d'ID non vérifié) + erreur
    journalisée.
    """
    target = path or REFERENCE_PATH
    with _ref_lock:
        cached = _ref_cache.get(target)
        if cached is not None:
            return cached
        try:
            with open(target, "r", encoding="utf-8") as fh:
                ref = _validate_reference(json.load(fh))
        except Exception as e:
            logger.error("[mitre] Référentiel ATT&CK illisible (%s) : %s", target, e)
            ref = None
        if ref is None:
            ref = {"attack_version": "inconnue", "domain": "enterprise-attack", "generated_at": "",
                   "source": "", "tactics": {}, "techniques": {}, "mitigations": {}}
        _ref_cache[target] = ref
        return ref


def _reset_reference_cache() -> None:
    """Tests uniquement."""
    with _ref_lock:
        _ref_cache.clear()


def attack_version() -> str:
    """Version ATT&CK Enterprise du référentiel local (ex. « 18.0 »)."""
    return load_reference()["attack_version"]


# ──────────────────────────────────────────────────────────────────────────
#  Techniques ATT&CK pertinentes pour de l'OSINT passif
# ──────────────────────────────────────────────────────────────────────────
TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1590.001": {
        "name": "Gather Victim Network Information: Domain Properties",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Activer le WHOIS privacy/proxy chez le registrar et limiter les métadonnées "
                  "d'enregistrement de domaine exposées publiquement.",
    },
    "T1590.002": {
        "name": "Gather Victim Network Information: DNS",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Activer DNSSEC, retirer les enregistrements DNS obsolètes/verbeux (TXT internes, "
                  "SPF/DKIM mal scopés) et auditer régulièrement la zone DNS publiée.",
    },
    "T1590.004": {
        "name": "Gather Victim Network Information: Network Topology",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Segmenter les plages IP/ASN publiques et éviter d'exposer la topologie interne "
                  "via des enregistrements PTR ou des routes BGP trop détaillés.",
    },
    "T1590.005": {
        "name": "Gather Victim Network Information: IP Addresses",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Placer les services non essentiels derrière un CDN/reverse proxy pour masquer "
                  "l'IP d'origine, et surveiller la réputation de ses propres plages IP (DNSBL).",
    },
    "T1592.002": {
        "name": "Gather Victim Host Information: Software",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Supprimer/minimiser les bannières de version (Server, X-Powered-By) et maintenir "
                  "les composants à jour puisque la stack technique est de toute façon déductible.",
    },
    "T1593.002": {
        "name": "Search Open Websites/Domains: Search Engines",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Vérifier périodiquement web.archive.org pour ce domaine : des URLs ou fichiers "
                  "sensibles retirés du site peuvent rester indexés indéfiniment.",
    },
    "T1593.003": {
        "name": "Search Open Websites/Domains: Code Repositories",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Auditer les dépôts publics de l'organisation (secrets, sous-domaines internes "
                  "cités dans le code/CI) — envisager trufflehog/gitleaks en scan périodique.",
    },
    "T1594": {
        "name": "Search Victim-Owned Websites",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Revoir robots.txt/sitemap.xml pour ne pas lister par inadvertance des chemins "
                  "sensibles, et auditer les bundles JS pour des endpoints d'API non documentés.",
    },
    "T1596.001": {
        "name": "Search Open Technical Databases: DNS/Passive DNS",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Partir du principe que tout sous-domaine ayant existé un jour est découvrable "
                  "via la Passive DNS — décommissionner proprement (DNS + certificat) plutôt que "
                  "de simplement arrêter le service.",
    },
    "T1596.003": {
        "name": "Search Open Technical Databases: Digital Certificates",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Les logs Certificate Transparency sont publics par design (RFC 6962) : surveiller "
                  "crt.sh sur son propre domaine pour détecter des certificats émis pour des "
                  "sous-domaines non autorisés (typosquatting, shadow IT).",
    },
    "T1596.005": {
        "name": "Search Open Technical Databases: Scan Databases",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Les bannières et CVE remontées par Shodan/InternetDB reflètent un scan déjà "
                  "public — traiter tout CVE listé ici comme prioritaire, il est trivialement "
                  "trouvable par un attaquant.",
    },
    # Phase 5 : techniques des nouveaux outils passifs
    "T1593": {
        "name": "Search Open Websites/Domains",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Surveiller la présence du domaine dans les listes de menaces publiques "
                  "(Safe Browsing, PhishTank) : un signalement y est visible de tous, attaquants compris.",
    },
    "T1593.001": {
        "name": "Search Open Websites/Domains: Social Media",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Relire les balises Open Graph/Twitter et les liens sortants de la page d'accueil : "
                  "ils révèlent comptes sociaux et prestataires tiers utilisables en ingénierie sociale.",
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Classements, réputation et listes de blocage sont publics : vérifier régulièrement "
                  "comment le domaine y apparaît et corriger les signalements légitimes.",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic_id": "TA0006", "tactic": "Credential Access",
        "note": "Risque projeté : des secrets publiés dans du code public sont directement réutilisables.",
        "advice": "Révoquer puis faire tourner immédiatement tout secret trouvé dans un dépôt public, "
                  "purger l'historique et activer le secret scanning.",
    },
    "T1589.002": {
        "name": "Gather Victim Identity Information: Email Addresses",
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "advice": "Les adresses email exposées dans des fuites connues alimentent le phishing ciblé "
                  "et le credential stuffing — forcer MFA sur les comptes correspondants et "
                  "sensibiliser les personnes concernées.",
    },
    "T1584.001": {
        "name": "Compromise Infrastructure: Domains",
        "tactic_id": "TA0042", "tactic": "Resource Development",
        "note": "Risque projeté, pas une technique de reconnaissance : un sous-domaine "
                "vulnérable au takeover peut être détourné pour héberger du phishing sous le nom "
                "de la victime.",
        "advice": "Retirer l'enregistrement DNS orphelin ou reprendre possession de la ressource "
                  "cloud pointée immédiatement — un takeover actif est une urgence, pas juste un "
                  "finding.",
    },
    # Phase 4 : le typosquatting relevait auparavant de T1584.001 (Compromise
    # Infrastructure). Un domaine imitant la marque est ENREGISTRÉ par un tiers,
    # il n'est pas compromis : la technique exacte est T1583.001 (Acquire
    # Infrastructure: Domains).
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic_id": "TA0042", "tactic": "Resource Development",
        "note": "Risque projeté : des domaines imitant la marque ont été enregistrés par des tiers "
                "(typosquatting) et peuvent servir de support à du phishing.",
        "advice": "Surveiller les domaines suspects avec MX configuré (campagne active probable) "
                  "et envisager un dépôt UDRP si l'usage est manifestement malveillant.",
    },
}

# ──────────────────────────────────────────────────────────────────────────
#  Outil (clé de `ALL_TOOLS`) → technique(s) ATT&CK associée(s)
# ──────────────────────────────────────────────────────────────────────────
TOOL_TECHNIQUES: Dict[str, List[str]] = {
    "whois":               ["T1590.001"],
    "rdap_info":           ["T1590.001"],
    "dns":                 ["T1590.002"],
    "dns_records":         ["T1590.002"],
    "dnssec":              ["T1590.002"],
    "email_config":        ["T1590.002"],
    "dkim_check":          ["T1590.002"],
    "spf_analysis":        ["T1590.002"],
    "ip_info":             ["T1590.005"],
    "ptr_records":         ["T1590.005"],
    "dnsbl_check":         ["T1590.005"],
    "asn_info":            ["T1590.004"],
    "reverse_ip":          ["T1590.004"],
    "ssl_info":            ["T1592.002"],
    "tls_config":          ["T1592.002"],
    "headers":             ["T1592.002"],
    "security_headers":    ["T1592.002"],
    "tech_stack":          ["T1592.002"],
    "waf_detection":       ["T1592.002"],
    "archive_history":     ["T1593.002"],
    "github":              ["T1593.003"],
    "redirect_chain":      ["T1594"],
    "robots_txt":          ["T1594"],
    "sitemap":             ["T1594"],
    "security_txt":        ["T1594"],
    "js_endpoints":        ["T1594"],
    "subfinder":           ["T1596.001"],
    "assetfinder":         ["T1596.001"],
    "amass":               ["T1596.001"],
    "otx_passive_dns":     ["T1596.001"],
    "crtsh":               ["T1596.003"],
    "favicon_hash":        ["T1596.005"],
    "shodan_internetdb":   ["T1596.005"],
    "xposedornot_breaches": ["T1589.002"],
    "subdomain_takeover":  ["T1584.001"],
    "typosquatting":       ["T1583.001"],
    "gau_urls":            ["T1594"],
    "urlscan_search":      ["T1593.002"],
    "dmarc_check":         ["T1590.002"],
    "mta_sts_check":       ["T1590.002"],
    "tlsrpt_check":        ["T1590.002"],
    "bimi_check":          ["T1590.002"],
    "caa_check":           ["T1596.003"],
    "dane_check":          ["T1596.003"],
    "http_observatory":    ["T1592.002"],
    "abuseipdb_check":     ["T1590.005"],
    # Phase 5 — collecte passive enrichie
    "dns_mass":            ["T1590.002", "T1590.005", "T1596.001", "T1590.001"],
    "blocklists":          ["T1596.001"],
    "threats_check":       ["T1596", "T1593"],
    "web_metadata":        ["T1593.001", "T1592.002"],
    "site_ranking":        ["T1590.001", "T1596"],
    "virustotal":          ["T1596.001", "T1596.005", "T1590.005"],
    "dnsdumpster":         ["T1590.002", "T1596.001", "T1590.005"],
    "grayhatwarfare":      ["T1596", "T1593.003"],
    "github_dorks":        ["T1593.003", "T1552.001"],
}


def map_tools_to_techniques(tools_executed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Corrèle les outils réellement exécutés (issus de `_tools_executed`) aux
    techniques ATT&CK associées.

    Args:
        tools_executed: liste de {"key", "name", "category", "status"}

    Returns:
        Liste triée (tactique puis technique) de :
        {technique_id, technique_name, tactic_id, tactic, advice, note,
         matched_tools: [clés d'outils ayant produit un résultat exploitable]}
        Vide si aucun outil connu n'a été exécuté avec succès.
    """
    matches: Dict[str, List[str]] = {}
    for tool in tools_executed or []:
        if tool.get("status") not in (None, "success", "ok"):
            continue
        key = tool.get("key")
        for technique_id in TOOL_TECHNIQUES.get(key, []):
            matches.setdefault(technique_id, []).append(key)

    result = []
    for technique_id, tool_keys in matches.items():
        meta = TECHNIQUES.get(technique_id)
        if not meta:
            continue
        result.append({
            "technique_id":   technique_id,
            "technique_name": meta["name"],
            "tactic_id":      meta["tactic_id"],
            "tactic":         meta["tactic"],
            "advice":         meta["advice"],
            "note":           meta.get("note"),
            "matched_tools":  sorted(set(tool_keys)),
        })

    return sorted(result, key=lambda r: (r["tactic_id"], r["technique_id"]))
