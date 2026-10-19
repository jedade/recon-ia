# utils/attack_enablement.py
"""
Constat → techniques ATT&CK « rendues possibles » + mitigations (plan
d'action, phase 4, B8).

`utils/mitre_attack.py` répond à « quelles informations notre méthode
collecte-t-elle » (outil → technique de Reconnaissance). Ce module répond à
« qu'est-ce que CETTE exposition permet à un attaquant » : une table
DÉTERMINISTE relie un type de constat à des techniques d'Initial Access,
Credential Access ou Resource Development, et à leurs mitigations.

    DMARC absent / p=none                → T1566              M1054, M1017
    Typosquatting (+ MX configuré)       → T1583.001 (→ T1566) M1056 (+ M1017)
    CVE exposée présente dans KEV        → T1190              M1051, M1050
    VPN / RDP / Citrix / admin exposé    → T1133              M1032, M1035
    Adresses du domaine dans des fuites  → T1078, T1110.004   M1032, M1027
    Sous-domaine vulnérable au takeover  → T1584.001          M1056 (nettoyage des CNAME)
    .env / .git / config dans archives   → T1552.001          M1022
    Secrets dans GitHub                  → T1593.003 → T1552  M1013, M1047, M1027

Règles de confiance :
- SEULE la table fait foi. Les champs `attack_enabled` / `mitigations`
  éventuellement produits par le LLM sont ignorés et ÉCRASÉS ; un ID absent
  du référentiel local (`api/data/attack_reference.json`, revalidé par regex)
  n'est jamais émis.
- Mitigations : les mitigations préférées de la table ne sont gardées que si
  le bundle STIX (relations `mitigates`) les rattache bien à l'une des
  techniques de la règle ; sinon on retombe sur les mitigations officielles
  de ces techniques.
- Idempotent : les champs dérivés sont recalculés à partir des seuls champs
  d'entrée (category, source_tool(s), severity_rule, titre, preuve), jamais à
  partir d'eux-mêmes. Appeler deux fois donne le même résultat.
- Les `signals` (contexte compact de routes/analyze.py::_extract_signals)
  servent seulement à CONFIRMER ou INFIRMER : un constat « takeover » alors que
  l'outil a compté 0 sous-domaine vulnérable n'ouvre aucune technique (LLM qui
  extrapole), un typosquatting n'ouvre T1566 que si un MX est configuré.
- Un constat de sévérité INFO ne rend aucune technique possible.

API publique :
    annotate_findings(findings, signals) -> list[dict]
    build_attack_chain(findings) -> list[dict]
    build_navigator_layer(findings, mitre_attack=None, domain="") -> dict
    attack_csv_fields(finding) -> dict           (pour l'export CSV)
"""
import logging
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional

from utils.mitre_attack import (
    MITIGATION_ID_RE, TECHNIQUE_ID_RE, TOOL_TECHNIQUES, load_reference,
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Étapes de la chaîne d'attaque, dans l'ordre où un attaquant les enchaîne.
# Les identifiants obtenus (Credential Access) alimentent l'accès initial
# (T1078, T1133) : ils viennent donc AVANT dans la chaîne.
STAGES = [
    {"key": "reconnaissance",       "tactic_id": "TA0043", "tactic": "Reconnaissance",
     "label": "Reconnaissance"},
    {"key": "resource-development", "tactic_id": "TA0042", "tactic": "Resource Development",
     "label": "Préparation de l'infrastructure"},
    {"key": "credential-access",    "tactic_id": "TA0006", "tactic": "Credential Access",
     "label": "Obtention d'identifiants"},
    {"key": "initial-access",       "tactic_id": "TA0001", "tactic": "Initial Access",
     "label": "Accès initial"},
]
_STAGE_INDEX = {s["key"]: i for i, s in enumerate(STAGES)}

# Étape de chaîne de chaque technique de la table (une technique peut relever
# de plusieurs tactiques ATT&CK — T1078 : Initial Access, Persistence… — on
# retient celle qui a un sens pour une exposition externe).
TECHNIQUE_STAGE = {
    "T1593.003": "reconnaissance",
    "T1583.001": "resource-development",
    "T1584.001": "resource-development",
    "T1110.004": "credential-access",
    "T1552":     "credential-access",
    "T1552.001": "credential-access",
    "T1566":     "initial-access",
    "T1190":     "initial-access",
    "T1133":     "initial-access",
    "T1078":     "initial-access",
}

_FID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ──────────────────────────────────────────────────────────────────────────
#  Normalisation du texte des constats
# ──────────────────────────────────────────────────────────────────────────

def _norm(value: Any) -> str:
    """Minuscules, sans accents, espaces réduits — pour la reconnaissance par mots-clés."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKD", str(value)[:2000])
    text = "".join(c for c in text if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", text.lower()).strip()


def _has(text: str, words: Iterable[str]) -> bool:
    return any(w in text for w in words)


def _has_word(text: str, words: Iterable[str]) -> bool:
    """Mot entier (évite « rdp » dans « wordpress », « vpn » dans un hash…)."""
    return any(re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text) for w in words)


def _severity(finding: dict) -> str:
    sev = str(finding.get("severity") or "").upper()
    return sev if sev in SEVERITY_ORDER else "INFO"


def _tools(finding: dict) -> set:
    tools = set()
    primary = finding.get("source_tool")
    if isinstance(primary, str):
        tools.add(primary.strip().lower())
    extra = finding.get("source_tools")
    if isinstance(extra, list):
        tools.update(t.strip().lower() for t in extra if isinstance(t, str))
    return tools


def _g(d: Any, *keys) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


class _Ctx:
    """Vue normalisée d'un constat, calculée une fois par constat."""

    def __init__(self, finding: dict):
        self.title = _norm(finding.get("title"))
        self.category = _norm(finding.get("category"))
        self.rule = _norm(finding.get("severity_rule")).replace("-", "_")
        self.evidence = _norm(finding.get("evidence"))
        self.tools = _tools(finding)
        # Titre + catégorie + règle : le cœur de la reconnaissance. La
        # description (texte libre du LLM) n'est volontairement PAS utilisée :
        # elle cite souvent d'autres sujets que le constat lui-même.
        self.head = " ".join(x for x in (self.title, self.category, self.rule.replace("_", " ")) if x)
        self.all = self.head + " " + self.evidence


# ──────────────────────────────────────────────────────────────────────────
#  Prédicats de reconnaissance (constat, signals) → bool
# ──────────────────────────────────────────────────────────────────────────

_NEGATIVE = ("absent", "manquant", "missing", "aucun", "aucune", "pas de", "sans ", "none",
             "faible", "weak", "surveillance", "monitor", "permissi", "non configur",
             "inexistant", "not configured", "not set", "insuffis", "non applique",
             "non publie", "not found", "introuvable", "p=none", "invalide", "invalid")


def _match_dmarc(c: _Ctx, signals: dict) -> bool:
    tokens = set(c.rule.split("_"))
    by_rule = "dmarc" in tokens and not (tokens & {"ok", "strict", "reject", "quarantine", "present", "valid"})
    by_text = "dmarc" in c.head and _has(c.head, _NEGATIVE)
    if not (by_rule or by_text):
        return False
    # Infirmation : l'outil a vu une politique DMARC appliquée (reject /
    # quarantine) → le LLM se trompe, aucune technique.
    dmarc = _g(signals, "email", "dmarc")
    if isinstance(dmarc, dict) and dmarc.get("present") is True:
        policy = str(dmarc.get("policy") or "").lower()
        pct = dmarc.get("percentage")
        if policy in ("reject", "quarantine") and (not isinstance(pct, int) or pct >= 100):
            return False
    return True


def _typosquat_mx(c: _Ctx, signals: dict) -> bool:
    count = _g(signals, "brand_protection", "mx_configured_count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count > 0
    return _has_word(c.all, ("mx",))


def _match_typosquat(c: _Ctx, signals: dict) -> bool:
    by_rule = "typosquat" in c.rule
    by_text = _has(c.head, ("typosquat", "typo-squat", "domaine similaire", "domaines similaires",
                            "lookalike", "look-alike", "domaine imitant", "domaines imitant",
                            "usurpation de marque", "brand impersonation"))
    by_tool = "typosquatting" in c.tools and not _has(c.head, ("aucun", "no suspicious"))
    if not (by_rule or by_text or by_tool):
        return False
    status = _g(signals, "brand_protection", "status")
    suspicious = _g(signals, "brand_protection", "suspicious_domains")
    if status == "success" and isinstance(suspicious, list) and not suspicious:
        return False
    return True


def _kev_flag_in_signals(signals: dict, cves: set) -> bool:
    """CVE marquée KEV dans les signaux (vulns_enriched) — sans aucun appel réseau."""
    enriched = _g(signals, "network", "shodan_internetdb", "vulns_enriched")
    if isinstance(enriched, list):
        for entry in enriched:
            if not isinstance(entry, dict):
                continue
            cve = str(entry.get("cve") or entry.get("id") or entry.get("cve_id") or "").upper()
            if (not cves or cve in cves) and any(entry.get(k) for k in ("kev", "in_kev", "known_exploited")):
                return True
    kev = signals.get("kev") if isinstance(signals, dict) else None
    if isinstance(kev, dict):
        listed = {str(k).upper() for k in kev.keys()} | {
            str(x).upper() for x in (kev.get("cves") or kev.get("listed") or []) if isinstance(x, str)}
        if cves & listed:
            return True
    return False


def _kev_cache_hit(cves: set) -> bool:
    """Cache local du catalogue CISA KEV (utils/kev.py, phase 3) — jamais de téléchargement ici."""
    if not cves:
        return False
    try:
        from utils.kev import kev_entries
        return bool(kev_entries(cves, allow_fetch=False))
    except Exception:
        return False


def _match_kev(c: _Ctx, signals: dict) -> bool:
    if "kev" in c.rule:
        return True
    if _has_word(c.head, ("kev",)) or _has(c.head, ("known exploited", "activement exploit",
                                                    "exploitee dans la nature", "exploitees dans la nature",
                                                    "exploited in the wild")):
        return True
    cves = {m.upper() for m in _CVE_RE.findall(c.title + " " + c.evidence)}
    if not cves:
        return False
    return _kev_flag_in_signals(signals, cves) or _kev_cache_hit(cves)


_REMOTE_WORDS = ("rdp", "vpn", "citrix", "netscaler", "fortigate", "fortinet", "globalprotect",
                 "anyconnect", "pulse secure", "ivanti", "ssl-vpn", "sslvpn", "vnc", "telnet",
                 "winrm", "ssh", "3389", "5900", "teamviewer", "anydesk")
_ADMIN_WORDS = ("panneau d'admin", "panneau admin", "panneau d administration", "interface d'admin",
                "interface d administration", "interface admin", "console d'admin",
                "console d administration", "admin panel", "administration panel", "back-office",
                "backoffice", "phpmyadmin", "wp-admin", "wp-login", "cpanel", "plesk", "webmin",
                "/admin", "admin.", "page de connexion admin", "acces distant", "remote access",
                "remote desktop", "bureau a distance", "prise en main a distance")


def _match_remote(c: _Ctx, signals: dict) -> bool:
    if _has(c.rule, ("remote", "rdp", "vpn", "citrix", "admin_panel", "admin_exposed",
                     "exposed_admin", "exposed_service", "ssh_exposed")):
        return True
    if _has_word(c.head, _REMOTE_WORDS) or _has(c.head, _ADMIN_WORDS):
        # « SSH correctement filtré » / « aucun RDP exposé » : pas une exposition
        return not _has(c.head, ("aucun", "non expose", "not exposed", "filtre", "ferme"))
    return False


def _match_leaks(c: _Ctx, signals: dict) -> bool:
    by_rule = _has(c.rule, ("breach", "leak", "fuite", "credential"))
    by_tool = "xposedornot_breaches" in c.tools
    by_text = (_has(c.head, ("fuite", "breach", "leak", "compromis", "violation de donnees",
                             "credential stuffing", "pwned"))
               and _has(c.head, ("adresse", "email", "e-mail", "mail", "compte", "account",
                                 "identifiant", "credential", "mot de passe", "password")))
    if not (by_rule or by_tool or by_text):
        return False
    if _has(c.head, ("secret", "github", "cle api", "api key", "token")) and not by_tool:
        return False  # secrets de code : règle dédiée
    count = _g(signals, "breaches", "breach_count")
    if isinstance(count, int) and not isinstance(count, bool) and count == 0:
        return False
    return True


def _match_takeover(c: _Ctx, signals: dict) -> bool:
    by_rule = "takeover" in c.rule
    by_text = _has(c.head, ("takeover", "prise de controle de sous-domaine", "detournement de sous-domaine",
                            "cname orphelin", "cname pendant", "dangling", "sous-domaine orphelin"))
    if not (by_rule or by_text):
        return False
    if _has(c.head, ("aucun", "no takeover", "non vulnerable")):
        return False
    count = _g(signals, "subdomains", "takeover", "vulnerable_count")
    if isinstance(count, int) and not isinstance(count, bool) and count == 0:
        return False
    return True


_ARCHIVE_TOOLS = {"archive_history", "gau_urls", "urlscan_search"}
_SENSITIVE_FILES = (".env", ".git", "wp-config", "config.php", "configuration.php", "settings.py",
                    ".htpasswd", ".sql", "dump", "backup", ".bak", "credentials", "secrets",
                    "fichier sensible", "fichiers sensibles", "sensitive file", "fichier de configuration",
                    "fichiers de configuration", "config file")


def _match_archives(c: _Ctx, signals: dict) -> bool:
    if _has(c.rule, ("archive", "sensitive_file", "exposed_file", "git_exposed", "env_exposed")):
        return True
    if not _has(c.head, _SENSITIVE_FILES):
        return False
    return bool(c.tools & _ARCHIVE_TOOLS) or _has(c.head, ("archive", "wayback", "historique",
                                                          "url historique", "urls historiques"))


def _match_github(c: _Ctx, signals: dict) -> bool:
    secret_words = ("secret", "cle api", "cles api", "api key", "token", "jeton", "mot de passe",
                    "password", "credential", "identifiant", "private key", "cle privee", "aws_")
    if "github" in c.rule and _has(c.rule, ("secret", "leak", "credential", "key", "token")):
        return True
    in_repo = "github" in c.tools or _has(c.head, ("github", "gitlab", "depot public", "depots publics",
                                                  "public repo", "code source public"))
    return in_repo and _has(c.head, secret_words)


# ──────────────────────────────────────────────────────────────────────────
#  Table déterministe
# ──────────────────────────────────────────────────────────────────────────
# `techniques` : chaîne de la règle, dans l'ordre (la 1re mène à la suivante).
# `mitigations` : mitigations préférées (plan), filtrées par le bundle STIX.
# `advice` : mesure concrète quand ATT&CK n'a qu'une mitigation générique.
RULES: List[Dict[str, Any]] = [
    {"rule": "dmarc_weak", "match": _match_dmarc,
     "techniques": ["T1566"], "mitigations": ["M1054", "M1017"],
     "advice": "Publier DMARC en p=quarantine puis p=reject (RFC 7489) et former les utilisateurs "
               "au repérage des mails usurpés."},
    {"rule": "typosquatting", "match": _match_typosquat,
     "techniques": ["T1583.001"], "mitigations": ["M1056"],
     "with_mx": {"techniques": ["T1566"], "mitigations": ["M1017"]},
     "advice": "Surveillance de marque : suivre les domaines imitant le vôtre, signaler ceux qui "
               "ont un MX (campagne de phishing probable), procédure UDRP si nécessaire."},
    {"rule": "cve_kev", "match": _match_kev,
     "techniques": ["T1190"], "mitigations": ["M1051", "M1050"],
     "advice": "Corriger en priorité absolue : la CVE figure au catalogue CISA KEV (exploitée "
               "dans la nature)."},
    {"rule": "remote_service_exposed", "match": _match_remote,
     "techniques": ["T1133"], "mitigations": ["M1032", "M1035"],
     "advice": "Placer l'accès distant ou d'administration derrière un VPN ou une liste "
               "d'adresses autorisées, avec authentification multifacteur."},
    {"rule": "breached_accounts", "match": _match_leaks,
     "techniques": ["T1110.004", "T1078"], "mitigations": ["M1032", "M1027"],
     "advice": "Réinitialiser les mots de passe des comptes concernés, imposer le MFA et bloquer "
               "les mots de passe connus des fuites."},
    {"rule": "subdomain_takeover", "match": _match_takeover,
     "techniques": ["T1584.001"], "mitigations": ["M1056"],
     "advice": "Nettoyage des CNAME : supprimer l'enregistrement DNS orphelin ou reprendre la "
               "ressource cloud pointée, immédiatement."},
    {"rule": "archived_sensitive_files", "match": _match_archives,
     "techniques": ["T1552.001"], "mitigations": ["M1022"],
     "advice": "Considérer les secrets de ces fichiers comme compromis (rotation), interdire "
               "l'accès web aux fichiers de configuration et demander leur retrait des archives."},
    {"rule": "github_secrets", "match": _match_github,
     "techniques": ["T1593.003", "T1552"], "mitigations": ["M1013", "M1047", "M1027"],
     "advice": "Rotation immédiate des secrets exposés, purge de l'historique Git et scan "
               "automatique des dépôts (gitleaks, trufflehog)."},
]


# ──────────────────────────────────────────────────────────────────────────
#  Résolution des ID (référentiel local)
# ──────────────────────────────────────────────────────────────────────────

def _technique_entry(tid: str, ref: dict) -> Optional[Dict[str, str]]:
    if not isinstance(tid, str) or not TECHNIQUE_ID_RE.match(tid):
        return None
    meta = ref["techniques"].get(tid)
    if not meta:
        return None
    return {"id": tid, "name": meta["name"]}


def _mitigations_for(preferred: List[str], techniques: List[str], ref: dict) -> List[str]:
    official = set()
    for tid in techniques:
        official.update((ref["techniques"].get(tid) or {}).get("mitigations") or [])
    kept = [m for m in preferred if MITIGATION_ID_RE.match(m) and m in official]
    if kept:
        return kept
    return sorted(official)


def _match_rule(rule: dict, ctx: _Ctx, signals: dict) -> bool:
    try:
        return bool(rule["match"](ctx, signals))
    except Exception as e:  # une règle défaillante ne doit jamais casser l'analyse
        logger.warning("[attack] Règle %s en erreur : %s", rule["rule"], e)
        return False


def _annotate_one(finding: dict, signals: dict, ref: dict) -> dict:
    out = dict(finding)
    techniques: List[str] = []
    mitigations: List[str] = []
    rules: List[str] = []
    advice: List[str] = []

    if _severity(finding) != "INFO":
        ctx = _Ctx(finding)
        for rule in RULES:
            if not _match_rule(rule, ctx, signals):
                continue
            rule_techs = list(rule["techniques"])
            preferred = list(rule["mitigations"])
            extra = rule.get("with_mx")
            if extra and _typosquat_mx(ctx, signals):
                rule_techs += extra["techniques"]
                preferred += extra["mitigations"]
            rule_techs = [t for t in rule_techs if _technique_entry(t, ref)]
            if not rule_techs:
                continue
            rules.append(rule["rule"])
            advice.append(rule["advice"])
            for t in rule_techs:
                if t not in techniques:
                    techniques.append(t)
            for m in _mitigations_for(preferred, rule_techs, ref):
                if m not in mitigations:
                    mitigations.append(m)

    techniques.sort(key=lambda t: (_STAGE_INDEX.get(TECHNIQUE_STAGE.get(t, ""), 99), t))
    out["attack_enabled"] = [_technique_entry(t, ref) for t in techniques]
    out["mitigations"] = [{"id": m, "name": ref["mitigations"][m]["name"]}
                          for m in mitigations if m in ref["mitigations"]]
    out["attack_rules"] = rules
    out["mitigation_advice"] = " ".join(advice)
    return out


def annotate_findings(findings: List[dict], signals: Optional[dict] = None) -> List[dict]:
    """
    Ajoute à chaque constat (copie superficielle, l'entrée n'est pas modifiée) :
      attack_enabled    [{id, name}]  techniques rendues possibles (table seule)
      mitigations       [{id, name}]  mitigations ATT&CK (relations `mitigates`)
      attack_rules      [str]         règles de la table qui ont reconnu le constat
      mitigation_advice str           mesure concrète (vide si aucune règle)
    Toute valeur préexistante de ces champs (LLM, appel précédent) est
    remplacée. Les éléments qui ne sont pas des dict sont rendus tels quels.
    """
    if not isinstance(findings, list):
        return []
    signals = signals if isinstance(signals, dict) else {}
    ref = load_reference()
    out = []
    for f in findings:
        out.append(_annotate_one(f, signals, ref) if isinstance(f, dict) else f)
    return out


# ──────────────────────────────────────────────────────────────────────────
#  Chaîne d'attaque plausible
# ──────────────────────────────────────────────────────────────────────────

def _finding_id(finding: dict, index: int) -> str:
    fid = finding.get("id")
    if isinstance(fid, str) and _FID_RE.match(fid.strip()):
        return fid.strip()
    return f"F-{index:03d}"


def _max_severity(sevs: Iterable[str]) -> str:
    sevs = list(sevs)
    for s in SEVERITY_ORDER:
        if s in sevs:
            return s
    return "INFO"


def _recon_techniques(finding: dict, ref: dict) -> List[str]:
    """Techniques de reconnaissance qui ont permis d'observer le constat (outil source)."""
    out = []
    for tool in sorted(_tools(finding)):
        for tid in TOOL_TECHNIQUES.get(tool, []):
            meta = ref["techniques"].get(tid)
            if meta and "reconnaissance" in meta.get("tactics", []) and tid not in out:
                out.append(tid)
    return out


def build_attack_chain(findings: List[dict]) -> List[dict]:
    """
    Chaîne d'attaque plausible déduite des constats ANNOTÉS (annotate_findings) :
    reconnaissance → préparation de l'infrastructure → obtention
    d'identifiants → accès initial. Les ID ATT&CK sont revalidés contre le
    référentiel (jamais repris aveuglément du constat) ; le récit éventuel est
    rédigé ailleurs (LLM) à partir de cette structure.

    Retourne [] si aucun constat ne rend de technique possible, sinon une
    liste d'étapes non vides, dans l'ordre :
      {order, stage, label, tactic_id, tactic, max_severity,
       finding_ids: [str],
       techniques: [{id, name, finding_ids: [str], max_severity}]}
    """
    if not isinstance(findings, list):
        return []
    ref = load_reference()
    stages: Dict[str, Dict[str, Dict[str, Any]]] = {s["key"]: {} for s in STAGES}

    def add(stage: str, tid: str, fid: str, sev: str):
        entry = _technique_entry(tid, ref)
        if not entry:
            return
        slot = stages[stage].setdefault(tid, {**entry, "finding_ids": [], "_sevs": []})
        if fid not in slot["finding_ids"]:
            slot["finding_ids"].append(fid)
        slot["_sevs"].append(sev)

    enabled_any = False
    for i, f in enumerate(findings, 1):
        if not isinstance(f, dict):
            continue
        enabled = [t.get("id") for t in (f.get("attack_enabled") or []) if isinstance(t, dict)]
        # Seules les techniques de la table, revalidées (ID et référentiel)
        enabled = [t for t in enabled if isinstance(t, str) and t in TECHNIQUE_STAGE
                   and _technique_entry(t, ref)]
        if not enabled:
            continue
        enabled_any = True
        fid, sev = _finding_id(f, i), _severity(f)
        for tid in _recon_techniques(f, ref):
            add("reconnaissance", tid, fid, sev)
        for tid in enabled:
            add(TECHNIQUE_STAGE[tid], tid, fid, sev)

    if not enabled_any:
        return []

    chain = []
    for stage in STAGES:
        techs = stages[stage["key"]]
        if not techs:
            continue
        tech_list = []
        for tid in sorted(techs):
            slot = techs[tid]
            tech_list.append({"id": slot["id"], "name": slot["name"],
                              "finding_ids": slot["finding_ids"],
                              "max_severity": _max_severity(slot["_sevs"])})
        finding_ids = []
        for t in tech_list:
            finding_ids += [x for x in t["finding_ids"] if x not in finding_ids]
        chain.append({
            "order":        len(chain) + 1,
            "stage":        stage["key"],
            "label":        stage["label"],
            "tactic_id":    stage["tactic_id"],
            "tactic":       stage["tactic"],
            "max_severity": _max_severity(t["max_severity"] for t in tech_list),
            "finding_ids":  finding_ids,
            "techniques":   tech_list,
        })
    return chain


def technique_context(technique_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """
    Contexte (relations STIX `uses`) : nombre de groupes connus qui emploient
    chaque technique, avec un échantillon de noms. Information GÉNÉRALE sur la
    technique, jamais une attribution ni une menace avérée pour la cible.
    """
    ref = load_reference()
    out = {}
    for tid in technique_ids or []:
        meta = ref["techniques"].get(tid) if isinstance(tid, str) and TECHNIQUE_ID_RE.match(tid) else None
        if meta:
            out[tid] = {"groups_count": meta.get("groups_count", 0),
                        "groups_sample": list(meta.get("groups_sample") or [])}
    return out


# ──────────────────────────────────────────────────────────────────────────
#  Export ATT&CK Navigator (layer 4.5)
# ──────────────────────────────────────────────────────────────────────────

# Couleurs fixes (jamais issues des données) — mêmes teintes que le PDF.
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#94a3b8",
}
RECON_COLOR = "#cbd5e1"
NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"
_MAX_COMMENT = 1500
_MAX_TITLE = 160


def _safe_text(value: Any, limit: int) -> str:
    """
    Texte venu du LLM ou des données collectées, avant d'entrer dans le layer :
    caractères de contrôle retirés, chevrons neutralisés (le Navigator affiche
    les commentaires comme du texte, mais un autre outil pourrait les
    interpréter), longueur bornée. L'encodage JSON (json.dumps) empêche toute
    injection de structure.
    """
    text = re.sub(r"[\x00-\x1f\x7f  ]", " ", str(value or ""))
    text = text.replace("<", "‹").replace(">", "›")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _tactic_for(tid: str, preferred: str, ref: dict) -> Optional[str]:
    tactics = (ref["techniques"].get(tid) or {}).get("tactics") or []
    if preferred in tactics:
        return preferred
    return tactics[0] if tactics else None


def build_navigator_layer(findings: List[dict], mitre_attack: Optional[List[dict]] = None,
                          domain: str = "") -> Dict[str, Any]:
    """
    Layer ATT&CK Navigator (format 4.5, domaine enterprise-attack) :
    - chaque technique rendue possible par un constat (attack_enabled des
      constats ANNOTÉS) est colorée selon la sévérité MAX des constats qui la
      rendent possible ; score = 1 (LOW) … 4 (CRITICAL) ; commentaire = ID et
      titres de ces constats ;
    - les techniques de reconnaissance corrélées aux outils exécutés
      (`analysis["mitre_attack"]`) apparaissent en gris clair, score 0.
    Tous les ID sont revalidés (regex + référentiel local).
    """
    ref = load_reference()
    entries: Dict[tuple, Dict[str, Any]] = {}

    for i, f in enumerate(findings if isinstance(findings, list) else [], 1):
        if not isinstance(f, dict):
            continue
        sev = _severity(f)
        label = f"{_finding_id(f, i)} [{sev}] {_safe_text(f.get('title') or 'Constat', _MAX_TITLE)}"
        for t in f.get("attack_enabled") or []:
            tid = t.get("id") if isinstance(t, dict) else None
            if not (isinstance(tid, str) and tid in TECHNIQUE_STAGE and _technique_entry(tid, ref)):
                continue
            tactic = _tactic_for(tid, TECHNIQUE_STAGE[tid], ref)
            if not tactic:
                continue
            slot = entries.setdefault((tid, tactic), {"sevs": [], "labels": [], "recon": []})
            slot["sevs"].append(sev)
            if label not in slot["labels"]:
                slot["labels"].append(label)

    for m in mitre_attack if isinstance(mitre_attack, list) else []:
        if not isinstance(m, dict):
            continue
        tid = m.get("technique_id")
        if not (isinstance(tid, str) and _technique_entry(tid, ref)):
            continue
        tactics = ref["techniques"][tid].get("tactics") or []
        tactic = "reconnaissance" if "reconnaissance" in tactics else (tactics[0] if tactics else None)
        if not tactic:
            continue
        tools = [x for x in (m.get("matched_tools") or []) if isinstance(x, str)
                 and re.match(r"^[a-z0-9_]{1,40}$", x)]
        slot = entries.setdefault((tid, tactic), {"sevs": [], "labels": [], "recon": []})
        slot["recon"].extend(t for t in tools if t not in slot["recon"])

    techniques = []
    for (tid, tactic), slot in sorted(entries.items()):
        if slot["sevs"]:
            sev = _max_severity(slot["sevs"])
            comment = "Rendue possible par : " + " | ".join(slot["labels"])
            color, score = SEVERITY_COLORS[sev], SEVERITY_SCORE[sev]
            meta = [{"name": "sévérité max", "value": sev}]
        else:
            comment = "Information collectable (reconnaissance passive)"
            color, score, meta = RECON_COLOR, 0, []
        if slot["recon"]:
            comment += " — outils : " + ", ".join(sorted(slot["recon"]))
        techniques.append({
            "techniqueID": tid,
            "tactic": tactic,
            "score": score,
            "color": color,
            "comment": _safe_text(comment, _MAX_COMMENT),
            "enabled": True,
            "metadata": meta,
            "links": [],
            "showSubtechniques": "." in tid,
        })

    safe_domain = _safe_text(domain, 120)
    return {
        "name": _safe_text(f"ReconIA — {safe_domain}" if safe_domain else "ReconIA", 200),
        "versions": {"attack": ref["attack_version"].split(".")[0] if ref["attack_version"] else "",
                     "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": _safe_text(
            "Techniques ATT&CK rendues possibles par les constats d'une reconnaissance passive "
            "(couleur = sévérité maximale) et techniques de reconnaissance correspondant aux "
            "informations collectées (gris). Table déterministe ReconIA, référentiel ATT&CK "
            f"Enterprise v{ref['attack_version']}.", 600),
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network Devices", "PRE", "IaaS",
                                  "SaaS", "Office Suite", "Identity Provider", "Containers", "ESXi"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": [RECON_COLOR, SEVERITY_COLORS["LOW"], SEVERITY_COLORS["MEDIUM"],
                                SEVERITY_COLORS["HIGH"], SEVERITY_COLORS["CRITICAL"]],
                     "minValue": 0, "maxValue": 4},
        "legendItems": [
            {"label": "Critique", "color": SEVERITY_COLORS["CRITICAL"]},
            {"label": "Élevée", "color": SEVERITY_COLORS["HIGH"]},
            {"label": "Moyenne", "color": SEVERITY_COLORS["MEDIUM"]},
            {"label": "Faible", "color": SEVERITY_COLORS["LOW"]},
            {"label": "Reconnaissance (information collectable)", "color": RECON_COLOR},
        ],
        "metadata": [{"name": "générateur", "value": "ReconIA — De la donnée à la décision (reconnaissance passive)"}],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


# ──────────────────────────────────────────────────────────────────────────
#  Aide à l'export CSV (routes/report.py)
# ──────────────────────────────────────────────────────────────────────────

def attack_csv_fields(finding: dict) -> Dict[str, str]:
    """
    Colonnes CSV d'un constat annoté : « T1566 Phishing; T1078 Valid Accounts ».
    Les ID sont revalidés (regex) ; les noms viennent du référentiel.
    """
    ref = load_reference()

    def fmt(items, regex, table):
        parts = []
        for it in items or []:
            iid = it.get("id") if isinstance(it, dict) else None
            if isinstance(iid, str) and regex.match(iid) and iid in table:
                parts.append(f"{iid} {table[iid]['name']}")
        return "; ".join(parts)

    if not isinstance(finding, dict):
        return {"attack_enabled": "", "mitigations": ""}
    return {
        "attack_enabled": fmt(finding.get("attack_enabled"), TECHNIQUE_ID_RE, ref["techniques"]),
        "mitigations":    fmt(finding.get("mitigations"), MITIGATION_ID_RE, ref["mitigations"]),
    }
