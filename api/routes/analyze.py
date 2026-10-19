# routes/analyze.py
"""
POST /analyze

Analyse OSINT IA — exécution séquentielle optimisée selon les quotas :

  DEEPSEEK (slot 0) — payant à l'usage, PAS de quota gratuit
    → Ajouté 2026-07-30 à la demande explicite de l'utilisateur, en tête de
      cascade, spécifiquement pour être testé (sinon Gemini réussit presque
      toujours et court-circuiterait la cascade avant d'atteindre un
      backend ajouté en dernier). Voir CLAUDE.md.
    → Actif uniquement si DEEPSEEK_API_KEY configuré
    → Modèle : deepseek-chat (deepseek-reasoner exclu, pas de support `tools`)

  GEMINI (slot 1) — contexte 1M tokens, 1500 req/jour gratuit
    → Moteur principal si GEMINI_API_KEY configuré
    → max_rounds complets, rotation automatique sur quota épuisé
    → Modèles : gemini-2.5-pro, gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash

  CEREBRAS (slot 2) — débit TPM très élevé, modèles llama-3.3-70b
    → Activé si DeepSeek/Gemini absents ou échoués
    → max_rounds complets, rotation automatique sur quota épuisé

  GROQ (slot 3) — 14 400 req/jour, ~30 req/min
    → Activé si DeepSeek/Gemini/Cerebras absents ou échoués
    → max_rounds = ANALYSIS_MAX_SEARCH_ROUNDS (défaut 6)
    → Rotation automatique de modèles sur quota TPD épuisé

  OPENROUTER (slot 4) — 50 req/jour seulement
    → Appelé si tous les slots cloud précédents échouent
    → max_rounds limité à OPENROUTER_MAX_ROUNDS (défaut 2) pour préserver le quota
    → Reprend la conversation du backend précédent si des tool results existent

  OLLAMA local (slot 5 — dernier recours absolu) — qwen3:8b, aucune limite
    → Analyse Map-Reduce : 6 sections indépendantes + synthèse finale
    → Chaque section : max OLLAMA_MAP_ROUNDS (défaut 3) tours de web_search
    → Budget tokens : ~2 700 tok/section MAP, ~6 500 tok pour REDUCE
    → Aucune dépendance externe — fonctionne même si toutes les APIs sont épuisées

Flux :
  1. Cache BD → retour immédiat si valide
  2. DeepSeek (si configuré) → analyse principale (rounds complets)
  3. Si DeepSeek absent/échoue → Gemini → analyse principale (rounds complets)
  4. Si Gemini échoue → Cerebras → analyse principale (rounds complets)
  5. Si Cerebras échoue → Groq → analyse principale (rounds complets)
  6. Si Groq échoue → OpenRouter → secours minimal (2 rounds max)
  7. Si tout échoue → Ollama Map-Reduce → analyse locale (6 sections + synthèse)
  8. Calcul score sécurité + persistance BD
"""

import json
import logging
import os
import re
import threading
import time as _time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flasgger import swag_from

from database import db
from extensions import limiter
from models.recon import Recon
from utils.auth import require_auth, require_service_or_auth
from utils.web_search import search_web
from utils.analysis_merger import merge_analyses, compute_security_score
from utils.mitre_attack import map_tools_to_techniques
from utils.attack_surface import build_attack_surface
from utils.grounding_check import compute_grounding_check
from utils.coverage_check import compute_coverage_check
from utils.rag_retrieval import retrieve_relevant_docs
from utils.email_sender import send_error_notification
from utils.signals_extra import extract_extra_signals
from utils.scan_stats import comparative_context, tld_of

_CACHE_TTL_H        = int(os.getenv("ANALYSIS_CACHE_TTL_HOURS", "168"))   # 7 jours
_GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
_CEREBRAS_API_KEY   = os.getenv("CEREBRAS_API_KEY", "")
_GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
_OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# ── DeepSeek — garde-fou double opt-in (2026-07-30) ──────────────────────────
# Contrairement aux 4 autres backends cloud (Gemini/Cerebras/Groq/OpenRouter,
# tous gratuits), DeepSeek est un service PAYANT et sort les données OSINT du
# scan (domaine cible, sous-domaines, WHOIS, headers, stack techno...) vers un
# prestataire tiers supplémentaire, dans une juridiction distincte des autres
# backends déjà en place. La seule présence de `DEEPSEEK_API_KEY` dans .env
# NE SUFFIT PAS à activer le slot : il faut EN PLUS positionner explicitement
# `DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true` — évite qu'une clé oubliée dans
# .env (ex: après un test) ne se remette silencieusement à envoyer les
# données de chaque scan à ce prestataire après un simple restart/rebuild.
_DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
_DEEPSEEK_CONFIRMED = os.getenv("DEEPSEEK_CONFIRM_EXTERNAL_SHARING", "").strip().lower() in (
    "1", "true", "yes", "oui",
)
_DEEPSEEK_ENABLED = bool(_DEEPSEEK_API_KEY) and _DEEPSEEK_CONFIRMED
if _DEEPSEEK_API_KEY and not _DEEPSEEK_CONFIRMED:
    logging.getLogger(__name__).warning(
        "[deepseek] DEEPSEEK_API_KEY présente mais DEEPSEEK_CONFIRM_EXTERNAL_SHARING "
        "absente/non vraie — slot 0 désactivé (garde-fou anti-partage silencieux). "
        "Ajouter DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true dans api/.env pour l'activer."
    )

# Quota OpenRouter : 50 req/jour → on le préserve en limitant les rounds
_OR_MAX_ROUNDS = int(os.getenv("OPENROUTER_MAX_ROUNDS", "2"))

# Regex stricte pour le nom de modèle
_MODEL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:/\-]{0,79}$')

logger = logging.getLogger(__name__)

analyze_bp = Blueprint("analyze", __name__)

_LANG = os.getenv("ANALYSIS_LANG", "fr")

# Suivi des analyses en arrière-plan : recon_id → True
_bg_running: Dict[int, bool] = {}
_bg_running_lock = threading.Lock()

# Timeout global de l'endpoint (secondes)
_BACKEND_TIMEOUT = int(os.getenv("ANALYSIS_BACKEND_TIMEOUT", "480"))


# ══════════════════════════════════════════════════════════════════════════════
#  Schéma JSON de sortie
# ══════════════════════════════════════════════════════════════════════════════

_OUTPUT_SCHEMA = {
    "domain":            "string — domaine analysé",
    "risk_score":        "integer 0-100  (0=parfait, 100=critique)",
    "risk_level":        "CRITICAL | HIGH | MEDIUM | LOW",
    "executive_summary": "string — résumé 3-5 phrases pour un CISO",
    "findings": [
        {
            "id":             "string — ex: DNS-001, WEB-002, EMAIL-003",
            "category":       "DNS | SSL | Email | Web | Infrastructure | Subdomain | Reputation | Cloud",
            "severity":       "CRITICAL | HIGH | MEDIUM | LOW | INFO — PROPOSITION : le serveur la recalcule par règle déterministe ; un constat positif est toujours INFO",
            "confidence":     "high | medium | low — ta confiance que le constat est exact au vu des données (low si déduit ou incertain)",
            "observed_at":    "string ISO 8601 UTC — reprendre `scan_date` des données (horodatage du scan)",
            "title":          "string — titre court et précis",
            "description":    "string — explication détaillée du problème",
            "evidence":       "string — données OSINT exactes qui prouvent le problème",
            "source_tool":    "string — OBLIGATOIRE : clé de l'outil OSINT d'où provient la preuve (ex: dns_records, ssl_info, shodan_internetdb). Doit figurer dans tools_executed.",
            "source_tools":   ["string — liste des clés d'outils sources si la preuve croise plusieurs outils (source_tool = le principal)"],
            "recommendation": "string — action corrective concrète et implémentable",
            "references":     ["string — CWE-XXX, OWASP A0X:2021, RFC XXXX, T1566 ; une CVE UNIQUEMENT si elle figure dans shodan_internetdb.vulns"],
            "web_sources":    ["string — URL des sources web consultées"],
        }
    ],
    "attack_surface": {
        "total_subdomains": "integer",
        "exposed_services": [
            {
                "host":         "string",
                "service_type": "string — ex: Webmail, SIEM, Admin panel, API",
                "risk":         "CRITICAL | HIGH | MEDIUM | LOW",
            }
        ],
        "technologies": ["string — technologies et versions détectées"],
        "cloud_providers": ["string — hébergeurs identifiés (AWS eu-west-2, Hetzner...)"],
    },
    "strengths": [
        "string — bonnes pratiques déjà en place (SPF strict, HSTS activé...)"
    ],
    "immediate_actions": [
        {
            "priority": "integer — 1=urgent maintenant, 2=cette semaine, 3=ce mois",
            "action":   "string — action concrète à effectuer",
        }
    ],
    "searches_performed": [
        {"query": "string", "results_count": "integer"}
    ],
    "model_used":   "string",
    "analyzed_at":  "string ISO 8601",
    # Champs calculés automatiquement après l'analyse (ne pas inclure dans ta réponse JSON)
    # "security_score", "security_grade", "security_posture", "security_breakdown", "findings_summary"
    # sont ajoutés par le serveur — produis uniquement les champs ci-dessus.
}


# ══════════════════════════════════════════════════════════════════════════════
#  Règles de traçabilité outil → conclusion (partagées par les deux prompts)
# ══════════════════════════════════════════════════════════════════════════════

_TRACEABILITY_RULES = """═══════════════════════════════════════════════════════════════
TRAÇABILITÉ OUTIL → CONCLUSION — EXIGENCE NON NÉGOCIABLE
═══════════════════════════════════════════════════════════════
Chaque finding DOIT être attribuable à l'outil OSINT qui a produit la donnée :

• `source_tool` est OBLIGATOIRE sur CHAQUE finding — c'est la clé technique de
  l'outil dont provient la preuve, telle qu'elle apparaît dans les données OSINT
  fournies (champ `tools_executed` du JSON d'entrée).
  Exemples de clés valides : whois, rdap_info, dns_records, dnssec, ssl_info,
  tls_config, security_headers, tech_stack, waf_detection, email_config,
  spf_analysis, dkim_check, ip_info, asn_info, ptr_records, reverse_ip,
  dnsbl_check, shodan_internetdb, xposedornot_breaches, otx_passive_dns,
  archive_history, subdomain_takeover, js_endpoints, favicon_hash,
  robots_txt, sitemap, security_txt, redirect_chain, crtsh, all_subdomains,
  typosquatting, gau_urls, urlscan_search, dmarc_check, mta_sts_check,
  tlsrpt_check, bimi_check, caa_check, dane_check, http_observatory,
  abuseipdb_check, abusech_check.
• Si la conclusion croise plusieurs outils, renseigne `source_tools` avec la liste
  complète ET `source_tool` avec l'outil principal.
• N'invente JAMAIS un nom d'outil : utilise uniquement des clés présentes dans
  `tools_executed`. Un finding dont tu ne peux pas nommer l'outil source ne doit
  PAS être produit — il n'est pas ancré dans les données.
• `evidence` doit être la donnée exacte telle que renvoyée par cet outil, afin que
  le couple (source_tool, evidence) soit vérifiable et reproductible.
• `web_sources` ne remplace pas `source_tool` : les sources web servent à qualifier
  le risque, l'outil OSINT sert à prouver le fait observé sur la cible.
• CVE : ne cite une CVE (titre, evidence, recommandation, références) QUE si elle
  figure dans `network.shodan_internetdb.vulns` — toute autre CVE est retirée
  automatiquement, et le finding avec elle s'il ne repose que sur elle.
  `kev_cves` liste celles du catalogue CISA KEV (exploitées activement).
• Sévérité : `severity` est une proposition. Le serveur la recalcule par une table
  de règles appliquée aux données brutes (`deterministic_findings` liste les
  constats déjà établis et leur sévérité imposée). Un constat POSITIF (bonne
  pratique en place) va dans `strengths`, jamais dans `findings` — et ne peut
  en aucun cas être HIGH ou CRITICAL.
• `confidence` : high (donnée directe et sans ambiguïté), medium (déduction
  raisonnable), low (indice faible) — le serveur peut l'abaisser, jamais l'élever.
• `passive_extra` résume les outils de collecte enrichie (dns_mass, blocklists,
  threats_check, web_metadata, site_ranking, virustotal, dnsdumpster,
  grayhatwarfare, github_dorks) : leurs clés sont des `source_tool` valides.
• `agent_pivots` : pivots passifs complémentaires choisis par l'agent ; un
  finding qui s'appuie dessus cite `agent_pivots` comme `source_tool`.
• `comparative_context` : statistiques anonymes des scans passés, pour SITUER le
  domaine (« comme 65 % des domaines .bj… »). Ce n'est JAMAIS la preuve d'un
  finding ni une `evidence`.

"""


# ══════════════════════════════════════════════════════════════════════════════
#  Prompt Groq — Analyste menaces techniques
# ══════════════════════════════════════════════════════════════════════════════

_SYSTEM_PROMPT_GROQ = f"""Tu es un analyste expert en cybersécurité offensive (OSCP, GPEN, CEH) spécialisé en OSINT, threat intelligence et exploitation de vulnérabilités.
Ta mission : analyser les données de reconnaissance passive et produire un rapport axé sur les MENACES TECHNIQUES et les VECTEURS D'ATTAQUE exploitables.

═══════════════════════════════════════════════════════════════
RÈGLE ABSOLUE — ZÉRO HALLUCINATION
═══════════════════════════════════════════════════════════════
• Tout finding DOIT être ancré dans les données OSINT fournies OU dans une source web vérifiée
• Ne JAMAIS inventer de CVE, de version logicielle ou de configuration non présente dans les données
• Si tu n'es pas sûr d'un fait → cherche sur le web avant d'affirmer
• Chaque finding doit avoir : evidence (donnée OSINT exacte) + au moins une référence web vérifiée
• Si une donnée est absente des signaux OSINT → indique "Non détecté" plutôt que de supposer

═══════════════════════════════════════════════════════════════
OUTIL web_search — UTILISATION OBLIGATOIRE
═══════════════════════════════════════════════════════════════
Tu DOIS effectuer des recherches web ciblées pour :

1. TECHNOLOGIES DÉTECTÉES → CVE actives, versions vulnérables, exploits publics
   Ex: "Nginx 1.18 CVE 2024 2025 exploit", "WordPress 6.x RCE vulnerability"

2. SERVICES EXPOSÉS → Risques d'accès non autorisé, exploitation
   Ex: "Wazuh SIEM exposed internet attack surface", "WHMCS admin panel CVE 2024"

3. CONFIGURATIONS EMAIL → SPF/DKIM/DMARC exploitabilité (phishing, spoofing)
   Ex: "SPF softfail email spoofing attack", "missing DMARC phishing risk"

4. TLS/SSL → Versions obsolètes, ciphers faibles, certificats
   Ex: "TLS 1.0 1.1 deprecated attack CVE", "weak cipher suite SSL stripping"

5. DNS & DNSSEC → Cache poisoning, zone transfer, subdomain takeover
   Ex: "DNSSEC not configured DNS spoofing risk", "subdomain takeover vulnerability"

6. RÉPUTATION → Blacklists, incidents passés, IOC
   Ex: "domain blacklist DNSBL threat intelligence"

═══════════════════════════════════════════════════════════════
PROCESSUS D'ANALYSE EN 6 ÉTAPES
═══════════════════════════════════════════════════════════════
ÉTAPE 1 — INVENTAIRE : Liste toutes les technologies, versions, services détectés
ÉTAPE 2 — RECHERCHES WEB : Lance des recherches pour chaque technologie/service
ÉTAPE 3 — CVE & EXPLOITS : Identifie CVE applicables avec score CVSS depuis tes recherches
ÉTAPE 4 — SURFACE D'ATTAQUE : Cartographie services exposés, subdomains sensibles
ÉTAPE 5 — SCORING : Calcule risk_score (0-100) basé sur criticité réelle des findings
ÉTAPE 6 — RAPPORT JSON : Produis le rapport final uniquement avec informations vérifiées

═══════════════════════════════════════════════════════════════
CRITÈRES DE SÉVÉRITÉ
═══════════════════════════════════════════════════════════════
CRITICAL (score +30) : RCE possible, credentials exposés, service admin sans auth, CVE CVSS ≥9.0
HIGH     (score +15) : Données sensibles exposées, auth faible, CVE CVSS 7-8.9, service critique mal configuré
MEDIUM   (score +8)  : Mauvaise pratique sécurité, CVE CVSS 4-6.9, header critique manquant (HSTS, CSP)
LOW      (score +3)  : Fuite d'information mineure, header non critique, configuration sous-optimale
INFO     (score +0)  : Observation factuelle sans impact direct

═══════════════════════════════════════════════════════════════
RÈGLES DE QUALITÉ
═══════════════════════════════════════════════════════════════
• evidence : cite EXACTEMENT la donnée OSINT (ex: "Server: Apache/2.4.41")
• recommendation : action concrète ("Mettre à jour Apache vers 2.4.62", pas "Mettre à jour le serveur")
• references : CVE réels trouvés + CWE + OWASP A-number
• web_sources : URLs des sources web consultées pour ce finding
• source_tool : clé de l'outil OSINT à l'origine de la preuve (obligatoire)
• Langue : {'français' if _LANG == 'fr' else 'anglais'}

{_TRACEABILITY_RULES}═══════════════════════════════════════════════════════════════
SCHÉMA JSON ATTENDU (RÉPONSE FINALE UNIQUEMENT)
═══════════════════════════════════════════════════════════════
{json.dumps(_OUTPUT_SCHEMA, ensure_ascii=False, indent=2)}

IMPORTANT : Ta réponse finale doit être UNIQUEMENT le JSON valide ci-dessus, sans texte avant ou après."""


# ══════════════════════════════════════════════════════════════════════════════
#  Prompt OpenRouter — Auditeur complet (bonnes pratiques + exhaustivité)
# ══════════════════════════════════════════════════════════════════════════════

_SYSTEM_PROMPT_OPENROUTER = f"""Tu es un auditeur expert en sécurité des systèmes d'information (CISSP, ISO 27001 Lead Auditor) spécialisé en OSINT et conformité.
Ta mission : produire un audit de sécurité EXHAUSTIF couvrant L'ENSEMBLE des données fournies — aussi bien les vulnérabilités que les BONNES PRATIQUES déjà en place.

═══════════════════════════════════════════════════════════════
RÈGLE ABSOLUE — ZÉRO HALLUCINATION
═══════════════════════════════════════════════════════════════
• Tout finding DOIT être ancré dans les données OSINT fournies OU dans une source web vérifiée
• Ne JAMAIS inventer de CVE, de version logicielle ou de configuration non présente dans les données
• Si tu n'es pas sûr d'un fait → cherche sur le web avant d'affirmer
• Chaque finding doit avoir : evidence (donnée OSINT exacte) + au moins une référence web vérifiée

═══════════════════════════════════════════════════════════════
CHECKLIST D'ANALYSE OBLIGATOIRE — COUVRE CHAQUE SECTION
═══════════════════════════════════════════════════════════════
Tu DOIS analyser et documenter des findings pour CHACUNE de ces catégories si des données sont présentes :

☐ DNS        : Enregistrements A, MX, NS, TXT, CAA, DNSSEC, zone transfer
☐ SSL/TLS    : Certificat (validité, émetteur, SANs), version TLS, ciphers, HSTS
☐ Email      : SPF (politique stricte/souple), DKIM (présence, algorithme), DMARC (politique), MX
☐ Web        : Headers de sécurité (CSP, X-Frame, XCTO, Referrer), technologies, WAF, redirections
☐ Subdomains : Nombre, services exposés, risques de takeover, environnements sensibles (admin, preprod)
☐ Cloud      : Buckets publics, fournisseurs identifiés, régions
☐ Réputation : DNSBL, blacklists, historique
☐ WHOIS      : Informations d'enregistrement, expiration, confidentialité
☐ Infrastructure : ASN, ISP, IPs, PTR records, reverse IP

═══════════════════════════════════════════════════════════════
DOCUMENTER AUSSI LES POINTS POSITIFS (section strengths)
═══════════════════════════════════════════════════════════════
Tu DOIS documenter dans "strengths" toutes les bonnes pratiques détectées :
• DNSSEC activé ✓, SPF strict (~all ou -all) ✓, DMARC avec p=reject ✓
• HSTS activé ✓, CSP présent ✓, WAF détecté ✓
• Certificat valide et à jour ✓, TLS 1.3 ✓
• DKIM configuré ✓, CAA records présents ✓
• Subdomains peu exposés ✓, aucun CNAME dangling ✓
Ne documente PAS uniquement ce qui est mauvais — un audit complet inclut aussi ce qui fonctionne bien.

═══════════════════════════════════════════════════════════════
OUTIL web_search — UTILISATION OBLIGATOIRE
═══════════════════════════════════════════════════════════════
Tu DOIS effectuer des recherches web pour :

1. CONFIGURATIONS DÉTECTÉES → Valider contre les standards actuels
   Ex: "SPF ~all vs -all security recommendation 2024", "DMARC p=quarantine best practice"

2. TECHNOLOGIES IDENTIFIÉES → Bonnes pratiques et versions recommandées
   Ex: "Nginx 1.x recommended security configuration 2024", "WordPress hardening checklist"

3. SERVICES EXPOSÉS → Évaluer l'exposition et les risques
   Ex: "Carbonio mail server security best practices", "WHMCS secure configuration guide"

4. CERTIFICATS & TLS → Standards actuels
   Ex: "TLS 1.3 benefits security 2024", "Let's Encrypt vs commercial certificate security"

5. HEADERS HTTP → Valeurs recommandées
   Ex: "Content-Security-Policy best practices 2024", "HSTS preload recommendation"

6. EMAIL SECURITY → Configurations optimales
   Ex: "DMARC policy reject vs quarantine recommendation", "DKIM 2048 bit key security"

═══════════════════════════════════════════════════════════════
PROCESSUS D'ANALYSE EN 6 ÉTAPES
═══════════════════════════════════════════════════════════════
ÉTAPE 1 — INVENTAIRE EXHAUSTIF : Note TOUT ce qui est présent dans les données (positif et négatif)
ÉTAPE 2 — RECHERCHES WEB : Vérifie les standards actuels pour chaque élément identifié
ÉTAPE 3 — AUDIT PAR CATÉGORIE : Passe en revue chaque section de la checklist ci-dessus
ÉTAPE 4 — BONNES PRATIQUES : Documente les points forts dans "strengths"
ÉTAPE 5 — SCORING : Calcule risk_score en pondérant aussi les éléments positifs
ÉTAPE 6 — RAPPORT JSON : Produis le rapport exhaustif avec findings ET strengths

═══════════════════════════════════════════════════════════════
CRITÈRES DE SÉVÉRITÉ
═══════════════════════════════════════════════════════════════
CRITICAL (score +30) : RCE possible, credentials exposés, service admin sans auth, CVE CVSS ≥9.0
HIGH     (score +15) : Données sensibles exposées, auth faible, CVE CVSS 7-8.9, service critique mal configuré
MEDIUM   (score +8)  : Mauvaise pratique sécurité, CVE CVSS 4-6.9, header critique manquant
LOW      (score +3)  : Fuite d'information mineure, header non critique, configuration sous-optimale
INFO     (score +0)  : Observation factuelle sans impact direct

═══════════════════════════════════════════════════════════════
RÈGLES DE QUALITÉ
═══════════════════════════════════════════════════════════════
• evidence : cite EXACTEMENT la donnée OSINT présente dans les données fournies
• recommendation : action concrète et précise, pas générique
• references : standards de référence (RFC, OWASP, ISO 27001, CIS Benchmark)
• source_tool : clé de l'outil OSINT à l'origine de la preuve (obligatoire)
• Langue : {'français' if _LANG == 'fr' else 'anglais'}

{_TRACEABILITY_RULES}═══════════════════════════════════════════════════════════════
SCHÉMA JSON ATTENDU (RÉPONSE FINALE UNIQUEMENT)
═══════════════════════════════════════════════════════════════
{json.dumps(_OUTPUT_SCHEMA, ensure_ascii=False, indent=2)}

IMPORTANT : Ta réponse finale doit être UNIQUEMENT le JSON valide ci-dessus, sans texte avant ou après."""


# ══════════════════════════════════════════════════════════════════════════════
#  Extraction des signaux OSINT
# ══════════════════════════════════════════════════════════════════════════════

def _g(d: dict, *keys, default=None) -> Any:
    """Accès sécurisé à un chemin de clés imbriquées."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _cap_list(v: Any, limit: int) -> Any:
    """Retourne v[:limit] si v est une liste, v inchangé sinon."""
    return v[:limit] if isinstance(v, list) else v


def _subdomain_headers_summary(d: dict) -> List[Dict]:
    """Résumé compact des headers HTTP par sous-domaine."""
    raw = _g(d, "headers", "data") or {}
    out = []
    for host, info in raw.items():
        if info.get("status") == "unreachable":
            out.append({"host": host, "reachable": False})
            continue
        h = info.get("data", {})
        out.append({
            "host":        host,
            "reachable":   True,
            "http_status": info.get("http_status"),
            "scheme":      info.get("scheme"),
            "server":      h.get("Server") or h.get("server"),
            "powered_by":  h.get("X-Powered-By"),
            "hsts":        bool(h.get("Strict-Transport-Security")),
            "csp":         bool(h.get("Content-Security-Policy")),
            "x_frame":     h.get("X-Frame-Options"),
            "xcto":        bool(h.get("X-Content-Type-Options")),
        })
    return out


def _archive_summary(d: dict) -> Optional[dict]:
    """
    Résumé Wayback Machine — les URLs historiques sont plafonnées pour ne pas
    saturer le contexte du modèle (l'outil peut en remonter jusqu'à 500).
    """
    arch = _g(d, "archive_history", "data")
    if not isinstance(arch, dict):
        return arch
    summary = {k: v for k, v in arch.items() if k != "historical_urls"}
    summary["historical_urls"] = _cap_list(arch.get("historical_urls"), 40)
    return summary


def _tools_executed(d: dict) -> List[Dict]:
    """
    Inventaire des outils réellement exécutés — base de la traçabilité
    outil → conclusion exigée dans le prompt (champ `source_tool` des findings).
    """
    out = []
    for key, value in d.items():
        if not isinstance(value, dict):
            continue
        meta = value.get("meta")
        if not isinstance(meta, dict) or not meta.get("tool"):
            continue
        out.append({
            "key":      key,                       # clé à reprendre dans source_tool
            "name":     meta.get("tool"),
            "category": meta.get("category"),
            "status":   value.get("status"),
        })
    return sorted(out, key=lambda t: (t.get("category") or "", t["key"]))


def _extract_signals(recon: dict) -> dict:
    """
    Transforme le JSON recon complet en contexte compact pour l'IA.
    """
    d = recon.get("data", recon)

    signals: Dict[str, Any] = {
        "domain":          d.get("domain", ""),
        "scan_date":       _g(d, "cache", "cached_at"),
        "scan_duration_s": _g(d, "cache", "scan_duration_s"),

        # Inventaire des outils — chaque finding doit citer une de ces clés
        # dans son champ `source_tool`.
        "tools_executed":  _tools_executed(d),

        "dns": {
            "records":  _g(d, "dns_records", "data"),
            "dnssec": {
                "enabled":    _g(d, "dnssec", "data", "enabled"),
                "has_dnskey": _g(d, "dnssec", "data", "has_dnskey"),
                "has_ds":     _g(d, "dnssec", "data", "has_ds"),
                "note":       _g(d, "dnssec", "data", "security_note"),
            },
        },

        "network": {
            "ips":        _g(d, "ip_info", "data", "ips"),
            "asn":        _g(d, "asn_info", "data"),
            "ptr":        _g(d, "ptr_records", "data"),
            "reverse_ip": _g(d, "reverse_ip", "data"),
            "dnsbl": {
                "clean":      _g(d, "dnsbl_check", "data", "clean"),
                "risk_level": _g(d, "dnsbl_check", "data", "risk_level"),
                "listed":     _g(d, "dnsbl_check", "data", "listed"),
                "dnsbls":     _g(d, "dnsbl_check", "data", "checked_dnsbls"),
            },
            # source_tool = shodan_internetdb (ports/CVE observés passivement par Shodan)
            "shodan_internetdb": {
                "ports":          _g(d, "shodan_internetdb", "data", "ports"),
                "cpes":           _cap_list(_g(d, "shodan_internetdb", "data", "cpes"), 30),
                "vulns":          _cap_list(_g(d, "shodan_internetdb", "data", "vulns"), 50),
                # source_tool = shodan_internetdb — CVE enrichies CVSS (CIRCL) + EPSS (FIRST)
                "vulns_enriched": _cap_list(_g(d, "shodan_internetdb", "data", "vulns_enriched"), 30),
                "tags":           _g(d, "shodan_internetdb", "data", "tags"),
                "hostnames":      _cap_list(_g(d, "shodan_internetdb", "data", "hostnames"), 20),
                "status":         _g(d, "shodan_internetdb", "status"),
            },
            # source_tool = otx_passive_dns (historique des résolutions dans le temps)
            "passive_dns": {
                "records":         _cap_list(_g(d, "otx_passive_dns", "data", "records"), 30),
                "unique_ips":      _cap_list(_g(d, "otx_passive_dns", "data", "unique_ips"), 30),
                "unique_ip_count": _g(d, "otx_passive_dns", "data", "unique_ip_count"),
                "status":          _g(d, "otx_passive_dns", "status"),
            },
            # source_tool = abuseipdb_check (score de confiance d'abus communautaire)
            "abuseipdb": {
                "max_abuse_score": _g(d, "abuseipdb_check", "data", "max_abuse_score"),
                "risk_level":      _g(d, "abuseipdb_check", "data", "risk_level"),
                "status":          _g(d, "abuseipdb_check", "status"),
            },
            # source_tool = abusech_check (URLhaus malware + ThreatFox C2/IOC)
            "abusech": {
                "urlhaus_urls":   _cap_list(_g(d, "abusech_check", "data", "urlhaus_urls"), 20),
                "threatfox_iocs": _cap_list(_g(d, "abusech_check", "data", "threatfox_iocs"), 20),
                "risk_level":     _g(d, "abusech_check", "data", "risk_level"),
                "status":         _g(d, "abusech_check", "status"),
            },
        },

        # source_tool = typosquatting (dnstwist) — domaines de phishing/typosquatting enregistrés
        "brand_protection": {
            "suspicious_domains": _cap_list(_g(d, "typosquatting", "data", "suspicious_domains"), 30),
            "mx_configured_count": _g(d, "typosquatting", "data", "mx_configured_count"),
            "risk_level":          _g(d, "typosquatting", "data", "risk_level"),
            "status":              _g(d, "typosquatting", "status"),
        },

        # source_tool = gau_urls / urlscan_search — URLs et scans historiques agrégés
        "external_history": {
            "gau_interesting_files": _cap_list(_g(d, "gau_urls", "data", "interesting_files"), 30),
            "gau_url_count":         _g(d, "gau_urls", "data", "url_count"),
            "urlscan_subdomains":    _cap_list(_g(d, "urlscan_search", "data", "subdomains_seen"), 30),
            "urlscan_scan_count":    _g(d, "urlscan_search", "data", "scan_count"),
        },

        # source_tool = xposedornot_breaches (fuites de données, adresses rôle du domaine)
        "breaches": {
            "status":            _g(d, "xposedornot_breaches", "status"),
            "breach_count":      _g(d, "xposedornot_breaches", "data", "breach_count"),
            "affected_accounts": _g(d, "xposedornot_breaches", "data", "affected_accounts"),
            "top_breaches":      _g(d, "xposedornot_breaches", "data", "top_breaches"),
        },

        "ssl_tls": {
            "certificate": _g(d, "ssl_info", "data"),
            "ssl_error":   _g(d, "ssl_info", "error"),
            "tls_config":  _g(d, "tls_config", "data"),
            # source_tool = caa_check — autorités de certification autorisées à émettre
            "caa":         _g(d, "caa_check", "data"),
            # source_tool = dane_check — pin de certificat lié au DNS (nécessite DNSSEC)
            "dane":        _g(d, "dane_check", "data"),
        },

        "web": {
            "security_headers":    _g(d, "security_headers", "data"),
            "sec_headers_error":   _g(d, "security_headers", "error"),
            "tech_stack":          _g(d, "tech_stack", "data"),
            "waf":                 _g(d, "waf_detection", "data"),
            "redirect_chain":      _g(d, "redirect_chain", "data"),
            "robots_txt":          _g(d, "robots_txt", "data"),
            "security_txt_status": _g(d, "security_txt", "status"),
            "sitemap_status":      _g(d, "sitemap", "status"),
            "js_endpoints":        _cap_list(_g(d, "js_endpoints", "data"), 20),
            "favicon":             _g(d, "favicon_hash", "data"),
            "archive":             _archive_summary(d),
            "subdomain_headers":   _subdomain_headers_summary(d),
            # source_tool = http_observatory — note normalisée A+ à F (Mozilla)
            "http_observatory": {
                "grade":             _g(d, "http_observatory", "data", "grade"),
                "score":             _g(d, "http_observatory", "data", "score"),
                "tests_failed":      _cap_list(_g(d, "http_observatory", "data", "tests_failed"), 20),
                "status":            _g(d, "http_observatory", "status"),
            },
        },

        "email": {
            "config":       _g(d, "email_config", "data"),
            "dkim":         _g(d, "dkim_check", "data"),
            "spf_analysis": _g(d, "spf_analysis", "data"),
            # source_tool = dmarc_check
            "dmarc":        _g(d, "dmarc_check", "data"),
            # source_tool = mta_sts_check
            "mta_sts":      _g(d, "mta_sts_check", "data"),
            # source_tool = tlsrpt_check
            "tlsrpt":       _g(d, "tlsrpt_check", "data"),
            # source_tool = bimi_check
            "bimi":         _g(d, "bimi_check", "data"),
        },

        "subdomains": {
            "all":               _cap_list(_g(d, "all_subdomains", "data"), 40),
            "count":             _g(d, "all_subdomains", "count"),
            "amass_status":      _g(d, "amass", "status"),
            "subfinder_count":   _g(d, "subfinder", "data", "count"),
            "assetfinder_count": _g(d, "assetfinder", "data", "count"),
            "takeover":          _g(d, "subdomain_takeover", "data"),
        },

        "whois": (
            _g(d, "whois", "data")
            or _g(d, "whois_info", "data")
        ),

        # source_tool = rdap_info — données d'enregistrement normalisées (RFC 9083),
        # complémentaires du WHOIS textuel ci-dessus.
        "rdap": _g(d, "rdap_info", "data"),
    }

    # Phase 5 : signaux compacts des outils de collecte enrichie (dns_mass,
    # blocklists, threats_check, web_metadata, site_ranking, virustotal…).
    try:
        signals["passive_extra"] = extract_extra_signals(d)
    except Exception as e:
        logger.warning("[analyze] signaux phase 5 ignorés : %s", e)

    # Phase 8 : pivots exécutés par la boucle agent — seulement les résumés
    # déjà nettoyés et bornés par utils/recon_agent.py, jamais raw_output.
    pivots = _g(d, "agent_pivots", "data", "decisions")
    if isinstance(pivots, list):
        executed = [
            {"tool": x.get("tool"), "target": (x.get("arguments") or {}).get("target")
             or next((v for k, v in (x.get("arguments") or {}).items() if k != "reason"), None),
             "result": x.get("result_summary")}
            for x in pivots
            if isinstance(x, dict) and x.get("outcome") == "executed"
        ][:15]
        if executed:
            signals["agent_pivots"] = executed

    # Phase 6 : statistiques agrégées et anonymisées des scans passés —
    # contexte comparatif seulement, jamais la preuve d'un finding.
    try:
        context = comparative_context(tld_of(signals["domain"]), signals)
        if context:
            signals["comparative_context"] = context
    except Exception as e:
        logger.warning("[analyze] contexte comparatif ignoré : %s", e)

    return {k: v for k, v in signals.items() if v is not None}


# ══════════════════════════════════════════════════════════════════════════════
#  Handler des tool calls (partagé par les deux backends)
# ══════════════════════════════════════════════════════════════════════════════

def _any_backend_available() -> bool:
    """
    Vrai si au moins un backend d'analyse peut servir : une clé cloud, OU le
    repli local Ollama joignable avec son modèle installé.

    Avant (constaté au premier déploiement réel, 2026-10-19) : seules les clés
    cloud comptaient. Sans clé, /analyze et /analyze/async répondaient 503
    avant même d'essayer Ollama — alors que setup.sh et le README promettent
    que « sans aucune clé, la cascade retombe automatiquement sur Ollama
    local ». Le pipeline n8n s'arrêtait donc après le scan OSINT.
    """
    if _DEEPSEEK_ENABLED or _GEMINI_API_KEY or _CEREBRAS_API_KEY or _GROQ_API_KEY or _OPENROUTER_API_KEY:
        return True
    from utils.ollama_client import OllamaClient
    client = OllamaClient()
    return client.is_available() and client.model_loaded()


def _tool_handler(tool_name: str, tool_args: dict) -> str:
    if tool_name == "web_search":
        query       = (tool_args.get("query") or "").strip()[:300]
        max_results = int(tool_args.get("max_results") or 5)
        max_results = max(1, min(max_results, 10))

        if not query:
            return json.dumps({"error": "query vide"})

        results = search_web(query, max_results=max_results)
        logger.info("web_search(%r) → %d résultats", query, len(results))
        return json.dumps(results, ensure_ascii=False)

    return json.dumps({"error": f"Outil inconnu : {tool_name}"})


# ══════════════════════════════════════════════════════════════════════════════
#  Parsing robuste du JSON de sortie
# ══════════════════════════════════════════════════════════════════════════════

def _strip_thinking_blocks(content: str) -> str:
    """
    Supprime les blocs de raisonnement des modèles 'thinking'
    (<think>...</think>, <reasoning>...</reasoning>, etc.)
    avant d'essayer d'extraire le JSON.
    """
    for tag in ("think", "reasoning", "thought", "internal"):
        content = re.sub(
            rf"<{tag}>.*?</{tag}>", "", content, flags=re.DOTALL | re.IGNORECASE
        )
    return content.strip()


def _extract_json_candidates(text: str) -> list:
    """
    Retourne tous les candidats JSON de la chaîne, du plus long au plus court.
    Cherche d'abord les blocs ```json```, puis les objets {...} imbriqués.
    """
    candidates = []

    # 1. Blocs markdown ```json ... ```
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        candidates.append(m.group(1))

    # 2. Tous les blocs {...} — cherche depuis la fin (dernier = souvent le vrai JSON final)
    stack, start = [], None
    for i, ch in enumerate(text):
        if ch == "{":
            if not stack:
                start = i
            stack.append(i)
        elif ch == "}" and stack:
            stack.pop()
            if not stack and start is not None:
                candidates.append(text[start:i + 1])
                start = None

    # Trier par longueur décroissante (le JSON complet est le plus long)
    candidates.sort(key=len, reverse=True)
    return candidates


def _parse_json_report(content: str) -> Optional[dict]:
    if not content:
        return None

    # 1. Supprimer les blocs <think> des modèles reasoning
    cleaned = _strip_thinking_blocks(content)

    # 2. Tenter un parse direct
    for text in (cleaned, content):
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    # 3. Extraire tous les candidats JSON et tenter chacun
    for candidate in _extract_json_candidates(cleaned):
        try:
            result = json.loads(candidate)
            if isinstance(result, dict) and len(result) > 1:
                return result
        except json.JSONDecodeError:
            continue

    # 4. Dernier recours : candidats dans le texte original (avant nettoyage)
    for candidate in _extract_json_candidates(content):
        try:
            result = json.loads(candidate)
            if isinstance(result, dict) and len(result) > 1:
                return result
        except json.JSONDecodeError:
            continue

    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Construction des messages pour chaque backend
# ══════════════════════════════════════════════════════════════════════════════

def _build_messages(system_prompt: str, domain: str, signals: dict, search_hints: str) -> List[Dict]:
    signals_json = json.dumps(signals, ensure_ascii=False, separators=(',', ':'))
    return [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"/no_think\n\n"
                f"## Analyse de sécurité OSINT pour : {domain}\n\n"
                f"### DONNÉES OSINT COLLECTÉES\n"
                f"```json\n{signals_json}\n```\n\n"
                f"### ÉLÉMENTS PRIORITAIRES\n"
                f"{search_hints}\n\n"
                f"### INSTRUCTIONS\n"
                f"1. Lance des recherches web pour chaque technologie, service et configuration détectés\n"
                f"2. COUVERTURE OBLIGATOIRE : pour CHAQUE outil de `tools_executed` ayant retourné des "
                f"données exploitables, tu DOIS soit produire un finding qui le cite, soit l'ajouter à "
                f"`strengths` en mentionnant explicitement sa clé entre parenthèses (ex: \"SPF correctement "
                f"configuré (spf_analysis)\") si les données sont propres — ne jamais ignorer silencieusement "
                f"un outil ayant produit des données, même en l'absence de problème\n"
                f"3. Documente aussi bien les vulnérabilités que les bonnes pratiques déjà en place\n"
                f"4. Ne documente QUE les findings appuyés par les données OSINT + sources web vérifiées\n"
                f"5. TRAÇABILITÉ : chaque finding DOIT porter un champ `source_tool` contenant la clé "
                f"de l'outil d'où vient la preuve — utilise exclusivement les clés listées dans "
                f"`tools_executed` des données ci-dessus (et `source_tools` si plusieurs outils)\n"
                f"6. Le champ `mitre_attack` liste les techniques MITRE ATT&CK déjà corrélées "
                f"déterministiquement aux outils exécutés (ne pas en inventer d'autres) — "
                f"référence-les explicitement dans `recommendation` des findings concernés "
                f"(ex: \"cf. T1596.001\") pour ancrer la recommandation dans un cadre reconnu\n"
                f"7. Le champ `rag_context` contient des extraits du corpus (normes RFC/OWASP/ANSSI, "
                f"MITRE ATT&CK, menaces, explications) sélectionnés PAR CONSTAT : chaque extrait "
                f"porte `topic` (le constat de `deterministic_findings` qu'il documente) et "
                f"`collection` — base la `recommendation` du finding correspondant dessus en "
                f"priorité, et cite la source (ex: \"cf. RFC 7489\") plutôt que de reformuler une "
                f"bonne pratique générique de mémoire\n"
                f"8. Une fois toutes tes recherches terminées, produis le rapport JSON final\n\n"
                f"Commence par tes recherches web, puis fournis le rapport JSON."
            ),
        },
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  Réparation JSON — appel dédié si la réponse principale est invalide
# ══════════════════════════════════════════════════════════════════════════════

def _repair_json(client, bad_content: str, backend_name: str) -> Optional[dict]:
    """
    Demande au modèle de ré-émettre uniquement le JSON valide à partir
    de sa réponse précédente invalide. Une seule tentative, sans tools.
    """
    # Tronquer si le contenu est gigantesque (modèles thinking)
    preview = bad_content[:3000] if len(bad_content) > 3000 else bad_content
    repair_messages = [
        {
            "role": "system",
            "content": (
                "Tu es un assistant qui extrait et retourne uniquement du JSON valide. "
                "Ne produis AUCUN texte hors du JSON. Pas de markdown, pas d'explication."
            ),
        },
        {
            "role": "user",
            "content": (
                "Voici une réponse qui contenait un rapport JSON mais qui n'est pas parseable. "
                "Extrait et retourne UNIQUEMENT le JSON valide correspondant au rapport d'analyse de sécurité, "
                "sans aucun texte avant ou après, sans balises markdown.\n\n"
                f"Réponse à réparer :\n{preview}"
            ),
        },
    ]
    try:
        msg = client.chat(repair_messages, tools=None, temperature=0.0)
        # Compatibilité dict (Ollama) et objet (Groq/Cerebras/Gemini)
        if isinstance(msg, dict):
            raw = msg.get("content", "") or ""
        else:
            raw = getattr(msg, "content", "") or ""
        repaired = _parse_json_report(raw)
        if repaired:
            logger.info("[%s] JSON réparé avec succès", backend_name)
        return repaired
    except Exception as e:
        logger.warning("[%s] Réparation JSON échouée: %s", backend_name, e)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Runner d'un backend IA unique (utilisé dans le ThreadPool)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_partial_from_msgs(msgs: List, searches_log: List[Dict]) -> Optional[Dict]:
    """
    Scanne la conversation accumulée à la recherche de tout contenu JSON utilisable.
    Retourne le meilleur rapport partiel trouvé, ou None.
    """
    candidates = []
    for m in reversed(msgs):  # du plus récent au plus ancien
        if not isinstance(m, dict):
            continue
        content = m.get("content") or ""
        if not content or m.get("role") not in ("assistant", "tool"):
            continue
        parsed = _parse_json_report(content)
        _ANALYSIS_KEYS = {'findings', 'risk_score', 'risk_level', 'executive_summary', 'attack_surface', 'strengths', 'immediate_actions'}
        if parsed and len(parsed) > 2 and any(k in parsed for k in _ANALYSIS_KEYS):
            candidates.append(parsed)

    if not candidates:
        return None

    # Prendre le rapport avec le plus de findings
    best = max(candidates, key=lambda r: len(r.get("findings") or []))
    best["_partial"]          = True
    best["searches_performed"] = searches_log
    logger.info("Rapport partiel extrait depuis la conversation (%d findings)", len(best.get("findings") or []))
    return best


def _run_backend(
    backend_name: str,
    client_class,
    model_override,
    messages: List[Dict],
    max_rounds: int,
    resume_msgs: Optional[List] = None,
) -> Tuple[Dict, List]:
    """
    Exécute un backend IA et retourne (rapport, msgs_accumulés).

    resume_msgs : conversation du backend précédent à continuer.
                  Si fourni, le backend reprend depuis ce point sans refaire
                  les recherches déjà effectuées.
    """
    try:
        client = client_class(model=model_override or None)
        if not client.is_available():
            logger.warning("[%s] Backend non disponible — ignoré", backend_name)
            return {}, []
        if not client.model_loaded():
            logger.warning("[%s] Modèle non chargé — ignoré", backend_name)
            return {}, []

        # Si une conversation précédente est fournie, on y ajoute une instruction
        # de reprise puis on continue — les recherches déjà faites sont préservées
        if resume_msgs:
            start_msgs = list(resume_msgs)
            start_msgs.append({
                "role": "user",
                "content": (
                    "/no_think\n\n"
                    f"Le modèle précédent n'a pas pu terminer (quota épuisé). "
                    f"Tu reprends l'analyse là où il s'est arrêté. "
                    f"Les {len([m for m in start_msgs if m.get('role') == 'tool'])} résultats "
                    f"de recherche déjà collectés sont dans la conversation ci-dessus. "
                    f"Produis directement le rapport JSON final en te basant sur ces données. "
                    f"Réponds UNIQUEMENT avec le JSON valide."
                ),
            })
            logger.info(
                "[%s] Reprise depuis la conversation Groq (%d msgs, dont %d tool results)",
                backend_name,
                len(start_msgs),
                len([m for m in start_msgs if m.get("role") == "tool"]),
            )
            # En mode reprise : demande directement le rapport (pas de rounds agentiques)
            try:
                msg = client.chat(start_msgs, tools=None, temperature=0.0)
                content = getattr(msg, "content", "") or ""
                report  = _parse_json_report(content)
                if not report and content:
                    report = _repair_json(client, content, backend_name)
                if report:
                    report["searches_performed"] = [
                        m for m in start_msgs if m.get("role") == "tool"
                    ]
                    report["model_used"] = getattr(client, "_current_model", lambda: client.model)()
                    report["tokens_used"] = dict(getattr(client, "usage", {}) or {})
                    report["_resumed"]   = True
                    logger.info("[%s] Reprise réussie depuis conversation précédente", backend_name)
                    return report, start_msgs
                logger.warning("[%s] Reprise directe échouée — tentative agentique courte", backend_name)
            except Exception as e:
                logger.warning("[%s] Erreur reprise directe: %s — tentative agentique", backend_name, e)
            # Fallback : lancer quand même une boucle courte
            use_msgs = start_msgs
        else:
            use_msgs = messages

        final_msg, searches_log, partial_msgs = client.agentic_chat(
            messages=use_msgs,
            tool_handler=_tool_handler,
            max_rounds=max_rounds,
        )

        content = final_msg.get("content", "")
        report  = _parse_json_report(content)

        # ── Tentative de réparation JSON ──────────────────────────────────────
        if not report and content:
            logger.warning("[%s] JSON invalide (%d chars) — tentative de réparation", backend_name, len(content))
            report = _repair_json(client, content, backend_name)

        # ── Extraction partielle depuis la conversation si tout échoue ────────
        if not report:
            logger.warning("[%s] Rapport final invalide — scan de la conversation pour résultats partiels", backend_name)
            report = _extract_partial_from_msgs(partial_msgs, searches_log)

        if not report:
            logger.error("[%s] Aucun résultat extractible — conversation préservée (%d msgs)", backend_name, len(partial_msgs))
            return {}, partial_msgs

        if not report.get("_partial"):
            report["searches_performed"] = searches_log
        report["model_used"]  = getattr(client, "_current_model", lambda: client.model)()
        report["tokens_used"] = dict(getattr(client, "usage", {}) or {})
        logger.info(
            "[%s] Analyse terminée%s — risk_score=%s | findings=%d | searches=%d",
            backend_name,
            " (partiel)" if report.get("_partial") else "",
            report.get("risk_score", "?"),
            len(report.get("findings") or []),
            len(searches_log),
        )
        return report, partial_msgs

    except Exception as e:
        logger.exception("[%s] Erreur inattendue : %s", backend_name, e)
        return {}, []


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 3 — préparation déterministe (avant LLM) et post-traitement (après)
# ══════════════════════════════════════════════════════════════════════════════
# Partagés par analyze() (sync) et _run_bg_analysis() (async) : avant cette
# factorisation, chaque étape était dupliquée dans les deux chemins, et un
# oubli d'un côté (ex. `source_tool` côté Ollama, voir CLAUDE.md) suffisait à
# faire diverger les rapports selon le point d'entrée.

# Champs de premier niveau acceptés depuis la sortie du LLM — tout autre champ
# (ex. un `security_score`, `grounding_check` ou `severity_check` « offert » par
# le modèle) est ignoré : ces champs sont calculés par le serveur.
_LLM_REPORT_KEYS = {
    "domain", "risk_score", "risk_level", "executive_summary", "findings", "strengths",
    "immediate_actions", "searches_performed", "model_used", "analyzed_at",
    "tokens_used", "_partial", "_resumed", "_reduce_degraded",
}


def _scan_data(recon_json: dict) -> dict:
    """Résultats bruts des outils, que `recon_json` soit enveloppé (`data`) ou non."""
    if not isinstance(recon_json, dict):
        return {}
    d = recon_json.get("data")
    return d if isinstance(d, dict) else recon_json


def _prepare_phase3(recon_json: dict, signals: dict, fallback_query: str,
                    kev_override: Optional[Dict] = None, retriever=None) -> Dict[str, Any]:
    """
    Avant l'appel au LLM : constats déterministes, KEV, contexte RAG par
    constat (B7). Ajoute à `signals` : `deterministic_findings`, `kev_cves`
    (dans shodan_internetdb) et `rag_context`. Ne lève jamais.

    `kev_override` / `retriever` : injection pour les tests et la mesure hors
    ligne (tools/measure_phase3.py) — en production, KEV vient de utils/kev.py
    et le RAG de pgvector.
    """
    from utils import kev as kev_mod
    from utils.finding_sanitizer import to_iso_utc
    from utils.rag_retrieval import TopicRetriever, build_rag_context
    from utils.severity_rules import RULES, detect_observations, observed_cves, rag_topics

    scan = _scan_data(recon_json)
    cves = observed_cves(scan)
    if kev_override is not None:
        kev = {c: kev_override[c] for c in cves if c in kev_override}
    else:
        kev = kev_mod.kev_entries(cves.keys()) if cves else {}
    observations = detect_observations(scan, kev)
    observed_at = to_iso_utc(signals.get("scan_date")) or to_iso_utc(datetime.utcnow())

    shodan = (signals.get("network") or {}).get("shodan_internetdb")
    if isinstance(shodan, dict):
        shodan["kev_cves"] = sorted(kev)

    signals["deterministic_findings"] = [
        {
            "rule":        rid,
            "category":    RULES[rid]["category"],
            "title":       RULES[rid]["title"],
            "severity":    o.get("severity") or RULES[rid]["severity"],
            "source_tool": o.get("source_tool"),
            "evidence":    str(o.get("evidence") or "")[:200],
        }
        for rid, o in observations.items()
        if not rid.startswith("_") and o.get("state") == "observed"
    ][:30]

    retriever = retriever or TopicRetriever()
    topics = rag_topics(observations)
    if not topics and fallback_query:
        topics = [{"id": "general", "query": fallback_query, "category": "Web"}]
    try:
        rag_context, rag_stats = build_rag_context(topics, retriever)
    except Exception as e:   # filet : le RAG ne doit jamais bloquer l'analyse
        logger.warning("[rag] Contexte RAG indisponible (%s)", e)
        rag_context, rag_stats = [], {"queries": 0, "filtered_by_collection": None}
    signals["rag_context"] = rag_context

    return {
        "scan": scan, "cves": cves, "kev": kev, "observations": observations,
        "observed_at": observed_at, "retriever": retriever, "rag_stats": rag_stats,
        "kev_status": kev_mod.status(),
    }


def _annotate_attack(findings: List[Dict], signals: dict) -> List[Dict]:
    """
    Point d'accroche phase 4 : `utils/attack_enablement.annotate_findings`
    ajoute `attack_enabled` / `mitigations`. Import protégé — no-op tant que
    le module n'existe pas, et une erreur du module ne casse pas l'analyse.
    """
    try:
        from utils.attack_enablement import annotate_findings
    except ImportError:
        return findings
    try:
        result = annotate_findings(findings, signals)
    except Exception:
        logger.exception("[attack_enablement] annotation échouée — findings conservés tels quels")
        return findings
    return result if isinstance(result, list) else findings


def _postprocess_report(report: dict, signals: dict, ctx: Dict[str, Any], used_backend: Optional[str]) -> dict:
    """
    Après le LLM : validation (sanitizer + B6), sévérité déterministe (B5),
    références RAG (B7), annotation ATT&CK (phase 4), score, contrôles
    d'ancrage/couverture. Retourne le rapport final.
    """
    from routes.recon import TOOLS_REGISTRY
    from utils.finding_sanitizer import (
        clean_text, ensure_unique_ids, sanitize_findings, sanitize_strengths,
    )
    from utils.rag_retrieval import attach_references
    from utils.severity_rules import apply_severity_rules, finalize_confidence, risk_level_from_findings

    report = {k: v for k, v in (report or {}).items() if k in _LLM_REPORT_KEYS}
    scan = ctx["scan"]

    # ── Validation des findings (liste blanche, bornes, B6) ──────────────────
    # Voir utils/finding_sanitizer.py : corrige aussi les défauts de format
    # constatés sur de vrais rapports (catégorie invalide, ID dupliqués,
    # références gabarit "CVE-XXXX"/"example.com").
    san_stats: Dict[str, Any] = {}
    findings = sanitize_findings(
        report.get("findings") or [], TOOLS_REGISTRY,
        observed_cves=set(ctx["cves"]), observed_at=ctx["observed_at"], stats=san_stats,
    )

    # ── Sévérité déterministe (B5) ───────────────────────────────────────────
    findings, sev_summary = apply_severity_rules(
        findings, scan, ctx["kev"], ctx["observed_at"], ctx["observations"],
    )
    ensure_unique_ids(findings)
    report["findings"]  = findings
    report["strengths"] = sanitize_strengths(report.get("strengths"))
    report["executive_summary"] = clean_text(report.get("executive_summary"), 5000)
    actions = []
    for a in (report.get("immediate_actions") or [])[:20] if isinstance(report.get("immediate_actions"), list) else []:
        if isinstance(a, dict) and clean_text(a.get("action"), 500):
            try:
                prio = max(1, min(int(a.get("priority") or 3), 3))
            except (TypeError, ValueError):
                prio = 3
            actions.append({"priority": prio, "action": clean_text(a.get("action"), 500)})
    report["immediate_actions"] = actions

    # ── Références RAG par finding (B7) ──────────────────────────────────────
    try:
        ref_stats = attach_references(findings, signals.get("rag_context") or [], ctx["retriever"])
    except Exception as e:
        logger.warning("[rag] Références RAG non attachées (%s)", e)
        ref_stats = {"finding_queries": 0, "findings_with_rag_references": 0}

    # ── Phase 4 : techniques ATT&CK rendues possibles (import protégé) ───────
    report["findings"] = findings = _annotate_attack(findings, signals)

    # ── Score déterministe, à partir des sévérités FINALES ───────────────────
    sec = compute_security_score(report)
    report["security_score"]     = sec["security_score"]
    report["security_grade"]     = sec["security_grade"]
    report["security_posture"]   = sec["security_posture"]
    report["security_breakdown"] = sec["security_breakdown"]
    report["findings_summary"]   = sec["findings_summary"]
    # `risk_score` n'est plus l'auto-évaluation du modèle (bug constaté : 0/100
    # sur example.com, et écart email/PDF documenté dans CLAUDE.md) : il est
    # dérivé du score déterministe. La valeur du modèle reste tracée à part.
    try:
        report["risk_score_llm"] = max(0, min(int(report.get("risk_score")), 100))
    except (TypeError, ValueError):
        report["risk_score_llm"] = None
    report["risk_score"] = 100 - sec["security_score"]
    report["risk_level"] = risk_level_from_findings(findings)

    report["mitre_attack"]       = signals.get("mitre_attack", [])
    # Déterministe, jamais le texte du LLM — voir utils/attack_surface.py
    # (bug réel constaté : champ absent/vide malgré des données réelles).
    report["attack_surface"]     = build_attack_surface(signals)
    report["_backend"]           = used_backend

    # ── Contrôle d'ancrage (grounding check) — voir utils/grounding_check.py ──
    # Vérifie programmatiquement ce que le prompt exige déjà par instruction.
    report["grounding_check"] = compute_grounding_check(report, scan)
    finalize_confidence(findings)

    # ── Contrôle de couverture — voir utils/coverage_check.py ────────────────
    # Question distincte du grounding check : les données collectées ont-elles
    # ÉTÉ EXAMINÉES (pas seulement : les findings produits sont-ils exacts) ?
    report["coverage_check"] = compute_coverage_check(report, scan, signals)
    report["coverage_check"].update({
        "rag_queries":                  ctx["rag_stats"].get("queries", 0) + ref_stats["finding_queries"],
        "rag_filtered_by_collection":   ctx["rag_stats"].get("filtered_by_collection"),
        "findings_with_rag_references": ref_stats["findings_with_rag_references"],
    })

    report["severity_check"] = {
        **sev_summary,
        "dropped_invalid":        san_stats.get("dropped_invalid", 0),
        "dropped_unverified_cve": san_stats.get("dropped_unverified_cve", 0),
        "cves_removed":           san_stats.get("cves_removed", []),
        "kev":                    ctx.get("kev_status"),
        "observed_at":            ctx["observed_at"],
    }
    return report


# ══════════════════════════════════════════════════════════════════════════════
#  Endpoint /analyze
# ══════════════════════════════════════════════════════════════════════════════

@analyze_bp.route("/analyze", methods=["POST"])
@require_service_or_auth
@limiter.limit("5 per hour")
@swag_from({
    "tags": ["IA Analysis"],
    "security": [{"basicAuth": []}],
    "summary": "Analyse IA synchrone d'un rapport de reconnaissance passive",
    "description": (
        "Exécute l'analyse IA de manière **synchrone** (bloque jusqu'à la fin).\n\n"
        "### Chaîne de backends (séquentielle, par priorité)\n\n"
        "| Slot | Backend | Modèle principal | Quota |\n"
        "|------|---------|-----------------|-------|\n"
        "| 1 | **Cerebras** | llama3.3-70b | TPM très élevé (wafer dédié) |\n"
        "| 2 | **Groq** | llama-3.3-70b-versatile | 14 400 req/jour |\n"
        "| 3 | **OpenRouter** | llama-3.3-70b-instruct:free | 50 req/jour (dernier recours) |\n\n"
        "Chaque backend tente l'analyse complète. Si un backend échoue (quota, erreur), "
        "le suivant reprend la conversation déjà accumulée (tool results préservés).\n\n"
        "### Rotation automatique de modèles\n"
        "Au sein de chaque backend, les modèles sont testés en séquence sur quota épuisé ou "
        "payload trop grand (413). Les modèles sans tool use (Gemma) et soumis à des "
        "restrictions guardrail (gpt-oss) sont exclus automatiquement.\n\n"
        "### Score de sécurité\n"
        "Le rapport final inclut `security_score` (/100), `security_grade` (A+ → F), "
        "`security_posture` et `security_breakdown` par catégorie (DNS, SSL, Email, Web…).\n\n"
        "⏱️ **Durée estimée** : 2–5 min.\n\n"
        "⚠️ **Timeout n8n** : si votre client a un timeout court, utilisez "
        "`POST /analyze/async` + `GET /analyze/wait/{recon_id}` à la place.\n\n"
        "💾 **Cache BD** : le rapport est mis en cache (TTL = `ANALYSIS_CACHE_TTL_HOURS`, défaut 7 jours). "
        "Un hit cache retourne immédiatement avec `cached: true`."
    ),
    "parameters": [
        {
            "in": "body",
            "name": "body",
            "required": True,
            "schema": {
                "type": "object",
                "properties": {
                    "recon_id": {
                        "type": "integer",
                        "description": (
                            "ID de l'enregistrement Recon (recommandé). "
                            "Si fourni et `scan_results` présent en BD, `recon_json` n'est pas requis — "
                            "les données OSINT sont chargées automatiquement."
                        ),
                        "example": 42,
                    },
                    "recon_json": {
                        "type": "object",
                        "description": (
                            "JSON complet retourné par POST /pass_recon. "
                            "Optionnel si `recon_id` est fourni et `scan_results` est en BD."
                        ),
                    },
                    "force_refresh": {
                        "type": "boolean",
                        "description": "Forcer une nouvelle analyse même si le cache BD est valide.",
                        "default": False,
                    },
                    "model": {
                        "type": "string",
                        "description": (
                            "Override du modèle pour le backend actif "
                            "(ex. `llama-3.3-70b-versatile` pour Groq). "
                            "Format : lettres, chiffres, `.`, `:`, `-`, `_`, `/` (80 chars max)."
                        ),
                        "example": "llama-3.3-70b-versatile",
                    },
                    "max_search_rounds": {
                        "type": "integer",
                        "description": "Nombre max de tours de recherche web par backend (1–8, défaut : 4).",
                        "minimum": 1,
                        "maximum": 8,
                        "default": 4,
                    },
                },
            },
        }
    ],
    "responses": {
        200: {
            "description": "Rapport d'analyse IA (résultat frais ou cache BD)",
            "schema": {
                "type": "object",
                "properties": {
                    "success":  {"type": "boolean", "example": True},
                    "cached":   {"type": "boolean", "description": "True si retourné depuis le cache BD"},
                    "recon_id": {"type": "integer", "description": "ID de l'enregistrement Recon"},
                    "data": {
                        "type": "object",
                        "description": "Rapport structuré",
                        "properties": {
                            "domain":             {"type": "string"},
                            "risk_score":         {"type": "integer", "description": "0–100 (0=parfait)"},
                            "risk_level":         {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                            "security_score":     {"type": "integer", "description": "Score IA /100"},
                            "security_grade":     {"type": "string",  "description": "A+ → F"},
                            "security_posture":   {"type": "string"},
                            "security_breakdown": {"type": "object",  "description": "Scores par catégorie"},
                            "grounding_check":    {"type": "object",  "description": (
                                "Contrôle d'ancrage automatique : pour chaque finding, vérifie que "
                                "`source_tool` correspond à un outil réellement exécuté avec succès "
                                "et que `evidence` chevauche sa donnée brute. Résumé agrégé + champ "
                                "`grounding` ajouté à chaque finding. Ne garantit pas l'exactitude "
                                "sémantique de l'interprétation, seulement l'ancrage factuel."
                            )},
                            "executive_summary":  {"type": "string"},
                            "findings":           {"type": "array"},
                            "strengths":          {"type": "array"},
                            "immediate_actions":  {"type": "array"},
                            "_backend":           {"type": "string", "description": "Backend utilisé : deepseek | gemini | cerebras | groq | openrouter | ollama"},
                            "_cache":             {"type": "object", "description": "Métadonnées cache"},
                        },
                    },
                },
            },
        },
        400: {"description": "`recon_json` manquant et `scan_results` absent en BD, ou paramètre invalide"},
        500: {"description": "Tous les backends IA ont échoué"},
        503: {"description": "Aucun backend IA configuré (clés API manquantes)"},
    },
})
def analyze():
    body           = request.get_json(silent=True) or {}
    recon_json     = body.get("recon_json")
    model_override = body.get("model")
    # Défaut 4 rounds : bon compromis qualité/quota Groq (14 400 req/j)
    max_rounds     = int(body.get("max_search_rounds") or os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", 4))
    max_rounds     = max(1, min(max_rounds, 8))
    recon_id       = body.get("recon_id")
    force_refresh  = bool(body.get("force_refresh", False))

    # ── Vérification du cache BD ──────────────────────────────────────────────
    recon_record = None
    if recon_id:
        try:
            recon_record = Recon.query.get(int(recon_id))
        except Exception:
            pass

        if recon_record and not force_refresh:
            if (
                recon_record.analysis_result and
                recon_record.analysis_expires_at and
                recon_record.analysis_expires_at > datetime.utcnow()
            ):
                cached = json.loads(recon_record.analysis_result)
                remaining_h = round(
                    (recon_record.analysis_expires_at - datetime.utcnow()).total_seconds() / 3600, 1
                )
                logger.info(
                    "Cache analyse valide — recon_id=%s domain=%s expires_in=%.1fh",
                    recon_id, recon_record.domain, remaining_h,
                )
                cached["_cache"] = {
                    "hit":          True,
                    "generated_at": recon_record.analysis_generated_at.isoformat(),
                    "expires_at":   recon_record.analysis_expires_at.isoformat(),
                    "expires_in_h": remaining_h,
                }
                return jsonify({
                    "success":  True,
                    "data":     cached,
                    "cached":   True,
                    "recon_id": int(recon_id),
                })

    # ── Chargement de recon_json depuis la BD si absent du body ──────────────
    if (not recon_json or not isinstance(recon_json, dict)) and recon_record:
        if recon_record.scan_results:
            try:
                recon_json = json.loads(recon_record.scan_results)
                logger.info(
                    "analyze — scan_results chargé depuis BD — recon_id=%s domain=%s",
                    recon_id, recon_record.domain,
                )
            except Exception as e:
                logger.warning("analyze — impossible de parser scan_results en BD: %s", e)

    if not recon_json or not isinstance(recon_json, dict):
        if recon_id:
            return jsonify({
                "success":  False,
                "error":    (
                    f"recon_json absent du body et scan_results non disponible en BD pour recon_id={recon_id}. "
                    "Lancez d'abord POST /pass_recon avec ce recon_id."
                ),
                "recon_id": int(recon_id) if recon_id else None,
            }), 400
        return jsonify({"success": False, "error": "recon_json requis (objet JSON valide)"}), 400

    if recon_record:
        recon_record.set_step('analyzing_ai')
        db.session.commit()

    # ── Validation du nom de modèle ───────────────────────────────────────────
    if model_override is not None:
        if not isinstance(model_override, str) or not _MODEL_RE.match(model_override):
            return jsonify({
                "success": False,
                "error": "Paramètre 'model' invalide. Format attendu : lettres, chiffres, '.', ':', '-', '_', '/' (80 chars max).",
            }), 400

    # ── Vérification qu'au moins un backend est configuré ────────────────────
    if not _any_backend_available():
        hint = (
            " (DEEPSEEK_API_KEY détectée mais DEEPSEEK_CONFIRM_EXTERNAL_SHARING absente — "
            "ajoutez cette variable pour l'activer)" if _DEEPSEEK_API_KEY else ""
        )
        return jsonify({
            "success": False,
            "error": (
                "Aucun backend IA disponible (ni clé cloud, ni Ollama local avec son modèle). "
                "Définissez au moins une clé dans .env : "
                "GEMINI_API_KEY (recommandé), CEREBRAS_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, "
                f"ou DEEPSEEK_API_KEY (payant, nécessite aussi DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true).{hint}"
            ),
        }), 503

    # ── Extraction des signaux ────────────────────────────────────────────────
    try:
        signals = _extract_signals(recon_json)
    except Exception as e:
        logger.exception("Erreur extraction signaux")
        return jsonify({"success": False, "error": f"Erreur extraction : {e}"}), 400

    signals["mitre_attack"] = map_tools_to_techniques(signals.get("tools_executed", []))
    domain = signals.get("domain", "unknown")

    # Construction des search hints
    _tech_hints: List[str] = []
    tech_stack = signals.get("web", {}).get("tech_stack") or {}
    if isinstance(tech_stack, dict):
        for cat, items in tech_stack.items():
            if isinstance(items, list):
                _tech_hints.extend(items[:3])
            elif isinstance(items, str):
                _tech_hints.append(items)
    ssl_data = signals.get("ssl_tls", {}).get("certificate") or {}
    tls_ver  = (ssl_data.get("protocol") or "") if isinstance(ssl_data, dict) else ""
    subdomains_sample = (signals.get("subdomains", {}).get("all") or [])[:5]
    email_config = signals.get("email", {}).get("config") or {}
    spf_val  = email_config.get("spf") or "" if isinstance(email_config, dict) else ""

    search_hints = "\n".join([
        f"• Technologies : {', '.join(_tech_hints[:6]) or 'voir données OSINT'}",
        f"• Version TLS  : {tls_ver or 'voir données OSINT'}",
        f"• Sous-domaines (échantillon) : {', '.join(subdomains_sample) or 'voir données OSINT'}",
        f"• SPF          : {spf_val or 'voir données OSINT'}",
    ])

    # Phase 3 : constats déterministes + KEV + contexte RAG PAR CONSTAT (B7).
    # La requête globale historique (mêmes signaux que search_hints) ne sert
    # plus que de repli quand aucun constat n'est observé. Dégrade
    # silencieusement si le RAG est indisponible (voir utils/rag_retrieval.py).
    _rag_query = f"Sécurité web pour {domain} — technologies: {', '.join(_tech_hints[:6])}; TLS: {tls_ver}; SPF: {spf_val}"
    p3_ctx = _prepare_phase3(recon_json, signals, _rag_query)

    logger.info(
        "Analyse démarrée — domaine=%s | deepseek=%s | gemini=%s | cerebras=%s | groq=%s | openrouter=%s | rounds=%d | or_rounds=%d",
        domain,
        "oui" if _DEEPSEEK_ENABLED else "non",
        "oui" if _GEMINI_API_KEY else "non",
        "oui" if _CEREBRAS_API_KEY else "non",
        "oui" if _GROQ_API_KEY else "non",
        "oui" if _OPENROUTER_API_KEY else "non",
        max_rounds,
        _OR_MAX_ROUNDS,
    )

    # ══════════════════════════════════════════════════════════════════════════
    #  Exécution séquentielle : DeepSeek → Gemini → Cerebras → Groq → OpenRouter
    #
    #  DeepSeek   : payant, PAS de quota gratuit — slot 0 (test, voir CLAUDE.md)
    #  Gemini     : contexte 1M tokens, 1500 req/jour gratuit — slot 1
    #  Cerebras   : débit TPM élevé, modèles llama-3.3-70b — slot 2
    #  Groq       : 14 400 req/jour, rotation modèles — slot 3
    #  OpenRouter : 50 req/jour — dernier recours, rounds limités
    #
    #  Chaque backend préserve sa conversation (msgs) pour transmission
    #  au suivant, évitant de perdre les tool results déjà collectés.
    # ══════════════════════════════════════════════════════════════════════════

    report       = None
    used_backend = None
    prev_msgs    = []   # conversation du backend précédent (tool results préservés)
    now          = datetime.utcnow()

    # ── Slot 0 : DeepSeek (payant — en tête pour test, voir CLAUDE.md) ────────
    if _DEEPSEEK_ENABLED:
        from utils.deepseek_client import DeepSeekClient
        logger.warning(
            "[deepseek] Données OSINT de %s envoyées à un prestataire tiers externe "
            "(DeepSeek) — DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true", domain,
        )
        logger.info("[deepseek] Démarrage analyse principale (%d rounds max)", max_rounds)
        deepseek_report, prev_msgs = _run_backend(
            "deepseek",
            DeepSeekClient,
            model_override,
            _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
            max_rounds,
        )
        if deepseek_report:
            report       = deepseek_report
            used_backend = "deepseek"
            logger.info("[deepseek] Succès — backends suivants non sollicités")
        else:
            searches_done = len([m for m in prev_msgs if m.get("role") == "tool"])
            logger.warning(
                "[deepseek] Aucun résultat — conversation préservée (%d msgs, %d recherches) → Gemini",
                len(prev_msgs), searches_done,
            )

    # ── Slot 1 : Gemini (principal si configuré) ──────────────────────────────
    if report is None and _GEMINI_API_KEY:
        from utils.gemini_client import GeminiClient
        logger.info("[gemini] Démarrage analyse principale (%d rounds max)", max_rounds)
        gemini_report, prev_msgs = _run_backend(
            "gemini",
            GeminiClient,
            model_override,
            _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
            max_rounds,
        )
        if gemini_report:
            report       = gemini_report
            used_backend = "gemini"
            logger.info("[gemini] Succès — backends suivants non sollicités")
        else:
            searches_done = len([m for m in prev_msgs if m.get("role") == "tool"])
            logger.warning(
                "[gemini] Aucun résultat — conversation préservée (%d msgs, %d recherches) → Cerebras",
                len(prev_msgs), searches_done,
            )

    # ── Slot 2 : Cerebras ─────────────────────────────────────────────────────
    if report is None and _CEREBRAS_API_KEY:
        from utils.cerebras_client import CerebrasClient
        logger.info("[cerebras] Démarrage analyse principale (%d rounds max)", max_rounds)
        cerebras_report, prev_msgs = _run_backend(
            "cerebras",
            CerebrasClient,
            model_override,
            _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
            max_rounds,
        )
        if cerebras_report:
            report       = cerebras_report
            used_backend = "cerebras"
            logger.info("[cerebras] Succès — Groq et OpenRouter non sollicités")
        else:
            searches_done = len([m for m in prev_msgs if m.get("role") == "tool"])
            logger.warning(
                "[cerebras] Aucun résultat — conversation préservée (%d msgs, %d recherches) → Groq",
                len(prev_msgs), searches_done,
            )

    # ── Slot 3 : Groq (14 400 req/jour) ──────────────────────────────────────
    if report is None and _GROQ_API_KEY:
        from utils.groq_client import GroqClient
        logger.info("[groq] Démarrage analyse (%d rounds max)", max_rounds)
        has_resume = bool(prev_msgs and any(m.get("role") == "tool" for m in prev_msgs))
        if has_resume:
            logger.info("[groq] Reprise depuis conversation Cerebras (%d msgs)", len(prev_msgs))
        groq_report, groq_msgs = _run_backend(
            "groq",
            GroqClient,
            model_override,
            _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
            max_rounds,
            resume_msgs=prev_msgs if has_resume else None,
        )
        if groq_report:
            report       = groq_report
            used_backend = "groq"
            logger.info("[groq] Succès — OpenRouter non sollicité (quota 50 req/j préservé)")
        else:
            prev_msgs     = groq_msgs  # propager vers OpenRouter
            searches_done = len([m for m in groq_msgs if m.get("role") == "tool"])
            logger.warning(
                "[groq] Aucun résultat — conversation préservée (%d msgs, %d recherches) → OpenRouter",
                len(prev_msgs), searches_done,
            )

    # ── Slot 4 : OpenRouter (dernier recours — 50 req/jour) ──────────────────
    # Reprend la conversation du backend précédent si tool results disponibles
    if report is None and _OPENROUTER_API_KEY:
        from utils.openrouter_client import OpenRouterClient
        or_rounds  = min(_OR_MAX_ROUNDS, max_rounds)
        has_resume = bool(prev_msgs and any(m.get("role") == "tool" for m in prev_msgs))

        if has_resume:
            logger.info(
                "[openrouter] Reprise depuis conversation précédente (%d msgs) — rounds limités: %d",
                len(prev_msgs), or_rounds,
            )
        else:
            logger.info("[openrouter] Démarrage à zéro (%d rounds max)", or_rounds)

        or_report, _ = _run_backend(
            "openrouter",
            OpenRouterClient,
            None,
            _build_messages(_SYSTEM_PROMPT_OPENROUTER, domain, signals, search_hints),
            or_rounds,
            resume_msgs=prev_msgs if has_resume else None,
        )
        if or_report:
            report       = or_report
            used_backend = "openrouter"
        else:
            logger.error("[openrouter] Dernier recours cloud échoué — tentative Ollama local")

    # ── Slot 5 : Ollama local (Map-Reduce — qwen3:8b) ─────────────────────────
    if report is None:
        try:
            from utils.ollama_client import OllamaClient
            ol_client = OllamaClient()
            if ol_client.is_available() and ol_client.model_loaded():
                logger.info("[ollama] Démarrage analyse Map-Reduce (%d sections)", 6)
                ol_msg, ol_searches, _ = ol_client.map_reduce_agentic_chat(
                    signals=signals,
                    tool_handler=_tool_handler,
                    map_rounds=int(os.getenv("OLLAMA_MAP_ROUNDS", "3")),
                )
                content   = ol_msg.get("content", "")
                ol_report = _parse_json_report(content)
                if not ol_report and content:
                    ol_report = _repair_json(ol_client, content, "ollama")
                if ol_report:
                    ol_report.setdefault("searches_performed", ol_searches)
                    ol_report.setdefault("model_used", ol_client.model)
                    ol_report["tokens_used"] = dict(ol_client.usage)
                    report       = ol_report
                    used_backend = "ollama"
                    logger.info("[ollama] Succès Map-Reduce")
                else:
                    logger.error("[ollama] JSON invalide après Map-Reduce")
            else:
                logger.warning("[ollama] Service non disponible ou modèle absent")
        except Exception as _ol_exc:
            logger.error("[ollama] Erreur Map-Reduce: %s", _ol_exc)

    # ── Échec total ───────────────────────────────────────────────────────────
    if not report:
        err_msg = (
            "Aucun backend IA n'a pu produire un rapport. "
            "DeepSeek : vérifiez DEEPSEEK_API_KEY et le solde du compte (payant). "
            "Gemini : vérifiez GEMINI_API_KEY et le quota (1500 req/jour). "
            "Cerebras : vérifiez CEREBRAS_API_KEY et le quota. "
            "Groq : quota TPD épuisé (reset quotidien). "
            "OpenRouter : quota 50 req/jour peut-être épuisé. "
            "Ollama : vérifiez que le service tourne et que qwen3:8b est installé."
        )
        # Notification email à l'utilisateur
        if recon_id:
            try:
                recon_obj = Recon.query.get(recon_id)
                if recon_obj and recon_obj.email:
                    send_error_notification(
                        to_email     = recon_obj.email,
                        firstname    = recon_obj.firstname or '',
                        lastname     = recon_obj.lastname  or '',
                        domain       = domain,
                        error_type   = "analyze_failed",
                        error_detail = "Tous les moteurs d'analyse IA sont temporairement indisponibles.",
                        recon_id     = int(recon_id),
                    )
            except Exception as _mail_e:
                logger.warning("Impossible d'envoyer l'email d'erreur d'analyse : %s", _mail_e)
        return jsonify({"success": False, "error": err_msg}), 500

    # ── Post-traitement déterministe (phase 3) — voir _postprocess_report() ──
    # Validation + B6, sévérité par règles (B5), références RAG (B7), hook
    # ATT&CK phase 4, score, grounding_check et coverage_check.
    report = _postprocess_report(report, signals, p3_ctx, used_backend)

    # Enrichir les métadonnées
    report.setdefault("domain",      domain)
    report.setdefault("analyzed_at", now.isoformat())

    logger.info(
        "Analyse finale — %s | risk_score=%s | findings=%d | searches=%d",
        domain,
        report.get("risk_score", "?"),
        len(report.get("findings") or []),
        len(report.get("searches_performed") or []),
    )

    # ── Persistance en BD si recon_id fourni ──────────────────────────────────
    if recon_record:
        # Horodatage FRAIS, pas `now` (capturé avant toute la cascade IA,
        # potentiellement 20+ minutes plus tôt avec le fallback Ollama) —
        # sans quoi `analysis_generated_at` mesure « début de la requête »
        # au lieu de « fin de l'analyse », et `_compute_timing()` (routes/
        # report.py) affiche une durée d'analyse ridiculement courte (ex.
        # 6.3s pour un Map-Reduce qui a réellement pris ~5 min) — bug réel
        # constaté sur un rapport produit (2026-07-29).
        finished_at = datetime.utcnow()
        expires_at = finished_at + timedelta(hours=_CACHE_TTL_H)
        try:
            # set_analysis_result met aussi à jour les colonnes dénormalisées
            # security_score/security_grade, qui ne peuvent donc pas diverger.
            recon_record.set_analysis_result(report, generated_at=finished_at, expires_at=expires_at)
            recon_record.set_compliance_metrics(
                report.get("findings"), signals.get("tools_executed"), report.get("mitre_attack"),
            )
            db.session.commit()
            logger.info(
                "Analyse sauvegardée en BD — recon_id=%s expires_at=%s",
                recon_id, expires_at.isoformat(),
            )
            report["_cache"] = {
                "hit":          False,
                "generated_at": now.isoformat(),
                "expires_at":   expires_at.isoformat(),
                "expires_in_h": _CACHE_TTL_H,
            }
        except Exception as e:
            logger.error("Erreur sauvegarde analyse BD — recon_id=%s : %s", recon_id, e)

    resp_body: Dict[str, Any] = {"success": True, "data": report, "cached": False}
    if recon_id:
        resp_body["recon_id"] = int(recon_id)
    return jsonify(resp_body)


# ── Endpoint utilitaire : infos backends IA ───────────────────────────────────

@analyze_bp.route("/analyze/status", methods=["GET"])
@require_auth
def analyze_status():
    """Vérifie la disponibilité des backends IA (DeepSeek, Gemini, Cerebras, Groq, OpenRouter) et liste les modèles."""
    status: Dict[str, Any] = {
        "success":         True,
        "search_provider": "tavily" if os.getenv("TAVILY_API_KEY") else "duckduckgo",
    }

    backends_active = []

    if _DEEPSEEK_API_KEY and not _DEEPSEEK_ENABLED:
        status["deepseek"] = {
            "configured": True,
            "enabled":    False,
            "slot":       0,
            "note": (
                "Clé présente mais DEEPSEEK_CONFIRM_EXTERNAL_SHARING absente/non vraie "
                "— slot désactivé (garde-fou anti-partage silencieux, voir CLAUDE.md)."
            ),
        }
    elif _DEEPSEEK_ENABLED:
        from utils.deepseek_client import DeepSeekClient
        ds_client = DeepSeekClient()
        ds_ok     = ds_client.is_available()
        status["deepseek"] = {
            "configured":   True,
            "enabled":      True,
            "online":       ds_ok,
            "model":        ds_client.model,
            "model_loaded": ds_client.model_loaded(),
            "models":       ds_client.list_models(),
            "slot":         0,
        }
        if ds_ok:
            backends_active.append("deepseek")
    else:
        status["deepseek"] = {"configured": False, "enabled": False, "slot": 0}

    if _GEMINI_API_KEY:
        from utils.gemini_client import GeminiClient
        gem_client = GeminiClient()
        gem_ok     = gem_client.is_available()
        status["gemini"] = {
            "configured":   True,
            "online":       gem_ok,
            "model":        gem_client.model,
            "model_loaded": gem_client.model_loaded(),
            "models":       gem_client.list_models(),
            "slot":         1,
        }
        if gem_ok:
            backends_active.append("gemini")
    else:
        status["gemini"] = {"configured": False, "slot": 1}

    if _CEREBRAS_API_KEY:
        from utils.cerebras_client import CerebrasClient
        cb_client = CerebrasClient()
        cb_ok     = cb_client.is_available()
        status["cerebras"] = {
            "configured":   True,
            "online":       cb_ok,
            "model":        cb_client.model,
            "model_loaded": cb_client.model_loaded(),
            "models":       cb_client.list_models(),
            "slot":         2,
        }
        if cb_ok:
            backends_active.append("cerebras")
    else:
        status["cerebras"] = {"configured": False, "slot": 2}

    if _GROQ_API_KEY:
        from utils.groq_client import GroqClient
        groq_client = GroqClient()
        groq_ok     = groq_client.is_available()
        status["groq"] = {
            "configured":   True,
            "online":       groq_ok,
            "model":        groq_client.model,
            "model_loaded": groq_client.model_loaded() if groq_ok else False,
            "models":       groq_client.list_models() if groq_ok else [],
            "slot":         3,
        }
        if groq_ok:
            backends_active.append("groq")
    else:
        status["groq"] = {"configured": False, "slot": 3}

    if _OPENROUTER_API_KEY:
        from utils.openrouter_client import OpenRouterClient
        or_client = OpenRouterClient()
        or_ok     = or_client.is_available()
        status["openrouter"] = {
            "configured":   True,
            "online":       or_ok,
            "model":        or_client.model,
            "model_loaded": or_client.model_loaded(),
        }
        if or_ok:
            backends_active.append("openrouter")
    else:
        status["openrouter"] = {"configured": False}

    # Ollama — toujours affiché (slot 5, dernier recours local, Map-Reduce)
    from utils.ollama_client import OllamaClient
    ol_client = OllamaClient()
    ol_ok     = ol_client.is_available()
    status["ollama"] = {
        "configured":   True,
        "online":       ol_ok,
        "url":          ol_client.base_url,
        "model":        ol_client.model,
        "model_loaded": ol_client.model_loaded() if ol_ok else False,
        "models":       ol_client.list_models() if ol_ok else [],
        "slot":         5,
        "mode":         "map_reduce",
    }
    if ol_ok and ol_client.model_loaded():
        backends_active.append("ollama")

    status["backends_active"] = backends_active
    status["dual_analysis"]   = len(backends_active) == 2
    status["success"]         = len(backends_active) > 0

    return jsonify(status)


# ══════════════════════════════════════════════════════════════════════════════
#  Analyse asynchrone — pour n8n et clients avec timeout court
# ══════════════════════════════════════════════════════════════════════════════

def _run_bg_analysis(
    app_obj,
    recon_id: int,
    recon_json: dict,
    model_override: Optional[str],
    max_rounds: int,
    or_max_rounds: int,
) -> None:
    """Exécute l'analyse complète (slots 1-5) en background avec son propre contexte Flask."""
    with app_obj.app_context():
        try:
            signals = _extract_signals(recon_json)
            signals["mitre_attack"] = map_tools_to_techniques(signals.get("tools_executed", []))
            domain  = signals.get("domain", "unknown")

            _tech_hints: List[str] = []
            tech_stack = signals.get("web", {}).get("tech_stack") or {}
            if isinstance(tech_stack, dict):
                for cat, items in tech_stack.items():
                    if isinstance(items, list):
                        _tech_hints.extend(items[:3])
                    elif isinstance(items, str):
                        _tech_hints.append(items)
            ssl_data = signals.get("ssl_tls", {}).get("certificate") or {}
            tls_ver  = (ssl_data.get("protocol") or "") if isinstance(ssl_data, dict) else ""
            subdomains_sample = (signals.get("subdomains", {}).get("all") or [])[:5]
            email_config = signals.get("email", {}).get("config") or {}
            spf_val = email_config.get("spf") or "" if isinstance(email_config, dict) else ""
            search_hints = "\n".join([
                f"• Technologies : {', '.join(_tech_hints[:6]) or 'voir données OSINT'}",
                f"• Version TLS  : {tls_ver or 'voir données OSINT'}",
                f"• Sous-domaines (échantillon) : {', '.join(subdomains_sample) or 'voir données OSINT'}",
                f"• SPF          : {spf_val or 'voir données OSINT'}",
            ])

            # Constats déterministes + KEV + RAG par constat — voir analyze() (chemin sync).
            _rag_query = f"Sécurité web pour {domain} — technologies: {', '.join(_tech_hints[:6])}; TLS: {tls_ver}; SPF: {spf_val}"
            p3_ctx = _prepare_phase3(recon_json, signals, _rag_query)

            report       = None
            used_backend = None
            prev_msgs    = []
            now          = datetime.utcnow()

            # Slot 0: DeepSeek (payant — en tête pour test, voir CLAUDE.md)
            if _DEEPSEEK_ENABLED:
                from utils.deepseek_client import DeepSeekClient
                logger.warning(
                    "[async][deepseek] Données OSINT de %s envoyées à un prestataire "
                    "tiers externe (DeepSeek) — DEEPSEEK_CONFIRM_EXTERNAL_SHARING=true",
                    domain,
                )
                ds_report, prev_msgs = _run_backend(
                    "deepseek", DeepSeekClient, model_override,
                    _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
                    max_rounds,
                )
                if ds_report:
                    report = ds_report; used_backend = "deepseek"

            # Slot 1: Gemini
            if report is None and _GEMINI_API_KEY:
                from utils.gemini_client import GeminiClient
                gem_report, prev_msgs = _run_backend(
                    "gemini", GeminiClient, model_override,
                    _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
                    max_rounds,
                )
                if gem_report:
                    report = gem_report; used_backend = "gemini"

            # Slot 2: Cerebras
            if report is None and _CEREBRAS_API_KEY:
                from utils.cerebras_client import CerebrasClient
                has_resume = bool(prev_msgs and any(m.get("role") == "tool" for m in prev_msgs))
                c_report, prev_msgs = _run_backend(
                    "cerebras", CerebrasClient, model_override,
                    _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
                    max_rounds,
                    resume_msgs=prev_msgs if has_resume else None,
                )
                if c_report:
                    report = c_report; used_backend = "cerebras"

            # Slot 3: Groq
            if report is None and _GROQ_API_KEY:
                from utils.groq_client import GroqClient
                has_resume = bool(prev_msgs and any(m.get("role") == "tool" for m in prev_msgs))
                g_report, g_msgs = _run_backend(
                    "groq", GroqClient, model_override,
                    _build_messages(_SYSTEM_PROMPT_GROQ, domain, signals, search_hints),
                    max_rounds,
                    resume_msgs=prev_msgs if has_resume else None,
                )
                if g_report:
                    report = g_report; used_backend = "groq"
                else:
                    prev_msgs = g_msgs

            # Slot 4: OpenRouter
            if report is None and _OPENROUTER_API_KEY:
                from utils.openrouter_client import OpenRouterClient
                or_rounds  = min(or_max_rounds, max_rounds)
                has_resume = bool(prev_msgs and any(m.get("role") == "tool" for m in prev_msgs))
                or_report, _ = _run_backend(
                    "openrouter", OpenRouterClient, None,
                    _build_messages(_SYSTEM_PROMPT_OPENROUTER, domain, signals, search_hints),
                    or_rounds,
                    resume_msgs=prev_msgs if has_resume else None,
                )
                if or_report:
                    report = or_report; used_backend = "openrouter"

            # Slot 5: Ollama local (Map-Reduce)
            if report is None:
                try:
                    from utils.ollama_client import OllamaClient
                    from utils.ollama_lock import ollama_slot
                    ol_client = OllamaClient()
                    if ol_client.is_available() and ol_client.model_loaded():
                        def _mark_queued():
                            try:
                                rec = Recon.query.get(recon_id)
                                if rec:
                                    rec.set_step('analyzing_ai_queued')
                                    db.session.commit()
                            except Exception:
                                logger.exception("[async][ollama] échec maj current_step (queued)")

                        logger.info("[async][ollama] Démarrage Map-Reduce")
                        # Ollama est une instance unique, CPU seul, partagée par tout
                        # le projet — deux analyses simultanées se ralentiraient
                        # mutuellement plutôt que de vraiment paralléliser (voir
                        # utils/ollama_lock.py). Le verrou sérialise l'accès ; le
                        # scan qui attend son tour est visible comme tel dans le
                        # dashboard via current_step='analyzing_ai_queued'.
                        with ollama_slot(on_wait=_mark_queued):
                            rec = Recon.query.get(recon_id)
                            if rec and rec.current_step == 'analyzing_ai_queued':
                                rec.set_step('analyzing_ai')
                                db.session.commit()
                            ol_msg, ol_searches, _ = ol_client.map_reduce_agentic_chat(
                                signals=signals,
                                tool_handler=_tool_handler,
                                map_rounds=int(os.getenv("OLLAMA_MAP_ROUNDS", "3")),
                            )
                        content   = ol_msg.get("content", "")
                        ol_report = _parse_json_report(content)
                        if not ol_report and content:
                            ol_report = _repair_json(ol_client, content, "ollama")
                        if ol_report:
                            ol_report.setdefault("searches_performed", ol_searches)
                            ol_report.setdefault("model_used", ol_client.model)
                            ol_report["tokens_used"] = dict(ol_client.usage)
                            report = ol_report; used_backend = "ollama"
                            logger.info("[async][ollama] Succès Map-Reduce")
                        else:
                            logger.error("[async][ollama] JSON invalide après Map-Reduce")
                    else:
                        logger.warning(
                            "[async][ollama] Service non disponible ou modèle absent "
                            "(available=%s, model=%s, model_loaded=%s)",
                            ol_client.is_available(), ol_client.model, ol_client.model_loaded(),
                        )
                except Exception as _ol_exc:
                    logger.error("[async][ollama] Erreur Map-Reduce: %s", _ol_exc)

            if not report:
                logger.error("[async] recon_id=%s — aucun backend n'a produit de rapport", recon_id)
                # Gap comblé (2026-07-29) : ce retour anticipé ne passait ni par
                # `status='failed'`, ni par une notification — un enregistrement
                # restait affiché `running` indéfiniment si les 5 backends (dont
                # Ollama, ex. verrou saturé — voir utils/ollama_lock.py) échouaient
                # tous, sans qu'aucune exception ne soit levée jusqu'ici.
                try:
                    rec_fail = Recon.query.get(recon_id)
                    if rec_fail:
                        rec_fail.status = 'failed'
                        db.session.commit()
                        if rec_fail.email:
                            send_error_notification(
                                to_email     = rec_fail.email,
                                firstname    = rec_fail.firstname or '',
                                lastname     = rec_fail.lastname  or '',
                                domain       = rec_fail.domain,
                                error_type   = "analyze_failed",
                                error_detail = "Aucun backend IA (Gemini, Cerebras, Groq, OpenRouter, Ollama) n'a produit de rapport exploitable.",
                                recon_id     = recon_id,
                            )
                except Exception:
                    logger.exception("[async] échec notification/statut (aucun backend) recon_id=%s", recon_id)
                    try: db.session.rollback()
                    except Exception: pass
                return

            # ── Post-traitement déterministe (phase 3) — même fonction que le
            # chemin sync, voir _postprocess_report() ──────────────────────
            report = _postprocess_report(report, signals, p3_ctx, used_backend)

            report.setdefault("domain",      domain)
            report.setdefault("analyzed_at", now.isoformat())

            recon_rec = Recon.query.get(recon_id)
            if recon_rec:
                # Horodatage FRAIS — voir commentaire équivalent dans analyze()
                # (chemin sync) : `now` a été capturé avant toute la cascade IA,
                # le réutiliser ici ferait mesurer une durée d'analyse quasi
                # nulle au lieu de la durée réelle (bug constaté en conditions
                # réelles : 6.3s affichés pour un Map-Reduce qui a pris ~5 min).
                finished_at = datetime.utcnow()
                expires_at = finished_at + timedelta(hours=_CACHE_TTL_H)
                recon_rec.set_analysis_result(report, generated_at=finished_at, expires_at=expires_at)
                recon_rec.set_compliance_metrics(
                    report.get("findings"), signals.get("tools_executed"), report.get("mitre_attack"),
                )
                db.session.commit()
                logger.info(
                    "[async] Analyse sauvegardée — recon_id=%s risk_score=%s findings=%d",
                    recon_id, report.get("risk_score", "?"), len(report.get("findings") or []),
                )

        except Exception as e:
            logger.exception("[async] Erreur analyse background recon_id=%s: %s", recon_id, e)
            # `current_step` reste tel quel (probablement 'analyzing_ai') pour
            # que le dashboard montre à quelle étape ça a échoué — voir le
            # même principe déjà appliqué à generate_final_report (routes/report.py).
            try:
                recon_fail = Recon.query.get(recon_id)
                if recon_fail:
                    recon_fail.status = 'failed'
                    db.session.commit()
                    if recon_fail.email:
                        send_error_notification(
                            to_email     = recon_fail.email,
                            firstname    = recon_fail.firstname or '',
                            lastname     = recon_fail.lastname  or '',
                            domain       = recon_fail.domain,
                            error_type   = "analyze_failed",
                            error_detail = "L'analyse IA en arrière-plan a échoué de façon inattendue.",
                            recon_id     = recon_id,
                        )
            except Exception as _notif_e:
                logger.error("[async] Échec notification/statut après erreur recon_id=%s: %s", recon_id, _notif_e)
                try: db.session.rollback()
                except Exception: pass
        finally:
            with _bg_running_lock:
                _bg_running.pop(recon_id, None)


@analyze_bp.route("/analyze/async", methods=["POST"])
@require_service_or_auth
@limiter.limit("5 per hour")
@swag_from({
    "tags": ["IA Analysis"],
    "security": [{"basicAuth": []}],
    "summary": "Lancer une analyse IA en arrière-plan (non-bloquant)",
    "description": (
        "Lance l'analyse IA dans un thread background et retourne **immédiatement** un `202`.\n\n"
        "Conçu pour les clients avec timeout court (n8n, Zapier, scripts CI/CD).\n\n"
        "### Flux recommandé\n\n"
        "```\n"
        "1. POST /analyze/async   → { status: 'processing', recon_id: 42, poll_url: '/analyze/wait/42' }\n"
        "2. GET  /analyze/wait/42 → attend jusqu'à 10 min, retourne le rapport quand prêt\n"
        "```\n\n"
        "### Comportements spéciaux\n\n"
        "- Si le cache BD est **valide** : retourne `200` immédiatement avec `status: 'cached'` "
        "(pas de thread lancé).\n"
        "- Si une analyse est **déjà en cours** pour ce `recon_id` : retourne `202` avec "
        "`status: 'already_running'` sans dupliquer le thread.\n"
        "- Le résultat est sauvegardé en BD dès qu'il est prêt — récupérable via "
        "`GET /analyze/wait/<recon_id>` ou `POST /analyze` (cache hit).\n\n"
        "### Même chaîne de backends que /analyze\n"
        "Cerebras (slot 1) → Groq (slot 2) → OpenRouter (slot 3), avec rotation automatique "
        "de modèles sur quota épuisé ou payload trop grand."
    ),
    "parameters": [
        {
            "in": "body",
            "name": "body",
            "required": True,
            "schema": {
                "type": "object",
                "required": ["recon_id"],
                "properties": {
                    "recon_id": {
                        "type": "integer",
                        "description": "ID de l'enregistrement Recon (doit avoir `scan_results` en BD).",
                        "example": 42,
                    },
                    "force_refresh": {
                        "type": "boolean",
                        "description": "Forcer une nouvelle analyse même si le cache BD est valide.",
                        "default": False,
                    },
                    "model": {
                        "type": "string",
                        "description": "Override du modèle pour le backend actif.",
                        "example": "llama-3.3-70b-versatile",
                    },
                    "max_search_rounds": {
                        "type": "integer",
                        "description": "Nombre max de tours de recherche web par backend (1–8, défaut : 4).",
                        "minimum": 1,
                        "maximum": 8,
                        "default": 4,
                    },
                },
            },
        }
    ],
    "responses": {
        200: {
            "description": "Cache BD valide — résultat déjà disponible, aucun thread lancé",
            "schema": {
                "type": "object",
                "properties": {
                    "success":  {"type": "boolean", "example": True},
                    "status":   {"type": "string", "enum": ["cached"], "example": "cached"},
                    "recon_id": {"type": "integer"},
                },
            },
        },
        202: {
            "description": "Analyse lancée (ou déjà en cours) — utiliser `poll_url` pour récupérer le résultat",
            "schema": {
                "type": "object",
                "properties": {
                    "success":  {"type": "boolean", "example": True},
                    "status":   {"type": "string", "enum": ["processing", "already_running"]},
                    "recon_id": {"type": "integer"},
                    "poll_url": {"type": "string", "example": "/analyze/wait/42"},
                },
            },
        },
        400: {"description": "`recon_id` manquant, invalide, ou `scan_results` absent en BD"},
        404: {"description": "`recon_id` introuvable en BD"},
        503: {"description": "Aucun backend IA configuré"},
    },
})
def analyze_async():
    """Lance l'analyse IA en arrière-plan et retourne immédiatement 202."""
    body           = request.get_json(silent=True) or {}
    recon_id       = body.get("recon_id")
    model_override = body.get("model")
    max_rounds     = int(body.get("max_search_rounds") or os.getenv("ANALYSIS_MAX_SEARCH_ROUNDS", 4))
    max_rounds     = max(1, min(max_rounds, 8))
    force_refresh  = bool(body.get("force_refresh", False))

    if not recon_id:
        return jsonify({"success": False, "error": "recon_id requis"}), 400
    try:
        recon_id = int(recon_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "recon_id doit être un entier"}), 400

    if model_override is not None:
        if not isinstance(model_override, str) or not _MODEL_RE.match(model_override):
            return jsonify({"success": False, "error": "Paramètre 'model' invalide."}), 400

    if not _any_backend_available():
        return jsonify({"success": False, "error": "Aucun backend IA configuré."}), 503

    recon_record = Recon.query.get(recon_id)
    if not recon_record:
        return jsonify({"success": False, "error": f"recon_id={recon_id} introuvable"}), 404

    # Cache valide → retour immédiat sans lancer l'analyse
    if not force_refresh and recon_record.analysis_result and recon_record.analysis_expires_at and \
       recon_record.analysis_expires_at > datetime.utcnow():
        return jsonify({"success": True, "status": "cached", "recon_id": recon_id}), 200

    if not recon_record.scan_results:
        return jsonify({
            "success": False,
            "error":   "scan_results absent en BD — lancez d'abord POST /pass_recon",
        }), 400

    try:
        recon_json = json.loads(recon_record.scan_results)
    except Exception as e:
        return jsonify({"success": False, "error": f"scan_results invalide: {e}"}), 400

    recon_record.set_step('analyzing_ai')
    db.session.commit()

    # Vérifier si une analyse est déjà en cours
    with _bg_running_lock:
        if recon_id in _bg_running:
            return jsonify({
                "success": True,
                "status":  "already_running",
                "recon_id": recon_id,
            }), 202
        _bg_running[recon_id] = True

    app_obj = current_app._get_current_object()
    t = threading.Thread(
        target=_run_bg_analysis,
        args=(app_obj, recon_id, recon_json, model_override, max_rounds, _OR_MAX_ROUNDS),
        daemon=True,
        name=f"analyze-bg-{recon_id}",
    )
    t.start()
    logger.info("[async] Analyse lancée en background — recon_id=%s thread=%s", recon_id, t.name)

    return jsonify({
        "success":  True,
        "status":   "processing",
        "recon_id": recon_id,
        "poll_url": f"/analyze/wait/{recon_id}",
    }), 202


@analyze_bp.route("/analyze/wait/<int:recon_id>", methods=["GET", "POST"])
@require_service_or_auth
@limiter.limit("60 per minute")
@swag_from({
    "tags": ["IA Analysis"],
    "security": [{"basicAuth": []}],
    "summary": "Attendre et récupérer le résultat d'une analyse async (long-polling)",
    "description": (
        "Attend la fin d'une analyse lancée via `POST /analyze/async`.\n\n"
        "### Mécanisme\n\n"
        "Interroge la base de données toutes les **5 secondes** jusqu'à ce que "
        "`analysis_result` soit renseigné pour ce `recon_id`. "
        "Retourne le rapport complet dès qu'il est disponible.\n\n"
        "### Timeout\n\n"
        "Par défaut 600 s (10 min). Configurable via le paramètre query `?timeout=<secondes>` "
        "(min : 10 s, max : 600 s). Si l'analyse n'est pas terminée dans ce délai, "
        "retourne `408` — l'analyse continue néanmoins en background.\n\n"
        "### Configuration n8n recommandée\n\n"
        "- **Node 1** : `POST /analyze/async` — timeout node : 30 000 ms\n"
        "- **Node 2** : `GET /analyze/wait/{{ $json.recon_id }}?timeout=600` — "
        "timeout node : **660 000 ms** (11 min, pour laisser 1 min de marge)\n\n"
        "### Utilisation directe (sans async)\n\n"
        "Cet endpoint fonctionne aussi si l'analyse a déjà été lancée et sauvegardée "
        "en BD par un autre appel — il retourne immédiatement si `analysis_result` est déjà présent."
    ),
    "parameters": [
        {
            "in": "path",
            "name": "recon_id",
            "type": "integer",
            "required": True,
            "description": "ID de l'enregistrement Recon à surveiller.",
            "example": 42,
        },
        {
            "in": "query",
            "name": "timeout",
            "type": "integer",
            "required": False,
            "description": "Durée maximale d'attente en secondes (10–600, défaut : 600).",
            "default": 600,
        },
    ],
    "responses": {
        200: {
            "description": "Analyse terminée — rapport disponible",
            "schema": {
                "type": "object",
                "properties": {
                    "success":  {"type": "boolean", "example": True},
                    "cached":   {"type": "boolean", "example": False},
                    "recon_id": {"type": "integer"},
                    "data": {
                        "type": "object",
                        "description": "Rapport structuré (même format que POST /analyze)",
                        "properties": {
                            "domain":             {"type": "string"},
                            "risk_score":         {"type": "integer"},
                            "risk_level":         {"type": "string"},
                            "security_score":     {"type": "integer"},
                            "security_grade":     {"type": "string"},
                            "security_posture":   {"type": "string"},
                            "security_breakdown": {"type": "object"},
                            "grounding_check":    {"type": "object", "description": "Contrôle d'ancrage automatique — voir POST /analyze"},
                            "executive_summary":  {"type": "string"},
                            "findings":           {"type": "array"},
                            "strengths":          {"type": "array"},
                            "immediate_actions":  {"type": "array"},
                            "_backend":           {"type": "string"},
                            "_cache":             {"type": "object"},
                        },
                    },
                },
            },
        },
        404: {"description": "`recon_id` introuvable en BD"},
        408: {
            "description": "Timeout — l'analyse n'est pas terminée dans le délai imparti",
            "schema": {
                "type": "object",
                "properties": {
                    "success":  {"type": "boolean", "example": False},
                    "status":   {"type": "string", "enum": ["timeout"]},
                    "error":    {"type": "string"},
                    "recon_id": {"type": "integer"},
                },
            },
        },
        500: {"description": "Erreur de parsing du résultat en BD"},
    },
})
def analyze_wait(recon_id: int):
    """Long-polling : attend la fin d'une analyse async et retourne le rapport."""
    timeout  = int(request.args.get("timeout", 600))
    timeout  = max(10, min(timeout, 600))
    interval = 5

    deadline = _time.monotonic() + timeout

    while _time.monotonic() < deadline:
        try:
            db.session.expire_all()
            recon_rec = Recon.query.get(recon_id)
        except Exception:
            db.session.rollback()
            recon_rec = Recon.query.get(recon_id)

        if not recon_rec:
            return jsonify({"success": False, "error": f"recon_id={recon_id} introuvable"}), 404

        if recon_rec.analysis_result:
            try:
                result = json.loads(recon_rec.analysis_result)
            except Exception as e:
                return jsonify({"success": False, "error": f"Erreur parsing résultat: {e}"}), 500
            result["_cache"] = {
                "hit":          False,
                "generated_at": recon_rec.analysis_generated_at.isoformat()
                                if recon_rec.analysis_generated_at else None,
                "expires_at":   recon_rec.analysis_expires_at.isoformat()
                                if recon_rec.analysis_expires_at else None,
            }
            return jsonify({
                "success":  True,
                "data":     result,
                "recon_id": recon_id,
                "cached":   False,
            })

        still_running = recon_id in _bg_running
        logger.debug(
            "[wait] recon_id=%s — pas encore disponible (running=%s, remaining=%.0fs)",
            recon_id, still_running, deadline - _time.monotonic(),
        )
        _time.sleep(interval)

    still_running = recon_id in _bg_running
    return jsonify({
        "success":  False,
        "status":   "timeout",
        "error":    f"Timeout ({timeout}s) — analyse toujours en cours : {still_running}",
        "recon_id": recon_id,
    }), 408
