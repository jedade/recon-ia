# utils/severity_rules.py
"""
Sévérité déterministe des findings (B5, phase 3 du plan) : le LLM propose,
la règle tranche.

Problème constaté sur de vrais rapports (CLAUDE.md, isoc.bj et example.com,
fallback Ollama qwen3:1.7b) : le petit modèle classe « Critique » des
constats entièrement POSITIFS (« DNSBL propre et SPF correctement
configuré »), invente un « HSTS non configuré » alors que l'en-tête est
présent, et aboutit à 0/100 sur example.com. La sévérité venait du texte
du LLM, le score en découlait : rien n'était défendable.

Principe :
  1. `detect_observations()` lit les données BRUTES du scan (jamais le texte
     du LLM) et établit, pour chaque type de constat de la table `RULES`, un
     état tri-valué : `observed` (le défaut est prouvé par la donnée),
     `absent` (la donnée prouve le contraire) ou `unknown` (outil absent,
     en échec, ou donnée insuffisante).
  2. `apply_severity_rules()` rattache chaque finding du LLM à une ou
     plusieurs règles par son texte (titre, puis evidence), puis :
       - règle `observed`   → sévérité = celle de la règle (la plus haute si
                              plusieurs), `severity_rule` = id de la règle ;
       - règle `absent` seulement → le finding contredit la donnée : il est
                              RETIRÉ (tracé dans `severity_check.dropped`) ;
       - règle `unknown` seulement → invérifiable : sévérité du LLM plafonnée
                              à MEDIUM, `severity_rule = "unverified"` ;
       - aucune règle, contenu positif → INFO (`positive_observation`) ;
         un constat positif ne peut JAMAIS être HIGH/CRITICAL ;
       - aucune règle, contenu négatif → sévérité du LLM plafonnée à
                              `SEVERITY_UNMATCHED_CAP` (défaut MEDIUM),
                              `severity_rule = "llm_capped"` ou `"llm_proposed"`.
  3. Les constats `observed` de sévérité ≥ `SEVERITY_INJECT_MIN` (défaut
     HIGH) qu'aucun finding ne couvre sont AJOUTÉS (finding déterministe,
     `generated_by = "rule"`) : un KEV ou un takeover ignoré par le modèle
     ne doit pas donner un bon score.

Le rattachement texte → règle est une heuristique par mots-clés (comme
l'avertissait CLAUDE.md) : c'est pourquoi elle ne sert qu'à CHOISIR la
règle candidate. La décision (sévérité, retrait) vient toujours de la
donnée brute, jamais du mot-clé seul.

Le module ne fait aucun appel réseau : la liste KEV est passée par
l'appelant (utils/kev.py).
"""
import logging
import os
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ["low", "medium", "high"]
_CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

# Seuil EPSS (probabilité d'exploitation à 30 jours, FIRST) au-delà duquel une
# CVE observée passe en HIGH. 0,1 = 10 % : ordre de grandeur couramment retenu
# pour isoler le haut de la distribution (la médiane EPSS est < 0,01).
_EPSS_THRESHOLD = float(os.getenv("EPSS_HIGH_THRESHOLD", "0.1"))
_UNMATCHED_CAP = os.getenv("SEVERITY_UNMATCHED_CAP", "MEDIUM").strip().upper()
if _UNMATCHED_CAP not in _RANK:
    _UNMATCHED_CAP = "MEDIUM"
_INJECT_MIN = os.getenv("SEVERITY_INJECT_MIN", "HIGH").strip().upper()
if _INJECT_MIN not in _RANK and _INJECT_MIN != "NONE":
    _INJECT_MIN = "HIGH"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def sev_max(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def sev_min(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) <= _RANK.get(b, 0) else b


def conf_min(a: Optional[str], b: Optional[str]) -> str:
    a = a if a in _CONF_RANK else "high"
    b = b if b in _CONF_RANK else "high"
    return a if _CONF_RANK[a] <= _CONF_RANK[b] else b


# ══════════════════════════════════════════════════════════════════════════════
#  Normalisation du texte pour le rattachement finding → règle
# ══════════════════════════════════════════════════════════════════════════════

def _norm(text: Any) -> str:
    """Minuscules, accents retirés ; conserve `. - _ / + ? ~ =` (SPF, en-têtes, versions)."""
    text = unicodedata.normalize("NFKD", str(text or ""))
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    text = re.sub(r"[^a-z0-9.\-_/+?~=]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# Tournures positives « figées » retirées AVANT la recherche de négation —
# sinon « aucun problème » ou « aucun CNAME dangling » passerait pour un
# défaut (« aucun » est aussi un marqueur d'absence).
_POSITIVE_PHRASES = re.compile(
    r"aucune? (probleme|vulnerabilite|anomalie|risque|faille|fuite|menace|cname dangling|"
    r"liste noire|blacklist|inscription|exposition|alerte|incident|ioc|port sensible)s?"
    r"|n.est (liste|reference|present) dans aucune?"
    r"|no (issue|problem|vulnerabilit\w*|risk|finding|leak)s?"
    r"|not listed|not blacklisted"
)
_NEGATION = re.compile(
    r"\b(absente?s?|manquante?s?|missing|non (configure|defini|present|active|deploye|publie|signe|trouve)\w*"
    r"|aucune?|pas de|pas d|sans|not (set|configured|present|found|enabled|deployed)"
    r"|not_found|desactive\w*|inexistante?s?|introuvables?|lacks?|lacking|no)\b"
)
_NEGATIVE_WORDS = re.compile(
    r"\b(faibles?|vulnerab\w*|risques?|expose\w*|obsolete\w*|critiques?|dangereu\w*|weak|insecure|"
    r"permissi\w*|non conforme|mal configure\w*|misconfigur\w*|expire\w*|perime\w*|invalide?|"
    r"compromi\w*|fuite\w*|leak\w*|malware|phishing|usurpation|spoofing|takeover|listee?s?|"
    r"blacklist\w*|ouverts?|open|mais|but|cependant|toutefois|however|partiel\w*|insuffisant\w*|"
    r"trop (court|faible|long)e?s?)\b"
)
# Tournures de contraste : « DMARC présent mais sans rua » ne doit pas être
# lu comme « DMARC absent » au point de retirer le finding.
_CONTRAST = re.compile(r"\b(mais|but|cependant|toutefois|however|bien que|although|partiel\w*)\b")
_POSITIVE_WORDS = re.compile(
    r"\b(correctement|bien configure\w*|conforme|valides?|propres?|clean|actives?|activee?s?|"
    r"en place|presente?s?|strict\w*|protege\w*|securise\w*|bonne pratique|best practice|"
    r"properly|enabled|configured|robuste|ok)\b"
)


def is_positive(text_norm: str) -> bool:
    """Vrai si le texte décrit un constat positif (aucun marqueur de défaut)."""
    stripped = _POSITIVE_PHRASES.sub(" ", text_norm)
    has_positive = bool(_POSITIVE_WORDS.search(stripped)) or stripped != text_norm
    if not has_positive:
        return False
    return not (_NEGATION.search(stripped) or _NEGATIVE_WORDS.search(stripped))


# ══════════════════════════════════════════════════════════════════════════════
#  Table des règles
# ══════════════════════════════════════════════════════════════════════════════
# topic   : regex (texte normalisé) qui rattache un finding à la règle
# neg     : True si le texte doit AUSSI exprimer une absence (« DMARC absent »)
# dedupe  : un seul finding par règle (pas de sujet multiple : pas un port, une CVE…)
# rag     : requête RAG du constat (utils/rag_retrieval.py, une requête par constat)

RULES: Dict[str, Dict[str, Any]] = {
    # ── Email ────────────────────────────────────────────────────────────────
    "dmarc_missing": {
        "severity": "HIGH", "category": "Email", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bdmarc\b", "exclude": r"\bp ?= ?none\b|\bp none\b|policy none|politique none",
        "title": "DMARC absent",
        "recommendation": "Publier un enregistrement DMARC (_dmarc) en p=quarantine puis p=reject, avec rapports rua.",
        "rag": "DMARC record missing email spoofing phishing RFC 7489 policy reject",
    },
    "dmarc_p_none": {
        "severity": "MEDIUM", "category": "Email", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"\bdmarc\b.*(\bp ?= ?none\b|\bp none\b|policy none|politique (none|permissive|de surveillance)|"
                 r"monitor|surveillance uniquement)|(\bp ?= ?none\b|\bp none\b).*\bdmarc\b",
        "title": "Politique DMARC en p=none (surveillance seule)",
        "recommendation": "Passer la politique DMARC de p=none à p=quarantine puis p=reject.",
        "rag": "DMARC policy p=none monitoring only no protection quarantine reject RFC 7489",
    },
    "spf_missing": {
        "severity": "HIGH", "category": "Email", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bspf\b", "exclude": r"[+?~-]all|softfail|lookup|recherches dns",
        "title": "SPF absent",
        "recommendation": "Publier un enregistrement SPF listant les expéditeurs légitimes et terminé par -all.",
        "rag": "SPF record missing sender policy framework RFC 7208 email spoofing",
    },
    "spf_permissive": {
        "severity": "HIGH", "category": "Email", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"\bspf\b.*(\+all|permissi|tout le monde|anyone)|\+all",
        "title": "SPF permissif (+all)",
        "recommendation": "Remplacer +all par -all (ou ~all le temps de valider les expéditeurs).",
        "rag": "SPF +all permissive any sender allowed RFC 7208",
    },
    "spf_neutral": {
        "severity": "MEDIUM", "category": "Email", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"\bspf\b.*(\?all|neutre|neutral)|\?all",
        "title": "SPF neutre (?all)",
        "recommendation": "Remplacer ?all par -all une fois les expéditeurs légitimes recensés.",
        "rag": "SPF ?all neutral qualifier no protection RFC 7208",
    },
    "spf_softfail": {
        "severity": "LOW", "category": "Email", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"\bspf\b.*(~all|softfail|soft fail)|~all",
        "title": "SPF en softfail (~all)",
        "recommendation": "Durcir en -all une fois DMARC en p=reject et les expéditeurs validés.",
        "rag": "SPF softfail ~all hardfail -all recommendation RFC 7208",
    },
    "spf_lookup_limit": {
        "severity": "LOW", "category": "Email", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"\bspf\b.*(lookup|limite|10 (requetes|recherches)|permerror)",
        "title": "SPF proche de la limite de 10 recherches DNS",
        "recommendation": "Aplatir les include: SPF pour rester sous 10 recherches DNS (RFC 7208 §4.6.4).",
        "rag": "SPF 10 DNS lookup limit permerror include flattening RFC 7208",
    },
    "dkim_missing": {
        "severity": "LOW", "category": "Email", "confidence": "low", "neg": True, "dedupe": True,
        "topic": r"\bdkim\b",
        "title": "Aucun sélecteur DKIM trouvé",
        "recommendation": "Signer les messages sortants en DKIM (clé RSA ≥ 2048 bits) et publier le sélecteur.",
        "rag": "DKIM signature missing selector RFC 6376 email authentication",
    },
    "mta_sts_missing": {
        "severity": "LOW", "category": "Email", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"mta.?sts",
        "title": "MTA-STS absent",
        "recommendation": "Publier une politique MTA-STS (RFC 8461) pour imposer TLS au SMTP entrant.",
        "rag": "MTA-STS missing SMTP TLS downgrade RFC 8461",
    },
    "tlsrpt_missing": {
        "severity": "INFO", "category": "Email", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"tls.?rpt",
        "title": "TLS-RPT absent",
        "recommendation": "Publier un enregistrement TLS-RPT (RFC 8460) pour recevoir les rapports d'échec TLS.",
        "rag": "TLS-RPT SMTP TLS reporting RFC 8460",
    },
    "bimi_missing": {
        "severity": "INFO", "category": "Email", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bbimi\b",
        "title": "BIMI absent",
        "recommendation": "Optionnel : publier BIMI une fois DMARC appliqué (p=quarantine ou p=reject).",
        "rag": "BIMI brand indicators DMARC enforcement",
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    "dnssec_missing": {
        "severity": "LOW", "category": "DNS", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bdnssec\b|non signee?",
        "title": "DNSSEC non activé",
        "recommendation": "Signer la zone (DNSSEC) et publier l'enregistrement DS chez le registraire.",
        "rag": "DNSSEC not enabled DNS spoofing cache poisoning zone signing DS record",
    },
    "caa_missing": {
        "severity": "LOW", "category": "DNS", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bcaa\b",
        "title": "Aucun enregistrement CAA",
        "recommendation": "Publier des enregistrements CAA limitant les autorités de certification autorisées (RFC 8659).",
        "rag": "CAA record certification authority authorization RFC 8659",
    },
    # ── SSL / TLS ────────────────────────────────────────────────────────────
    "cert_expired": {
        "severity": "HIGH", "category": "SSL", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"(certificat|certificate|\bcert\b|ssl|tls).*(\bexpired\b|a expire|est expire|perime|expire depuis|"
                 r"\bexpiree?s?\b(?!\s+(dans|bientot|prochainement|in|soon|le)\b))"
                 r"|(\bexpired\b|perime).*(certificat|certificate)",
        "title": "Certificat TLS expiré",
        "recommendation": "Renouveler immédiatement le certificat et automatiser le renouvellement (ACME).",
        "rag": "TLS certificate expired renewal ACME transport layer security",
    },
    "cert_expiring": {
        "severity": "MEDIUM", "category": "SSL", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"(certificat|certificate|\bcert\b).*(expir\w* (dans|bientot|prochainement|in|soon)|proche|"
                 r"jours? (avant|restants)|expiring|days_until_expiry)|expiration (proche|imminente)",
        "title": "Certificat TLS proche de l'expiration",
        "recommendation": "Renouveler le certificat avant échéance et automatiser le renouvellement (ACME).",
        "rag": "TLS certificate expiring soon renewal monitoring",
    },
    "cert_invalid": {
        "severity": "HIGH", "category": "SSL", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"(certificat|certificate|\bcert\b).*(invalide|invalid|auto.?signe|self.?signed|untrusted|"
                 r"non approuve|verification)",
        "title": "Certificat TLS invalide",
        "recommendation": "Installer un certificat valide émis par une autorité reconnue, couvrant le nom servi.",
        "rag": "TLS certificate validation failed self-signed untrusted hostname mismatch",
    },
    "tls_weak_protocols": {
        "severity": "MEDIUM", "category": "SSL", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"tls ?v?1\.[01]\b|sslv?[23]\b|ssl ?v?[23]\b|protocoles? (faibles?|obsoletes?|anciens?)|"
                 r"weak protocol|deprecated protocol",
        "title": "Protocoles TLS obsolètes acceptés",
        "recommendation": "Désactiver SSLv3, TLS 1.0 et 1.1 ; n'accepter que TLS 1.2 et 1.3.",
        "rag": "TLS 1.0 1.1 deprecated protocols disable RFC 8996 transport layer protection",
    },
    "tls_weak_ciphers": {
        "severity": "MEDIUM", "category": "SSL", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"(cipher|chiffrement|suite).*(faible|weak|rc4|\bdes\b|null|export|obsolete)",
        "title": "Suites de chiffrement faibles acceptées",
        "recommendation": "Retirer les suites RC4, DES, 3DES, NULL et EXPORT de la configuration TLS.",
        "rag": "weak cipher suites RC4 DES NULL EXPORT TLS configuration",
    },
    # ── Web : en-têtes de sécurité ───────────────────────────────────────────
    "hsts_missing": {
        "severity": "MEDIUM", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bhsts\b|strict.transport", "header": "strict-transport-security",
        "title": "En-tête HSTS absent",
        "recommendation": "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        "rag": "HTTP Strict Transport Security HSTS header missing SSL stripping",
    },
    "csp_missing": {
        "severity": "LOW", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"\bcsp\b|content.security.policy", "header": "content-security-policy",
        "title": "En-tête Content-Security-Policy absent",
        "recommendation": "Définir une Content-Security-Policy restrictive (default-src 'self').",
        "rag": "Content Security Policy header missing XSS mitigation",
    },
    "xfo_missing": {
        "severity": "LOW", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"x.frame.options|clickjacking", "header": "x-frame-options",
        "title": "En-tête X-Frame-Options absent",
        "recommendation": "Définir X-Frame-Options: DENY (ou frame-ancestors dans la CSP).",
        "rag": "X-Frame-Options clickjacking frame-ancestors",
    },
    "xcto_missing": {
        "severity": "LOW", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"x.content.type.options|nosniff", "header": "x-content-type-options",
        "title": "En-tête X-Content-Type-Options absent",
        "recommendation": "Définir X-Content-Type-Options: nosniff.",
        "rag": "X-Content-Type-Options nosniff MIME sniffing",
    },
    "minor_headers_missing": {
        "severity": "LOW", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"referrer.policy|permissions.policy|cross.origin|\bcoop\b|\bcorp\b",
        "headers": ["referrer-policy", "permissions-policy",
                    "cross-origin-opener-policy", "cross-origin-resource-policy"],
        "title": "En-têtes de sécurité secondaires absents",
        "recommendation": "Ajouter Referrer-Policy, Permissions-Policy, COOP et CORP.",
        "rag": "Referrer-Policy Permissions-Policy cross-origin headers HTTP security headers",
    },
    "xxss_missing": {
        "severity": "INFO", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"x.xss", "header": "x-xss-protection",
        "title": "En-tête X-XSS-Protection absent (obsolète)",
        "recommendation": "Aucune action requise : en-tête obsolète, préférer une CSP.",
        "rag": "X-XSS-Protection deprecated header",
    },
    "security_headers_missing": {
        # Finding agrégé « en-têtes de sécurité manquants » sans en-tête nommé :
        # sévérité = la plus haute des en-têtes réellement absents.
        "severity": "LOW", "category": "Web", "confidence": "high", "neg": True, "dedupe": True,
        "topic": r"en.?tetes? (http )?(de )?securite|security headers?",
        "title": "En-têtes de sécurité HTTP absents",
        "recommendation": "Ajouter les en-têtes de sécurité manquants (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
        "rag": "HTTP security headers missing OWASP secure headers",
    },
    # ── Sous-domaines ────────────────────────────────────────────────────────
    "subdomain_takeover": {
        # Détection passive non confirmée (routes/recon.py) → HIGH, jamais CRITICAL.
        "severity": "HIGH", "category": "Subdomain", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": r"takeover|prise de controle|dangling|cname (orphelin|pendant|suspendu)",
        "title": "Sous-domaine exposé à une prise de contrôle (CNAME dangling)",
        "recommendation": "Supprimer les CNAME pointant vers des services tiers désaffectés, ou réclamer la ressource.",
        "rag": "subdomain takeover dangling CNAME cloud service",
    },
    # ── Ports exposés (Shodan InternetDB) ────────────────────────────────────
    "port_database_exposed": {
        "severity": "HIGH", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": r"mysql|mariadb|postgres|mongo|redis|elasticsearch|memcache|mssql|sql server|oracle|couchdb|"
                 r"cassandra|etcd|influx|neo4j|base de donnees? expose|database expose|"
                 r"\b(3306|5432|27017|6379|9200|9300|11211|1433|1521|5984|9042|2379|8086|7474)\b",
        "ports": [3306, 5432, 27017, 6379, 9200, 9300, 11211, 1433, 1521, 5984, 9042, 2379, 8086, 7474],
        "title": "Port de base de données exposé sur Internet",
        "recommendation": "Fermer le port de base de données au public (pare-feu, écoute sur localhost/réseau privé).",
        "rag": "database port exposed internet MySQL Redis MongoDB Elasticsearch firewall",
    },
    "port_remote_admin_exposed": {
        "severity": "HIGH", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": r"\brdp\b|remote desktop|bureau a distance|\bvnc\b|telnet|docker (api|daemon)|\bsmb\b|"
                 r"netbios|winrm|\b(3389|5900|5901|23|2375|2376|445|139|5985|5986)\b",
        "ports": [3389, 5900, 5901, 23, 2375, 2376, 445, 139, 5985, 5986],
        "title": "Service d'administration distante exposé (RDP/VNC/Telnet/SMB/Docker)",
        "recommendation": "Retirer le service d'Internet ; accès via VPN avec MFA uniquement.",
        "rag": "external remote services RDP VNC SMB exposed internet VPN MFA",
    },
    "port_ftp_exposed": {
        "severity": "MEDIUM", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"\bftp\b|port 21\b", "ports": [21],
        "title": "Service FTP exposé",
        "recommendation": "Remplacer FTP par SFTP/FTPS et restreindre l'accès.",
        "rag": "FTP cleartext protocol exposed SFTP",
    },
    "port_ssh_exposed": {
        "severity": "LOW", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"\bssh\b|port 22\b", "ports": [22],
        "title": "Service SSH exposé",
        "recommendation": "Restreindre SSH par IP/VPN, authentification par clé uniquement.",
        "rag": "SSH exposed internet hardening key authentication",
    },
    # ── CVE (Shodan InternetDB, version déduite — jamais confirmée) ─────────
    "cve_kev": {
        "severity": "CRITICAL", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": None, "title": "CVE activement exploitée (catalogue CISA KEV)",
        "recommendation": "Appliquer en priorité le correctif de l'éditeur (CVE listée dans CISA KEV).",
        "rag": "known exploited vulnerability patch exploit public-facing application",
    },
    "cve_epss_high": {
        "severity": "HIGH", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": None, "title": "CVE à forte probabilité d'exploitation (EPSS)",
        "recommendation": "Corriger rapidement : probabilité d'exploitation élevée (EPSS).",
        "rag": "vulnerability exploitation probability EPSS patch management",
    },
    "cve_cvss_critical": {
        "severity": "HIGH", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": None, "title": "CVE critique (CVSS ≥ 9) annoncée sur un service exposé",
        "recommendation": "Vérifier la version réellement déployée et appliquer le correctif.",
        "rag": "critical vulnerability CVSS patch exposed service",
    },
    "cve_cvss_high": {
        "severity": "MEDIUM", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": None, "title": "CVE élevée (CVSS 7–8,9) annoncée sur un service exposé",
        "recommendation": "Vérifier la version réellement déployée et planifier le correctif.",
        "rag": "high severity vulnerability CVSS patch",
    },
    "cve_cvss_low": {
        "severity": "LOW", "category": "Infrastructure", "confidence": "medium", "neg": False, "dedupe": False,
        "topic": None, "title": "CVE de sévérité modérée ou non notée annoncée",
        "recommendation": "Vérifier la version déployée et inclure le correctif au cycle normal de mises à jour.",
        "rag": "vulnerability management patch cycle",
    },
    # ── Réputation ───────────────────────────────────────────────────────────
    "dnsbl_listed": {
        "severity": "MEDIUM", "category": "Reputation", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"dnsbl|liste noire|listes noires|blacklist|blocklist|spamhaus",
        "title": "Adresse IP inscrite sur une liste noire (DNSBL)",
        "recommendation": "Identifier la cause de l'inscription (relais, compromission) puis demander le retrait.",
        "rag": "IP blacklisted DNSBL spam reputation delisting",
    },
    "abusech_hits": {
        "severity": "HIGH", "category": "Reputation", "confidence": "high", "neg": False, "dedupe": True,
        "topic": r"urlhaus|threatfox|abuse.?ch|malware|\bc2\b|commande et controle|\bioc\b",
        "title": "Domaine ou IP référencé pour malware / C2 (abuse.ch)",
        "recommendation": "Rechercher une compromission (fichiers servis, processus) et nettoyer avant demande de retrait.",
        "rag": "malware distribution URLhaus ThreatFox compromise incident response",
    },
    "abuseipdb_high": {
        "severity": "MEDIUM", "category": "Reputation", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"abuseipdb|score d.?abus|abuse (confidence )?score",
        "title": "IP signalée pour abus (AbuseIPDB)",
        "recommendation": "Analyser les signalements AbuseIPDB et l'activité sortante de l'hôte.",
        "rag": "IP abuse reports reputation",
    },
    "breaches_found": {
        "severity": "MEDIUM", "category": "Reputation", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"fuites? de donnees|breach|data leak|xposedornot|haveibeenpwned|comptes? compromis|"
                 r"identifiants? (divulgue|fuite|compromis)",
        "title": "Adresses du domaine présentes dans des fuites de données",
        "recommendation": "Réinitialiser les mots de passe concernés, imposer la MFA, surveiller les connexions.",
        "rag": "credential leak data breach password reset MFA valid accounts",
    },
    "typosquatting_mx": {
        "severity": "MEDIUM", "category": "Reputation", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"typo.?squat|domaines? (similaires|suspects|imitant|frauduleux)|homoglyph|dnstwist|"
                 r"phishing domain|domaine de phishing",
        "title": "Domaines de typosquatting avec MX configuré",
        "recommendation": "Surveiller ces domaines, demander leur suspension si abusifs, sensibiliser au phishing.",
        "rag": "typosquatting lookalike domain phishing brand monitoring",
    },
    "typosquatting_registered": {
        "severity": "LOW", "category": "Reputation", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"typo.?squat|domaines? (similaires|suspects|imitant)|homoglyph|dnstwist",
        "title": "Domaines de typosquatting enregistrés",
        "recommendation": "Surveiller les domaines proches ; envisager l'enregistrement défensif des plus proches.",
        "rag": "typosquatting lookalike domain registration monitoring",
    },
    # ── Secrets / fichiers sensibles ─────────────────────────────────────────
    "sensitive_file_archived": {
        "severity": "MEDIUM", "category": "Web", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"\.env\b|\.git\b|\.sql\b|\.bak\b|fichiers? sensibles?|sensitive files?|sauvegardes? expose",
        "title": "Fichiers sensibles référencés dans les archives (.env, .sql, .bak…)",
        "recommendation": "Vérifier que ces fichiers ne sont plus servis, et faire tourner tout secret qu'ils contenaient.",
        "rag": "sensitive files exposed .env .git backup credentials in files",
    },
    "secrets_exposed": {
        "severity": "HIGH", "category": "Web", "confidence": "medium", "neg": False, "dedupe": True,
        "topic": r"secrets?|api ?keys?|cles? d.?api|jetons?|tokens?|mots? de passe en clair|hardcoded",
        "title": "Secrets exposés publiquement",
        "recommendation": "Révoquer et faire tourner immédiatement les secrets exposés, purger l'historique.",
        "rag": "exposed secrets API keys rotation credentials leak",
    },
}

_CVE_RULES = ("cve_kev", "cve_epss_high", "cve_cvss_critical", "cve_cvss_high", "cve_cvss_low")
_HEADER_RULES = ("hsts_missing", "csp_missing", "xfo_missing", "xcto_missing",
                 "minor_headers_missing", "xxss_missing")

_COMPILED = {
    rid: (re.compile(r["topic"]) if r.get("topic") else None,
          re.compile(r["exclude"]) if r.get("exclude") else None)
    for rid, r in RULES.items()
}


# ══════════════════════════════════════════════════════════════════════════════
#  Lecture des données brutes du scan
# ══════════════════════════════════════════════════════════════════════════════

def _tool(scan: Dict, key: str) -> Tuple[Optional[str], Dict]:
    entry = scan.get(key)
    if not isinstance(entry, dict):
        return None, {}
    data = entry.get("data")
    return entry.get("status"), (data if isinstance(data, dict) else {})


def _num(v) -> Optional[float]:
    """CVSS/EPSS : nombre, chaîne numérique ou dict CIRCL ({"baseScore": ...})."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    if isinstance(v, dict):
        for k in ("baseScore", "score", "cvss3", "cvss"):
            if k in v:
                return _num(v[k])
    return None


def observed_cves(scan: Dict) -> Dict[str, Dict]:
    """
    CVE réellement observées par le scan → entrée enrichie (cvss, epss…).
    Seule source acceptée pour une CVE citée par le LLM (B6) : Shodan
    InternetDB (`vulns`, `vulns_enriched`, `ips[].vulns`) et tout outil
    dont la donnée expose `vulns_enriched` / `vulns` (signaux ajoutés par
    d'autres phases).
    """
    out: Dict[str, Dict] = {}
    if not isinstance(scan, dict):
        return out
    for key, entry in scan.items():
        if not isinstance(entry, dict) or entry.get("status") != "success":
            continue
        data = entry.get("data")
        if not isinstance(data, dict):
            continue
        lists = [data.get("vulns")]
        for ip in data.get("ips") or []:
            if isinstance(ip, dict):
                lists.append(ip.get("vulns"))
        for lst in lists:
            for v in lst or []:
                if isinstance(v, str) and CVE_RE.fullmatch(v.strip()):
                    out.setdefault(v.strip().upper(), {"source_tool": key})
        for e in data.get("vulns_enriched") or []:
            if isinstance(e, dict) and isinstance(e.get("id"), str) and CVE_RE.fullmatch(e["id"].strip()):
                cid = e["id"].strip().upper()
                out[cid] = {
                    "source_tool": key,
                    "cvss": _num(e.get("cvss")),
                    "epss": _num(e.get("epss")),
                }
    return out


def classify_cve(entry: Dict, kev: Dict) -> str:
    """Règle applicable à une CVE observée (KEV > EPSS > CVSS)."""
    cid = entry.get("id")
    if cid and cid in kev:
        return "cve_kev"
    epss = entry.get("epss")
    if epss is not None and epss >= _EPSS_THRESHOLD:
        return "cve_epss_high"
    cvss = entry.get("cvss")
    if cvss is not None and cvss >= 9.0:
        return "cve_cvss_critical"
    if cvss is not None and cvss >= 7.0:
        return "cve_cvss_high"
    return "cve_cvss_low"


def _obs(state: str, severity: Optional[str] = None, source_tool: Optional[str] = None,
         evidence: str = "", subjects: Optional[List[str]] = None, **extra) -> Dict[str, Any]:
    return {"state": state, "severity": severity, "source_tool": source_tool,
            "evidence": evidence, "subjects": subjects or [], **extra}


def detect_observations(scan: Dict, kev: Optional[Dict] = None) -> Dict[str, Dict[str, Any]]:
    """
    État de chaque règle d'après les données BRUTES (jamais le texte du LLM).
    `kev` : {cve_id: meta} déjà résolu par utils/kev.py (peut être vide).
    """
    scan = scan if isinstance(scan, dict) else {}
    kev = kev or {}
    out: Dict[str, Dict[str, Any]] = {rid: _obs("unknown") for rid in RULES}

    # ── Email ────────────────────────────────────────────────────────────────
    ec_status, ec = _tool(scan, "email_config")
    dm_status, dm = _tool(scan, "dmarc_check")
    mx_present = bool(ec.get("mx")) if ec_status == "success" else None

    dmarc_present = None
    policy = None
    if dm_status == "success" and dm.get("present"):
        dmarc_present, policy = True, dm.get("policy")
    elif ec_status == "success" and ec.get("dmarc_status") == "found":
        dmarc_present, policy = True, ec.get("dmarc_policy")
    elif ec_status == "success" and ec.get("dmarc_status") == "not_found":
        dmarc_present = False
    elif dm_status == "no_data" and dm.get("present") is False:
        dmarc_present = False
    if dmarc_present is False:
        src = "email_config" if ec_status == "success" else "dmarc_check"
        out["dmarc_missing"] = _obs("observed", source_tool=src, evidence="dmarc_status: not_found"
                                    if src == "email_config" else "present: False")
        out["dmarc_p_none"] = _obs("absent")
    elif dmarc_present:
        out["dmarc_missing"] = _obs("absent")
        if str(policy or "").lower() == "none":
            src = "dmarc_check" if dm_status == "success" else "email_config"
            out["dmarc_p_none"] = _obs("observed", source_tool=src,
                                       evidence="policy: none" if src == "dmarc_check" else "dmarc_policy: none")
        else:
            out["dmarc_p_none"] = _obs("absent")

    spf_status, spf = _tool(scan, "spf_analysis")
    if ec_status == "success" and ec.get("spf_status") == "not_found":
        out["spf_missing"] = _obs("observed", source_tool="email_config", evidence="spf_status: not_found")
        for rid in ("spf_permissive", "spf_neutral", "spf_softfail"):
            out[rid] = _obs("absent")
    elif ec_status == "success" and ec.get("spf_status") == "found":
        out["spf_missing"] = _obs("absent")
        record = str(ec.get("spf") or "")
        allm = (spf.get("all_mechanism") if spf_status == "success" else None) or \
            next((p for p in record.split() if p.lstrip("+?~-").startswith("all")), None)
        allm = str(allm or "")
        for rid, qual in (("spf_permissive", "+all"), ("spf_neutral", "?all"), ("spf_softfail", "~all")):
            # Sans qualificatif, « all » vaut « +all » (RFC 7208 §4.6.2).
            hit = allm == qual or (qual == "+all" and allm == "all")
            out[rid] = _obs("observed", source_tool="email_config", evidence=f"spf: {record}") if hit \
                else _obs("absent")
    if spf_status == "success":
        if spf.get("lookup_limit_warning"):
            out["spf_lookup_limit"] = _obs("observed", source_tool="spf_analysis",
                                           evidence=f"lookup_count: {spf.get('lookup_count')}")
        else:
            out["spf_lookup_limit"] = _obs("absent")

    dk_status, dk = _tool(scan, "dkim_check")
    if dk_status == "success":
        if not dk.get("found"):
            out["dkim_missing"] = _obs("observed", source_tool="dkim_check", evidence="found: [], count: 0")
        else:
            out["dkim_missing"] = _obs("absent")

    for rid, key in (("mta_sts_missing", "mta_sts_check"), ("tlsrpt_missing", "tlsrpt_check"),
                     ("bimi_missing", "bimi_check")):
        st, d = _tool(scan, key)
        if st == "success" and d.get("present"):
            out[rid] = _obs("absent")
        elif st == "no_data" and d.get("present") is False:
            # Sans MX, MTA-STS/TLS-RPT n'ont pas d'objet.
            if rid != "bimi_missing" and mx_present is False:
                out[rid] = _obs("absent")
            else:
                out[rid] = _obs("observed", source_tool=key, evidence="present: False")

    # ── DNS ──────────────────────────────────────────────────────────────────
    ds_status, ds = _tool(scan, "dnssec")
    if ds_status == "success" and ds.get("enabled") is not None:
        out["dnssec_missing"] = _obs("observed", source_tool="dnssec", evidence="enabled: False") \
            if ds.get("enabled") is False else _obs("absent")
    caa_status, caa = _tool(scan, "caa_check")
    if caa_status == "success" and caa.get("present"):
        out["caa_missing"] = _obs("absent")
    elif caa_status == "no_data":
        out["caa_missing"] = _obs("observed", source_tool="caa_check", evidence="present: False")

    # ── SSL / TLS ────────────────────────────────────────────────────────────
    ssl_entry = scan.get("ssl_info") if isinstance(scan.get("ssl_info"), dict) else {}
    ssl_status, ssl_d = _tool(scan, "ssl_info")
    if ssl_status == "success":
        days = ssl_d.get("days_until_expiry")
        out["cert_invalid"] = _obs("absent")
        if ssl_d.get("expired"):
            out["cert_expired"] = _obs("observed", source_tool="ssl_info", evidence=f"expired: True, days_until_expiry: {days}")
            out["cert_expiring"] = _obs("absent")
        else:
            out["cert_expired"] = _obs("absent") if days is not None else _obs("unknown")
            if ssl_d.get("expiry_warning"):
                out["cert_expiring"] = _obs("observed", source_tool="ssl_info",
                                            evidence=f"days_until_expiry: {days}, expiry_warning: True")
            elif days is not None:
                out["cert_expiring"] = _obs("absent")
    elif ssl_status == "error" and "rification ssl" in str(ssl_entry.get("error") or "").lower():
        out["cert_invalid"] = _obs("observed", source_tool="ssl_info",
                                   evidence=str(ssl_entry.get("raw_output") or ssl_entry.get("error"))[:200])

    tls_status, tls = _tool(scan, "tls_config")
    if tls_status == "success":
        weak = [p for p in (tls.get("weak_protocols") or []) if isinstance(p, str)]
        if weak:
            sev = "HIGH" if any(p.upper().startswith("SSL") for p in weak) else "MEDIUM"
            out["tls_weak_protocols"] = _obs("observed", severity=sev, source_tool="tls_config",
                                             evidence=f"weak_protocols: {weak}", subjects=weak)
        else:
            out["tls_weak_protocols"] = _obs("absent")
        wc = tls.get("weak_ciphers") or []
        out["tls_weak_ciphers"] = _obs("observed", source_tool="tls_config", evidence=f"weak_ciphers: {wc}") \
            if wc else _obs("absent")

    # ── En-têtes de sécurité (domaine racine + sous-domaines joignables) ─────
    sh_status, sh = _tool(scan, "security_headers")
    root_headers = sh.get("headers") if isinstance(sh.get("headers"), dict) else None
    _, sub_hdr = _tool(scan, "headers")
    sub_missing: Dict[str, List[str]] = {}
    for host, info in (sub_hdr or {}).items():
        if not isinstance(info, dict) or info.get("status") == "unreachable":
            continue
        h = {str(k).lower(): v for k, v in (info.get("data") or {}).items()} \
            if isinstance(info.get("data"), dict) else {}
        if not h:
            continue
        for name in ("strict-transport-security", "content-security-policy", "x-frame-options",
                     "x-content-type-options"):
            if name not in h:
                sub_missing.setdefault(name, []).append(str(host)[:253])

    any_header_observed = []
    if sh_status == "success" and root_headers:
        for rid in _HEADER_RULES:
            names = RULES[rid].get("headers") or [RULES[rid]["header"]]
            missing = [n for n in names if isinstance(root_headers.get(n), dict)
                       and root_headers[n].get("present") is False]
            known = [n for n in names if isinstance(root_headers.get(n), dict)]
            subs = sorted({s for n in names for s in sub_missing.get(n, [])})[:20]
            if missing:
                h0 = root_headers[missing[0]]
                out[rid] = _obs("observed", source_tool="security_headers",
                                evidence=f"{missing[0]}: name {h0.get('name')}, present False",
                                subjects=missing + subs)
            elif subs:
                out[rid] = _obs("observed", source_tool="headers",
                                evidence=f"{names[0]} absent sur {', '.join(subs[:5])}", subjects=subs)
            elif known:
                out[rid] = _obs("absent")
            if out[rid]["state"] == "observed":
                any_header_observed.append(rid)
        if any_header_observed:
            sev = "INFO"
            for rid in any_header_observed:
                sev = sev_max(sev, RULES[rid]["severity"])
            first = out[any_header_observed[0]]
            out["security_headers_missing"] = _obs("observed", severity=sev, source_tool=first["source_tool"],
                                                   evidence=first["evidence"],
                                                   subjects=list(sh.get("missing_headers") or [])[:12])
        else:
            out["security_headers_missing"] = _obs("absent")

    # ── Takeover ─────────────────────────────────────────────────────────────
    tk_status, tk = _tool(scan, "subdomain_takeover")
    if tk_status == "success":
        vuln = [v for v in (tk.get("vulnerable") or []) if isinstance(v, dict)]
        if vuln:
            subs = [str(v.get("subdomain"))[:253] for v in vuln][:20]
            out["subdomain_takeover"] = _obs("observed", source_tool="subdomain_takeover",
                                             evidence=f"subdomain: {vuln[0].get('subdomain')}, cname: {vuln[0].get('cname')}",
                                             subjects=subs)
        else:
            out["subdomain_takeover"] = _obs("absent")

    # ── Ports Shodan ─────────────────────────────────────────────────────────
    sd_status, sd = _tool(scan, "shodan_internetdb")
    if sd_status == "success":
        ports = {p for p in (sd.get("ports") or []) if isinstance(p, int) and not isinstance(p, bool)}
        for rid in ("port_database_exposed", "port_remote_admin_exposed", "port_ftp_exposed", "port_ssh_exposed"):
            hit = sorted(ports & set(RULES[rid]["ports"]))
            out[rid] = _obs("observed", source_tool="shodan_internetdb",
                            evidence=f"ports: {sorted(ports)}", subjects=[str(p) for p in hit]) if hit \
                else _obs("absent")
    elif sd_status == "no_data":
        for rid in ("port_database_exposed", "port_remote_admin_exposed", "port_ftp_exposed", "port_ssh_exposed"):
            out[rid] = _obs("absent")

    # ── CVE ──────────────────────────────────────────────────────────────────
    cves = observed_cves(scan)
    by_rule: Dict[str, List[str]] = {rid: [] for rid in _CVE_RULES}
    for cid, e in sorted(cves.items()):
        by_rule[classify_cve({"id": cid, **e}, kev)].append(cid)
    for rid in _CVE_RULES:
        if by_rule[rid]:
            first = by_rule[rid][0]
            out[rid] = _obs("observed", source_tool=cves[first]["source_tool"],
                            evidence=f"vulns: {', '.join(by_rule[rid][:10])}", subjects=by_rule[rid])
        elif sd_status in ("success", "no_data"):
            out[rid] = _obs("absent")
    out["_cves"] = {"state": "meta", "cves": cves, "by_rule": by_rule}

    # ── Réputation ───────────────────────────────────────────────────────────
    bl_status, bl = _tool(scan, "dnsbl_check")
    if bl_status == "success":
        n = int(bl.get("listed_count") or 0) if str(bl.get("listed_count") or "0").isdigit() else 0
        out["dnsbl_listed"] = _obs("observed", severity="HIGH" if n >= 3 else "MEDIUM", source_tool="dnsbl_check",
                                   evidence=f"listed_count: {n}") if n else _obs("absent")
    ab_status, ab = _tool(scan, "abusech_check")
    if ab_status == "success":
        hits = (ab.get("urlhaus_urls") or []) + (ab.get("threatfox_iocs") or [])
        out["abusech_hits"] = _obs("observed", source_tool="abusech_check",
                                   evidence=f"risk_level: {ab.get('risk_level')}") if hits else _obs("absent")
    ai_status, ai = _tool(scan, "abuseipdb_check")
    if ai_status == "success":
        score = _num(ai.get("max_abuse_score"))
        if score is not None:
            out["abuseipdb_high"] = _obs("observed", source_tool="abuseipdb_check",
                                         evidence=f"max_abuse_score: {ai.get('max_abuse_score')}") \
                if score >= 50 else _obs("absent")
    br_status, br = _tool(scan, "xposedornot_breaches")
    if br_status == "success":
        n = _num(br.get("breach_count")) or 0
        out["breaches_found"] = _obs("observed", source_tool="xposedornot_breaches",
                                     evidence=f"breach_count: {br.get('breach_count')}") if n > 0 \
            else _obs("absent")
    ty_status, ty = _tool(scan, "typosquatting")
    if ty_status == "success":
        mx_n = _num(ty.get("mx_configured_count")) or 0
        cnt = _num(ty.get("count")) or len(ty.get("suspicious_domains") or [])
        out["typosquatting_mx"] = _obs("observed", source_tool="typosquatting",
                                       evidence=f"mx_configured_count: {ty.get('mx_configured_count')}") \
            if mx_n > 0 else _obs("absent")
        out["typosquatting_registered"] = _obs("observed", source_tool="typosquatting",
                                               evidence=f"count: {ty.get('count')}") if cnt > 0 else _obs("absent")

    # ── Fichiers sensibles archivés / secrets ────────────────────────────────
    gau_status, gau = _tool(scan, "gau_urls")
    if gau_status in ("success", "timeout_partial"):
        sens = [u for u in (gau.get("interesting_files") or []) if isinstance(u, str)
                and re.search(r"\.(env|sql|bak|git|config)(\?|$)", u.lower())]
        out["sensitive_file_archived"] = _obs("observed", source_tool="gau_urls",
                                              evidence=sens[0][:300], subjects=sens[:20]) if sens \
            else (_obs("absent") if gau_status == "success" else _obs("unknown"))
    for key, entry in scan.items():
        if not isinstance(entry, dict) or entry.get("status") != "success":
            continue
        d = entry.get("data")
        if isinstance(d, dict):
            secrets = d.get("secrets_found") or d.get("secrets")
            if isinstance(secrets, list) and secrets:
                out["secrets_exposed"] = _obs("observed", source_tool=key,
                                              evidence=f"secrets_found: {len(secrets)}")
                break
            # github_dorks (phase 5) : secrets confirmés comptés, valeurs jamais conservées
            confirmed = d.get("confirmed_secret_count")
            if isinstance(confirmed, int) and not isinstance(confirmed, bool) and confirmed > 0:
                types = [t for t in (d.get("secret_types") or []) if isinstance(t, str)][:5]
                out["secrets_exposed"] = _obs("observed", source_tool=key,
                                              evidence=f"confirmed_secret_count: {confirmed}"
                                                       + (f" ({', '.join(types)})" if types else ""))
                break
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Rattachement d'un finding aux règles
# ══════════════════════════════════════════════════════════════════════════════

def _neg_near(text_norm: str, topic: "re.Pattern", window: int = 3) -> bool:
    """
    Vrai si un marqueur d'absence figure à moins de `window` mots du sujet :
    « HSTS absent » oui, « HSTS présent ; aucun problème sur CSP » non.
    """
    stripped = _POSITIVE_PHRASES.sub(" ", text_norm)
    words = stripped.split()
    for m in topic.finditer(stripped):
        start = stripped[:m.start()].count(" ")
        end = stripped[:m.end()].count(" ")
        chunk = " ".join(words[max(0, start - window):end + window + 1])
        if _NEGATION.search(chunk):
            return True
    return False


def _candidate_rules(text_norm: str) -> List[str]:
    found = []
    for rid, (topic, exclude) in _COMPILED.items():
        if topic is None or not topic.search(text_norm):
            continue
        if exclude is not None and exclude.search(text_norm):
            continue
        if RULES[rid]["neg"] and not _neg_near(text_norm, topic):
            continue
        found.append(rid)
    # Une règle précise l'emporte sur le finding agrégé « en-têtes manquants ».
    if "security_headers_missing" in found and any(r in found for r in _HEADER_RULES):
        found.remove("security_headers_missing")
    # Typosquatting : la variante « avec MX » englobe la variante simple.
    if "typosquatting_mx" in found and "typosquatting_registered" in found:
        found.remove("typosquatting_registered") if "mx" in text_norm.split() else found.remove("typosquatting_mx")
    return found


def match_rules(finding: Dict, observed_cve_ids: Optional[set] = None) -> Tuple[List[str], Optional[str]]:
    """
    Règles candidates d'un finding : CVE citées, puis titre, puis evidence.
    Retourne (règles, champ ayant servi au rattachement : "title"/"evidence"/None).
    """
    rules: List[str] = []
    cited = {c.upper() for c in CVE_RE.findall(" ".join(
        str(finding.get(k) or "") for k in ("title", "evidence", "description")))}
    if observed_cve_ids is not None:
        cited &= observed_cve_ids
    if cited:
        rules.append("_cve")
    via = None
    for field in ("title", "evidence"):
        cand = _candidate_rules(_norm(finding.get(field)))
        if cand:
            rules.extend(cand)
            via = field
            break
    return list(dict.fromkeys(rules)), via


def _finding_from_rule(rid: str, obs: Dict, observed_at: Optional[str]) -> Dict[str, Any]:
    rule = RULES[rid]
    subjects = obs.get("subjects") or []
    title = rule["title"] + (f" : {', '.join(subjects[:5])}" if subjects else "")
    return {
        "id":             None,
        "category":       rule["category"],
        "severity":       obs.get("severity") or rule["severity"],
        "severity_rule":  rid,
        "confidence":     rule["confidence"],
        "observed_at":    observed_at,
        "title":          title[:200],
        "description":    "Constat établi de façon déterministe à partir des données brutes du scan "
                          "(absent de l'analyse du modèle).",
        "evidence":       str(obs.get("evidence") or "")[:2000],
        "source_tool":    obs.get("source_tool"),
        "source_tools":   [obs.get("source_tool")] if obs.get("source_tool") else [],
        "recommendation": rule["recommendation"],
        "references":     [],
        "web_sources":    [],
        "generated_by":   "rule",
    }


def apply_severity_rules(
    findings: List[Dict],
    scan: Dict,
    kev: Optional[Dict] = None,
    observed_at: Optional[str] = None,
    observations: Optional[Dict] = None,
) -> Tuple[List[Dict], Dict[str, Any]]:
    """
    Applique la table de règles. Retourne (findings_finaux, résumé) ; le
    résumé est à stocker dans `report["severity_check"]`.

    Chaque finding conservé reçoit : `severity` (finale), `severity_llm`
    (proposée par le modèle), `severity_rule`, `category` (celle de la règle
    si elle s'applique), `confidence` (provisoire, affinée après grounding).
    """
    obs = observations if observations is not None else detect_observations(scan, kev)
    cve_meta = obs.get("_cves") or {"cves": {}, "by_rule": {}}
    cve_ids = set(cve_meta["cves"])
    cve_rule_of = {c: rid for rid, lst in cve_meta["by_rule"].items() for c in lst}

    kept: List[Dict] = []
    dropped: List[Dict] = []
    covered: set = set()
    seen_dedupe: Dict[str, Dict] = {}
    counts = {"rule_applied": 0, "positive_capped": 0, "llm_capped": 0, "llm_proposed": 0,
              "unverified": 0, "contradicted_dropped": 0, "contradicted_info": 0,
              "duplicates_dropped": 0}

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        proposed = str(f.get("severity") or "INFO").upper()
        proposed = proposed if proposed in _RANK else "INFO"
        f["severity_llm"] = proposed
        title_norm = _norm(f.get("title"))
        text_all = _norm(" ".join(str(f.get(k) or "") for k in ("title", "evidence", "description")))
        rules, via = match_rules(f, cve_ids)

        # ── CVE citées (déjà filtrées par B6 sur les CVE observées) ─────────
        best_rid, best_sev = None, None
        if "_cve" in rules:
            for c in CVE_RE.findall(" ".join(str(f.get(k) or "") for k in ("title", "evidence", "description"))):
                rid = cve_rule_of.get(c.upper())
                if rid and (best_sev is None or _RANK[RULES[rid]["severity"]] > _RANK[best_sev]):
                    best_rid, best_sev = rid, RULES[rid]["severity"]
        named = [r for r in rules if r != "_cve"]

        states = {r: obs.get(r, {}).get("state", "unknown") for r in named}
        observed = [r for r in named if states[r] == "observed"]
        for r in observed:
            sev = obs[r].get("severity") or RULES[r]["severity"]
            if best_sev is None or _RANK[sev] > _RANK[best_sev]:
                best_rid, best_sev = r, sev

        # Contenu positif (« DNSBL propre », « SPF correctement configuré ») :
        # jamais HIGH/CRITICAL — INFO, sauf si la donnée prouve un défaut.
        if best_rid is None and (is_positive(title_norm) or (not named and is_positive(text_all))):
            f["severity"] = "INFO"
            f["severity_rule"] = "positive_observation"
            f["_conf"] = "medium"
            counts["positive_capped"] += 1
            kept.append(f)
            continue

        if best_rid:
            if RULES[best_rid]["dedupe"] and best_rid in seen_dedupe:
                first = seen_dedupe[best_rid]
                extra = [t for t in [f.get("source_tool")] + list(f.get("source_tools") or []) if t]
                first["source_tools"] = list(dict.fromkeys(list(first.get("source_tools") or []) + extra))[:10]
                counts["duplicates_dropped"] += 1
                dropped.append({"id": f.get("id"), "title": str(f.get("title"))[:200],
                                "reason": f"duplicate_of:{first.get('id')}", "rule": best_rid})
                continue
            f["severity"] = best_sev
            f["severity_rule"] = best_rid
            f["category"] = RULES[best_rid]["category"]
            f["_conf"] = RULES[best_rid]["confidence"]
            covered.add(best_rid)
            if RULES[best_rid]["dedupe"]:
                seen_dedupe[best_rid] = f
            counts["rule_applied"] += 1
            kept.append(f)
            continue

        if named and all(states[r] == "absent" for r in named):
            # La donnée brute prouve le contraire (ex. « HSTS absent » alors que
            # l'en-tête est présent). Rattachement net (titre, sans tournure de
            # contraste) → retiré ; rattachement plus fragile → conservé en INFO
            # pour ne jamais perdre un vrai constat sur une heuristique de mots.
            if via == "title" and not _CONTRAST.search(title_norm):
                counts["contradicted_dropped"] += 1
                dropped.append({"id": f.get("id"), "title": str(f.get("title"))[:200],
                                "reason": "contradicted_by_data", "rule": named[0]})
                logger.info("[severity] Finding retiré, contredit par la donnée brute (%s) : %s",
                            named[0], str(f.get("title"))[:120])
                continue
            f["severity"] = "INFO"
            f["severity_rule"] = "contradicted_by_data"
            f["_conf"] = "low"
            counts["contradicted_info"] += 1
            kept.append(f)
            continue

        if named:
            f["severity"] = sev_min(proposed, "MEDIUM")
            f["severity_rule"] = "unverified"
            f["_conf"] = "low"
            counts["unverified"] += 1
            kept.append(f)
            continue

        capped = sev_min(proposed, _UNMATCHED_CAP)
        f["severity"] = capped
        f["severity_rule"] = "llm_capped" if capped != proposed else "llm_proposed"
        counts["llm_capped" if capped != proposed else "llm_proposed"] += 1
        kept.append(f)

    # ── Constats graves ignorés par le modèle : ajoutés ─────────────────────
    injected = []
    if _INJECT_MIN != "NONE":
        for rid, o in obs.items():
            if rid.startswith("_") or o.get("state") != "observed" or rid in covered:
                continue
            if rid == "security_headers_missing":
                continue
            sev = o.get("severity") or RULES[rid]["severity"]
            if _RANK[sev] < _RANK[_INJECT_MIN]:
                continue
            nf = _finding_from_rule(rid, o, observed_at)
            nf["severity_llm"] = None
            nf["_conf"] = RULES[rid]["confidence"]
            kept.append(nf)
            injected.append(rid)

    summary = {
        **counts,
        "injected":        injected,
        "dropped":         dropped[:50],
        "rules_observed":  sorted(r for r, o in obs.items() if not r.startswith("_") and o.get("state") == "observed"),
        "kev_cves":        sorted(cve_meta["by_rule"].get("cve_kev") or []),
        "epss_threshold":  _EPSS_THRESHOLD,
        "unmatched_cap":   _UNMATCHED_CAP,
        "method": (
            "Sévérité tranchée par une table de règles appliquée aux données brutes du scan ; "
            "la proposition du modèle (`severity_llm`) n'est retenue, plafonnée, que si aucune "
            "règle ne s'applique. Un constat positif est toujours INFO."
        ),
    }
    return kept, summary


def rag_topics(observations: Dict[str, Dict]) -> List[Dict[str, str]]:
    """
    Constats observés → requêtes RAG (B7, une requête par constat), triés par
    sévérité décroissante pour que le plafond `RAG_MAX_QUERIES` garde les
    plus graves.
    """
    topics = []
    for rid, o in (observations or {}).items():
        if rid.startswith("_") or o.get("state") != "observed" or rid not in RULES:
            continue
        sev = o.get("severity") or RULES[rid]["severity"]
        topics.append({"id": rid, "query": RULES[rid]["rag"], "category": RULES[rid]["category"],
                       "_rank": _RANK[sev]})
    topics.sort(key=lambda t: (-t["_rank"], t["id"]))
    for t in topics:
        t.pop("_rank")
    return topics


def finalize_confidence(findings: List[Dict]) -> None:
    """
    `confidence` final (high/medium/low), après grounding_check :
      - provisoire posé par la règle (`_conf`) ;
      - sans règle : medium si l'evidence est vérifiée, low sinon ;
      - le LLM peut ABAISSER la confiance, jamais l'élever.
    """
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        conf = f.pop("_conf", None)
        grounded = (f.get("grounding") or {}).get("status") == "verified"
        if conf is None:
            conf = "medium" if grounded else "low"
        elif conf == "high" and not grounded and f.get("generated_by") != "rule":
            conf = "medium"
        llm_conf = f.pop("_llm_confidence", None)
        f["confidence"] = conf_min(conf, llm_conf) if llm_conf in _CONF_RANK else conf


def risk_level_from_findings(findings: List[Dict]) -> str:
    """Niveau de risque global = sévérité finale la plus haute (LOW si rien de pire)."""
    level = "LOW"
    for f in findings or []:
        if isinstance(f, dict):
            sev = str(f.get("severity") or "INFO").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                level = sev_max(level, sev)
    return level
