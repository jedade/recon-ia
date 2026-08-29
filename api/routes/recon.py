# routes/recon.py
"""
Reconnaissance passive OSINT — 47 outils agrégés.

Chaque résultat d'outil respecte le format enrichi suivant :
  {
    "status"     : "success" | "error" | "not_installed" | "timeout" | "not_found" |
                   "unreachable" | "skipped" | "no_data" | "limited" | "unavailable",
    "meta"       : { "tool", "category", "description", "indicators": {champ: explication} },
    "data"       : { ... données structurées et annotées ... },
    "raw_output" : "sortie brute exacte de l'outil (pour interprétation IA)"
  }
"""
import logging
import os
import ssl
import socket
import subprocess
import tempfile
import json
import re
import hashlib
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

import requests as _requests
from requests.adapters import HTTPAdapter as _HTTPAdapter
from urllib3.util.retry import Retry as _Retry
import dns.resolver as _dns_resolver
import dns.reversename as _dns_reversename

from flask import Blueprint, request, jsonify
from flasgger import swag_from

from extensions import limiter
from utils.auth import require_auth
from utils.validators import is_valid_domain, is_safe_domain
from utils.parallel import (
    ToolTask,
    run_tools_parallel,
    DEFAULT_MAX_WORKERS as _PARALLEL_DEFAULT_WORKERS,
)

logger = logging.getLogger(__name__)

# ── Réglages de l'exécution parallèle des outils ─────────────────────────────
# Nombre de threads : les outils sont I/O-bound (attente réseau), on peut donc
# dépasser le nombre de cœurs. On reste volontairement modeste pour ne pas
# marteler les services tiers interrogés — une reconnaissance passive doit
# rester discrète et ne pas déclencher de rate-limiting.
_SCAN_MAX_WORKERS = max(1, int(os.getenv('SCAN_MAX_WORKERS', str(_PARALLEL_DEFAULT_WORKERS))))

# Borne globale de la vague parallèle. Empêche un outil bloqué de faire
# expirer la requête HTTP côté client ou le workflow n8n en amont.
_SCAN_DEADLINE_S = float(os.getenv('SCAN_DEADLINE_SECONDS', '180'))

# Outils dont le résultat alimente l'union `all_subs`.
_SUBDOMAIN_TOOLS = ('crtsh', 'subfinder', 'assetfinder', 'github', 'amass')


# ── Session HTTP partagée (connexions persistantes + retries) ────────────────
def _build_http_session() -> "_requests.Session":
    """
    Session `requests` unique et réutilisée par tous les outils OSINT.

    Deux bénéfices :

    1. CONNEXIONS PERSISTANTES — sans session, chaque appel rouvre une
       connexion TCP et refait la poignée de main TLS. Plusieurs outils
       interrogent les mêmes hôtes (crt.sh, l'API Shodan, OTX…) : le pool
       keep-alive supprime ce coût répété, ce qui compte d'autant plus
       maintenant que les outils tournent en parallèle.

    2. RETRIES CIBLÉS — les API publiques renvoient fréquemment 429 (quota) ou
       502/503/504 (indisponibilité passagère). Un `backoff_factor` de 1 espace
       les tentatives (1 s puis 2 s), ce qui est le comportement correct face à
       un 429 : réessayer immédiatement aggraverait la limitation.

    Seules les méthodes idempotentes sont réessayées (`allowed_methods`), et
    uniquement sur les statuts listés — jamais sur une 4xx métier comme 404,
    qui est une réponse légitime signifiant « rien trouvé ».
    """
    session = _requests.Session()
    retry = _Retry(
        total=2,
        backoff_factor=1,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS']),
        raise_on_status=False,
    )
    adapter = _HTTPAdapter(
        max_retries=retry,
        # Le pool doit pouvoir servir tous les threads de la vague parallèle
        # sans les sérialiser sur un nombre de connexions trop faible.
        pool_connections=_SCAN_MAX_WORKERS * 2,
        pool_maxsize=_SCAN_MAX_WORKERS * 4,
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.headers.update({'User-Agent': 'OSINT-Recon/1.1 (security research)'})
    return session


# `requests.Session` est documenté comme thread-safe pour l'envoi de requêtes,
# ce qui est requis ici puisque les outils partagent cette instance.
_http = _build_http_session()

pass_recon_bp = Blueprint('pass_recon', __name__)

# ---------------------------------------------------------------------------
# Résolveur DNS partagé — nameservers publics (contourne le DNS interne Docker)
# ---------------------------------------------------------------------------
_resolver = _dns_resolver.Resolver(configure=False)
_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
_resolver.timeout = 5
_resolver.lifetime = 10


def _resolve_ips(domain: str) -> list:
    """
    Résout les IPv4 (et optionnellement IPv6) d'un domaine via DNS public.
    Remplace socket.getaddrinfo() qui utilise le résolveur système (Docker interne).
    Retourne une liste vide si la résolution échoue.
    """
    ips = []
    try:
        for rdata in _resolver.resolve(domain, 'A'):
            ips.append(str(rdata))
    except Exception:
        pass
    try:
        for rdata in _resolver.resolve(domain, 'AAAA'):
            ips.append(str(rdata))
    except Exception:
        pass
    return ips


# ===========================================================================
# Registre des outils — descriptions et signification de chaque indicateur
# ===========================================================================

TOOLS_REGISTRY = {
    "whois": {
        "tool": "WHOIS Lookup",
        "category": "Domain Intelligence",
        "description": (
            "Interroge la base de données WHOIS pour récupérer les métadonnées "
            "d'enregistrement du domaine : propriétaire, bureau d'enregistrement, "
            "dates clés et serveurs de noms. Première étape essentielle pour établir "
            "le profil d'identité d'un domaine."
        ),
        "indicators": {
            "Registrar": "Société auprès de laquelle le domaine est enregistré (ex: OVH, GoDaddy). Peut révéler une infrastructure partagée entre domaines d'un même acteur.",
            "Creation Date": "Date de création du domaine. Un domaine récent (<1 an) associé à une marque connue est suspect (phishing/typosquatting).",
            "Updated Date": "Dernière modification des informations WHOIS. Un changement récent peut indiquer une prise de contrôle ou une préparation à une campagne.",
            "Expiration Date": "Date d'expiration. Si proche, le domaine peut être non renouvelé et récupéré par un tiers.",
            "Name Servers": "Serveurs DNS autoritaires. Révèle l'hébergeur DNS et peut être partagé entre plusieurs domaines du même propriétaire.",
            "Status": "Statut de protection (clientTransferProhibited = verrouillé contre le vol, redemptionPeriod = en attente de suppression).",
            "Registrant": "Informations sur le propriétaire — souvent masquées par un privacy shield (WhoisGuard, Domains By Proxy).",
            "DNSSEC": "Indique si la signature DNSSEC est activée au niveau du registrar.",
        },
    },
    "dns": {
        "tool": "DNS Lookup (nslookup)",
        "category": "DNS / Réseau",
        "description": (
            "Résolution DNS basique via nslookup. Identifie le serveur DNS utilisé "
            "pour la résolution et l'adresse IP principale du domaine. "
            "Complément rapide avant une analyse DNS complète."
        ),
        "indicators": {
            "Server": "Serveur DNS utilisé pour la résolution (résolveur local ou public comme 8.8.8.8).",
            "Address": "Adresse IP résolue — point d'entrée réseau du domaine.",
            "Non-authoritative answer": "La réponse provient du cache du résolveur, pas du serveur autoritaire.",
        },
    },
    "crtsh": {
        "tool": "Certificate Transparency (crt.sh)",
        "category": "Subdomain Discovery",
        "description": (
            "Interroge les journaux de transparence des certificats SSL/TLS via crt.sh. "
            "Chaque certificat émis pour un domaine (ou ses sous-domaines) est enregistré "
            "publiquement. Source passive très fiable pour découvrir des sous-domaines, "
            "y compris des environnements de staging ou d'administration non publics."
        ),
        "indicators": {
            "subdomain": "Sous-domaine extrait du champ CN ou SAN du certificat. Peut révéler des environnements internes exposés (api., admin., staging., dev.).",
            "count": "Nombre total de sous-domaines uniques découverts via cette source.",
        },
    },
    "subfinder": {
        "tool": "Subfinder",
        "category": "Subdomain Discovery",
        "description": (
            "Outil d'énumération passive de sous-domaines par ProjectDiscovery. "
            "Interroge des dizaines de sources OSINT (DNS passif, APIs publiques, "
            "Certificate Transparency, archives). Complément à crt.sh avec une couverture plus large."
        ),
        "indicators": {
            "subdomain": "Sous-domaine découvert via les sources OSINT agrégées par subfinder.",
        },
    },
    "assetfinder": {
        "tool": "Assetfinder (TomNomNom)",
        "category": "Subdomain Discovery",
        "description": (
            "Découverte de sous-domaines et d'assets associés via des sources passives "
            "(Facebook Graph, VirusTotal, crt.sh, etc.). Particulièrement efficace pour "
            "trouver des domaines liés (CDN, services tiers)."
        ),
        "indicators": {
            "subdomain": "Sous-domaine ou domaine associé découvert.",
        },
    },
    "amass": {
        "tool": "OWASP Amass (mode passif)",
        "category": "Subdomain Discovery",
        "description": (
            "Framework de reconnaissance réseau par l'OWASP. En mode passif (-passive), "
            "n'envoie aucun paquet directement à la cible — agrège uniquement des sources "
            "OSINT tierces (DNS passif, scraping, APIs). L'outil le plus complet pour "
            "la cartographie de surface d'attaque."
        ),
        "indicators": {
            "subdomain": "Sous-domaine découvert via les sources OSINT d'Amass.",
        },
    },
    "github": {
        "tool": "GitHub Subdomains",
        "category": "Subdomain Discovery",
        "description": (
            "Recherche dans les dépôts publics GitHub des sous-domaines mentionnés "
            "dans le code source, les fichiers de configuration, les CI/CD, etc. "
            "Peut révéler des environnements internes non documentés exposés accidentellement."
        ),
        "indicators": {
            "subdomain": "Sous-domaine trouvé dans un dépôt GitHub public. Possiblement sensible si non documenté.",
        },
    },
    "headers": {
        "tool": "HTTP Headers (sous-domaines)",
        "category": "Web / HTTP",
        "description": (
            "Récupère les en-têtes HTTP des 10 premiers sous-domaines découverts. "
            "Permet de confirmer quels sous-domaines sont actifs et de fingerprinter "
            "leur serveur, framework et configuration de sécurité."
        ),
        "indicators": {
            "Server": "Logiciel serveur web (nginx, Apache, IIS) et parfois sa version exacte.",
            "X-Powered-By": "Framework backend exposé (PHP, Express, ASP.NET) — information utile pour cibler des vulnérabilités.",
            "Set-Cookie": "Cookies définis — les flags HttpOnly et Secure indiquent le niveau de sécurité.",
            "http_status": "Code HTTP de réponse (200=actif, 301/302=redirect, 403=accès refusé, 404=inexistant).",
            "scheme": "Protocole utilisé (https=chiffré, http=non chiffré).",
        },
    },
    "ip_info": {
        "tool": "IP Geolocation & ASN (ipinfo.io)",
        "category": "Réseau / Infrastructure",
        "description": (
            "Résout le domaine en adresses IP puis interroge ipinfo.io pour obtenir "
            "la localisation géographique, l'Autonomous System Number (ASN) et "
            "l'organisation hébergeant chaque IP. Permet d'identifier l'hébergeur, "
            "la juridiction légale applicable et les IPs partagées."
        ),
        "indicators": {
            "ip": "Adresse IP résolue. Plusieurs IPs indiquent du load balancing ou un CDN.",
            "org": "Organisation propriétaire du bloc IP au format 'AS[numéro] [nom]' (ex: AS13335 CLOUDFLARENET).",
            "country": "Pays d'hébergement (code ISO). Important pour la juridiction et les lois applicables.",
            "city / region": "Localisation estimée du datacenter (précision variable selon l'hébergeur).",
            "loc": "Coordonnées GPS (latitude,longitude) — utile pour la cartographie géographique.",
            "timezone": "Fuseau horaire du datacenter — utile pour corréler des événements avec des logs horaires.",
            "postal": "Code postal approximatif de la zone d'hébergement.",
        },
    },
    "dns_records": {
        "tool": "DNS Records Complets",
        "category": "DNS / Réseau",
        "description": (
            "Énumère tous les types d'enregistrements DNS du domaine via dnspython. "
            "Fournit une vue complète de l'infrastructure DNS : résolution, messagerie, "
            "délégation, vérifications de domaine et autorisation de certificats."
        ),
        "indicators": {
            "A": "Adresse IPv4 du domaine. Multiples enregistrements = load balancing ou CDN.",
            "AAAA": "Adresse IPv6 — présence indique une infrastructure moderne dual-stack.",
            "MX": "Serveurs de messagerie avec priorité. Révèle le prestataire email (Google, Microsoft, OVH...).",
            "NS": "Serveurs de noms autoritaires. Identifie le fournisseur DNS (Cloudflare, AWS Route53...).",
            "TXT": "Enregistrements texte : contiennent SPF, DKIM, vérifications Google/Microsoft, DMARC.",
            "SOA": "Start Of Authority — serveur DNS primaire, email admin et paramètres de zone (TTL, refresh).",
            "CAA": "Certification Authority Authorization — liste les CA autorisées à émettre des certificats pour ce domaine.",
            "CNAME": "Alias vers un autre domaine — révèle les services tiers utilisés (CDN, SaaS).",
        },
    },
    "ssl_info": {
        "tool": "SSL/TLS Certificate Analysis",
        "category": "SSL / TLS",
        "description": (
            "Analyse le certificat SSL/TLS du domaine via une connexion directe au port 443. "
            "Extrait les informations de l'émetteur, les Subject Alternative Names (SANs), "
            "les dates de validité et le protocole négocié. Les SANs peuvent révéler "
            "d'autres domaines/sous-domaines couverts par le même certificat."
        ),
        "indicators": {
            "subject.CN": "Common Name — nom principal du certificat (généralement le domaine principal).",
            "issuer": "Autorité de Certification (CA) qui a émis le certificat (Let's Encrypt, DigiCert, Sectigo...).",
            "san": "Subject Alternative Names — liste TOUS les domaines couverts par ce certificat. Source précieuse de sous-domaines et domaines associés.",
            "san_count": "Nombre de SANs — un certificat wildcard (*.domain.com) a peu de SANs ; un cert multi-domaine en a beaucoup.",
            "not_after / days_until_expiry": "Date d'expiration et jours restants. Un certificat expirant sous 30 jours est un risque opérationnel.",
            "expired": "True si le certificat est expiré — connexion non sécurisée potentielle.",
            "tls_version": "Version TLS négociée lors de la connexion (TLSv1.2 ou TLSv1.3 recommandé).",
            "cipher.name": "Suite cryptographique utilisée — doit être une suite moderne (AES-GCM, ChaCha20).",
            "cipher.bits": "Longueur de clé en bits (≥128 bits recommandé).",
            "serial_number": "Numéro de série unique du certificat — peut être utilisé pour le révoquer ou le tracer dans les CT logs.",
        },
    },
    "email_config": {
        "tool": "Email Security Configuration",
        "category": "Email / Messagerie",
        "description": (
            "Analyse la configuration de sécurité email du domaine via des requêtes DNS. "
            "Évalue la protection contre le spoofing (SPF, DMARC), les standards modernes "
            "(BIMI, MTA-STS) et calcule un score de sécurité email global."
        ),
        "indicators": {
            "mx": "Serveurs de messagerie entrants. Révèle le prestataire email et son infrastructure.",
            "spf": "Sender Policy Framework — liste les serveurs autorisés à envoyer des emails au nom du domaine. Absence = vulnérable au spoofing.",
            "spf_status": "found = SPF configuré (protection active), not_found = domaine spoofable.",
            "dmarc": "Domain-based Message Authentication — politique de traitement des emails non authentifiés.",
            "dmarc_policy": "Politique DMARC : 'none'=monitoring seulement (pas de protection), 'quarantine'=spam, 'reject'=blocage total.",
            "dmarc_status": "found = DMARC configuré, not_found = aucune politique d'authentification globale.",
            "bimi": "Brand Indicators for Message Identification — affiche le logo de la marque dans les clients email (nécessite DMARC enforce).",
            "mta_sts": "MTA Strict Transport Security — force le chiffrement TLS pour la réception d'emails. Protection contre les attaques MITM sur le transit email.",
            "security_score": "Score global /6 synthétisant la posture de sécurité email (MX + SPF + DMARC + politique stricte).",
        },
    },
    "tech_stack": {
        "tool": "Technology Stack Fingerprint",
        "category": "Web / HTTP",
        "description": (
            "Identifie les technologies utilisées par le site via l'analyse des en-têtes HTTP, "
            "des cookies et du contenu HTML. Révèle le CMS, les frameworks JavaScript, "
            "le CDN, les outils analytics et les métadonnées social (Open Graph, Twitter Cards)."
        ),
        "indicators": {
            "server": "Logiciel serveur web (nginx, Apache, Microsoft-IIS, cloudflare...). La version exacte peut révéler des CVEs.",
            "powered_by": "Framework backend exposé via X-Powered-By (PHP/7.4, Express, ASP.NET). Éviter d'exposer cette info.",
            "cms": "CMS détecté (WordPress, Drupal, Shopify...). Chaque CMS a ses vulnérabilités connues et ses vecteurs d'attaque spécifiques.",
            "javascript_frameworks": "Frameworks JS côté client (React, Vue, Angular...). Utile pour évaluer la surface d'attaque XSS.",
            "cdn": "CDN/réseau de distribution détecté (Cloudflare, Fastly, Akamai...). Impacte les tests d'origine réelle.",
            "analytics": "Outils d'analytics présents (Google Analytics, Hotjar...). Révèle les prestataires tiers avec accès aux données.",
            "social_tags": "Métadonnées Open Graph et Twitter Cards — contenu partagé sur les réseaux sociaux. Révèle la description officielle et les images de la cible.",
            "cookies_detected": "Noms des cookies définis — peuvent révéler les technologies utilisées (PHPSESSID=PHP, ASP.NET_SessionId=.NET).",
            "interesting_headers": "En-têtes HTTP non standard révélant l'infrastructure technique (X-Generator, X-Drupal-Cache...).",
        },
    },
    "security_headers": {
        "tool": "HTTP Security Headers Analysis",
        "category": "Web / Sécurité",
        "description": (
            "Analyse 9 en-têtes de sécurité HTTP et attribue un grade de A+ à F selon "
            "leur présence et leur configuration. Chaque en-tête absent ou mal configuré "
            "représente une vulnérabilité potentielle exploitable côté client."
        ),
        "indicators": {
            "grade": "Note globale de sécurité HTTP : A+=parfait, A=excellent, B=bon, C=passable, D=faible, F=dangereux.",
            "score / max_score": "Score numérique sur le total maximum possible selon la pondération de chaque en-tête.",
            "strict-transport-security (HSTS)": "Force les navigateurs à utiliser HTTPS. Sans lui, attaque SSL-strip possible. max-age=31536000 + preload recommandé.",
            "content-security-policy (CSP)": "Restreint les sources de contenu chargées (scripts, styles, iframes). Principal rempart contre les attaques XSS.",
            "x-frame-options": "Empêche l'intégration du site dans un iframe (clickjacking). Valeurs valides : DENY ou SAMEORIGIN.",
            "x-content-type-options": "Empêche le MIME-sniffing. Valeur : nosniff. Protection contre certaines attaques XSS via fichiers malveillants.",
            "referrer-policy": "Contrôle les informations envoyées dans l'en-tête Referer lors des navigations. Protège la vie privée des utilisateurs.",
            "permissions-policy": "Restreint l'accès aux APIs du navigateur (caméra, micro, géolocalisation) pour les scripts tiers.",
            "x-xss-protection": "Filtre XSS des anciens navigateurs. Déprécié — la CSP est préférable mais utile en fallback.",
            "cross-origin-opener-policy (COOP)": "Isole le contexte de navigation pour se protéger contre les attaques cross-origin (Spectre).",
            "cross-origin-resource-policy (CORP)": "Empêche d'autres origines de charger les ressources de ce site.",
            "present": "True = en-tête présent dans la réponse HTTP du serveur.",
            "valid": "True = valeur de l'en-tête correctement configurée selon les bonnes pratiques.",
            "recommendation": "Action corrective suggérée si l'en-tête est absent ou mal configuré.",
        },
    },
    "robots_txt": {
        "tool": "Robots.txt Analysis",
        "category": "Web / OSINT",
        "description": (
            "Récupère et analyse le fichier robots.txt qui indique aux robots d'indexation "
            "les chemins à ne PAS explorer. Paradoxalement, les chemins Disallow révèlent "
            "souvent des URLs sensibles (admin, API, backups) que le propriétaire tente "
            "de cacher des moteurs de recherche — mais pas des attaquants."
        ),
        "indicators": {
            "disallowed_paths": "Chemins interdits aux robots. Chaque entrée Disallow peut indiquer une ressource existante et potentiellement sensible.",
            "interesting_paths": "Sous-ensemble des chemins Disallow contenant des mots-clés sensibles (admin, api, backup, staging, config, login...). Priorité d'investigation.",
            "interesting_count": "Nombre de chemins potentiellement sensibles identifiés.",
            "sitemaps": "URLs des sitemaps référencés — peut révéler la structure complète du site.",
            "user_agents": "Agents ciblés par les règles. Un '*' signifie règle universelle. Des agents spécifiques peuvent révéler des outils de monitoring.",
            "raw": "Contenu brut du fichier robots.txt — à analyser intégralement pour ne manquer aucun chemin.",
        },
    },
    "sitemap": {
        "tool": "Sitemap.xml Parser",
        "category": "Web / OSINT",
        "description": (
            "Récupère et analyse sitemap.xml pour extraire les URLs référencées par le site. "
            "Fournit une cartographie des pages publiques et peut révéler des sections "
            "inattendues du site (API docs, fichiers, environnements de test)."
        ),
        "indicators": {
            "type": "'sitemap'=liste directe d'URLs, 'index'=sitemap de sitemaps (structure hiérarchique).",
            "urls": "Liste des URLs publiquement référencées dans le sitemap (jusqu'à 50 extraites).",
            "url_count": "Nombre total d'URLs dans le sitemap — indicateur de la taille du site.",
            "sitemaps": "Sous-sitemaps référencés si type=index. Peuvent cibler des sections spécifiques (blog, produits, docs).",
        },
    },
    "redirect_chain": {
        "tool": "HTTP Redirect Chain",
        "category": "Web / HTTP",
        "description": (
            "Suit la chaîne complète de redirections HTTP depuis le domaine racine. "
            "Révèle la destination finale, les intermédiaires (CDN, load balancers), "
            "et peut exposer des URLs internes ou des configurations d'infrastructure."
        ),
        "indicators": {
            "chain": "Liste ordonnée des redirections avec URL, code HTTP et en-tête Location.",
            "hops": "Nombre de sauts avant la destination finale. >3 sauts = infrastructure complexe ou mauvaise configuration.",
            "final_url": "URL de destination réelle après toutes les redirections — peut différer du domaine initial.",
            "final_status": "Code HTTP final (200=OK, 403=interdit, 404=inexistant, 503=service indisponible).",
            "status_code": "301=redirect permanent, 302=redirect temporaire, 307=temporaire (méthode préservée), 308=permanent (méthode préservée).",
        },
    },
    "security_txt": {
        "tool": "Security.txt (RFC 9116)",
        "category": "Web / Sécurité",
        "description": (
            "Vérifie la présence du fichier security.txt défini par la RFC 9116. "
            "Ce fichier standardise la déclaration du programme de divulgation responsable "
            "et du contact sécurité de l'organisation. Son absence peut indiquer l'absence "
            "d'un programme de bug bounty ou de processus de gestion des vulnérabilités."
        ),
        "indicators": {
            "contact": "Email ou URL pour signaler des vulnérabilités de sécurité (ex: mailto:security@example.com).",
            "expires": "Date d'expiration du fichier — au-delà, les informations peuvent être obsolètes.",
            "encryption": "URL vers la clé PGP publique pour chiffrer les rapports de vulnérabilité.",
            "policy": "URL vers la politique de divulgation responsable (Responsible Disclosure Policy).",
            "acknowledgments": "URL de la page de remerciements des chercheurs en sécurité.",
            "preferred_languages": "Langues préférées pour recevoir les rapports.",
        },
    },
    "dnssec": {
        "tool": "DNSSEC Validation",
        "category": "DNS / Sécurité",
        "description": (
            "Vérifie si le domaine a activé DNSSEC (DNS Security Extensions). "
            "DNSSEC protège contre la falsification des réponses DNS (DNS spoofing/poisoning) "
            "en signant cryptographiquement les enregistrements DNS."
        ),
        "indicators": {
            "enabled": "True si DNSSEC est actif sur ce domaine. False = vulnérable aux attaques de type DNS cache poisoning.",
            "has_rrsig": "Présence de signatures RRSIG — preuve que les enregistrements DNS sont signés cryptographiquement.",
            "has_ds": "Présence d'un enregistrement DS (Delegation Signer) — ancre de confiance dans la chaîne de validation.",
            "has_dnskey": "Présence de clés DNSKEY publiques utilisées pour vérifier les signatures RRSIG.",
            "dnskey_records": "Clés DNSKEY brutes — contiennent le flag, le protocole, l'algorithme et la clé publique encodée en base64.",
        },
    },
    "waf_detection": {
        "tool": "WAF / CDN Detection",
        "category": "Infrastructure / Sécurité",
        "description": (
            "Détecte la présence d'un Web Application Firewall (WAF) ou d'un CDN "
            "en analysant les en-têtes HTTP, le nom du serveur et les cookies. "
            "Un WAF intercepte les requêtes malveillantes avant qu'elles atteignent "
            "l'application. Sa présence est un indicateur fort de maturité sécurité."
        ),
        "indicators": {
            "protected": "True si au moins un WAF/CDN a été détecté.",
            "detected[].name": "Nom du WAF/CDN identifié (Cloudflare, Akamai, Imperva, F5 BIG-IP...).",
            "detected[].confidence": "'high'=2+ indicateurs concordants (très fiable), 'medium'=1 indicateur (possible).",
            "detected[].indicators": "Éléments qui ont déclenché la détection (ex: 'header:cf-ray', 'cookie:__cfduid').",
            "server": "Valeur brute de l'en-tête Server — révèle parfois directement le WAF ou le serveur d'origine.",
            "via": "En-tête Via — révèle les proxies intermédiaires traversés (CDN, reverse proxy).",
        },
    },
    "archive_history": {
        "tool": "Wayback Machine Archive History",
        "category": "OSINT Externe",
        "description": (
            "Interroge l'API CDX du Wayback Machine (archive.org) pour retrouver "
            "l'historique d'archivage du domaine. Permet de déterminer depuis quand "
            "le domaine est actif et d'accéder à d'anciennes versions du site "
            "(URLs, contenu, fichiers supprimés, anciennes technologies)."
        ),
        "indicators": {
            "first_snapshot.date": "Date du premier archivage connu — ancienneté réelle du domaine en ligne.",
            "last_snapshot.date": "Date du dernier archivage connu — site encore actif si récent.",
            "first_snapshot.status": "Code HTTP lors du premier archivage (200=site actif, 301=redirect...).",
            "total_pages_index": "Nombre approximatif de pages d'index archivées — indicateur de la taille de l'historique.",
            "wayback_url": "Lien direct vers l'historique complet sur archive.org pour navigation manuelle.",
            "historical_urls": "URLs distinctes archivées (collapse=urlkey) — révèle d'anciens chemins, fichiers supprimés, endpoints d'admin ou de sauvegarde qui existaient par le passé.",
            "historical_urls_count": "Nombre d'URLs distinctes retournées (plafonné pour éviter des réponses massives).",
            "historical_urls_truncated": "True si la limite d'URLs a été atteinte — l'historique réel est plus large.",
        },
    },
    "tls_config": {
        "tool": "TLS Configuration Audit",
        "category": "SSL / TLS",
        "description": (
            "Analyse la configuration TLS du serveur via sslscan (ou Python ssl en fallback). "
            "Identifie les protocoles supportés, les suites cryptographiques acceptées, "
            "et détecte les configurations obsolètes ou dangereuses (TLS 1.0/1.1, RC4, DES)."
        ),
        "indicators": {
            "protocols": "Map protocole → activé/désactivé. TLSv1.3 recommandé, TLSv1.0/1.1 obsolètes (RFC 8996).",
            "weak_protocols": "Protocoles dangereux encore acceptés (SSLv2, SSLv3, TLSv1.0, TLSv1.1) — vulnérables à POODLE, BEAST, DROWN.",
            "cipher_suites": "Suites cryptographiques acceptées avec protocole, taille de clé et nom.",
            "weak_ciphers": "Chiffrements dangereux détectés (RC4=cassé, DES=56bits insuffisant, NULL=pas de chiffrement).",
            "source": "'sslscan'=analyse complète via outil CLI, 'python_ssl_fallback'=test basique des protocoles uniquement.",
        },
    },
    "reverse_ip": {
        "tool": "Reverse IP Lookup",
        "category": "Réseau / Infrastructure",
        "description": (
            "Identifie tous les autres domaines hébergés sur la même adresse IP via l'API "
            "HackerTarget. Révèle le contexte d'hébergement : serveur dédié (IP unique), "
            "hébergement mutualisé (centaines de domaines), ou infrastructure CDN. "
            "Peut révéler des domaines liés appartenant à la même organisation."
        ),
        "indicators": {
            "domains": "Liste des domaines partageant la même IP. Un grand nombre = hébergement partagé.",
            "count": "Nombre total de co-hébergés. 1=dédié, 2-10=probable même org, >50=hébergement mutualisé.",
            "ip": "Adresse IP sur laquelle la recherche a été effectuée.",
            "note": "Indication sur le type d'hébergement déduit du nombre de domaines co-hébergés.",
        },
    },
    "asn_info": {
        "tool": "ASN & IP Ranges",
        "category": "Réseau / Infrastructure",
        "description": (
            "Résout l'ASN (Autonomous System Number) de l'organisation via l'API RIPEstat "
            "du RIPE NCC (aucune clé requise) et récupère les blocs IP (préfixes CIDR) "
            "annoncés par cet AS. Permet de connaître l'ensemble de l'infrastructure réseau "
            "d'une organisation, y compris les plages IP non documentées sur leur site public. "
            "Remplace bgpview.io, arrêté définitivement fin novembre 2025."
        ),
        "indicators": {
            "asn": "Numéro d'AS de l'organisation (ex: AS13335 pour Cloudflare).",
            "asn_name": "Nom de l'AS tel qu'enregistré auprès du RIR (holder RIPEstat).",
            "ipv4_prefixes": "Blocs IPv4 annoncés par l'AS (ex: 192.168.0.0/24), plafonnés à 100 entrées.",
            "ipv6_prefixes": "Blocs IPv6 annoncés — indique la maturité de l'infrastructure réseau.",
            "prefix_count": "Nombre total de plages IP annoncées (avant troncature), indicateur de la taille de l'infrastructure.",
            "prefix_list_truncated": "True si le nombre réel de préfixes dépasse la limite affichée (100).",
        },
    },
    "ptr_records": {
        "tool": "PTR / Reverse DNS Records",
        "category": "DNS / Réseau",
        "description": (
            "Effectue une résolution DNS inverse (PTR) pour chaque adresse IP découverte. "
            "Les enregistrements PTR peuvent révéler des noms d'hôtes internes, "
            "des noms de serveurs spécifiques, et confirmer si l'IP appartient "
            "effectivement à l'organisation cible ou à un CDN/hébergeur."
        ),
        "indicators": {
            "ip": "Adresse IP pour laquelle la résolution inverse a été effectuée.",
            "ptr": "Hostname inversé associé à l'IP. Peut révéler 'internal-server.corp.example.com' ou 'ec2-x-x-x-x.compute.amazonaws.com'.",
            "aliases": "Noms alternatifs retournés par la résolution inverse.",
            "is_cloud": "True si le PTR pointe vers un fournisseur cloud connu (AWS, Azure, GCP, OVH...) — confirme l'hébergeur.",
        },
    },
    "dkim_check": {
        "tool": "DKIM Selector Enumeration",
        "category": "Email / Messagerie",
        "description": (
            "Teste une liste de sélecteurs DKIM courants en interrogeant les enregistrements "
            "TXT DNS du type '{selecteur}._domainkey.domain'. Révèle les clés DKIM actives, "
            "l'algorithme de signature utilisé, et indirectement les prestataires email "
            "(Google Workspace, Microsoft 365, SendGrid, Mailchimp...) via leurs sélecteurs caractéristiques."
        ),
        "indicators": {
            "found[].selector": "Nom du sélecteur DKIM actif (ex: 'google', 'selector1', 'k1').",
            "found[].record": "Contenu de l'enregistrement TXT DKIM (clé publique en base64 via p=, algorithme via k=).",
            "found[].algorithm": "Algorithme de signature (rsa=standard, ed25519=moderne et plus sécurisé).",
            "found[].provider": "Prestataire email déduit du nom du sélecteur (Google, Microsoft, Mailchimp...).",
            "selectors_tested": "Liste complète des sélecteurs testés.",
            "count": "Nombre de sélecteurs DKIM actifs trouvés — plusieurs clés = rotation ou multi-provider.",
        },
    },
    "spf_analysis": {
        "tool": "SPF Record Deep Analysis",
        "category": "Email / Messagerie",
        "description": (
            "Effectue une expansion récursive du record SPF : suit tous les include: et redirect= "
            "pour construire l'arbre complet des expéditeurs email autorisés. Révèle tous les "
            "prestataires tiers pouvant envoyer des emails au nom du domaine (ESPs, CRMs, outils marketing), "
            "ainsi que les plages IP directement autorisées."
        ),
        "indicators": {
            "includes_tree": "Arbre hiérarchique des includes SPF — montre la chaîne de délégation.",
            "mechanisms": "Liste complète des mécanismes avec le domaine source (ip4:, ip6:, a:, mx:, all).",
            "ip4_ranges": "Plages IPv4 explicitement autorisées à envoyer des emails.",
            "ip6_ranges": "Plages IPv6 autorisées.",
            "all_mechanism": "'~all'=softfail (spam), '-all'=hard fail (rejet), '?all'=neutre (aucune protection), '+all'=DANGEREUX (tout autorisé).",
            "domains_visited": "Tous les domaines SPF résolus récursivement.",
            "lookup_count": "Nombre de lookups DNS effectués — SPF limite à 10 lookups max (RFC 7208), au-delà = SPF permerror.",
        },
    },
    "subdomain_takeover": {
        "tool": "Subdomain Takeover Detection",
        "category": "Vulnérabilités / OSINT",
        "description": (
            "Détecte les sous-domaines vulnérables à une prise de contrôle (subdomain takeover). "
            "Un sous-domaine avec un CNAME pointant vers un service externe non revendiqué "
            "(GitHub Pages supprimé, bucket S3 inexistant, app Heroku retirée...) "
            "peut être réclamé par un attaquant pour héberger du contenu malveillant "
            "sous le domaine légitime de la victime. Détection strictement PASSIVE : "
            "résolution DNS du CNAME uniquement, aucune requête HTTP de confirmation "
            "n'est envoyée vers la cible."
        ),
        "indicators": {
            "vulnerable[].subdomain": "Sous-domaine possiblement vulnérable à une prise de contrôle.",
            "vulnerable[].cname": "CNAME vers lequel le sous-domaine pointe (service externe potentiellement non revendiqué).",
            "vulnerable[].service": "Service externe identifié (GitHub Pages, Heroku, Netlify, AWS S3...).",
            "vulnerable[].confidence": "Toujours 'medium' — détection strictement passive (CNAME dangling), sans confirmation HTTP active.",
            "checked_count": "Nombre de sous-domaines vérifiés.",
        },
    },
    "js_endpoints": {
        "tool": "JavaScript Endpoint Extraction",
        "category": "Web / OSINT",
        "description": (
            "Analyse les fichiers JavaScript publics du site pour extraire les endpoints d'API, "
            "les chemins de routes, et les URLs internes. Les développeurs exposent souvent "
            "inadvertamment des endpoints non documentés, des clés API en dur, "
            "et la structure interne de l'application dans le code JS côté client."
        ),
        "indicators": {
            "endpoints": "Chemins d'API et routes extraits des fichiers JS (ex: /api/v1/users, /graphql).",
            "js_files": "Fichiers JavaScript analysés avec leur URL.",
            "interesting": "Endpoints contenant des mots-clés sensibles (admin, secret, key, token, password, internal...).",
            "endpoint_count": "Nombre total d'endpoints uniques extraits.",
            "js_files_count": "Nombre de fichiers JS analysés.",
        },
    },
    "dnsbl_check": {
        "tool": "DNS Blacklist Check",
        "category": "Réputation / Threat Intel",
        "description": (
            "Vérifie si le domaine ou ses adresses IP sont référencés dans les principales "
            "listes noires DNS (DNSBL). Une présence en blacklist indique une réputation "
            "compromise : envoi de spam, activité malveillante, ou hébergement de contenu illicite. "
            "Essentiel pour évaluer la réputation d'un domaine cible."
        ),
        "indicators": {
            "listed[].ip": "Adresse IP blacklistée.",
            "listed[].dnsbl": "Nom de la blacklist (zen.spamhaus.org, bl.spamcop.net...).",
            "listed[].return_code": "Code de retour DNS indiquant le type de listing (127.0.0.2=SBL spam, 127.0.0.4=XBL exploits...).",
            "clean": "True si aucune IP n'est référencée dans les blacklists testées.",
            "checked_dnsbls": "Liste des blacklists vérifiées.",
            "risk_level": "Niveau de risque déduit : clean/low/medium/high.",
        },
    },
    "favicon_hash": {
        "tool": "Favicon Hash (Shodan Fingerprint)",
        "category": "Web / Fingerprinting",
        "description": (
            "Récupère le favicon du site et calcule son hash MD5 et MurmurHash3 (format Shodan). "
            "Le hash de favicon est une empreinte unique permettant de retrouver toutes les "
            "instances du même serveur/application sur Internet via Shodan (shodan.io) ou Fofa. "
            "Technique clé pour identifier l'infrastructure réelle derrière un CDN."
        ),
        "indicators": {
            "md5": "Hash MD5 du favicon — utilisable pour recherche manuelle.",
            "murmur3": "Hash MurmurHash3 du favicon encodé en base64 — format exact utilisé par Shodan (http.favicon.hash:{hash}).",
            "base64": "Favicon encodé en base64 — format intermédiaire pour le calcul Shodan.",
            "size_bytes": "Taille du favicon en octets — trop petit (<64B) peut indiquer un favicon générique.",
            "url": "URL depuis laquelle le favicon a été récupéré.",
            "shodan_query": "Requête Shodan pré-formatée pour pivoter sur ce favicon et trouver d'autres serveurs identiques.",
        },
    },
    "shodan_internetdb": {
        "tool": "Shodan InternetDB",
        "category": "Réputation / Threat Intel",
        "description": (
            "Interroge l'API publique et gratuite InternetDB de Shodan "
            "(https://internetdb.shodan.io) pour chaque IP du domaine. Restitue la vue "
            "que Shodan a déjà collectée sur cette IP : ports ouverts observés, "
            "logiciels identifiés (CPE), CVE associées et hostnames connus. "
            "Strictement passif : aucune sonde n'est envoyée à la cible, seules les "
            "observations préexistantes de Shodan sont consultées."
        ),
        "indicators": {
            "ports": "Ports observés ouverts par les scans Shodan. Un port d'administration (22, 3389, 5432, 9200...) exposé est un risque majeur.",
            "cpes": "Identifiants CPE des logiciels détectés (ex: cpe:/a:nginx:nginx:1.18.0) — permet de corréler avec des CVE connues.",
            "vulns": "CVE associées à cette IP dans la base Shodan. Indicateur direct de vulnérabilités potentiellement exploitables.",
            "hostnames": "Noms d'hôtes associés à l'IP par Shodan — peut révéler d'autres domaines hébergés sur la même machine.",
            "tags": "Étiquettes Shodan (cdn, cloud, self-signed, honeypot...) — qualifie la nature de l'hôte.",
            "status_per_ip": "Statut de la requête pour chaque IP : success, no_data (IP inconnue de Shodan), error.",
        },
    },
    "otx_passive_dns": {
        "tool": "AlienVault OTX Passive DNS",
        "category": "OSINT Externe",
        "description": (
            "Interroge l'Open Threat Exchange d'AlienVault pour obtenir l'historique "
            "des résolutions DNS du domaine (passive DNS). Contrairement au DNS courant, "
            "le passive DNS restitue les IP auxquelles le domaine a pointé DANS LE TEMPS, "
            "avec les dates de première et dernière observation. Permet de reconstituer "
            "les migrations d'hébergement et de repérer d'anciennes IP encore exposées."
        ),
        "indicators": {
            "records[].address": "Adresse IP historiquement associée au domaine (ou hostname si enregistrement inverse).",
            "records[].first": "Date de première observation de cette résolution — début de l'utilisation de l'IP.",
            "records[].last": "Date de dernière observation — si ancienne, l'IP n'est plus utilisée mais peut rester exposée.",
            "records[].hostname": "Sous-domaine concerné par la résolution — source complémentaire de découverte de sous-domaines.",
            "unique_ips": "IP distinctes ayant hébergé le domaine — révèle l'historique d'infrastructure.",
            "unique_hostnames": "Hostnames distincts observés dans le passive DNS.",
            "authenticated": "True si une clé OTX_API_KEY a été utilisée (quotas plus élevés et données plus complètes).",
        },
    },
    "rdap_info": {
        "tool": "RDAP Domain Registration (RFC 9083)",
        "category": "Domain Intelligence",
        "description": (
            "Interroge le service RDAP (Registration Data Access Protocol, RFC 9083) via "
            "rdap.org, successeur normalisé de WHOIS. Contrairement au WHOIS textuel dont "
            "le format varie selon chaque registre, RDAP retourne du JSON structuré et "
            "standardisé : registrar, identifiant IANA, dates d'événements, statuts EPP "
            "et serveurs de noms. Complémentaire au WHOIS (les deux sont exécutés) et "
            "beaucoup plus fiable pour un traitement automatisé."
        ),
        "indicators": {
            "registrar": "Bureau d'enregistrement déclaré dans les entités RDAP — donnée normalisée, sans parsing fragile.",
            "registrar_iana_id": "Identifiant IANA officiel du registrar — permet une identification non ambiguë.",
            "events.registration": "Date de création du domaine (événement RDAP 'registration').",
            "events.expiration": "Date d'expiration (événement 'expiration') — un domaine proche de l'expiration peut être récupéré par un tiers.",
            "events.last_changed": "Date de dernière modification de l'enregistrement.",
            "status": "Statuts EPP normalisés (client transfer prohibited, server delete prohibited...) — niveau de verrouillage du domaine.",
            "nameservers": "Serveurs de noms déclarés au registre — comparables aux NS DNS pour détecter une désynchronisation.",
            "dnssec_delegated": "True si le registre déclare une délégation DNSSEC (enregistrements DS présents).",
        },
    },
    "xposedornot_breaches": {
        "tool": "XposedOrNot — Breach Analytics",
        "category": "Réputation / Threat Intel",
        "description": (
            "Interroge XposedOrNot (gratuit, sans clé) pour lister les fuites de données "
            "publiques connues touchant des adresses email « rôle » courantes du domaine "
            "(admin@, contact@…). Remplace l'ancien HIBP, payant et inutilisable sans "
            "vérification de propriété du domaine. Couverture partielle par conception : "
            "seules les adresses testées sont couvertes, pas le domaine entier."
        ),
        "indicators": {
            "breaches": "Liste des fuites connues, avec les alias d'adresses email affectés pour chacune.",
            "breach_count": "Nombre de fuites distinctes touchant les adresses testées.",
            "affected_accounts": "Nombre d'alias testés apparaissant dans au moins une fuite.",
            "top_breaches": "Fuites impactant le plus grand nombre d'alias — à traiter en priorité.",
            "emails_checked": "Adresses rôle effectivement testées (admin@, contact@…).",
        },
    },
    "typosquatting": {
        "tool": "dnstwist — Typosquatting & Phishing",
        "category": "Réputation / Threat Intel",
        "description": (
            "Génère les permutations du domaine (fautes de frappe, homoglyphes, IDN, "
            "dictionnaire) et ne conserve que celles réellement enregistrées. Détecte les "
            "domaines de phishing/typosquatting imitant la cible — lacune absente des "
            "autres outils. 100% passif : seuls les domaines candidats sont interrogés, "
            "jamais la cible elle-même."
        ),
        "indicators": {
            "suspicious_domains": "Domaines similaires enregistrés, avec leurs résolutions DNS/MX.",
            "mx_configured": "Domaines suspects ayant un serveur mail configuré — signal fort de campagne de phishing active.",
            "risk_level": "high si MX configuré (campagne active probable), medium si juste enregistré, low sinon.",
        },
    },
    "gau_urls": {
        "tool": "gau — Get All URLs (Common Crawl + Wayback + OTX + urlscan)",
        "category": "OSINT Externe",
        "description": (
            "Agrège les URLs historiques connues pour le domaine depuis plusieurs sources "
            "(Wayback Machine, Common Crawl, AlienVault OTX, urlscan.io) en un seul appel. "
            "Complète `archive_history` (Wayback seul) : Common Crawl en particulier "
            "remonte souvent des endpoints, paramètres ou fichiers oubliés (.sql, .bak, "
            ".env) absents de Wayback."
        ),
        "indicators": {
            "urls": "URLs historiques agrégées, toutes sources confondues.",
            "interesting_files": "URLs se terminant par une extension sensible (.sql, .bak, .env, .zip, .log…).",
            "url_count": "Nombre total d'URLs uniques trouvées.",
        },
    },
    "dmarc_check": {
        "tool": "DMARC Policy",
        "category": "Email / Messagerie",
        "description": (
            "Enregistrement DMARC (_dmarc.<domaine>) — politique anti-usurpation qui "
            "s'appuie sur SPF et DKIM déjà vérifiés séparément. Sans DMARC, un attaquant "
            "peut usurper le domaine dans l'en-tête From même avec SPF/DKIM corrects "
            "ailleurs (misalignment)."
        ),
        "indicators": {
            "present": "True si un enregistrement DMARC valide existe.",
            "policy": "none (surveillance seule) / quarantine (spam) / reject (rejet) — none n'apporte aucune protection réelle.",
            "percentage": "Pourcentage des emails non conformes soumis à la politique (pct=).",
            "report_address": "Adresse de réception des rapports agrégés DMARC (rua=).",
        },
    },
    "mta_sts_check": {
        "tool": "MTA-STS",
        "category": "Email / Messagerie",
        "description": (
            "MTA-STS (_mta-sts.<domaine> + politique HTTPS) force le chiffrement TLS pour "
            "le courrier SMTP entrant, empêchant un downgrade vers une connexion non "
            "chiffrée (contournement historique de STARTTLS)."
        ),
        "indicators": {
            "present": "True si l'enregistrement DNS MTA-STS existe.",
            "policy_mode": "none (inactif) / testing (surveillance) / enforce (TLS imposé).",
        },
    },
    "tlsrpt_check": {
        "tool": "TLS-RPT",
        "category": "Email / Messagerie",
        "description": (
            "TLS-RPT (_smtp._tls.<domaine>) fait remonter des rapports lorsqu'une "
            "connexion SMTP entrante échoue à établir TLS — visibilité opérationnelle "
            "complémentaire à MTA-STS."
        ),
        "indicators": {
            "present": "True si l'enregistrement TLS-RPT existe.",
            "report_address": "Adresse de réception des rapports d'échec TLS (rua=).",
        },
    },
    "bimi_check": {
        "tool": "BIMI",
        "category": "Email / Messagerie",
        "description": (
            "BIMI (default._bimi.<domaine>) permet d'afficher le logo de la marque dans "
            "les clients mail compatibles — signal indirect de maturité de la posture "
            "email (BIMI exige généralement DMARC en mode reject/quarantine en amont)."
        ),
        "indicators": {
            "present": "True si un enregistrement BIMI valide existe.",
            "logo_url": "URL du logo SVG déclaré (l=).",
        },
    },
    "caa_check": {
        "tool": "CAA Record",
        "category": "SSL / TLS",
        "description": (
            "Enregistrement CAA (<domaine> CAA) restreint les autorités de certification "
            "autorisées à émettre un certificat pour ce domaine. Son absence permet à "
            "n'importe quelle CA publique d'émettre un certificat — surface d'attaque sur "
            "l'émission frauduleuse de certificats."
        ),
        "indicators": {
            "present": "True si au moins un enregistrement CAA existe.",
            "authorized_cas": "Autorités de certification autorisées (tag issue).",
            "has_iodef": "True si un contact de notification d'incident (tag iodef) est déclaré.",
        },
    },
    "dane_check": {
        "tool": "DANE / TLSA",
        "category": "SSL / TLS",
        "description": (
            "Enregistrements TLSA (_443._tcp / _25._tcp.<domaine>) lient un certificat "
            "précis au DNS (pin), rendant une autorité de certification compromise "
            "insuffisante pour émettre un certificat accepté. N'a de valeur que si "
            "DNSSEC est actif (cf. outil dnssec) — sinon les enregistrements TLSA "
            "eux-mêmes ne sont pas dignes de confiance."
        ),
        "indicators": {
            "present": "True si au moins un enregistrement TLSA existe (HTTPS ou SMTP).",
            "by_service": "Détail des enregistrements TLSA par service (https, smtp).",
        },
    },
    "http_observatory": {
        "tool": "Mozilla HTTP Observatory v2",
        "category": "Web / HTTP",
        "description": (
            "Convertit les en-têtes de sécurité bruts (cf. `security_headers`) en une note "
            "normalisée A+ → F reconnue par les équipes sécurité, avec le détail des tests "
            "échoués. API publique gratuite, sans clé (observatory-api.mdn.mozilla.net)."
        ),
        "indicators": {
            "grade": "Note normalisée A+ à F.",
            "score": "Score numérique associé à la note.",
            "tests_failed": "Tests échoués avec leur description — base directe des recommandations.",
        },
    },
    "abuseipdb_check": {
        "tool": "AbuseIPDB",
        "category": "Réputation / Threat Intel",
        "description": (
            "Score de réputation des IP résolues via AbuseIPDB (free tier 1000 req/j, "
            "sans carte bancaire). Complète `dnsbl_check`/`shodan_internetdb` avec un "
            "score de confiance d'abus communautaire. ABUSEIPDB_API_KEY optionnel — "
            "outil ignoré (status 'skipped') si absent."
        ),
        "indicators": {
            "ips[].abuse_score": "Score de confiance d'abus 0-100 (communautaire AbuseIPDB).",
            "max_abuse_score": "Score maximal observé parmi les IP du domaine.",
            "risk_level": "high (≥50) / medium (≥10) / low.",
        },
    },
    "abusech_check": {
        "tool": "abuse.ch (URLhaus + ThreatFox)",
        "category": "Réputation / Threat Intel",
        "description": (
            "Présence du domaine/IP dans les bases malware (URLhaus) et IOC de menace "
            "(ThreatFox) d'abuse.ch — signal de compromission bien plus fort qu'une simple "
            "réputation DNSBL (distribution de malware ou infrastructure C2 confirmée). "
            "ABUSECH_AUTH_KEY optionnel (gratuit) — outil ignoré si absent."
        ),
        "indicators": {
            "urlhaus_urls": "URLs malveillantes hébergées sur ce domaine, avec le type de menace.",
            "threatfox_iocs": "IOC associés aux IP du domaine (malware, C2) dans ThreatFox.",
            "risk_level": "high si au moins un hit, clean sinon.",
        },
    },
    "urlscan_search": {
        "tool": "urlscan.io — Historical Scan Search",
        "category": "OSINT Externe",
        "description": (
            "Recherche passive dans l'historique des scans publics déjà soumis par des "
            "tiers sur urlscan.io (jamais de scan actif soumis par nous-mêmes). Révèle des "
            "sous-domaines, technologies et redirections observés lors de scans antérieurs. "
            "URLSCAN_API_KEY optionnel (gratuit) — outil ignoré si absent."
        ),
        "indicators": {
            "scans": "Scans historiques trouvés (URL, IP, serveur, date).",
            "subdomains_seen": "Sous-domaines distincts observés dans les scans passés.",
        },
    },
}


# ===========================================================================
# Helpers — infrastructure
# ===========================================================================

def _run_subprocess(cmd: list, timeout: int = 60, cwd: str = None,
                    env_extra: dict = None) -> dict:
    """
    Exécute une commande CLI et retourne un résultat structuré avec stdout brut.

    En cas de timeout, récupère la sortie partielle déjà produite (crucial pour amass
    qui peut émettre des résultats avant d'atteindre la limite de temps).

    env_extra : variables d'environnement supplémentaires pour le sous-processus.
        À utiliser pour les SECRETS (jetons d'API) plutôt que de les passer en
        argument de ligne de commande, où ils seraient lisibles par tout
        processus du conteneur via `ps` ou /proc/*/cmdline.
    """
    env = None
    if env_extra:
        env = {**os.environ, **env_extra}
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd, env=env
        )
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        return {
            "status": "success",
            "lines": lines,
            "returncode": out.returncode,
            "raw": out.stdout,
        }
    except FileNotFoundError:
        return {"status": "not_installed",
                "error": f"Outil non trouvé : {cmd[0]}",
                "raw": ""}
    except subprocess.TimeoutExpired as e:
        # Récupère la sortie partielle produite avant le timeout
        partial_raw = ""
        try:
            if e.stdout:
                partial_raw = (
                    e.stdout if isinstance(e.stdout, str)
                    else e.stdout.decode("utf-8", errors="replace")
                )
        except Exception:
            pass
        partial_lines = [l.strip() for l in partial_raw.splitlines() if l.strip()]
        if partial_lines:
            return {
                "status": "timeout_partial",
                "lines": partial_lines,
                "raw": partial_raw,
                "error": (
                    f"Timeout après {timeout}s — {len(partial_lines)} résultats "
                    f"partiels récupérés avant interruption"
                ),
            }
        return {
            "status": "timeout",
            "lines": [],
            "raw": "",
            "error": f"Timeout après {timeout}s pour {cmd[0]} — aucun résultat partiel",
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "raw": "", "lines": []}


def _filter_subdomains(lines: list, domain: str) -> list:
    result = []
    for line in lines:
        if isinstance(line, str) and (line == domain or line.endswith(f".{domain}")):
            result.append(line)
    return result


def _tool_result(raw: dict, domain: str) -> dict:
    """
    Construit le résultat filtré d'un outil CLI (sous-domaines).

    Accepte timeout_partial : si l'outil a été interrompu mais a déjà produit
    des lignes, les sous-domaines valides sont extraits et retournés.
    """
    if raw["status"] not in ("success", "timeout_partial"):
        return {
            "status": raw["status"],
            "data": [],
            "error": raw.get("error"),
            "raw_output": raw.get("raw", ""),
        }
    subs = _filter_subdomains(raw.get("lines", []), domain)
    result = {
        "status": raw["status"],   # "success" ou "timeout_partial"
        "data": subs,
        "count": len(subs),
        "raw_output": raw.get("raw", ""),
    }
    if raw["status"] == "timeout_partial":
        result["warning"] = raw.get("error", "Résultats partiels — timeout atteint")
    return result


def _enrich(tool_name: str, result: dict) -> dict:
    """Injecte les métadonnées du registre dans un résultat d'outil."""
    meta = TOOLS_REGISTRY.get(tool_name, {})
    return {"meta": meta, **result}


# ===========================================================================
# Outils extraits pour l'exécution parallèle (phase 4)
# ===========================================================================
# Ces fonctions étaient auparavant du code inline dans pass_recon(), qui
# mutait directement `result` et `all_subs`. Les extraire en fonctions pures
# — elles reçoivent leurs entrées et RETOURNENT leur résultat sans toucher
# d'état partagé — est la condition pour pouvoir les exécuter dans des
# threads sans course de données. L'union des sous-domaines est ensuite faite
# par le thread principal, après la vague.
#
# Elles sont au niveau module (et non des closures) afin de rester
# patchables par les tests, comme les autres outils.

def _whois_tool(domain: str) -> dict:
    """WHOIS via la CLI système, parsé en champs structurés."""
    raw = _run_subprocess(['whois', domain], timeout=30)
    if raw["status"] == "success":
        raw_text = raw.get("raw", "")
        return {
            "status": "success",
            "data": _parse_whois(raw_text),
            "raw_output": raw_text,
        }
    return {
        "status": raw["status"], "data": {},
        "error": raw.get("error"), "raw_output": raw.get("raw", ""),
    }


def _dns_lookup_tool(domain: str) -> dict:
    """Résolution DNS via la CLI nslookup."""
    raw = _run_subprocess(['nslookup', domain], timeout=10)
    if raw["status"] == "success":
        return {
            "status": "success",
            "data": "\n".join(raw["lines"]),
            "raw_output": raw.get("raw", ""),
        }
    return {
        "status": raw["status"], "data": None,
        "error": raw.get("error"), "raw_output": raw.get("raw", ""),
    }


def _crtsh_tool(domain: str) -> dict:
    """Sous-domaines issus des journaux de transparence de certificats (crt.sh)."""
    try:
        api_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = _http.get(api_url, timeout=15)
        resp.raise_for_status()
        raw_json = resp.text
        subs: set = set()
        for entry in resp.json():
            for line in entry.get("name_value", "").split("\n"):
                clean = line.strip().lstrip("*.")
                if clean and (clean == domain or clean.endswith(f".{domain}")):
                    subs.add(clean)
        crt_list = sorted(subs)
        return {
            "status": "success",
            "data": {"subdomains": crt_list, "count": len(crt_list)},
            "raw_output": raw_json[:8000],
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {"subdomains": [], "count": 0},
                "error": "crt.sh timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {"subdomains": [], "count": 0},
                "error": str(e), "raw_output": ""}


def _subfinder_tool(domain: str, cwd: str = None) -> dict:
    """Énumération passive de sous-domaines via subfinder."""
    raw = _run_subprocess(['subfinder', '-d', domain, '-silent'], timeout=90, cwd=cwd)
    tool_res = _tool_result(raw, domain)
    tool_res["data"] = {
        "subdomains": tool_res.pop("data"),
        "count": tool_res.pop("count", 0),
    }
    return tool_res


def _assetfinder_tool(domain: str, cwd: str = None) -> dict:
    """Énumération passive de sous-domaines via assetfinder."""
    raw = _run_subprocess(['assetfinder', '--subs-only', domain], timeout=120, cwd=cwd)
    tool_res = _tool_result(raw, domain)
    tool_res["data"] = {
        "subdomains": tool_res.pop("data"),
        "count": tool_res.pop("count", 0),
    }
    return tool_res


def _github_subdomains_tool(domain: str, cwd: str = None) -> dict:
    """
    Sous-domaines mentionnés dans le code public GitHub.

    Sans GITHUB_TOKEN l'outil est ignoré proprement (status "skipped") plutôt
    que de produire une erreur : la clé est optionnelle par conception.
    """
    github_token = os.getenv('GITHUB_TOKEN', '').strip()
    if not github_token:
        return {
            "status": "skipped",
            "data": {"subdomains": [], "count": 0},
            "error": "GITHUB_TOKEN non configuré — ajoutez GITHUB_TOKEN=<votre_token> dans api/.env",
            "raw_output": "",
        }
    # Le token passe par l'environnement du sous-processus, PAS par argv :
    # les arguments sont lisibles par tout processus du conteneur (`ps auxww`,
    # /proc/*/cmdline) et, si _run_subprocess sérialisait la commande dans un
    # message d'erreur, le secret finirait persisté dans scan_results en base.
    raw = _run_subprocess(
        ['github-subdomains', '-d', domain],
        timeout=60, cwd=cwd,
        env_extra={'GITHUB_TOKEN': github_token},
    )
    tool_res = _tool_result(raw, domain)
    tool_res["data"] = {
        "subdomains": tool_res.pop("data"),
        "count": tool_res.pop("count", 0),
    }
    return tool_res


def _amass_tool(domain: str, cwd: str = None) -> dict:
    """
    Énumération passive via amass — le plus exhaustif, et le plus lent.

    Les résultats partiels d'un timeout sont valides et conservés.
    """
    raw = _run_subprocess(
        [
            'amass', 'enum', '-passive',
            '-d', domain,
            '-timeout', '2',     # 2 minutes internes amass
            '-nocolor',          # pas d'escape ANSI dans stdout
        ],
        timeout=180,            # subprocess kill à 180s (> timeout interne amass)
        cwd=cwd,
    )
    tool_res = _tool_result(raw, domain)
    subs_list = tool_res.pop("data")
    count = tool_res.pop("count", 0)
    tool_res["data"] = {
        "subdomains": subs_list,
        "count": count,
        "performance_note": (
            "Amass est l'outil le plus exhaustif mais aussi le plus lent. "
            "Un timeout_partial signifie que des résultats ont été récupérés "
            "avant l'expiration — ils sont valides et intégrés à all_subdomains."
        ),
    }
    return tool_res


def _http_headers_tool(subdomains) -> dict:
    """En-têtes HTTP des premiers sous-domaines découverts (max 10)."""
    headers_result: dict = {}
    targets = sorted(subdomains)[:10]
    for sub in targets:
        hit = False
        for scheme in ("https", "http"):
            try:
                resp = _http.head(
                    f"{scheme}://{sub}", timeout=5, allow_redirects=True,
                    headers={"User-Agent": "OSINT-Recon/1.1 (security research)"},
                )
                headers_result[sub] = {
                    "status": "success",
                    "scheme": scheme,
                    "http_status": resp.status_code,
                    "data": dict(resp.headers),
                }
                hit = True
                break
            except _requests.exceptions.SSLError:
                continue
            except _requests.exceptions.ConnectionError:
                continue
            except _requests.exceptions.Timeout:
                headers_result[sub] = {"status": "timeout", "data": {}}
                hit = True
                break
            except Exception as e:
                headers_result[sub] = {"status": "error", "data": {}, "error": str(e)}
                hit = True
                break
        if not hit:
            headers_result[sub] = {"status": "unreachable", "data": {}}

    return {
        "status": "success",
        "data": headers_result,
        "raw_output": "\n\n".join(
            f"=== {sub} ===\n" + "\n".join(f"{k}: {v}" for k, v in info.get("data", {}).items())
            for sub, info in headers_result.items()
        ),
    }


def _extract_subdomains(tool_result: dict) -> list:
    """
    Extrait la liste de sous-domaines d'un résultat d'outil de découverte.

    Tolère les résultats d'échec (l'exécuteur parallèle renvoie alors
    data={}), afin qu'un outil planté n'interrompe pas l'union.
    """
    data = (tool_result or {}).get("data")
    if not isinstance(data, dict):
        return []
    subs = data.get("subdomains")
    return subs if isinstance(subs, list) else []


# ===========================================================================
# Helpers — nouveaux outils passifs
# ===========================================================================

def _parse_whois(raw_text: str) -> dict:
    """
    Parse une sortie WHOIS brute en champs structurés.
    Gère les formats WHOIS classiques (Registrar, Creation Date, etc.).
    """
    fields = {}

    # Patterns avec plusieurs variantes de clé (insensible à la casse)
    PATTERNS = [
        ("registrar",         r'(?:Registrar|Registrar Name)\s*:\s*(.+)'),
        ("creation_date",     r'(?:Creation Date|Created Date|Created On|Domain Registration Date|Registered on)\s*:\s*(.+)'),
        ("updated_date",      r'(?:Updated Date|Last Updated|Modified|Last Modified|Domain Last Updated Date)\s*:\s*(.+)'),
        ("expiration_date",   r'(?:Expiry Date|Expiration Date|Registry Expiry Date|Domain Expiration Date|Expire Date|Expires On)\s*:\s*(.+)'),
        ("status",            r'Domain Status\s*:\s*(.+)'),
        ("dnssec",            r'DNSSEC\s*:\s*(.+)'),
        ("registrant_org",    r'Registrant Organization\s*:\s*(.+)'),
        ("registrant_name",   r'Registrant Name\s*:\s*(.+)'),
        ("registrant_email",  r'Registrant Email\s*:\s*(.+)'),
        ("registrant_country",r'Registrant Country\s*:\s*(.+)'),
        ("admin_email",       r'Admin Email\s*:\s*(.+)'),
        ("registrar_url",     r'Registrar URL\s*:\s*(.+)'),
        ("registrar_iana",    r'Registrar IANA ID\s*:\s*(.+)'),
    ]

    for key, pattern in PATTERNS:
        matches = re.findall(pattern, raw_text, re.IGNORECASE)
        if matches:
            unique = list(dict.fromkeys(m.strip() for m in matches if m.strip()))
            fields[key] = unique[0] if len(unique) == 1 else unique

    # Name Servers — peut en avoir plusieurs
    ns_matches = re.findall(r'Name Server\s*:\s*(.+)', raw_text, re.IGNORECASE)
    if ns_matches:
        fields["name_servers"] = sorted(set(ns.strip().lower() for ns in ns_matches if ns.strip()))

    # Privacy shield check
    privacy_kw = ["whoisguard", "domains by proxy", "privacy", "redacted", "protected", "withheld"]
    raw_lower = raw_text.lower()
    fields["privacy_protected"] = any(kw in raw_lower for kw in privacy_kw)

    # Registrant info summary
    registrant_parts = []
    for f in ("registrant_name", "registrant_org"):
        if f in fields:
            registrant_parts.append(fields[f])
    fields["registrant"] = " / ".join(registrant_parts) if registrant_parts else None

    return fields


def _ip_info(domain: str) -> dict:
    """Géolocalisation + ASN pour chaque IP résolue."""
    ips = _resolve_ips(domain)[:5]
    if not ips:
        return {"status": "error", "data": [], "error": f"Résolution DNS échouée pour {domain}", "raw_output": ""}

    results = []
    raw_parts = []
    for ip in ips:
        try:
            resp = _http.get(f"https://ipinfo.io/{ip}/json", timeout=8)
            raw_parts.append(f"=== IP: {ip} ===\n{resp.text}")
            if resp.status_code == 200:
                d = resp.json()
                results.append({
                    "ip": ip,
                    "hostname": d.get("hostname"),
                    "city": d.get("city"),
                    "region": d.get("region"),
                    "country": d.get("country"),
                    "loc": d.get("loc"),
                    "org": d.get("org"),
                    "timezone": d.get("timezone"),
                    "postal": d.get("postal"),
                })
            else:
                results.append({"ip": ip, "error": f"HTTP {resp.status_code}"})
        except Exception as e:
            raw_parts.append(f"=== IP: {ip} ===\nERROR: {e}")
            results.append({"ip": ip, "error": str(e)})

    return {
        "status": "success",
        "data": {"ips": results, "count": len(results)},
        "raw_output": "\n\n".join(raw_parts),
    }


def _dns_records(domain: str) -> dict:
    """Énumère tous les enregistrements DNS : A, AAAA, MX, NS, TXT, SOA, CAA, CNAME."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"]
    results = {}
    raw_parts = []

    for rtype in record_types:
        try:
            answers = _resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            results[rtype] = records
            raw_parts.append(f";; {rtype} records\n" + "\n".join(
                f"{domain}. IN {rtype} {r}" for r in records
            ))
        except (_dns_resolver.NoAnswer, _dns_resolver.NXDOMAIN,
                _dns_resolver.NoNameservers, _dns_resolver.LifetimeTimeout):
            results[rtype] = []
        except Exception:
            results[rtype] = []

    return {
        "status": "success",
        "data": results,
        "raw_output": "\n\n".join(raw_parts) if raw_parts else "(aucun enregistrement trouvé)",
    }


def _ssl_info(domain: str) -> dict:
    """Certificat SSL : émetteur, SANs, expiration, protocole négocié."""
    try:
        # Pré-résolution via DNS public pour contourner le résolveur Docker interne
        ips = _resolve_ips(domain)
        connect_host = ips[0] if ips else domain
        ctx = ssl.create_default_context()
        with socket.create_connection((connect_host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        days_left = None
        try:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days
        except Exception:
            pass

        data = {
            "subject": subject,
            "issuer": issuer,
            "san": sans,
            "san_count": len(sans),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "expired": days_left is not None and days_left < 0,
            "expiry_warning": days_left is not None and 0 <= days_left < 30,
            "tls_version": version,
            "cipher": {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2],
            } if cipher else None,
            "serial_number": cert.get("serialNumber"),
            "cert_version": cert.get("version"),
        }

        raw_output = (
            f"Subject        : {subject}\n"
            f"Issuer         : {issuer}\n"
            f"SANs ({len(sans)})    : {', '.join(sans[:20])}\n"
            f"Not Before     : {not_before}\n"
            f"Not After      : {not_after}\n"
            f"Days Until Exp : {days_left}\n"
            f"TLS Version    : {version}\n"
            f"Cipher         : {cipher[0] if cipher else 'N/A'} ({cipher[2] if cipher else '?'} bits)\n"
            f"Serial         : {cert.get('serialNumber')}\n"
        )

        return {"status": "success", "data": data, "raw_output": raw_output}

    except ssl.SSLCertVerificationError as e:
        return {"status": "error", "data": {}, "error": f"Vérification SSL échouée : {e}", "raw_output": str(e)}
    except (socket.timeout, TimeoutError):
        return {"status": "timeout", "data": {}, "error": "Timeout port 443", "raw_output": ""}
    except ConnectionRefusedError:
        return {"status": "error", "data": {}, "error": "Port 443 refusé", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": str(e)}


def _email_config(domain: str) -> dict:
    """MX, SPF, DMARC, BIMI, MTA-STS + score de sécurité email."""
    result = {}
    raw_parts = []

    # MX
    try:
        mx = _resolver.resolve(domain, "MX")
        result["mx"] = sorted([str(r) for r in mx])
        raw_parts.append(f";; MX\n" + "\n".join(f"{domain}. IN MX {r}" for r in result["mx"]))
    except Exception:
        result["mx"] = []

    # SPF
    try:
        txts = _resolver.resolve(domain, "TXT")
        spf_records = [str(r).strip('"') for r in txts if "v=spf1" in str(r)]
        result["spf"] = spf_records[0] if spf_records else None
        result["spf_status"] = "found" if spf_records else "not_found"
        if spf_records:
            raw_parts.append(f";; SPF\n{domain}. IN TXT \"{spf_records[0]}\"")
    except Exception:
        result["spf"] = None
        result["spf_status"] = "error"

    # DMARC
    try:
        dmarc = _resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r).strip('"') for r in dmarc if "v=DMARC1" in str(r)]
        result["dmarc"] = dmarc_records[0] if dmarc_records else None
        result["dmarc_status"] = "found" if dmarc_records else "not_found"
        if dmarc_records:
            policy_match = re.search(r'p=(\w+)', dmarc_records[0])
            result["dmarc_policy"] = policy_match.group(1) if policy_match else None
            raw_parts.append(f";; DMARC\n_dmarc.{domain}. IN TXT \"{dmarc_records[0]}\"")
    except Exception:
        result["dmarc"] = None
        result["dmarc_status"] = "not_found"
        result["dmarc_policy"] = None

    # BIMI
    try:
        bimi = _resolver.resolve(f"default._bimi.{domain}", "TXT")
        bimi_records = [str(r).strip('"') for r in bimi]
        result["bimi"] = bimi_records[0] if bimi_records else None
        result["bimi_status"] = "found" if bimi_records else "not_found"
        if bimi_records:
            raw_parts.append(f";; BIMI\ndefault._bimi.{domain}. IN TXT \"{bimi_records[0]}\"")
    except Exception:
        result["bimi"] = None
        result["bimi_status"] = "not_found"

    # MTA-STS
    try:
        mta = _resolver.resolve(f"_mta-sts.{domain}", "TXT")
        mta_records = [str(r).strip('"') for r in mta]
        result["mta_sts"] = mta_records[0] if mta_records else None
        result["mta_sts_status"] = "found" if mta_records else "not_found"
        if mta_records:
            raw_parts.append(f";; MTA-STS\n_mta-sts.{domain}. IN TXT \"{mta_records[0]}\"")
    except Exception:
        result["mta_sts"] = None
        result["mta_sts_status"] = "not_found"

    # Score
    score = 0
    if result["mx"]:
        score += 1
    if result["spf_status"] == "found":
        score += 2
    if result["dmarc_status"] == "found":
        score += 2
        if result.get("dmarc_policy") in ("reject", "quarantine"):
            score += 1
    result["security_score"] = f"{score}/6"
    result["security_level"] = (
        "Excellent" if score >= 5 else
        "Bon"       if score >= 3 else
        "Faible"    if score >= 1 else
        "Critique"
    )

    return {
        "status": "success",
        "data": result,
        "raw_output": "\n\n".join(raw_parts) if raw_parts else "(aucun enregistrement email trouvé)",
    }


def _tech_stack(domain: str) -> dict:
    """Fingerprint technologique via en-têtes HTTP et contenu HTML."""
    tech = {
        "server": None,
        "powered_by": None,
        "cms": [],
        "javascript_frameworks": [],
        "cdn": [],
        "analytics": [],
        "social_tags": {},
        "cookies_detected": [],
        "interesting_headers": {},
    }

    CDN_SIGNATURES = {
        "cf-ray": "Cloudflare", "x-fastly-request-id": "Fastly",
        "x-amz-cf-id": "AWS CloudFront", "x-azure-ref": "Azure CDN",
        "x-akamai-request-id": "Akamai", "x-served-by": "Fastly/Varnish",
    }

    for scheme in ("https", "http"):
        try:
            resp = _http.get(
                f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            tech["server"] = headers_lower.get("server")
            tech["powered_by"] = headers_lower.get("x-powered-by")

            for h, name in CDN_SIGNATURES.items():
                if h in headers_lower:
                    tech["cdn"].append(name)

            for h in ("x-generator", "x-drupal-cache", "x-pingback", "x-wp-total"):
                if h in headers_lower:
                    tech["interesting_headers"][h] = headers_lower[h]

            tech["cookies_detected"] = list(resp.cookies.keys())

            content_type = headers_lower.get("content-type", "")
            html_excerpt = ""
            if "text/html" in content_type:
                html = resp.text[:60000]
                html_excerpt = html[:3000]

                for cms, patterns in {
                    "WordPress": ["wp-content", "wp-includes"],
                    "Drupal": ["/sites/default/files/", "Drupal.settings"],
                    "Joomla": ["/components/com_"], "Magento": ["mage/cookies.js"],
                    "Shopify": ["cdn.shopify.com"], "Ghost": ["content/themes/"],
                    "Wix": ["_wix_", "wixstatic.com"],
                    "Squarespace": ["squarespace.com"],
                    "PrestaShop": ["prestashop"], "OpenCart": ["catalog/view/theme"],
                }.items():
                    if any(p in html for p in patterns):
                        tech["cms"].append(cms)

                for fw, patterns in {
                    "React": ["data-reactroot", "__REACT"],
                    "Vue.js": ["__VUE__", "data-v-"],
                    "Angular": ["ng-version="],
                    "jQuery": ["jquery.min.js", "jquery-"],
                    "Next.js": ["__NEXT_DATA__"],
                    "Nuxt.js": ["__NUXT__"],
                    "Svelte": ["__svelte"],
                }.items():
                    if any(p in html for p in patterns):
                        tech["javascript_frameworks"].append(fw)

                for tool, patterns in {
                    "Google Analytics": ["gtag/js", "UA-"],
                    "Matomo": ["matomo.js"], "Hotjar": ["hotjar.com/c/hotjar"],
                    "Segment": ["cdn.segment.com"],
                    "Plausible": ["plausible.io/js"],
                }.items():
                    if any(p in html for p in patterns):
                        tech["analytics"].append(tool)

                og_tags = {}
                for m in re.finditer(
                    r'<meta\s+(?:property|name)=["\']([^"\']+)["\']\s+content=["\']([^"\']*)["\']',
                    html, re.IGNORECASE
                ):
                    prop, content = m.group(1), m.group(2)
                    if prop.startswith("og:") or prop.startswith("twitter:"):
                        og_tags[prop] = content
                tech["social_tags"] = og_tags

            for key in ("cdn", "cms", "javascript_frameworks", "analytics"):
                tech[key] = list(set(tech[key]))

            raw_output = (
                f"=== HTTP Response Headers ===\n"
                + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                + f"\n\n=== HTML Excerpt (first 3000 chars) ===\n{html_excerpt}"
            )

            return {"status": "success", "data": tech, "raw_output": raw_output}

        except _requests.exceptions.SSLError:
            continue
        except Exception as e:
            return {"status": "error", "data": tech, "error": str(e), "raw_output": str(e)}

    return {"status": "unreachable", "data": tech, "error": "Domaine inaccessible", "raw_output": ""}


def _security_headers(domain: str) -> dict:
    """Analyse 9 en-têtes de sécurité HTTP avec grade A+…F."""
    HEADERS_CONFIG = {
        "strict-transport-security": {
            "name": "HSTS", "weight": 2,
            "check": lambda v: "max-age" in v.lower(),
            "recommendation": "Ajouter max-age=31536000; includeSubDomains; preload",
        },
        "content-security-policy": {
            "name": "CSP", "weight": 2,
            "check": lambda v: bool(v),
            "recommendation": "Définir une politique CSP stricte",
        },
        "x-frame-options": {
            "name": "X-Frame-Options", "weight": 2,
            "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
            "recommendation": "Définir à DENY ou SAMEORIGIN",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options", "weight": 2,
            "check": lambda v: v.lower() == "nosniff",
            "recommendation": "Définir à nosniff",
        },
        "referrer-policy": {
            "name": "Referrer-Policy", "weight": 1,
            "check": lambda v: bool(v),
            "recommendation": "Définir à strict-origin-when-cross-origin",
        },
        "permissions-policy": {
            "name": "Permissions-Policy", "weight": 1,
            "check": lambda v: bool(v),
            "recommendation": "Restreindre les permissions des fonctionnalités du navigateur",
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection", "weight": 1,
            "check": lambda v: v.startswith("1"),
            "recommendation": "Définir à 1; mode=block (préférer CSP)",
        },
        "cross-origin-opener-policy": {
            "name": "COOP", "weight": 1,
            "check": lambda v: bool(v),
            "recommendation": "Définir à same-origin",
        },
        "cross-origin-resource-policy": {
            "name": "CORP", "weight": 1,
            "check": lambda v: bool(v),
            "recommendation": "Définir à same-origin ou same-site",
        },
    }

    for scheme in ("https", "http"):
        try:
            resp = _http.head(
                f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                headers={"User-Agent": "OSINT-Recon/1.1"},
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            raw_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

            analysis = {}
            score = 0
            max_score = sum(c["weight"] for c in HEADERS_CONFIG.values())

            for key, config in HEADERS_CONFIG.items():
                if key in headers_lower:
                    value = headers_lower[key]
                    valid = config["check"](value)
                    pts = config["weight"] if valid else 0
                    score += pts
                    analysis[key] = {
                        "name": config["name"],
                        "present": True,
                        "value": value,
                        "valid": valid,
                        "score": pts,
                        "recommendation": None if valid else config["recommendation"],
                    }
                else:
                    analysis[key] = {
                        "name": config["name"],
                        "present": False,
                        "value": None,
                        "valid": False,
                        "score": 0,
                        "recommendation": config["recommendation"],
                    }

            pct = score / max_score
            grade = (
                "A+" if score == max_score else
                "A"  if pct >= 0.90 else
                "B"  if pct >= 0.75 else
                "C"  if pct >= 0.50 else
                "D"  if pct >= 0.25 else "F"
            )

            missing = [v["name"] for v in analysis.values() if not v["present"]]

            return {
                "status": "success",
                "data": {
                    "grade": grade,
                    "score": score,
                    "max_score": max_score,
                    "missing_headers": missing,
                    "headers": analysis,
                },
                "raw_output": f"HTTP {resp.status_code} {scheme.upper()}\n\n{raw_headers}",
            }
        except _requests.exceptions.SSLError:
            continue
        except Exception as e:
            return {"status": "error", "data": {}, "error": str(e), "raw_output": str(e)}

    return {"status": "unreachable", "data": {}, "error": "Domaine inaccessible", "raw_output": ""}


def _robots_txt(domain: str) -> dict:
    """Récupère et analyse robots.txt — extrait les chemins sensibles."""
    SENSITIVE_KW = [
        "admin", "api", "login", "auth", "backup", "config", "private",
        "secret", "test", "dev", "staging", "internal", "dashboard",
        "manage", "console", "debug", "upload", "tmp", "hidden",
    ]

    for scheme in ("https", "http"):
        try:
            resp = _http.get(
                f"{scheme}://{domain}/robots.txt", timeout=10,
                headers={"User-Agent": "OSINT-Recon/1.1"},
            )
            if resp.status_code == 200:
                content = resp.text
                disallowed, sitemaps, user_agents = [], [], []
                current_agent = None

                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith("user-agent:"):
                        current_agent = line.split(":", 1)[1].strip()
                        user_agents.append(current_agent)
                    elif line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append({"agent": current_agent, "path": path})
                    elif line.lower().startswith("sitemap:"):
                        url = line.split(":", 1)[1].strip()
                        if url:
                            sitemaps.append(url)

                interesting = [
                    d for d in disallowed
                    if any(kw in d["path"].lower() for kw in SENSITIVE_KW)
                ]

                return {
                    "status": "success",
                    "data": {
                        "raw": content[:5000],
                        "disallowed_paths": disallowed[:50],
                        "sitemaps": sitemaps,
                        "user_agents": list(set(user_agents)),
                        "interesting_paths": interesting,
                        "interesting_count": len(interesting),
                        "total_disallowed": len(disallowed),
                    },
                    "raw_output": content,
                }
            else:
                return {
                    "status": "not_found", "data": {},
                    "error": f"HTTP {resp.status_code}",
                    "raw_output": f"HTTP {resp.status_code}",
                }
        except _requests.exceptions.SSLError:
            continue
        except Exception as e:
            return {"status": "error", "data": {}, "error": str(e), "raw_output": str(e)}

    return {"status": "unreachable", "data": {}, "error": "Domaine inaccessible", "raw_output": ""}


def _sitemap(domain: str) -> dict:
    """Récupère sitemap.xml et extrait les URLs référencées."""
    for url in [
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/sitemap_index.xml",
        f"http://{domain}/sitemap.xml",
    ]:
        try:
            resp = _http.get(url, timeout=10, headers={"User-Agent": "OSINT-Recon/1.1"})
            ct = resp.headers.get("content-type", "")
            if resp.status_code == 200 and (
                "xml" in ct or resp.text.strip().startswith("<?xml")
            ):
                raw_xml = resp.text
                try:
                    root = ET.fromstring(raw_xml)
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    sitemaps = root.findall("sm:sitemap/sm:loc", ns)
                    urls = root.findall("sm:url/sm:loc", ns)
                    return {
                        "status": "success",
                        "data": {
                            "url": url,
                            "type": "index" if sitemaps else "sitemap",
                            "sitemaps": [s.text for s in sitemaps[:20]],
                            "urls": [u.text for u in urls[:50]],
                            "url_count": len(urls),
                            "sitemap_count": len(sitemaps),
                        },
                        "raw_output": raw_xml[:10000],
                    }
                except ET.ParseError:
                    continue
        except _requests.exceptions.SSLError:
            continue
        except Exception:
            continue

    return {"status": "not_found", "data": {}, "error": "Aucun sitemap trouvé", "raw_output": ""}


def _redirect_chain(domain: str) -> dict:
    """Suit la chaîne de redirections HTTP."""
    for scheme in ("https", "http"):
        try:
            resp = _http.get(
                f"{scheme}://{domain}", timeout=15, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            chain = [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "location": r.headers.get("Location"),
                }
                for r in resp.history
            ]
            chain.append({
                "url": resp.url,
                "status_code": resp.status_code,
                "location": None,
                "final": True,
            })

            raw_lines = []
            for i, hop in enumerate(chain):
                raw_lines.append(
                    f"[{i+1}] {hop['status_code']} {hop['url']}"
                    + (f" → {hop['location']}" if hop.get("location") else "")
                )

            return {
                "status": "success",
                "data": {
                    "chain": chain,
                    "hops": len(chain),
                    "final_url": resp.url,
                    "final_status": resp.status_code,
                    "has_redirects": len(resp.history) > 0,
                },
                "raw_output": "\n".join(raw_lines),
            }
        except _requests.exceptions.SSLError:
            continue
        except Exception as e:
            return {"status": "error", "data": {}, "error": str(e), "raw_output": str(e)}

    return {"status": "unreachable", "data": {}, "error": "Domaine inaccessible", "raw_output": ""}


def _security_txt(domain: str) -> dict:
    """Vérifie la présence du fichier security.txt (RFC 9116)."""
    for url in [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
        f"http://{domain}/.well-known/security.txt",
    ]:
        try:
            resp = _http.get(url, timeout=10, headers={"User-Agent": "OSINT-Recon/1.1"})
            if resp.status_code == 200 and (
                "contact" in resp.text.lower() or "security" in resp.text.lower()
            ):
                content = resp.text
                parsed = {}
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        key, _, value = line.partition(":")
                        parsed[key.strip().lower()] = value.strip()

                return {
                    "status": "success",
                    "data": {
                        "url": url,
                        "contact": parsed.get("contact"),
                        "expires": parsed.get("expires"),
                        "encryption": parsed.get("encryption"),
                        "policy": parsed.get("policy"),
                        "acknowledgments": parsed.get("acknowledgments"),
                        "preferred_languages": parsed.get("preferred-languages"),
                        "hiring": parsed.get("hiring"),
                    },
                    "raw_output": content,
                }
        except Exception:
            continue

    return {
        "status": "not_found", "data": {},
        "error": "Aucun security.txt trouvé (/.well-known/security.txt et /security.txt testés)",
        "raw_output": "",
    }


def _dnssec(domain: str) -> dict:
    """Vérifie DNSSEC via RRSIG, DS et DNSKEY."""
    raw_parts = []

    raw_a = _run_subprocess(["dig", "+dnssec", "+short", domain, "A"], timeout=10)
    raw_parts.append(f";; dig +dnssec +short {domain} A\n{raw_a.get('raw', '')}")
    has_rrsig = any("RRSIG" in line for line in raw_a.get("lines", []))

    raw_ds = _run_subprocess(["dig", "+short", domain, "DS"], timeout=10)
    raw_parts.append(f";; dig +short {domain} DS\n{raw_ds.get('raw', '')}")
    has_ds = raw_ds["status"] == "success" and bool(raw_ds.get("lines"))

    raw_dnskey = _run_subprocess(["dig", "+short", domain, "DNSKEY"], timeout=10)
    raw_parts.append(f";; dig +short {domain} DNSKEY\n{raw_dnskey.get('raw', '')}")
    has_dnskey = raw_dnskey["status"] == "success" and bool(raw_dnskey.get("lines"))

    if raw_a["status"] not in ("success", "timeout"):
        return {
            "status": raw_a["status"], "data": {},
            "error": raw_a.get("error"), "raw_output": "\n\n".join(raw_parts),
        }

    return {
        "status": "success",
        "data": {
            "enabled": has_rrsig or has_ds or has_dnskey,
            "has_rrsig": has_rrsig,
            "has_ds": has_ds,
            "has_dnskey": has_dnskey,
            "dnskey_records": raw_dnskey.get("lines", [])[:3] if has_dnskey else [],
            "security_note": (
                "DNSSEC activé — réponses DNS signées cryptographiquement"
                if has_rrsig or has_ds or has_dnskey
                else "DNSSEC non activé — vulnérable au DNS cache poisoning"
            ),
        },
        "raw_output": "\n\n".join(raw_parts),
    }


def _waf_detection(domain: str) -> dict:
    """Détecte WAF/CDN via en-têtes HTTP et cookies."""
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "server": ["cloudflare"], "cookies": ["__cfduid", "cf_clearance"],
        },
        "AWS WAF / CloudFront": {
            "headers": ["x-amz-cf-id", "x-amzn-requestid"],
            "server": ["amazons3", "cloudfront"], "cookies": [],
        },
        "Akamai": {
            "headers": ["x-akamai-request-id", "akamai-origin-hop"],
            "server": ["akamaighost"], "cookies": ["ak_bmsc", "bm_sv"],
        },
        "Fastly": {
            "headers": ["x-fastly-request-id", "x-served-by"],
            "server": ["varnish"], "cookies": [],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": ["sucuri"], "cookies": [],
        },
        "Imperva / Incapsula": {
            "headers": ["x-iinfo"],
            "server": ["incapsula"], "cookies": ["incap_ses", "visid_incap"],
        },
        "F5 BIG-IP": {
            "headers": ["x-wa-info"],
            "server": ["big-ip"], "cookies": ["BIGipServer"],
        },
        "Azure Front Door": {
            "headers": ["x-azure-ref", "x-fd-healthprobe"],
            "server": [], "cookies": [],
        },
    }

    for scheme in ("https", "http"):
        try:
            resp = _http.get(
                f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            server = headers_lower.get("server", "")
            cookies_str = " ".join(resp.cookies.keys()).lower()
            raw_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

            detected = []
            for waf_name, sigs in WAF_SIGNATURES.items():
                indicators = []
                for h in sigs["headers"]:
                    if h in headers_lower:
                        indicators.append(f"header:{h}={headers_lower[h][:60]}")
                for s in sigs["server"]:
                    if s in server:
                        indicators.append(f"server:{server}")
                for c in sigs["cookies"]:
                    if c.lower() in cookies_str:
                        indicators.append(f"cookie:{c}")
                if indicators:
                    detected.append({
                        "name": waf_name,
                        "confidence": "high" if len(indicators) >= 2 else "medium",
                        "indicators": indicators,
                    })

            return {
                "status": "success",
                "data": {
                    "protected": len(detected) > 0,
                    "detected": detected,
                    "server": resp.headers.get("Server"),
                    "via": resp.headers.get("Via"),
                    "x_powered_by": resp.headers.get("X-Powered-By"),
                },
                "raw_output": f"HTTP {resp.status_code} {scheme.upper()}\n\n{raw_headers}",
            }
        except _requests.exceptions.SSLError:
            continue
        except Exception as e:
            return {"status": "error", "data": {}, "error": str(e), "raw_output": str(e)}

    return {"status": "unreachable", "data": {}, "error": "Domaine inaccessible", "raw_output": ""}


# Nombre maximal d'URLs historiques distinctes remontées par l'API CDX
_WAYBACK_URL_LIMIT = 500


def _archive_history(domain: str) -> dict:
    """Historique Wayback Machine via CDX API (snapshots + URLs distinctes archivées)."""
    raw_parts = []
    try:
        url_first = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}&output=json&fl=timestamp,statuscode&limit=1"
        )
        resp_first = _http.get(url_first, timeout=15)
        raw_parts.append(f"=== First snapshot query ===\n{resp_first.text[:500]}")
        resp_first.raise_for_status()
        data_first = resp_first.json()

        first_snapshot = None
        if len(data_first) > 1:
            ts = data_first[1][0]
            first_snapshot = {
                "timestamp": ts,
                "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                "status": data_first[1][1],
            }

        # ⚠️ `reverse=true&limit=1` ne renvoie PAS le snapshot le plus récent —
        # vérifié en conditions réelles (idachallenge.bj, example.com) : la
        # réponse est identique à celle de `limit=1` seul (le premier
        # snapshot), le paramètre `reverse` étant sans effet sur un index CDX
        # trié en avant sans passer par une lecture complète. Le raccourci
        # documenté par l'API CDX pour lire la fin de l'index sans scan
        # complet est un **`limit` négatif** (`limit=-1`) — confirmé en
        # conditions réelles : renvoie bien la date la plus récente,
        # distincte du premier snapshot.
        url_last = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}&output=json&fl=timestamp,statuscode&limit=-1"
        )
        resp_last = _http.get(url_last, timeout=15)
        raw_parts.append(f"=== Last snapshot query ===\n{resp_last.text[:500]}")
        resp_last.raise_for_status()
        data_last = resp_last.json()

        last_snapshot = None
        if len(data_last) > 1:
            ts = data_last[1][0]
            last_snapshot = {
                "timestamp": ts,
                "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                "status": data_last[1][1],
            }

        total_pages = None
        try:
            # ⚠️ `showNumPages=true` combiné à `output=json`/`fl=` ne renvoie
            # PAS un nombre de pages — vérifié en conditions réelles : la
            # réponse devient alors des données CDX littérales
            # (`[["timestamp"],[null]]`), qu'aucune des branches de parsing
            # ci-dessous ne reconnaît (dégradation silencieuse vers `None`).
            # Seule une requête `showNumPages=true` ISOLÉE (sans `output`/
            # `fl`) renvoie bien un entier brut, confirmé sur deux domaines.
            url_count = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url={domain}&showNumPages=true"
            )
            rc = _http.get(url_count, timeout=10)
            txt = rc.text.strip()
            # L'API retourne soit un entier brut, soit un JSON comme {"pages": N}
            if txt.lstrip('-').isdigit():
                total_pages = int(txt)
            elif txt.startswith('{'):
                import json as _j
                total_pages = _j.loads(txt).get('pages')
            else:
                # Extraire le premier nombre trouvé dans la réponse
                import re as _re2
                m = _re2.search(r'\d+', txt)
                if m:
                    total_pages = int(m.group())
        except Exception:
            pass

        # Calcul ancienneté
        age_note = None
        if first_snapshot:
            try:
                first_dt = datetime.strptime(first_snapshot["date"], "%Y-%m-%d")
                days_old = (datetime.utcnow() - first_dt).days
                age_note = f"Domaine actif depuis ~{days_old} jours ({first_snapshot['date']})"
            except Exception:
                pass

        # URLs historiques distinctes (collapse=urlkey → une entrée par URL unique)
        historical_urls = []
        urls_truncated = False
        try:
            url_list = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=json&fl=original"
                f"&collapse=urlkey&limit={_WAYBACK_URL_LIMIT}"
            )
            resp_urls = _http.get(url_list, timeout=20)
            raw_parts.append(f"=== Historical URLs query ===\n{resp_urls.text[:2000]}")
            if resp_urls.status_code == 200 and resp_urls.text.strip():
                rows = resp_urls.json()
                # La 1re ligne est l'en-tête CDX (["original"])
                seen = set()
                for row in rows[1:]:
                    u = row[0] if isinstance(row, list) and row else None
                    if isinstance(u, str) and u and u not in seen:
                        seen.add(u)
                        historical_urls.append(u)
                urls_truncated = len(rows) - 1 >= _WAYBACK_URL_LIMIT
        except Exception as url_err:
            raw_parts.append(f"=== Historical URLs query ===\nERROR: {url_err}")

        return {
            "status": "success",
            "data": {
                "first_snapshot": first_snapshot,
                "last_snapshot": last_snapshot,
                "total_pages_index": total_pages,
                "age_note": age_note,
                "wayback_url": f"https://web.archive.org/web/*/{domain}",
                "historical_urls": historical_urls,
                "historical_urls_count": len(historical_urls),
                "historical_urls_truncated": urls_truncated,
            },
            "raw_output": "\n\n".join(raw_parts),
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "Wayback Machine timeout", "raw_output": "\n\n".join(raw_parts)}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": "\n\n".join(raw_parts)}


def _tls_config(domain: str) -> dict:
    """Protocoles TLS et suites cryptographiques via sslscan (fallback Python ssl)."""
    raw = _run_subprocess(["sslscan", "--no-colour", domain], timeout=60)

    if raw["status"] == "not_installed":
        protocols_support = {}
        PROTO_MAP = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        raw_lines = []
        # Pré-résolution DNS via résolveur public
        _tls_ips = _resolve_ips(domain)
        _tls_connect = _tls_ips[0] if _tls_ips else domain
        for proto_name, proto_version in PROTO_MAP:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = proto_version
                ctx.maximum_version = proto_version
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((_tls_connect, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain):
                        protocols_support[proto_name] = True
                        raw_lines.append(f"[enabled]  {proto_name}")
            except Exception:
                protocols_support[proto_name] = False
                raw_lines.append(f"[disabled] {proto_name}")

        weak = [p for p, v in protocols_support.items() if v and p in ("TLSv1.0", "TLSv1.1")]
        return {
            "status": "success",
            "data": {
                "source": "python_ssl_fallback",
                "protocols": protocols_support,
                "cipher_suites": [],
                "weak_protocols": weak,
                "weak_ciphers": [],
                "security_note": (
                    f"ATTENTION : protocoles faibles actifs : {', '.join(weak)}" if weak
                    else "Protocoles TLS corrects"
                ),
            },
            "raw_output": "\n".join(raw_lines),
        }

    if raw["status"] != "success":
        return {"status": raw["status"], "data": {}, "error": raw.get("error"), "raw_output": raw.get("raw", "")}

    lines = raw["lines"]
    protocols = {}
    ciphers = []

    for line in lines:
        if any(p in line for p in ("TLSv", "SSLv")):
            if "enabled" in line.lower():
                protocols[line.split()[0]] = True
            elif "disabled" in line.lower():
                protocols[line.split()[0]] = False
        if "Accepted" in line or "Preferred" in line:
            parts = line.split()
            if len(parts) >= 4:
                ciphers.append({
                    "status": parts[0], "protocol": parts[1],
                    "bits": parts[2], "name": parts[3],
                })

    weak_protos = [p for p, v in protocols.items() if v and p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]
    weak_ciphers = [c for c in ciphers if any(kw in c["name"] for kw in ("RC4", "DES", "NULL", "EXPORT"))]

    return {
        "status": "success",
        "data": {
            "source": "sslscan",
            "protocols": protocols,
            "cipher_suites": ciphers[:30],
            "weak_protocols": weak_protos,
            "weak_ciphers": weak_ciphers,
            "security_note": (
                f"ATTENTION : configurations faibles détectées — protocoles: {weak_protos}, chiffrements: {[c['name'] for c in weak_ciphers]}"
                if weak_protos or weak_ciphers
                else "Configuration TLS correcte"
            ),
        },
        "raw_output": raw.get("raw", ""),
    }


# ===========================================================================
# Endpoint principal
# ===========================================================================

# ===========================================================================
# Helpers — nouveaux outils passifs (session 2)
# ===========================================================================

def _reverse_ip(domain: str) -> dict:
    """Trouve les domaines co-hébergés sur la même IP via HackerTarget."""
    try:
        ips = [ip for ip in _resolve_ips(domain) if ":" not in ip]  # IPv4 seulement
        if not ips:
            return {"status": "error", "data": {}, "error": "Aucune IPv4 résolue", "raw_output": ""}

        ip = ips[0]
        resp = _http.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=15,
        )
        raw = resp.text.strip()

        if resp.status_code != 200 or "error" in raw.lower():
            return {"status": "error", "data": {}, "error": raw[:200], "raw_output": raw}

        domains = [d.strip() for d in raw.splitlines() if d.strip()]
        count = len(domains)
        note = (
            "Serveur dédié — infrastructure propre à l'organisation" if count <= 2 else
            "Probable même organisation (plusieurs services)" if count <= 10 else
            "Hébergement partagé / mutualisé" if count <= 100 else
            "CDN ou hébergeur partagé massif"
        )

        return {
            "status": "success",
            "data": {"ip": ip, "domains": domains, "count": count, "note": note},
            "raw_output": raw,
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "HackerTarget timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


_ASN_PREFIX_CAP = 100  # évite un raw_output/data démesuré pour un gros ASN (ex: Cloudflare a 5000+ préfixes)


def _asn_info(domain: str) -> dict:
    """
    Récupère l'ASN et les préfixes IP de l'organisation via RIPEstat (RIPE NCC).

    Remplace bgpview.io (2026-07-29) : ce service est arrêté DÉFINITIVEMENT
    depuis le 26 novembre 2025 (le domaine bgpview.io lui-même redirige
    désormais vers bgp.tools comme alternative) — ce n'était pas une panne
    transitoire, `api.bgpview.io` ne résout plus du tout. RIPEstat est
    l'API officielle du RIPE NCC (Regional Internet Registry) : aucune clé
    requise, pas de limite de débit pour un usage ponctuel comme le nôtre
    (RIPE demande juste un paramètre `sourceapp` identifiant l'appelant, pas
    d'inscription en dessous de ~1000 requêtes/jour). Sources : RIPEstat Data
    API docs (stat.ripe.net/docs/02.data-api/), reconfirmé au 29/07/2026.
    """
    try:
        ips = [ip for ip in _resolve_ips(domain) if ":" not in ip]  # IPv4 seulement
        if not ips:
            return {"status": "error", "data": {}, "error": "Aucune IPv4 résolue", "raw_output": ""}

        ip = ips[0]
        raw_parts = []

        # Étape 1 — IP → ASN + organisation (RIPEstat aligne parfois sur le
        # bloc annoncé le moins spécifique englobant l'IP, cf. `data.resource`)
        resp_ip = _http.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": ip, "sourceapp": "recon-ia"}, timeout=10,
        )
        raw_parts.append(f"=== RIPEstat prefix-overview /{ip} ===\n{resp_ip.text[:1500]}")
        data_ip = resp_ip.json().get("data", {})

        asns = data_ip.get("asns") or []
        if not asns:
            return {
                "status": "error", "data": {},
                "error": "Aucun ASN annoncé trouvé pour cette IP (RIPEstat)",
                "raw_output": "\n\n".join(raw_parts),
            }

        asn = asns[0].get("asn")
        asn_holder = asns[0].get("holder", "")
        if not asn:
            return {"status": "error", "data": {}, "error": "ASN non trouvé", "raw_output": "\n\n".join(raw_parts)}

        # Étape 2 — ASN → tous les préfixes annoncés
        resp_asn = _http.get(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={"resource": f"AS{asn}", "sourceapp": "recon-ia"}, timeout=10,
        )
        raw_parts.append(f"=== RIPEstat announced-prefixes AS{asn} ===\n{resp_asn.text[:2500]}")
        prefixes_data = resp_asn.json().get("data", {}).get("prefixes", [])

        all_prefixes = [p.get("prefix") for p in prefixes_data if p.get("prefix")]
        ipv4 = [p for p in all_prefixes if ":" not in p]
        ipv6 = [p for p in all_prefixes if ":" in p]
        total = len(ipv4) + len(ipv6)
        truncated = total > _ASN_PREFIX_CAP

        return {
            "status": "success",
            "data": {
                "ip_queried": ip,
                "asn": f"AS{asn}",
                "asn_name": asn_holder,
                "ipv4_prefixes": ipv4[:_ASN_PREFIX_CAP],
                "ipv6_prefixes": ipv6[:max(0, _ASN_PREFIX_CAP - len(ipv4[:_ASN_PREFIX_CAP]))],
                "prefix_count": total,
                "prefix_list_truncated": truncated,
                "source": "ripestat",
            },
            "raw_output": "\n\n".join(raw_parts),
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "stat.ripe.net timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _ptr_records(domain: str) -> dict:
    """Résolution DNS inverse (PTR) pour les IPs du domaine."""
    CLOUD_PATTERNS = [
        "amazonaws.com", "azure.com", "cloudapp.net", "googleusercontent.com",
        "compute.internal", "ovh.net", "hetzner.com", "digitalocean.com",
        "linode.com", "vultr.com", "cloudflare.com", "fastly.net",
    ]
    ips = _resolve_ips(domain)[:8]
    if not ips:
        return {"status": "error", "data": [], "error": f"Résolution DNS échouée pour {domain}", "raw_output": ""}

    results = []
    raw_parts = []

    for ip in ips:
        try:
            # Résolution PTR via dnspython avec DNS public
            rev_name = _dns_reversename.from_address(ip)
            ptr_answers = _resolver.resolve(rev_name, "PTR")
            hostname = str(ptr_answers[0]).rstrip(".")
            is_cloud = any(p in hostname for p in CLOUD_PATTERNS)
            results.append({
                "ip": ip,
                "ptr": hostname,
                "aliases": [],
                "is_cloud": is_cloud,
                "cloud_provider": next((p for p in CLOUD_PATTERNS if p in hostname), None),
            })
            raw_parts.append(f"{ip} → {hostname}")
        except (_dns_resolver.NoAnswer, _dns_resolver.NXDOMAIN, _dns_resolver.NoNameservers):
            results.append({"ip": ip, "ptr": None, "aliases": [], "is_cloud": False, "cloud_provider": None})
            raw_parts.append(f"{ip} → (no PTR record)")
        except Exception as e:
            results.append({"ip": ip, "ptr": None, "error": str(e), "is_cloud": False, "cloud_provider": None})
            raw_parts.append(f"{ip} → ERROR: {e}")

    return {
        "status": "success",
        "data": {"records": results, "count": len(results)},
        "raw_output": "\n".join(raw_parts),
    }


def _dkim_check(domain: str) -> dict:
    """Teste les sélecteurs DKIM courants pour identifier les clés actives."""
    SELECTORS = [
        "google", "k1", "k2", "mail", "default", "dkim", "selector1", "selector2",
        "email", "s1", "s2", "mimecast", "zoho", "protonmail", "20161025", "20210112",
        "smtp", "mandrill", "mailchimp-1", "sendgrid", "amazonses", "mailgun",
        "pm", "brevo", "sg", "mx", "dkimkey", "dkimrsa",
    ]

    PROVIDER_HINTS = {
        "google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365",
        "k1": "Mailchimp / Mandrill", "k2": "Mailchimp", "mandrill": "Mandrill",
        "mailchimp-1": "Mailchimp", "amazonses": "Amazon SES",
        "sendgrid": "SendGrid", "mailgun": "Mailgun",
        "mimecast": "Mimecast", "zoho": "Zoho Mail",
        "protonmail": "ProtonMail", "brevo": "Brevo (ex-Sendinblue)",
        "pm": "Postmark",
    }

    found = []
    raw_parts = []

    for selector in SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        try:
            answers = _resolver.resolve(name, "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    algo_match = re.search(r'k=(\w+)', txt)
                    found.append({
                        "selector": selector,
                        "record": txt[:300],
                        "algorithm": algo_match.group(1) if algo_match else "rsa",
                        "provider": PROVIDER_HINTS.get(selector),
                        "has_key": bool(re.search(r'p=[A-Za-z0-9+/=]+', txt)),
                    })
                    raw_parts.append(f"{name}. IN TXT \"{txt[:200]}\"")
        except Exception:
            pass

    return {
        "status": "success",
        "data": {
            "found": found,
            "count": len(found),
            "selectors_tested": SELECTORS,
        },
        "raw_output": "\n".join(raw_parts) if raw_parts else "Aucun sélecteur DKIM trouvé",
    }


def _spf_analysis(domain: str) -> dict:
    """Expansion récursive du SPF — révèle tous les expéditeurs email autorisés."""
    visited: set = set()
    mechanisms: list = []
    includes_tree: dict = {}
    raw_records: list = []
    lookup_count = [0]

    def expand_spf(d: str, depth: int = 0):
        if depth > 10 or d in visited or lookup_count[0] >= 10:
            return
        visited.add(d)
        lookup_count[0] += 1
        try:
            txts = _resolver.resolve(d, "TXT")
            for r in txts:
                txt = str(r).strip('"')
                if not txt.startswith("v=spf1"):
                    continue
                raw_records.append(f"{d}: {txt}")
                for part in txt.split():
                    if part.startswith("include:"):
                        inc = part[8:]
                        includes_tree.setdefault(d, []).append(inc)
                        expand_spf(inc, depth + 1)
                    elif part.startswith("redirect="):
                        redir = part[9:]
                        includes_tree.setdefault(d, []).append(f"redirect:{redir}")
                        expand_spf(redir, depth + 1)
                    elif part not in ("v=spf1",):
                        mechanisms.append({"domain": d, "mechanism": part})
        except Exception:
            pass

    expand_spf(domain)

    ip4 = [m["mechanism"][4:] for m in mechanisms if m["mechanism"].startswith("ip4:")]
    ip6 = [m["mechanism"][4:] for m in mechanisms if m["mechanism"].startswith("ip6:")]
    all_mech = next((m["mechanism"] for m in mechanisms if m["mechanism"].startswith("all")), None)

    all_risk = {
        "+all": "CRITIQUE — tout le monde peut envoyer (SPF inutile)",
        "?all": "Neutre — aucune protection réelle",
        "~all": "SoftFail — emails non autorisés marqués comme spam (protection partielle)",
        "-all": "HardFail — rejet strict des emails non autorisés (protection maximale)",
    }

    return {
        "status": "success",
        "data": {
            "includes_tree": includes_tree,
            "mechanisms": mechanisms,
            "ip4_ranges": ip4,
            "ip6_ranges": ip6,
            "all_mechanism": all_mech,
            "all_risk": all_risk.get(all_mech, "Non défini"),
            "domains_visited": list(visited),
            "lookup_count": lookup_count[0],
            "lookup_limit_warning": lookup_count[0] >= 10,
        },
        "raw_output": "\n".join(raw_records) if raw_records else "Aucun enregistrement SPF trouvé",
    }


def _subdomain_takeover(all_subs: set, domain: str) -> dict:
    """
    Détecte les CNAMEs dangling potentiellement vulnérables à une prise de contrôle.

    Détection strictement PASSIVE : seule la résolution DNS du CNAME est effectuée.
    Aucune requête HTTP n'est envoyée vers la cible pour confirmer le fingerprint,
    d'où une confiance systématiquement « medium » : le résultat signale un CNAME
    pointant vers un service externe connu pour être « takeover-able », pas une
    vulnérabilité confirmée.
    """
    TAKEOVER_SERVICES = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "bitbucket.io": "Bitbucket",
        "wordpress.com": "WordPress.com",
        "ghost.io": "Ghost",
        "surge.sh": "Surge.sh",
        "shopify.com": "Shopify",
        "zendesk.com": "Zendesk",
        "s3.amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure Web Apps",
        "cloudapp.net": "Azure",
        "readthedocs.io": "ReadTheDocs",
        "pantheonsite.io": "Pantheon",
        "netlify.app": "Netlify",
        "fly.io": "Fly.io",
        "strikingly.com": "Strikingly",
        "cargo.site": "Cargo",
        "fastly.com": "Fastly",
    }

    vulnerable = []
    checked = 0
    raw_parts = []

    targets = list(all_subs)[:50]  # Limite à 50 sous-domaines
    for sub in targets:
        checked += 1
        try:
            cname_answers = _resolver.resolve(sub, "CNAME")
            for cname_rdata in cname_answers:
                cname_target = str(cname_rdata.target).rstrip(".")
                raw_parts.append(f"{sub} CNAME → {cname_target}")

                # Vérifie si le CNAME pointe vers un service vulnérable connu
                for service_domain, service_name in TAKEOVER_SERVICES.items():
                    if service_domain in cname_target:
                        vulnerable.append({
                            "subdomain": sub,
                            "cname": cname_target,
                            "service": service_name,
                            "confidence": "medium",
                        })
                        raw_parts.append(
                            f"  ⚠️  CNAME dangling potentiel [{service_name}] — "
                            f"non confirmé (détection passive)"
                        )
                        break
        except (_dns_resolver.NoAnswer, _dns_resolver.NXDOMAIN):
            pass
        except Exception:
            pass

    return {
        "status": "success",
        "data": {
            "vulnerable": vulnerable,
            "vulnerable_count": len(vulnerable),
            "checked_count": checked,
            # Détection passive non confirmée → au plus "high", jamais "critical"
            "risk_level": ("high" if vulnerable else "none"),
        },
        "raw_output": "\n".join(raw_parts) if raw_parts else "Aucun CNAME dangling détecté",
    }


def _js_endpoints(domain: str) -> dict:
    """Extrait les endpoints d'API depuis les fichiers JavaScript publics."""
    ENDPOINT_PATTERNS = [
        r'["\'](/(?:api|v\d+|graphql|rest|rpc|service|endpoint|webhook|internal)[/\w\-\.{}:?=&%]*)["\']',
        r'(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete|http\.get|http\.post)\s*\(\s*["\']([^"\']{5,100})["\']',
        r'(?:url|path|endpoint|baseURL|baseUrl)\s*[=:]\s*["\']([/][^"\']{3,80})["\']',
        r'["\`](/(?:admin|auth|user|account|profile|dashboard|settings|config|data|files|upload|download)[/\w\-\.{}?=&]*)["\`]',
    ]
    INTERESTING_KW = [
        "admin", "secret", "key", "token", "password", "internal",
        "debug", "test", "dev", "staging", "backup", "config", "private",
    ]

    endpoints: set = set()
    js_files_analyzed = []
    raw_parts = []

    for scheme in ("https", "http"):
        try:
            resp = _http.get(
                f"{scheme}://{domain}", timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            # Collecte les scripts externes du même domaine
            script_urls = []
            for tag in soup.find_all("script", src=True):
                src = tag["src"]
                if src.startswith("//"):
                    src = f"https:{src}"
                elif src.startswith("/"):
                    src = f"{scheme}://{domain}{src}"
                parsed = urlparse(src)
                if domain in parsed.netloc or not parsed.netloc:
                    script_urls.append(src)

            # Aussi les scripts inline
            inline_content = " ".join(t.string or "" for t in soup.find_all("script", src=False))
            if inline_content:
                raw_parts.append(f"=== Inline scripts ({len(inline_content)} chars) ===")
                for pattern in ENDPOINT_PATTERNS:
                    for m in re.finditer(pattern, inline_content):
                        endpoints.add(m.group(1))

            # Analyse chaque fichier JS (max 6)
            for js_url in script_urls[:6]:
                try:
                    js_resp = _http.get(js_url, timeout=8,
                                            headers={"User-Agent": "Mozilla/5.0"})
                    if js_resp.status_code == 200:
                        js_content = js_resp.text[:200000]  # 200KB max
                        js_files_analyzed.append({"url": js_url, "size_kb": len(js_resp.content) // 1024})
                        raw_parts.append(f"=== {js_url} ({len(js_resp.content)//1024}KB) ===")
                        for pattern in ENDPOINT_PATTERNS:
                            for m in re.finditer(pattern, js_content):
                                endpoints.add(m.group(1))
                except Exception:
                    pass

            break
        except _requests.exceptions.SSLError:
            continue
        except Exception:
            break

    endpoints_list = sorted(endpoints)
    interesting = [e for e in endpoints_list if any(kw in e.lower() for kw in INTERESTING_KW)]

    return {
        "status": "success",
        "data": {
            "endpoints": endpoints_list[:200],
            "endpoint_count": len(endpoints_list),
            "interesting": interesting,
            "js_files": js_files_analyzed,
            "js_files_count": len(js_files_analyzed),
        },
        "raw_output": "\n".join(raw_parts[:100]),
    }


def _dnsbl_check(domain: str) -> dict:
    """Vérifie la présence du domaine/IPs dans les blacklists DNS majeures."""
    DNSBLS = [
        ("zen.spamhaus.org",        "Spamhaus ZEN (SBL+XBL+PBL)"),
        ("bl.spamcop.net",          "SpamCop"),
        ("dnsbl.sorbs.net",         "SORBS"),
        ("b.barracudacentral.org",  "Barracuda"),
        ("dnsbl-1.uceprotect.net",  "UCEprotect L1"),
        ("db.wpbl.info",            "WPBL"),
        ("ix.dnsbl.manitu.net",     "Manitu"),
        ("ubl.unsubscore.com",      "Unsubscore"),
    ]

    ips = [ip for ip in _resolve_ips(domain) if ":" not in ip]  # IPv4 seulement
    if not ips:
        return {"status": "error", "data": {}, "error": f"Résolution DNS échouée pour {domain}", "raw_output": ""}

    listed = []
    clean_count = 0
    raw_parts = []

    for ip in ips[:4]:
        reversed_ip = ".".join(reversed(ip.split(".")))
        for dnsbl, dnsbl_name in DNSBLS:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                _resolver.resolve(query, "A")
                # Si une réponse A est retournée, l'IP est blacklistée
                listed.append({"ip": ip, "dnsbl": dnsbl, "dnsbl_name": dnsbl_name, "query": query})
                raw_parts.append(f"LISTED   {ip} in {dnsbl_name} ({dnsbl})")
            except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
                clean_count += 1
                raw_parts.append(f"clean    {ip} not in {dnsbl_name}")
            except Exception:
                raw_parts.append(f"error    {ip} {dnsbl}")

    total_checks = len(ips[:4]) * len(DNSBLS)
    listed_count = len(listed)
    risk_level = (
        "high"   if listed_count >= 3 else
        "medium" if listed_count >= 1 else
        "low"    if total_checks == 0 else
        "clean"
    )

    return {
        "status": "success",
        "data": {
            "listed": listed,
            "listed_count": listed_count,
            "clean": listed_count == 0,
            "risk_level": risk_level,
            "ips_checked": ips[:4],
            "checked_dnsbls": [d for d, _ in DNSBLS],
            "total_checks": total_checks,
        },
        "raw_output": "\n".join(raw_parts),
    }


def _favicon_hash(domain: str) -> dict:
    """Calcule le hash du favicon pour pivot Shodan/Fofa."""
    def _murmurhash3_32(data: bytes) -> int:
        """MurmurHash3 32-bit — algorithme exact utilisé par Shodan."""
        h = 0
        length = len(data)
        nblocks = length // 4
        for block in range(nblocks):
            k = int.from_bytes(data[block * 4:block * 4 + 4], "little")
            k = (k * 0xCC9E2D51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1B873593) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
        tail = data[nblocks * 4:]
        k = 0
        if len(tail) >= 3:
            k ^= tail[2] << 16
        if len(tail) >= 2:
            k ^= tail[1] << 8
        if len(tail) >= 1:
            k ^= tail[0]
            k = (k * 0xCC9E2D51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1B873593) & 0xFFFFFFFF
            h ^= k
        h ^= length
        h ^= h >> 16
        h = (h * 0x85EBCA6B) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xC2B2AE35) & 0xFFFFFFFF
        h ^= h >> 16
        # Signed 32-bit
        if h >= 0x80000000:
            h -= 0x100000000
        return h

    FAVICON_PATHS = ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]

    for scheme in ("https", "http"):
        for path in FAVICON_PATHS:
            url = f"{scheme}://{domain}{path}"
            try:
                resp = _http.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 and len(resp.content) > 64:
                    raw_bytes = resp.content
                    b64 = base64.encodebytes(raw_bytes).decode("utf-8")
                    md5 = hashlib.md5(raw_bytes).hexdigest()
                    mmh3 = _murmurhash3_32(b64.encode("utf-8"))

                    return {
                        "status": "success",
                        "data": {
                            "url": url,
                            "size_bytes": len(raw_bytes),
                            "md5": md5,
                            "murmur3": mmh3,
                            "base64": b64[:200] + "..." if len(b64) > 200 else b64,
                            "shodan_query": f"http.favicon.hash:{mmh3}",
                            "fofa_query": f'icon_hash="{mmh3}"',
                        },
                        "raw_output": (
                            f"URL      : {url}\n"
                            f"Size     : {len(raw_bytes)} bytes\n"
                            f"MD5      : {md5}\n"
                            f"MurmurH3 : {mmh3}\n"
                            f"Shodan   : http.favicon.hash:{mmh3}\n"
                            f"Fofa     : icon_hash=\"{mmh3}\"\n"
                        ),
                    }
            except _requests.exceptions.SSLError:
                continue
            except Exception:
                continue

    return {
        "status": "not_found", "data": {},
        "error": "Aucun favicon trouvé (/favicon.ico, /favicon.png, /apple-touch-icon.png testés)",
        "raw_output": "",
    }


def _enrich_cves(cve_ids: list) -> list:
    """
    Enrichit une liste d'identifiants CVE nus avec CVSS/résumé (CIRCL) et score
    d'exploitabilité EPSS (FIRST) — transforme une liste d'IDs en priorisation
    défendable, sans coût token supplémentaire pour l'analyse IA en aval.

    Best-effort et strictement borné dans le temps : EPSS se fait en un seul
    appel batché (jusqu'à 100 CVE, rapide). CIRCL (CVSS + résumé) est limité
    aux 10 premières CVE, interrogées EN PARALLÈLE (pas en séquence — 10
    requêtes séquentielles à 8s chacune suffiraient à elles seules à épuiser
    tout le budget global du scan, qui est PARTAGÉ entre tous les outils de la
    vague parallèle) avec un budget global de 6s : passé ce délai, les CVE
    restantes gardent juste leur ID nu + EPSS, jamais de blocage prolongé.
    """
    if not cve_ids:
        return []

    epss_scores: dict = {}
    try:
        resp = _http.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": ",".join(cve_ids[:100])},
            timeout=10,
        )
        if resp.status_code == 200:
            for item in (resp.json() or {}).get("data", []):
                epss_scores[item.get("cve")] = {
                    "epss": item.get("epss"),
                    "percentile": item.get("percentile"),
                }
    except Exception:
        pass

    circl_details: dict = {}
    to_lookup = cve_ids[:10]
    if to_lookup:
        import concurrent.futures as _cf

        def _fetch_circl(cve_id):
            resp = _http.get(f"https://vulnerability.circl.lu/api/cve/{cve_id}", timeout=5)
            if resp.status_code == 200:
                d = resp.json() or {}
                return cve_id, {
                    "cvss": d.get("cvss") or d.get("cvss3") or d.get("cvss_version"),
                    "summary": d.get("summary") or d.get("id"),
                }
            return cve_id, None

        # PAS de `with` ici : ThreadPoolExecutor.__exit__ appelle shutdown(wait=True),
        # qui attend la fin de TOUS les threads même après le wait(timeout=6)
        # ci-dessous — annulant tout l'effet du budget de temps (bug constaté :
        # 328s au lieu de ~6s). `shutdown(wait=False)` laisse les threads bloqués
        # sur leur requête HTTP se terminer seuls en arrière-plan (même logique
        # que `utils/parallel.py::run_tools_parallel`), sans bloquer la réponse.
        pool = _cf.ThreadPoolExecutor(max_workers=min(10, len(to_lookup)))
        try:
            futures = {pool.submit(_fetch_circl, cve_id): cve_id for cve_id in to_lookup}
            done, pending = _cf.wait(futures, timeout=6)
            for future in done:
                try:
                    cve_id, detail = future.result()
                    if detail:
                        circl_details[cve_id] = detail
                except Exception:
                    pass
            for future in pending:
                future.cancel()
        finally:
            pool.shutdown(wait=False)

    enriched = []
    for cve_id in cve_ids:
        epss = epss_scores.get(cve_id, {})
        detail = circl_details.get(cve_id, {})
        enriched.append({
            "id": cve_id,
            "epss": epss.get("epss"),
            "epss_percentile": epss.get("percentile"),
            "cvss": detail.get("cvss"),
            "summary": detail.get("summary"),
        })

    return enriched


def _shodan_internetdb(domain: str, ips: list = None) -> dict:
    """
    Ports, CPE, CVE et hostnames connus de Shodan via l'API gratuite InternetDB.

    Aucune clé requise, aucune sonde envoyée à la cible : seules les observations
    déjà collectées par Shodan sont consultées (100 % passif). Les CVE listées
    sont enrichies (CVSS + score d'exploitabilité EPSS) via `_enrich_cves`.
    Les IP sont réutilisées depuis l'outil ip_info si elles sont fournies,
    afin d'éviter une seconde résolution DNS.
    """
    if not ips:
        ips = _resolve_ips(domain)
    ips = [ip for ip in ips if ":" not in ip][:5]   # InternetDB ne couvre que l'IPv4
    if not ips:
        return {"status": "error", "data": {}, "error": f"Aucune IPv4 résolue pour {domain}", "raw_output": ""}

    results = []
    raw_parts = []
    all_ports, all_cpes, all_vulns, all_tags, all_hostnames = set(), set(), set(), set(), set()

    for ip in ips:
        try:
            resp = _http.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            raw_parts.append(f"=== InternetDB {ip} (HTTP {resp.status_code}) ===\n{resp.text[:2000]}")

            if resp.status_code == 404:
                # IP inconnue de Shodan — absence de donnée, pas une erreur
                results.append({"ip": ip, "status": "no_data",
                                "note": "IP absente de la base Shodan (aucune observation)"})
                continue
            if resp.status_code != 200:
                results.append({"ip": ip, "status": "error", "error": f"HTTP {resp.status_code}"})
                continue

            d = resp.json()
            ports     = [p for p in (d.get("ports") or []) if isinstance(p, int)]
            cpes      = [c for c in (d.get("cpes") or []) if isinstance(c, str)]
            vulns     = [v for v in (d.get("vulns") or []) if isinstance(v, str)]
            hostnames = [h for h in (d.get("hostnames") or []) if isinstance(h, str)]
            tags      = [t for t in (d.get("tags") or []) if isinstance(t, str)]

            all_ports.update(ports)
            all_cpes.update(cpes)
            all_vulns.update(vulns)
            all_tags.update(tags)
            all_hostnames.update(hostnames)

            results.append({
                "ip": ip,
                "status": "success",
                "ports": sorted(ports),
                "cpes": cpes,
                "vulns": vulns,
                "hostnames": hostnames,
                "tags": tags,
            })
        except _requests.exceptions.Timeout:
            raw_parts.append(f"=== InternetDB {ip} ===\nTIMEOUT")
            results.append({"ip": ip, "status": "timeout", "error": "internetdb.shodan.io timeout"})
        except Exception as e:
            raw_parts.append(f"=== InternetDB {ip} ===\nERROR: {e}")
            results.append({"ip": ip, "status": "error", "error": str(e)})

    # Statut global : no_data si aucune IP n'est connue de Shodan
    if results and all(r.get("status") == "no_data" for r in results):
        return {
            "status": "no_data",
            "data": {"ips": results, "count": len(results)},
            "error": "Aucune des IP du domaine n'est référencée dans la base Shodan",
            "raw_output": "\n\n".join(raw_parts),
        }

    return {
        "status": "success",
        "data": {
            "ips": results,
            "count": len(results),
            "ports": sorted(all_ports),
            "cpes": sorted(all_cpes),
            "vulns": sorted(all_vulns),
            "vulns_enriched": _enrich_cves(sorted(all_vulns)),
            "tags": sorted(all_tags),
            "hostnames": sorted(all_hostnames),
            "port_count": len(all_ports),
            "vuln_count": len(all_vulns),
        },
        "raw_output": "\n\n".join(raw_parts),
    }


def _otx_passive_dns(domain: str) -> dict:
    """
    Historique des résolutions DNS (passive DNS) via AlienVault OTX.

    OTX_API_KEY est optionnelle : si elle est présente elle est envoyée dans
    l'en-tête X-OTX-API-KEY (quotas plus élevés), sinon la requête est tentée
    en accès anonyme et le statut passe à 'limited' si l'API exige une clé.
    """
    otx_key = os.getenv('OTX_API_KEY', '').strip()
    headers = {"User-Agent": "OSINT-Recon/1.1 (security research)"}
    if otx_key:
        headers["X-OTX-API-KEY"] = otx_key

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = _http.get(url, headers=headers, timeout=15)
        raw_output = f"=== OTX passive_dns {domain} (HTTP {resp.status_code}) ===\n{resp.text[:4000]}"

        if resp.status_code in (401, 403):
            return {
                "status": "limited",
                "data": {"records": [], "count": 0, "authenticated": bool(otx_key)},
                "error": (
                    "Accès OTX restreint (HTTP %d) — définissez OTX_API_KEY=<votre_clé> "
                    "dans api/.env pour un accès complet" % resp.status_code
                ),
                "raw_output": raw_output,
            }
        if resp.status_code == 404:
            return {
                "status": "no_data",
                "data": {"records": [], "count": 0, "authenticated": bool(otx_key)},
                "error": "Domaine inconnu de l'Open Threat Exchange",
                "raw_output": raw_output,
            }
        if resp.status_code != 200:
            return {
                "status": "error",
                "data": {"records": [], "count": 0, "authenticated": bool(otx_key)},
                "error": f"HTTP {resp.status_code}",
                "raw_output": raw_output,
            }

        payload = resp.json()
        entries = payload.get("passive_dns") or []

        records = []
        unique_ips, unique_hostnames = set(), set()
        for e in entries:
            if not isinstance(e, dict):
                continue
            address  = e.get("address")
            hostname = e.get("hostname")
            records.append({
                "address":     address,
                "hostname":    hostname,
                "record_type": e.get("record_type"),
                "first":       e.get("first"),
                "last":        e.get("last"),
                "flag_title":  e.get("flag_title"),
            })
            if isinstance(address, str) and address:
                unique_ips.add(address)
            if isinstance(hostname, str) and hostname:
                unique_hostnames.add(hostname)

        return {
            "status": "success",
            "data": {
                "records": records,
                "count": len(records),
                "unique_ips": sorted(unique_ips),
                "unique_ip_count": len(unique_ips),
                "unique_hostnames": sorted(unique_hostnames),
                "authenticated": bool(otx_key),
            },
            "raw_output": raw_output,
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "otx.alienvault.com timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _rdap_info(domain: str) -> dict:
    """
    Données d'enregistrement structurées via RDAP (RFC 9083) — complément du WHOIS.

    rdap.org redirige automatiquement vers le serveur RDAP du registre concerné.
    Les TLD sans service RDAP renvoient 404 → status 'unavailable'.
    """
    try:
        resp = _http.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json",
                     "User-Agent": "OSINT-Recon/1.1 (security research)"},
            timeout=15,
        )
        raw_output = f"=== RDAP {domain} (HTTP {resp.status_code}) ===\n{resp.text[:4000]}"

        if resp.status_code in (404, 400, 501):
            return {
                "status": "unavailable",
                "data": {},
                "error": (
                    f"Aucun service RDAP disponible pour ce domaine/TLD (HTTP {resp.status_code}) "
                    "— se référer au résultat WHOIS"
                ),
                "raw_output": raw_output,
            }
        if resp.status_code != 200:
            return {"status": "error", "data": {}, "error": f"HTTP {resp.status_code}", "raw_output": raw_output}

        d = resp.json()

        # ── Registrar : entité portant le rôle 'registrar' ────────────────────
        registrar = None
        registrar_iana_id = None
        abuse_email = None
        for entity in (d.get("entities") or []):
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles") or []
            vcard = entity.get("vcardArray")
            names = []
            emails = []
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4:
                        if item[0] == "fn":
                            names.append(str(item[3]))
                        elif item[0] == "email":
                            emails.append(str(item[3]))
            if "registrar" in roles:
                if names:
                    registrar = names[0]
                for pid in (entity.get("publicIds") or []):
                    if isinstance(pid, dict) and pid.get("type", "").lower().startswith("iana"):
                        registrar_iana_id = pid.get("identifier")
            if "abuse" in roles and emails:
                abuse_email = emails[0]

        # ── Événements normalisés (registration / expiration / last changed) ──
        events = {}
        for ev in (d.get("events") or []):
            if isinstance(ev, dict) and ev.get("eventAction"):
                events[str(ev["eventAction"]).replace(" ", "_")] = ev.get("eventDate")

        nameservers = [
            ns.get("ldhName") for ns in (d.get("nameservers") or [])
            if isinstance(ns, dict) and ns.get("ldhName")
        ]

        secure_dns = d.get("secureDNS") or {}
        dnssec_delegated = secure_dns.get("delegationSigned") if isinstance(secure_dns, dict) else None

        return {
            "status": "success",
            "data": {
                "handle": d.get("handle"),
                "ldh_name": d.get("ldhName"),
                "registrar": registrar,
                "registrar_iana_id": registrar_iana_id,
                "abuse_email": abuse_email,
                "events": {
                    "registration": events.get("registration"),
                    "expiration": events.get("expiration"),
                    "last_changed": events.get("last_changed") or events.get("last_update_of_RDAP_database"),
                    "all": events,
                },
                "status": d.get("status") or [],
                "nameservers": nameservers,
                "dnssec_delegated": dnssec_delegated,
                "port43": d.get("port43"),
            },
            "raw_output": raw_output,
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "rdap.org timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _xposedornot_breaches(domain: str) -> dict:
    """
    Fuites de données connues via XposedOrNot — remplace l'ancien HIBP.

    HIBP exige un abonnement payant ET une vérification de propriété du
    domaine (HTTP 403 systématique sur un domaine tiers, cf. CLAUDE.md) :
    inutilisable pour cette plateforme. XposedOrNot est gratuit et sans clé,
    mais interroge une adresse email précise, pas un domaine entier — on
    teste donc une liste d'adresses "rôle" courantes (admin@, contact@…),
    même logique que le brute-force de sélecteurs DKIM ci-dessus.

    Quota anonyme : ~2-3 req/s — respecté via une pause entre requêtes.
    Liste et timeout volontairement courts (5 adresses, 6s/requête, pause
    réduite) : le budget global du scan est partagé entre tous les outils de
    la vague parallèle, pire cas ~35s au lieu de ~75s avec la liste complète.
    """
    import time as _t

    ROLE_LOCALS = ["admin", "contact", "info", "support", "webmaster"]
    breach_map: dict = {}
    checked = []
    raw_parts = []

    for local in ROLE_LOCALS:
        email = f"{local}@{domain}"
        try:
            resp = _http.get(
                f"https://api.xposedornot.com/v1/check-email/{email}",
                headers={"User-Agent": "OSINT-Recon/1.1 (security research)"},
                timeout=6,
            )
            raw_parts.append(f"=== check-email {email} (HTTP {resp.status_code}) ===\n{resp.text[:1000]}")
            checked.append(email)

            if resp.status_code == 200:
                payload = resp.json() or {}
                breaches = payload.get("breaches")
                # Format XposedOrNot : {"breaches": [["Breach1", "Breach2", ...]]} ou {"breaches": []}
                names = breaches[0] if breaches and isinstance(breaches[0], list) else (breaches or [])
                for name in names:
                    breach_map.setdefault(str(name), []).append(email)
        except _requests.exceptions.Timeout:
            raw_parts.append(f"=== check-email {email} ===\nTIMEOUT")
        except Exception as e:
            raw_parts.append(f"=== check-email {email} ===\nERROR: {e}")
        _t.sleep(0.4)

    breaches_list = [
        {"name": name, "affected_aliases": sorted(aliases), "affected_count": len(aliases)}
        for name, aliases in breach_map.items()
    ]
    breaches_list.sort(key=lambda b: b["affected_count"], reverse=True)

    return {
        "status": "success",
        "data": {
            "breaches": breaches_list,
            "breach_count": len(breaches_list),
            "affected_accounts": len({a for b in breaches_list for a in b["affected_aliases"]}),
            "top_breaches": [b["name"] for b in breaches_list[:5]],
            "emails_checked": checked,
            "note": (
                "Couverture limitée aux adresses email « rôle » courantes "
                "(admin@, contact@…) — XposedOrNot n'offre pas de recherche par "
                "domaine entier en accès gratuit, comme HIBP."
            ),
        },
        "raw_output": "\n\n".join(raw_parts),
    }


def _typosquatting(domain: str) -> dict:
    """
    Détecte les domaines de typosquatting/phishing imitant le domaine cible via dnstwist.

    Génère les permutations (homoglyphes, fautes de frappe, IDN) et ne conserve
    que celles réellement enregistrées (--registered) : DNS, MX, et bannière de
    similarité si résolues. 100% passif — aucune requête n'est envoyée à la
    cible elle-même, seulement aux domaines candidats.

    Timeout volontairement court (60s, --threads augmenté) : le budget global
    du scan (`SCAN_DEADLINE_SECONDS`) est partagé entre TOUS les outils de la
    vague parallèle — un domaine massivement squatté (ex: github.com, 250s+
    en pratique) ne doit jamais pouvoir affamer les autres outils. Le fuzzer
    `dictionary`, le plus coûteux en candidats, est exclu ; sur un domaine très
    connu, un `status: timeout` ici est attendu et sans impact sur le reste.
    """
    raw = _run_subprocess(
        ['dnstwist', '--format', 'json', '--registered', '--threads', '30',
         '--fuzzers', 'addition,bitsquatting,homoglyph,hyphenation,insertion,'
                      'omission,repetition,replacement,subdomain,transposition,'
                      'vowel-swap',
         domain],
        timeout=60,
    )
    if raw["status"] == "not_installed":
        return {"status": "not_installed", "data": {}, "error": raw.get("error", ""), "raw_output": ""}
    if raw["status"] in ("timeout", "error") and not raw.get("raw"):
        return {"status": raw["status"], "data": {}, "error": raw.get("error", ""), "raw_output": raw.get("raw", "")}

    try:
        permutations = json.loads(raw["raw"]) if raw.get("raw", "").strip() else []
    except (json.JSONDecodeError, ValueError):
        permutations = []

    suspicious = []
    for p in permutations if isinstance(permutations, list) else []:
        if not isinstance(p, dict) or p.get("domain") == domain:
            continue
        suspicious.append({
            "domain":     p.get("domain"),
            "fuzzer":     p.get("fuzzer"),
            "dns_a":      p.get("dns_a"),
            "dns_ns":     p.get("dns_ns"),
            "dns_mx":     p.get("dns_mx"),
            "geoip":      p.get("geoip"),
        })

    mx_hijack = [p for p in suspicious if p.get("dns_mx")]

    return {
        "status": "success",
        "data": {
            "suspicious_domains": suspicious,
            "count": len(suspicious),
            "mx_configured": mx_hijack,
            "mx_configured_count": len(mx_hijack),
            "risk_level": "high" if mx_hijack else ("medium" if suspicious else "low"),
        },
        "raw_output": raw.get("raw", "")[:8000],
    }


def _gau_urls(domain: str, cwd: str = None) -> dict:
    """
    URLs historiques agrégées (Wayback + Common Crawl + OTX + urlscan) via gau.

    Complète `archive_history` (Wayback seul) : Common Crawl en particulier
    remonte souvent des endpoints/paramètres/fichiers oubliés absents de
    Wayback. 100% passif — consultation d'archives tierces uniquement.

    Timeout volontairement court (45s) : sur un domaine très populaire (des
    centaines de milliers d'URLs historiques), gau peut prendre plusieurs
    minutes — le budget global du scan est partagé entre tous les outils de
    la vague parallèle, un seul outil ne doit pas pouvoir affamer les autres.
    `_run_subprocess` récupère les URLs déjà collectées au moment du timeout
    (statut `timeout_partial`), donc même interrompu ce n'est pas vide.
    """
    raw = _run_subprocess(['gau', '--subs', domain], timeout=45, cwd=cwd)
    if raw["status"] == "not_installed":
        return {"status": "not_installed", "data": {}, "error": raw.get("error", ""), "raw_output": ""}

    urls = sorted(set(raw.get("lines") or []))
    interesting_ext = (".sql", ".bak", ".env", ".json", ".zip", ".log", ".config", ".yml", ".yaml")
    interesting = [u for u in urls if u.lower().endswith(interesting_ext)]

    status = raw["status"] if raw["status"] in ("timeout", "timeout_partial", "error") else "success"
    return {
        "status": status,
        "data": {
            "urls": urls[:500],
            "url_count": len(urls),
            "interesting_files": interesting[:100],
            "interesting_count": len(interesting),
        },
        "error": raw.get("error"),
        "raw_output": "\n".join(urls[:200]),
    }


# ── Enregistrements DNS de confiance email/TLS ───────────────────────────────
# DMARC, MTA-STS, TLS-RPT, BIMI complètent SPF/DKIM déjà couverts ; CAA et
# DANE/TLSA sont plus larges (contrôle d'émission de certificats) mais
# relèvent du même type de vérification — simple lookup DNS, aucune clé.

def _dmarc_check(domain: str) -> dict:
    """Politique DMARC (_dmarc.<domain> TXT) — anti-spoofing par-dessus SPF/DKIM."""
    name = f"_dmarc.{domain}"
    try:
        answers = _resolver.resolve(name, "TXT")
        record = next((str(r).strip('"') for r in answers if "v=DMARC1" in str(r)), None)
        if not record:
            return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement DMARC",
                    "raw_output": ""}
        policy_match = re.search(r'p=(\w+)', record)
        pct_match = re.search(r'pct=(\d+)', record)
        rua_match = re.search(r'rua=([^;]+)', record)
        policy = policy_match.group(1) if policy_match else None
        return {
            "status": "success",
            "data": {
                "present": True,
                "record": record,
                "policy": policy,
                "policy_risk": {
                    "none":       "Aucune action — surveillance uniquement, pas de protection réelle",
                    "quarantine": "Emails non conformes marqués comme spam — protection partielle",
                    "reject":     "Emails non conformes rejetés — protection maximale",
                }.get(policy, "Politique non reconnue"),
                "percentage": int(pct_match.group(1)) if pct_match else 100,
                "report_address": rua_match.group(1) if rua_match else None,
            },
            "raw_output": f"{name}. IN TXT \"{record}\"",
        }
    except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
        return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement DMARC",
                "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _mta_sts_check(domain: str) -> dict:
    """MTA-STS (_mta-sts.<domain> TXT + politique HTTPS) — force TLS pour le SMTP entrant."""
    name = f"_mta-sts.{domain}"
    dns_present = False
    record = None
    try:
        answers = _resolver.resolve(name, "TXT")
        record = next((str(r).strip('"') for r in answers if "v=STSv1" in str(r)), None)
        dns_present = record is not None
    except Exception:
        pass

    policy_mode = None
    policy_raw = ""
    if dns_present:
        try:
            resp = _http.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=8)
            if resp.status_code == 200:
                policy_raw = resp.text[:2000]
                mode_match = re.search(r'mode:\s*(\w+)', policy_raw)
                policy_mode = mode_match.group(1) if mode_match else None
        except Exception:
            pass

    return {
        "status": "success" if dns_present else "no_data",
        "data": {
            "present": dns_present,
            "record": record,
            "policy_mode": policy_mode,
            "policy_risk": {
                "none":     "Mode 'none' — MTA-STS déclaré mais inactif",
                "testing":  "Mode 'testing' — surveillance sans application stricte",
                "enforce":  "Mode 'enforce' — TLS imposé pour le SMTP entrant",
            }.get(policy_mode, "Politique non récupérée ou non reconnue"),
        },
        "error": None if dns_present else "Aucun enregistrement MTA-STS",
        "raw_output": f"{name}. IN TXT \"{record}\"\n{policy_raw}" if record else "",
    }


def _tlsrpt_check(domain: str) -> dict:
    """TLS-RPT (_smtp._tls.<domain> TXT) — rapports de blocage TLS pour le SMTP entrant."""
    name = f"_smtp._tls.{domain}"
    try:
        answers = _resolver.resolve(name, "TXT")
        record = next((str(r).strip('"') for r in answers if "v=TLSRPTv1" in str(r)), None)
        if not record:
            return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement TLS-RPT",
                    "raw_output": ""}
        rua_match = re.search(r'rua=([^;]+)', record)
        return {
            "status": "success",
            "data": {"present": True, "record": record,
                     "report_address": rua_match.group(1) if rua_match else None},
            "raw_output": f"{name}. IN TXT \"{record}\"",
        }
    except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
        return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement TLS-RPT",
                "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _bimi_check(domain: str) -> dict:
    """BIMI (default._bimi.<domain> TXT) — logo de marque affiché par les clients mail compatibles."""
    name = f"default._bimi.{domain}"
    try:
        answers = _resolver.resolve(name, "TXT")
        record = next((str(r).strip('"') for r in answers if "v=BIMI1" in str(r)), None)
        if not record:
            return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement BIMI",
                    "raw_output": ""}
        logo_match = re.search(r'l=([^;]+)', record)
        return {
            "status": "success",
            "data": {"present": True, "record": record,
                     "logo_url": logo_match.group(1) if logo_match else None},
            "raw_output": f"{name}. IN TXT \"{record}\"",
        }
    except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
        return {"status": "no_data", "data": {"present": False}, "error": "Aucun enregistrement BIMI",
                "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _caa_check(domain: str) -> dict:
    """CAA (<domain> CAA) — autorités de certification autorisées à émettre pour ce domaine."""
    try:
        answers = _resolver.resolve(domain, "CAA")
        records = []
        for r in answers:
            records.append({"flags": r.flags, "tag": r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag),
                             "value": r.value.decode() if isinstance(r.value, bytes) else str(r.value)})
        issue_cas = [r["value"] for r in records if r["tag"] == "issue"]
        return {
            "status": "success",
            "data": {
                "present": True,
                "records": records,
                "authorized_cas": issue_cas,
                "has_iodef": any(r["tag"] == "iodef" for r in records),
            },
            "raw_output": "\n".join(f"{domain}. IN CAA {r['flags']} {r['tag']} \"{r['value']}\"" for r in records),
        }
    except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
        return {
            "status": "no_data",
            "data": {"present": False},
            "error": "Aucun enregistrement CAA — n'importe quelle autorité de certification publique peut émettre pour ce domaine",
            "raw_output": "",
        }
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _dane_check(domain: str) -> dict:
    """DANE/TLSA (_443._tcp / _25._tcp.<domain> TLSA) — pin de certificat lié au DNS (nécessite DNSSEC)."""
    results = {}
    raw_parts = []
    for service_port, service_name in (("443", "https"), ("25", "smtp")):
        name = f"_{service_port}._tcp.{domain}"
        try:
            answers = _resolver.resolve(name, "TLSA")
            entries = [{"usage": r.usage, "selector": r.selector, "matching_type": r.mtype} for r in answers]
            results[service_name] = entries
            raw_parts.append(f"{name}. IN TLSA — {len(entries)} enregistrement(s)")
        except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
            results[service_name] = []
        except Exception:
            results[service_name] = []

    present = any(v for v in results.values())
    return {
        "status": "success" if present else "no_data",
        "data": {
            "present": present,
            "by_service": results,
            "note": "DANE n'a de valeur que si DNSSEC est actif sur le domaine (cf. outil dnssec)",
        },
        "error": None if present else "Aucun enregistrement TLSA (DANE non déployé)",
        "raw_output": "\n".join(raw_parts),
    }


def _http_observatory(domain: str) -> dict:
    """
    Note de posture de sécurité web via Mozilla HTTP Observatory (API v2, gratuite, sans clé).

    Convertit les en-têtes bruts (cf. `security_headers`) en un score normalisé
    A+ → F reconnu par les clients, avec le détail des tests échoués/réussis.
    """
    try:
        resp = _http.post(
            "https://observatory-api.mdn.mozilla.net/api/v2/scan",
            params={"host": domain},
            timeout=25,
        )
        raw_output = f"=== HTTP Observatory scan {domain} (HTTP {resp.status_code}) ===\n{resp.text[:3000]}"

        if resp.status_code not in (200, 201):
            return {
                "status": "error", "data": {},
                "error": f"HTTP {resp.status_code}", "raw_output": raw_output,
            }

        payload = resp.json() or {}
        grade = payload.get("grade")
        score = payload.get("score")
        tests = payload.get("tests") or {}
        failed = [
            {"name": name, "description": t.get("scoreDescription")}
            for name, t in tests.items() if isinstance(t, dict) and not t.get("pass", True)
        ]

        return {
            "status": "success",
            "data": {
                "grade": grade,
                "score": score,
                "tests_failed": failed,
                "tests_failed_count": len(failed),
                "tests_total": len(tests),
                "scan_url": f"https://developer.mozilla.org/en-US/observatory/analyze?host={domain}",
            },
            "raw_output": raw_output,
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "observatory-api.mdn.mozilla.net timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


def _abuseipdb_check(domain: str, ips: list = None) -> dict:
    """
    Score de réputation des IP résolues via AbuseIPDB (free tier 1000 req/j, sans CB).

    ABUSEIPDB_API_KEY optionnel : outil ignoré (status 'skipped') si absent,
    même comportement que github/hibp/otx.
    """
    api_key = os.getenv('ABUSEIPDB_API_KEY', '').strip()
    if not api_key:
        return {
            "status": "skipped", "data": {},
            "error": "ABUSEIPDB_API_KEY non configuré — clé gratuite sur https://www.abuseipdb.com/register",
            "raw_output": "",
        }

    if not ips:
        ips = _resolve_ips(domain)
    ips = [ip for ip in ips if ":" not in ip][:4]
    if not ips:
        return {"status": "error", "data": {}, "error": f"Aucune IPv4 résolue pour {domain}", "raw_output": ""}

    results = []
    raw_parts = []
    for ip in ips:
        try:
            resp = _http.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10,
            )
            raw_parts.append(f"=== AbuseIPDB {ip} (HTTP {resp.status_code}) ===\n{resp.text[:1000]}")
            if resp.status_code == 200:
                d = (resp.json() or {}).get("data", {})
                results.append({
                    "ip": ip,
                    "abuse_score": d.get("abuseConfidenceScore"),
                    "total_reports": d.get("totalReports"),
                    "isp": d.get("isp"),
                    "country": d.get("countryCode"),
                    "is_tor": d.get("isTor"),
                })
            else:
                results.append({"ip": ip, "status": "error", "error": f"HTTP {resp.status_code}"})
        except Exception as e:
            results.append({"ip": ip, "status": "error", "error": str(e)})

    max_score = max((r.get("abuse_score") or 0 for r in results), default=0)
    return {
        "status": "success",
        "data": {
            "ips": results,
            "max_abuse_score": max_score,
            "risk_level": "high" if max_score >= 50 else ("medium" if max_score >= 10 else "low"),
        },
        "raw_output": "\n\n".join(raw_parts),
    }


def _abusech_check(domain: str, ips: list = None) -> dict:
    """
    Présence dans les bases malware/C2 abuse.ch (URLhaus + ThreatFox), gratuit avec clé.

    ABUSECH_AUTH_KEY optionnel (clé unique pour les deux APIs, obtenue sur
    https://auth.abuse.ch/) : outil ignoré si absent.
    """
    auth_key = os.getenv('ABUSECH_AUTH_KEY', '').strip()
    if not auth_key:
        return {
            "status": "skipped", "data": {},
            "error": "ABUSECH_AUTH_KEY non configuré — clé gratuite sur https://auth.abuse.ch/",
            "raw_output": "",
        }

    headers = {"Auth-Key": auth_key}
    raw_parts = []
    urlhaus_hits, threatfox_hits = [], []

    try:
        resp = _http.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain}, headers=headers, timeout=12,
        )
        raw_parts.append(f"=== URLhaus host/{domain} (HTTP {resp.status_code}) ===\n{resp.text[:1500]}")
        payload = resp.json() or {}
        if payload.get("query_status") == "ok":
            urlhaus_hits = [
                {"url": u.get("url"), "threat": u.get("threat"), "date_added": u.get("date_added")}
                for u in (payload.get("urls") or [])
            ]
    except Exception as e:
        raw_parts.append(f"=== URLhaus ===\nERROR: {e}")

    if not ips:
        ips = _resolve_ips(domain)
    for ip in [i for i in ips if ":" not in i][:3]:
        try:
            resp = _http.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip}, headers=headers, timeout=12,
            )
            raw_parts.append(f"=== ThreatFox {ip} (HTTP {resp.status_code}) ===\n{resp.text[:1000]}")
            payload = resp.json() or {}
            if payload.get("query_status") == "ok":
                for ioc in (payload.get("data") or []):
                    threatfox_hits.append({
                        "ioc": ioc.get("ioc"), "malware": ioc.get("malware_printable"),
                        "ip": ip, "confidence": ioc.get("confidence_level"),
                    })
        except Exception as e:
            raw_parts.append(f"=== ThreatFox {ip} ===\nERROR: {e}")

    total = len(urlhaus_hits) + len(threatfox_hits)
    return {
        "status": "success",
        "data": {
            "urlhaus_urls": urlhaus_hits,
            "threatfox_iocs": threatfox_hits,
            "total_hits": total,
            "risk_level": "high" if total else "clean",
        },
        "raw_output": "\n\n".join(raw_parts),
    }


def _urlscan_search(domain: str) -> dict:
    """
    Historique de scans publics via urlscan.io (free tier, clé gratuite requise).

    Recherche passive dans les scans déjà soumis par d'autres (on ne soumet
    jamais de scan nous-mêmes — `/search/`, jamais `/scan/`, pour rester
    strictement passif et éviter de publier une nouvelle capture publique).
    """
    api_key = os.getenv('URLSCAN_API_KEY', '').strip()
    if not api_key:
        return {
            "status": "skipped", "data": {},
            "error": "URLSCAN_API_KEY non configuré — clé gratuite sur https://urlscan.io/user/signup",
            "raw_output": "",
        }

    try:
        resp = _http.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{domain}", "size": 50},
            headers={"API-Key": api_key},
            timeout=15,
        )
        raw_output = f"=== urlscan.io search page.domain:{domain} (HTTP {resp.status_code}) ===\n{resp.text[:3000]}"
        if resp.status_code != 200:
            return {"status": "error", "data": {}, "error": f"HTTP {resp.status_code}", "raw_output": raw_output}

        payload = resp.json() or {}
        results = payload.get("results") or []
        scans = [
            {
                "url": r.get("page", {}).get("url"),
                "domain": r.get("page", {}).get("domain"),
                "ip": r.get("page", {}).get("ip"),
                "server": r.get("page", {}).get("server"),
                "scan_date": r.get("task", {}).get("time"),
                "screenshot": r.get("screenshot"),
            }
            for r in results
        ]
        subdomains_seen = sorted({s["domain"] for s in scans if s.get("domain")})

        return {
            "status": "success",
            "data": {
                "scans": scans[:50],
                "scan_count": len(scans),
                "subdomains_seen": subdomains_seen,
                "total_results": payload.get("total", len(scans)),
            },
            "raw_output": raw_output,
        }
    except _requests.exceptions.Timeout:
        return {"status": "timeout", "data": {}, "error": "urlscan.io timeout", "raw_output": ""}
    except Exception as e:
        return {"status": "error", "data": {}, "error": str(e), "raw_output": ""}


# ===========================================================================

@pass_recon_bp.route('/pass_recon', methods=['POST'])
@require_auth
# Limite dédiée — jusque-là seul le défaut global le protégeait, partagé avec
# tout le reste (dashboard, n8n...) et régulièrement épuisé par du trafic de
# routine avant même d'atteindre cet endpoint (voir extensions.py). 30/h reste
# largement suffisant pour un usage self-hosted mono-tenant tout en bornant
# l'endpoint le plus coûteux (jusqu'à 47 outils, appels réseau externes réels)
# indépendamment du reste — CLAUDE.md §8 documentait ce manque.
@limiter.limit("30 per hour")
@swag_from({
    'tags': ['Passive Reconnaissance'],
    'summary': 'Reconnaissance passive complète sur un domaine (47 outils)',
    'description': (
        'Agrège **47 outils OSINT passifs** organisés en 11 catégories.\n\n'
        '### Format de chaque résultat\n'
        'Chaque outil retourne un objet structuré :\n'
        '```json\n'
        '{\n'
        '  "meta": {\n'
        '    "tool": "Nom affiché",\n'
        '    "category": "Catégorie",\n'
        '    "description": "Ce que fait l\'outil",\n'
        '    "indicators": { "champ": "signification" }\n'
        '  },\n'
        '  "data": { ... },\n'
        '  "status": "success|error|not_installed|timeout|not_found|unreachable|'
        'skipped|no_data|limited|unavailable",\n'
        '  "raw_output": "sortie brute pour interprétation IA"\n'
        '}\n'
        '```\n\n'
        '### Catégories d\'outils\n'
        '| Catégorie | Outils |\n'
        '|-----------|--------|\n'
        '| **Domain Intelligence** | `whois`, `rdap_info` |\n'
        '| **Subdomain Discovery** | `crtsh`, `subfinder`, `assetfinder`, `amass`, `github` |\n'
        '| **DNS / Réseau** | `dns`, `dns_records`, `dnssec`, `ip_info`, `ptr_records`, `asn_info` |\n'
        '| **SSL / TLS** | `ssl_info`, `tls_config`, `caa_check`, `dane_check` |\n'
        '| **Email / Messagerie** | `email_config`, `dkim_check`, `spf_analysis`, `dmarc_check`, '
        '`mta_sts_check`, `tlsrpt_check`, `bimi_check` |\n'
        '| **Web / HTTP** | `headers`, `security_headers`, `tech_stack`, `waf_detection`, '
        '`redirect_chain`, `favicon_hash`, `http_observatory` |\n'
        '| **Web / OSINT** | `robots_txt`, `sitemap`, `security_txt`, `js_endpoints` |\n'
        '| **Infrastructure / Cloud** | `reverse_ip` |\n'
        '| **Vulnérabilités Passives** | `subdomain_takeover`, `typosquatting` |\n'
        '| **Réputation / Threat Intel** | `dnsbl_check`, `shodan_internetdb`, `xposedornot_breaches`, '
        '`abuseipdb_check`, `abusech_check` |\n'
        '| **OSINT Externe** | `archive_history`, `otx_passive_dns`, `gau_urls`, `urlscan_search` |\n\n'
        '### Notes importantes\n'
        '- `subdomain_takeover` s\'exécute après la découverte de sous-domaines '
        '(détection passive par CNAME dangling, confiance `medium`, sans confirmation HTTP)\n'
        '- `shodan_internetdb` réutilise les IP résolues par `ip_info` (API gratuite, sans clé, '
        'consultation des observations Shodan existantes — aucune sonde envoyée à la cible) et enrichit '
        'ses CVE via CIRCL (CVSS) + EPSS (score d\'exploitabilité)\n'
        '- `rdap_info` complète `whois` avec des données structurées RFC 9083 (les deux coexistent)\n'
        '- `xposedornot_breaches` remplace l\'ancien HIBP (payant, inutilisable sans vérification de '
        'domaine) — teste des adresses rôle courantes (admin@, contact@…), pas le domaine entier\n'
        '- Clés d\'API optionnelles (dégradation propre en `skipped`/`limited` si absentes) : '
        '`OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSECH_AUTH_KEY`, `URLSCAN_API_KEY`\n'
        '- Si `tools` est omis, **tous les outils** sont lancés (peut prendre 5-15 min)\n'
    ),
    'parameters': [
        {
            'name': 'body', 'in': 'body', 'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'recon_id': {
                        'type': 'integer',
                        'example': 42,
                        'description': (
                            '(Recommandé) ID de l\'enregistrement Recon. '
                            'Si fourni, domain est lu depuis la BD et les résultats sont '
                            'automatiquement stockés dans recon.scan_results.'
                        ),
                    },
                    'domain': {
                        'type': 'string',
                        'example': 'example.com',
                        'description': (
                            'Domaine cible (sans http://). '
                            'Optionnel si recon_id est fourni (lu depuis la BD).'
                        ),
                    },
                    'email': {
                        'type': 'string',
                        'format': 'email',
                        'example': 'contact@example.com',
                        'description': (
                            '(Optionnel) Email de contact associé au scan — conservé pour la '
                            'traçabilité/les logs. Aucun outil n\'interroge de plateforme tierce '
                            'avec cette adresse.'
                        ),
                    },
                    'tools': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                # Découverte de sous-domaines / domaine (vague 1)
                                'whois', 'dns', 'crtsh', 'subfinder', 'assetfinder', 'amass', 'github',
                                # Réseau / DNS
                                'headers', 'ip_info', 'dns_records', 'dnssec', 'reverse_ip', 'asn_info',
                                'ptr_records', 'dnsbl_check',
                                # SSL / TLS
                                'ssl_info', 'tls_config',
                                # Email / anti-spoofing
                                'email_config', 'dkim_check', 'spf_analysis', 'dmarc_check',
                                'mta_sts_check', 'tlsrpt_check', 'bimi_check', 'dane_check',
                                # Web / surface applicative
                                'tech_stack', 'security_headers', 'robots_txt', 'sitemap',
                                'redirect_chain', 'security_txt', 'waf_detection', 'archive_history',
                                'caa_check', 'http_observatory',
                                # Sous-domaines / takeover / exposition
                                'subdomain_takeover', 'js_endpoints', 'favicon_hash', 'typosquatting',
                                'gau_urls',
                                # Réputation / threat intel / fuites
                                'shodan_internetdb', 'otx_passive_dns', 'rdap_info',
                                'xposedornot_breaches', 'abuseipdb_check', 'abusech_check',
                                'urlscan_search',
                            ],
                        },
                        'example': ['crtsh', 'subfinder', 'ssl_info', 'email_config', 'security_headers', 'waf_detection'],
                        'description': (
                            '(Optionnel) Liste des outils à exécuter. '
                            'Si absent, tous les 47 outils sont lancés. '
                            'Utilisez un sous-ensemble pour des analyses ciblées et rapides.'
                        ),
                    },
                },
                'additionalProperties': False,
            },
        }
    ],
    'responses': {
        200: {
            'description': 'Reconnaissance terminée avec succès',
            'schema': {
                'type': 'object',
                'properties': {
                    'success':  {'type': 'boolean', 'example': True},
                    'recon_id': {'type': 'integer', 'example': 42,
                                 'description': 'ID de l\'enregistrement Recon (présent si recon_id fourni)'},
                    'data': {
                        'type': 'object',
                        'properties': {
                            'domain': {'type': 'string', 'example': 'example.com'},
                            'tools_requested': {
                                'type': 'array',
                                'items': {'type': 'string'},
                                'description': 'Liste triée des outils exécutés',
                            },
                            'legend': {
                                'type': 'object',
                                'description': 'Format des résultats et catégories d\'outils',
                            },
                            'all_subdomains': {
                                'type': 'object',
                                'properties': {
                                    'data': {'type': 'array', 'items': {'type': 'string'}},
                                    'count': {'type': 'integer'},
                                },
                                'description': 'Union dédupliquée de tous les sous-domaines découverts',
                            },
                            'whois': {'$ref': '#/definitions/ToolResult'},
                            'dns': {'$ref': '#/definitions/ToolResult'},
                            'crtsh': {'$ref': '#/definitions/ToolResult'},
                            'subfinder': {'$ref': '#/definitions/ToolResult'},
                            'assetfinder': {'$ref': '#/definitions/ToolResult'},
                            'amass': {'$ref': '#/definitions/ToolResult'},
                            'github': {'$ref': '#/definitions/ToolResult'},
                            'headers': {'$ref': '#/definitions/ToolResult'},
                            'ip_info': {'$ref': '#/definitions/ToolResult'},
                            'dns_records': {'$ref': '#/definitions/ToolResult'},
                            'ssl_info': {'$ref': '#/definitions/ToolResult'},
                            'email_config': {'$ref': '#/definitions/ToolResult'},
                            'tech_stack': {'$ref': '#/definitions/ToolResult'},
                            'security_headers': {'$ref': '#/definitions/ToolResult'},
                            'robots_txt': {'$ref': '#/definitions/ToolResult'},
                            'sitemap': {'$ref': '#/definitions/ToolResult'},
                            'redirect_chain': {'$ref': '#/definitions/ToolResult'},
                            'security_txt': {'$ref': '#/definitions/ToolResult'},
                            'dnssec': {'$ref': '#/definitions/ToolResult'},
                            'waf_detection': {'$ref': '#/definitions/ToolResult'},
                            'archive_history': {'$ref': '#/definitions/ToolResult'},
                            'tls_config': {'$ref': '#/definitions/ToolResult'},
                            'reverse_ip': {'$ref': '#/definitions/ToolResult'},
                            'asn_info': {'$ref': '#/definitions/ToolResult'},
                            'ptr_records': {'$ref': '#/definitions/ToolResult'},
                            'dkim_check': {'$ref': '#/definitions/ToolResult'},
                            'spf_analysis': {'$ref': '#/definitions/ToolResult'},
                            'subdomain_takeover': {'$ref': '#/definitions/ToolResult'},
                            'js_endpoints': {'$ref': '#/definitions/ToolResult'},
                            'dnsbl_check': {'$ref': '#/definitions/ToolResult'},
                            'favicon_hash': {'$ref': '#/definitions/ToolResult'},
                        },
                    },
                },
            },
        },
        400: {
            'description': 'Requête invalide',
            'schema': {
                'type': 'object',
                'properties': {
                    'success': {'type': 'boolean', 'example': False},
                    'error': {'type': 'string', 'example': 'Format de domaine invalide'},
                },
            },
        },
        401: {
            'description': 'Authentification requise (Basic Auth)',
            'schema': {
                'type': 'object',
                'properties': {
                    'success': {'type': 'boolean', 'example': False},
                    'error': {'type': 'string', 'example': 'Authentification requise'},
                },
            },
        },
    },
    'definitions': {
        'ToolResult': {
            'type': 'object',
            'properties': {
                'status': {
                    'type': 'string',
                    'enum': ['success', 'error', 'not_installed', 'timeout', 'not_found',
                             'unreachable', 'skipped', 'no_data', 'limited', 'unavailable'],
                    'description': 'Statut de l\'exécution de l\'outil',
                },
                'meta': {
                    'type': 'object',
                    'description': 'Métadonnées de l\'outil : nom, catégorie, description, indicateurs expliqués',
                    'properties': {
                        'tool': {'type': 'string'},
                        'category': {'type': 'string'},
                        'description': {'type': 'string'},
                        'indicators': {
                            'type': 'object',
                            'additionalProperties': {'type': 'string'},
                            'description': 'Dictionnaire champ → explication de sa signification',
                        },
                    },
                },
                'data': {
                    'description': 'Données structurées retournées par l\'outil (format variable selon l\'outil)',
                },
                'raw_output': {
                    'type': 'string',
                    'description': 'Sortie brute exacte de l\'outil — à transmettre à l\'IA pour interprétation complémentaire',
                },
                'error': {
                    'type': 'string',
                    'description': 'Message d\'erreur (présent uniquement si status != success)',
                },
            },
        },
    },
    'security': [{'BasicAuth': []}],
    'x-code-samples': [
        {
            'lang': 'curl',
            'label': 'Scan rapide (DNS + SSL + Email)',
            'source': (
                'curl -u user:password -X POST https://api.idachallenge.bj/pass_recon \\\n'
                '  -H "Content-Type: application/json" \\\n'
                '  -d \'{"domain": "example.com", "tools": ["dns_records", "ssl_info", "email_config", "dkim_check", "spf_analysis"]}\''
            ),
        },
        {
            'lang': 'curl',
            'label': 'Scan web complet',
            'source': (
                'curl -u user:password -X POST https://api.idachallenge.bj/pass_recon \\\n'
                '  -H "Content-Type: application/json" \\\n'
                '  -d \'{"domain": "example.com", "tools": ["security_headers", "tech_stack", "waf_detection", "robots_txt", "js_endpoints", "favicon_hash"]}\''
            ),
        },
        {
            'lang': 'curl',
            'label': 'Scan infrastructure',
            'source': (
                'curl -u user:password -X POST https://api.idachallenge.bj/pass_recon \\\n'
                '  -H "Content-Type: application/json" \\\n'
                '  -d \'{"domain": "example.com", "tools": ["ip_info", "asn_info", "ptr_records", "reverse_ip", "dnsbl_check"]}\''
            ),
        },
        {
            'lang': 'python',
            'label': 'Python — scan complet',
            'source': (
                'import requests\n\n'
                'resp = requests.post(\n'
                '    "https://api.idachallenge.bj/pass_recon",\n'
                '    auth=("user", "password"),\n'
                '    json={"domain": "example.com"}\n'
                ')\n'
                'data = resp.json()["data"]\n'
                'print(f"Grade sécurité HTTP : {data[\'security_headers\'][\'data\'][\'grade\']}")\n'
                'print(f"Sous-domaines : {data[\'all_subdomains\'][\'count\']}")\n'
                'print(f"DMARC : {data[\'email_config\'][\'data\'][\'dmarc_status\']}")'
            ),
        },
    ],
})
def run_recon():
    """Reconnaissance passive — 35 outils avec cache 30 jours, métadonnées et sortie brute."""
    import time as _time
    from datetime import timedelta
    from models.pass_recon_cache import PassReconCache, CACHE_DEFAULT_TTL_DAYS
    from models.recon import Recon
    from database import db

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Données JSON requises"}), 400

    # ── Support recon_id — charge le domaine depuis la BD si non fourni ───────
    recon_id = data.get('recon_id')
    recon_record = None
    if recon_id:
        try:
            recon_record = Recon.query.get(int(recon_id))
            if not recon_record:
                return jsonify({"success": False,
                                "error": f"Enregistrement recon_id={recon_id} introuvable"}), 404
        except Exception as e:
            return jsonify({"success": False,
                            "error": f"recon_id invalide : {e}"}), 400

    # domain : depuis le body ou depuis la BD via recon_id
    if 'domain' not in data:
        if recon_record:
            data = dict(data)
            data['domain'] = recon_record.domain
        else:
            return jsonify({"success": False,
                            "error": "Champ 'domain' requis (ou fournissez recon_id)"}), 400

    domain = data['domain'].lower().strip()
    if not is_valid_domain(domain):
        return jsonify({"success": False, "error": "Format de domaine invalide"}), 400

    safe, ssrf_reason = is_safe_domain(domain)
    if not safe:
        return jsonify({"success": False, "error": f"Domaine refusé : {ssrf_reason}"}), 400

    email = data.get('email', '').strip()
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"success": False, "error": "Format d'email invalide"}), 400

    # Forçage du rescan (ignore le cache) et TTL personnalisé
    force_refresh = bool(data.get('force_refresh', False))
    cache_ttl_days = int(data.get('cache_ttl_days', CACHE_DEFAULT_TTL_DAYS))
    cache_ttl_days = max(1, min(cache_ttl_days, 365))  # borne entre 1 et 365 jours

    ALL_TOOLS = {
        # Subdomain Discovery
        'whois', 'dns', 'crtsh', 'subfinder', 'assetfinder', 'amass', 'github',
        # Domain Intelligence
        'rdap_info',
        # DNS / Réseau
        'dns_records', 'dnssec', 'ip_info', 'ptr_records', 'asn_info',
        # SSL / TLS
        'ssl_info', 'tls_config', 'caa_check', 'dane_check',
        # Email / Messagerie
        'email_config', 'dkim_check', 'spf_analysis',
        'dmarc_check', 'mta_sts_check', 'tlsrpt_check', 'bimi_check',
        # Web / HTTP
        'headers', 'security_headers', 'tech_stack', 'waf_detection',
        'redirect_chain', 'favicon_hash', 'http_observatory',
        # Web / OSINT
        'robots_txt', 'sitemap', 'security_txt', 'js_endpoints',
        # Infrastructure / Cloud
        'reverse_ip',
        # Vulnérabilités
        'subdomain_takeover', 'typosquatting',
        # Réputation / Threat Intel
        'dnsbl_check', 'shodan_internetdb', 'xposedornot_breaches',
        'abuseipdb_check', 'abusech_check',
        # OSINT Externe
        'archive_history', 'otx_passive_dns', 'gau_urls', 'urlscan_search',
    }

    requested_tools_raw = data.get('tools', list(ALL_TOOLS))
    requested_tools = {t.lower() for t in requested_tools_raw if isinstance(t, str)} & ALL_TOOLS

    if not requested_tools:
        return jsonify({"success": False,
                        "error": f"Aucun outil valide. Valeurs : {', '.join(sorted(ALL_TOOLS))}"}), 400

    # Tous les outils restants sont passifs et cachables
    CACHEABLE_TOOLS = set(requested_tools)
    tools_key = ",".join(sorted(CACHEABLE_TOOLS))

    logger.info("POST /pass_recon — domain=%s email=%s tools=%s force=%s IP=%s",
                domain, email or 'N/A', sorted(requested_tools), force_refresh, request.remote_addr)

    # ── Vérification du cache ──────────────────────────────────────────────────
    scan_start = _time.perf_counter()

    if not force_refresh and CACHEABLE_TOOLS:
        try:
            cache_entry = (
                PassReconCache.query
                .filter_by(domain=domain, tools_key=tools_key)
                .filter(PassReconCache.expires_at > datetime.utcnow())
                .first()
            )
            if cache_entry:
                cached_result = cache_entry.get_result()
                cache_entry.record_hit()
                db.session.commit()

                cached_result["cache"] = {
                    "hit": True,
                    "cache_id": cache_entry.id,
                    "cached_at": cache_entry.created_at.isoformat(),
                    "expires_at": cache_entry.expires_at.isoformat(),
                    "remaining_days": cache_entry.remaining_days,
                    "hit_count": cache_entry.hit_count,
                    "subdomain_count": cache_entry.subdomain_count,
                    "note": (
                        "Résultats servis depuis le cache. "
                        f"Expiration dans {cache_entry.remaining_days} jour(s). "
                        "Utilisez force_refresh=true pour relancer le scan."
                    ),
                }
                logger.info(
                    "POST /pass_recon — CACHE HIT domain=%s tools=%s hits=%d expires=%s",
                    domain, tools_key[:60], cache_entry.hit_count, cache_entry.expires_at.date(),
                )
                # Si recon_id fourni, stocker le résultat cache en BD
                if recon_record:
                    try:
                        _now = datetime.utcnow()
                        recon_record.scan_results = json.dumps(cached_result, ensure_ascii=False,
                                                               default=str)
                        recon_record.set_tools_status_summary(cached_result, ALL_TOOLS)
                        if not recon_record.started_at:
                            recon_record.started_at = _now
                        recon_record.completed_at   = _now
                        # `end_report_date` n'est PLUS positionné ici (bug corrigé
                        # 2026-07-29, même classe que `execution_time` ci-dessous) :
                        # ce champ représente la fin de TOUT le flux (utilisé par
                        # `flow_duration_s()`), pas la fin du scan seul — `completed_at`
                        # capture déjà correctement et sans ambiguïté "scan terminé"
                        # (utilisé par `scan_duration_s()`). Le figer ici à un cache-hit
                        # quasi instantané empêchait `flow_duration_s()` de jamais
                        # refléter la vraie durée totale (constaté : « Durée totale du
                        # processus » à 0,5s alors que l'analyse IA seule avait pris
                        # plus de 20 minutes).
                        # `execution_time` n'est PLUS positionné ici (bug corrigé
                        # 2026-07-29) : il ne représente que la durée scan→cache-hit
                        # (quasi instantanée), pas la durée totale du flux. Il est
                        # écrit une seule fois, à la vraie fin du pipeline
                        # (routes/report.py::generate_report, après PDF généré) —
                        # sans quoi ce très petit total figeait `execution_time` et
                        # empêchait la valeur finale correcte de jamais s'écrire
                        # (garde `not recon.execution_time` déjà vraie → jamais mise
                        # à jour). Constaté en conditions réelles : « Durée totale
                        # du processus » affichée à 0,5s alors que l'analyse IA
                        # seule avait pris plus de 20 minutes.
                        recon_record.status = 'running'   # scan terminé mais workflow n8n encore actif
                        recon_record.set_step('scanning_osint')
                        db.session.commit()
                        logger.info("pass_recon CACHE HIT — résultats stockés en BD recon_id=%s", recon_id)
                    except Exception as _e:
                        logger.error("pass_recon — erreur stockage cache→BD recon_id=%s: %s", recon_id, _e)
                        try: db.session.rollback()
                        except Exception: pass
                resp_data = {"success": True, "data": cached_result}
                if recon_record:
                    resp_data["recon_id"] = int(recon_id)
                return jsonify(resp_data), 200
        except Exception as cache_err:
            # Une erreur de cache ne bloque jamais le scan
            logger.warning("pass_recon — erreur lecture cache: %s", cache_err)

    # ── Pas de cache valide → scan complet ────────────────────────────────────

    # Marquer le début du scan en BD si recon_id fourni
    if recon_record:
        try:
            _scan_start_dt = datetime.utcnow()
            recon_record.started_at = _scan_start_dt
            recon_record.status     = 'running'
            recon_record.set_step('scanning_osint')
            db.session.commit()
            logger.info("pass_recon — statut 'running' enregistré en BD recon_id=%s", recon_id)
        except Exception as _e:
            logger.error("pass_recon — erreur mise à jour statut BD recon_id=%s: %s", recon_id, _e)
            try: db.session.rollback()
            except Exception: pass

    result = {
        "domain": domain,
        "tools_requested": sorted(requested_tools),
        "legend": {
            "result_format": {
                "meta": "Description de l'outil et signification de chaque indicateur",
                "data": "Données structurées et traitées",
                "raw_output": "Sortie brute exacte de l'outil — à transmettre à l'IA pour interprétation complémentaire",
                "status": ("success | error | not_installed | timeout | not_found | unreachable | "
                           "skipped (clé d'API absente) | no_data (source interrogée, aucun résultat) | "
                           "limited (accès anonyme restreint) | unavailable (service inexistant pour la cible)"),
            },
            "categories": {
                "Domain Intelligence": ["whois", "rdap_info"],
                "Subdomain Discovery": ["crtsh", "subfinder", "assetfinder", "amass", "github"],
                "DNS / Réseau": ["dns", "dns_records", "dnssec", "ip_info", "ptr_records", "asn_info"],
                "SSL / TLS": ["ssl_info", "tls_config", "caa_check", "dane_check"],
                "Email / Messagerie": ["email_config", "dkim_check", "spf_analysis",
                                       "dmarc_check", "mta_sts_check", "tlsrpt_check", "bimi_check"],
                "Web / HTTP": ["headers", "security_headers", "tech_stack", "waf_detection",
                               "redirect_chain", "favicon_hash", "http_observatory"],
                "Web / OSINT": ["robots_txt", "sitemap", "security_txt", "js_endpoints"],
                "Infrastructure / Cloud": ["reverse_ip"],
                "Vulnérabilités Passives": ["subdomain_takeover", "typosquatting"],
                "Réputation / Threat Intel": ["dnsbl_check", "shodan_internetdb", "xposedornot_breaches",
                                              "abuseipdb_check", "abusech_check"],
                "OSINT Externe": ["archive_history", "otx_passive_dns", "gau_urls", "urlscan_search"],
            },
        },
    }

    all_subs: set = set()

    with tempfile.TemporaryDirectory() as tmpdir:

        # ── VAGUE 1 : découverte et outils sans dépendance ────────────────────
        # amass, subfinder, assetfinder, crtsh et github alimentent tous
        # `all_subs` mais sont indépendants ENTRE EUX. Auparavant ils
        # s'exécutaient en série, si bien que la durée de cette phase était la
        # somme de leurs latences — dominée par amass (jusqu'à 180 s).
        # Ils tournent désormais ensemble ; l'union des sous-domaines est faite
        # après la vague, par le thread principal, donc sans course de données.
        # ip_info est inclus ici car shodan_internetdb (vague 2) réutilise les
        # IP qu'il résout.
        _wave1_specs = [
            ('whois',        lambda: _whois_tool(domain)),
            ('rdap_info',    lambda: _rdap_info(domain)),
            ('dns',          lambda: _dns_lookup_tool(domain)),
            ('crtsh',        lambda: _crtsh_tool(domain)),
            ('subfinder',    lambda: _subfinder_tool(domain, cwd=tmpdir)),
            ('assetfinder',  lambda: _assetfinder_tool(domain, cwd=tmpdir)),
            ('github',       lambda: _github_subdomains_tool(domain, cwd=tmpdir)),
            ('amass',        lambda: _amass_tool(domain, cwd=tmpdir)),
            ('ip_info',      lambda: _ip_info(domain)),
        ]
        _wave1_tasks = [
            ToolTask(key=_key, fn=_fn)
            for _key, _fn in _wave1_specs
            if _key in requested_tools
        ]

        if _wave1_tasks:
            logger.info(
                "pass_recon — vague 1 : %d outils de découverte en parallèle (max %d threads)",
                len(_wave1_tasks), _SCAN_MAX_WORKERS,
            )
            _wave1 = run_tools_parallel(
                _wave1_tasks,
                max_workers=_SCAN_MAX_WORKERS,
                overall_deadline_s=_SCAN_DEADLINE_S,
            )
            # Écriture et union depuis le seul thread principal.
            # L'ordre suit _wave1_specs, pas l'ordre d'achèvement des threads :
            # la sortie reste déterministe (cf. dataset_sha256 de la phase 3).
            for _key, _fn in _wave1_specs:
                _outcome = _wave1.get(_key)
                if _outcome is None:
                    continue
                result[_key] = _enrich(_key, _outcome.result)
                if _key in _SUBDOMAIN_TOOLS:
                    all_subs.update(_extract_subdomains(_outcome.result))

            if "rdap_info" in result:
                logger.info("pass_recon — rdap_info: %s", result["rdap_info"]["status"])
            for _sub_tool in _SUBDOMAIN_TOOLS:
                if _sub_tool in result:
                    logger.info(
                        "pass_recon — %s: %s (%d)", _sub_tool,
                        result[_sub_tool]["status"],
                        len(_extract_subdomains(result[_sub_tool])),
                    )

        # ── Synthèse sous-domaines ────────────────────────────────────────────
        result["all_subdomains"] = {
            "data": sorted(all_subs),
            "count": len(all_subs),
            "note": "Union dédupliquée de tous les outils de découverte de sous-domaines",
        }
        logger.info("pass_recon — %d sous-domaines uniques pour %s", len(all_subs), domain)

        # ── VAGUE 2 : outils dépendant de la vague 1 + outils indépendants ────
        # `headers` et `subdomain_takeover` consomment all_subs (désormais
        # complet) ; `shodan_internetdb` réutilise les IP résolues par ip_info
        # en vague 1 plutôt que de relancer une résolution DNS. Tout le reste
        # ne dépend que du domaine. Aucun de ces outils ne consomme le résultat
        # d'un autre de la même vague : ils s'exécutent donc simultanément.
        #
        # Résilience (utils/parallel.py) : l'exception d'un outil est isolée en
        # résultat status="error" au lieu de faire échouer tout le scan, et un
        # outil bloqué est borné par le deadline global.
        _ip_data = (result.get("ip_info") or {}).get("data")
        _ip_entries = _ip_data.get("ips") if isinstance(_ip_data, dict) else None
        _known_ips = [
            entry.get("ip")
            for entry in (_ip_entries or [])
            if isinstance(entry, dict) and entry.get("ip")
        ]

        _parallel_specs = [
            ('headers',            lambda: _http_headers_tool(all_subs)),
            ('shodan_internetdb',  lambda: _shodan_internetdb(domain, ips=_known_ips)),
            ('dns_records',        lambda: _dns_records(domain)),
            ('ssl_info',           lambda: _ssl_info(domain)),
            ('email_config',       lambda: _email_config(domain)),
            ('tech_stack',         lambda: _tech_stack(domain)),
            ('security_headers',   lambda: _security_headers(domain)),
            ('robots_txt',         lambda: _robots_txt(domain)),
            ('sitemap',            lambda: _sitemap(domain)),
            ('redirect_chain',     lambda: _redirect_chain(domain)),
            ('security_txt',       lambda: _security_txt(domain)),
            ('dnssec',             lambda: _dnssec(domain)),
            ('waf_detection',      lambda: _waf_detection(domain)),
            ('archive_history',    lambda: _archive_history(domain)),
            ('otx_passive_dns',    lambda: _otx_passive_dns(domain)),
            ('tls_config',         lambda: _tls_config(domain)),
            ('reverse_ip',         lambda: _reverse_ip(domain)),
            ('asn_info',           lambda: _asn_info(domain)),
            ('ptr_records',        lambda: _ptr_records(domain)),
            ('dkim_check',         lambda: _dkim_check(domain)),
            ('spf_analysis',       lambda: _spf_analysis(domain)),
            ('subdomain_takeover', lambda: _subdomain_takeover(all_subs, domain)),
            ('js_endpoints',       lambda: _js_endpoints(domain)),
            ('dnsbl_check',        lambda: _dnsbl_check(domain)),
            ('xposedornot_breaches', lambda: _xposedornot_breaches(domain)),
            ('favicon_hash',       lambda: _favicon_hash(domain)),
            ('typosquatting',      lambda: _typosquatting(domain)),
            ('gau_urls',           lambda: _gau_urls(domain)),
            ('dmarc_check',        lambda: _dmarc_check(domain)),
            ('mta_sts_check',      lambda: _mta_sts_check(domain)),
            ('tlsrpt_check',       lambda: _tlsrpt_check(domain)),
            ('bimi_check',         lambda: _bimi_check(domain)),
            ('caa_check',          lambda: _caa_check(domain)),
            ('dane_check',         lambda: _dane_check(domain)),
            ('http_observatory',   lambda: _http_observatory(domain)),
            ('abuseipdb_check',    lambda: _abuseipdb_check(domain, ips=_known_ips)),
            ('abusech_check',      lambda: _abusech_check(domain, ips=_known_ips)),
            ('urlscan_search',     lambda: _urlscan_search(domain)),
        ]

        _tasks = [
            ToolTask(key=_key, fn=_fn)
            for _key, _fn in _parallel_specs
            if _key in requested_tools
        ]

        if _tasks:
            logger.info(
                "pass_recon — vague 2 : %d outils en parallèle (max %d threads)",
                len(_tasks), _SCAN_MAX_WORKERS,
            )
            _outcomes = run_tools_parallel(
                _tasks,
                max_workers=_SCAN_MAX_WORKERS,
                overall_deadline_s=_SCAN_DEADLINE_S,
            )
            # Écriture dans `result` depuis le seul thread principal : aucune
            # section critique, l'ordre des clés reste déterministe car il suit
            # _parallel_specs et non l'ordre d'achèvement des threads.
            for _key, _fn in _parallel_specs:
                _outcome = _outcomes.get(_key)
                if _outcome is not None:
                    result[_key] = _enrich(_key, _outcome.result)

            # Journalisation métier conservée pour les outils qui l'avaient.
            if "otx_passive_dns" in result:
                logger.info("pass_recon — otx_passive_dns: %s (%s enregistrement(s))",
                            result["otx_passive_dns"]["status"],
                            result["otx_passive_dns"]["data"].get("count", 0))
            if "xposedornot_breaches" in result:
                logger.info("pass_recon — xposedornot_breaches: %s (%s fuite(s))",
                            result["xposedornot_breaches"]["status"],
                            result["xposedornot_breaches"]["data"].get("breach_count", 0))
            if "subdomain_takeover" in result:
                _vuln = result["subdomain_takeover"]["data"].get("vulnerable_count", 0)
                if _vuln:
                    logger.warning(
                        "pass_recon — %d sous-domaine(s) potentiellement vulnérable(s) pour %s",
                        _vuln, domain,
                    )
            if "shodan_internetdb" in result:
                logger.info("pass_recon — shodan_internetdb: %s (%d port(s))",
                            result["shodan_internetdb"]["status"],
                            len(result["shodan_internetdb"]["data"].get("ports", []) or []))

    scan_duration = _time.perf_counter() - scan_start

    logger.info(
        "POST /pass_recon — terminé pour %s — %d sous-domaines — %d outils — %.1fs",
        domain, len(all_subs), len(requested_tools), scan_duration,
    )

    # ── Sauvegarde du résultat en cache ───────────────────────────────────────
    if CACHEABLE_TOOLS:
        try:
            result_json = json.dumps(result, ensure_ascii=False, default=str)
            expires_at = datetime.utcnow() + timedelta(days=cache_ttl_days)

            existing = PassReconCache.query.filter_by(
                domain=domain, tools_key=tools_key
            ).first()

            if existing:
                # Mise à jour (rescan après expiration ou force_refresh)
                existing.result_json = result_json
                existing.scan_duration_s = scan_duration
                existing.subdomain_count = len(all_subs)
                existing.expires_at = expires_at
                existing.hit_count = 0
                existing.last_hit_at = None
                logger.info("pass_recon — cache UPDATED domain=%s expires=%s", domain, expires_at.date())
            else:
                # Nouvelle entrée
                cache_entry = PassReconCache(
                    domain=domain,
                    tools_key=tools_key,
                    result_json=result_json,
                    scan_duration_s=scan_duration,
                    subdomain_count=len(all_subs),
                    expires_at=expires_at,
                )
                db.session.add(cache_entry)
                logger.info("pass_recon — cache SAVED domain=%s ttl=%dd expires=%s",
                            domain, cache_ttl_days, expires_at.date())

            db.session.commit()
        except Exception as cache_err:
            logger.error("pass_recon — erreur sauvegarde cache: %s", cache_err)
            try:
                db.session.rollback()
            except Exception:
                pass

    # ── Persistance des résultats scan en BD si recon_id fourni ──────────────
    if recon_record:
        try:
            _scan_end_dt = datetime.utcnow()
            recon_record.scan_results    = json.dumps(result, ensure_ascii=False, default=str)
            recon_record.set_tools_status_summary(result, ALL_TOOLS)
            recon_record.completed_at    = _scan_end_dt
            # `end_report_date` n'est PLUS positionné ici — même bug et même
            # correctif que le repli cache-hit ci-dessus (`completed_at` capture
            # déjà "scan terminé" sans ambiguïté).
            recon_record.status          = 'running'   # scan terminé mais analyze + PDF encore en cours
            # `execution_time` n'est PLUS positionné ici (bug corrigé 2026-07-29,
            # voir le repli cache-hit ci-dessus pour l'explication complète) : ce
            # champ représente la durée TOTALE du flux, écrite une seule fois à
            # la vraie fin du pipeline (routes/report.py::generate_report). La
            # figer ici à la seule durée du scan empêchait la valeur finale
            # correcte de jamais s'écrire (garde `not recon.execution_time`).
            db.session.commit()
            logger.info(
                "pass_recon — résultats stockés en BD recon_id=%s domain=%s durée=%.1fs",
                recon_id, domain, scan_duration,
            )
        except Exception as _e:
            logger.error("pass_recon — erreur stockage résultats BD recon_id=%s: %s", recon_id, _e)
            try: db.session.rollback()
            except Exception: pass

    # Ajoute les infos de cache dans la réponse
    result["cache"] = {
        "hit": False,
        "cached_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(days=cache_ttl_days)).isoformat(),
        "ttl_days": cache_ttl_days,
        "scan_duration_s": round(scan_duration, 1),
        "note": f"Résultat mis en cache pour {cache_ttl_days} jours.",
    }

    resp_data = {"success": True, "data": result}
    if recon_record:
        resp_data["recon_id"] = int(recon_id)
    return jsonify(resp_data), 200
