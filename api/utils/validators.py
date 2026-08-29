import logging
import re
import ipaddress
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Plages IP privées/réservées bloquées pour protéger contre le SSRF
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (métadonnées cloud)
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking (RFC 2544)
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # réservé
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
]

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "broadcasthost"}

# Noms de services du réseau Docker interne — jamais des cibles légitimes.
_INTERNAL_NAMES = {"postgres", "redis", "ollama", "n8n", "api", "web",
                   "host.docker.internal"}


def _ip_is_blocked(addr) -> bool:
    """Vrai si l'adresse tombe dans une plage privée/réservée."""
    if any(addr in net for net in _PRIVATE_RANGES):
        return True
    # Filet de sécurité : couvre les plages que la liste explicite oublierait.
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def resolve_domain_ips(domain: str) -> list:
    """
    Résout un nom en toutes ses adresses (A et AAAA).

    Retourne une liste éventuellement vide ; ne lève jamais.
    """
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def is_safe_domain(domain: str) -> tuple:
    """
    Vérifie qu'un domaine ne désigne pas une adresse IP privée ou réservée.

    Retourne (True, None) si sûr, (False, raison) si SSRF potentiel détecté.

    La version précédente ne testait que les IP littérales et trois noms
    locaux : elle ne RÉSOLVAIT pas le domaine. Il suffisait donc de faire
    pointer un nom public vers 169.254.169.254 (métadonnées cloud) ou vers un
    service du réseau interne pour que le scanner aille l'interroger et
    retourne son contenu dans `raw_output`. On résout désormais le nom et on
    refuse si UNE SEULE des adresses obtenues est interne.

    Limite connue (DNS rebinding) : le nom est résolu ici, puis à nouveau par
    chaque outil au moment de la connexion. Un attaquant contrôlant un DNS à
    TTL très court peut renvoyer une IP publique à la vérification et une IP
    interne ensuite. S'en prémunir totalement impose d'épingler la connexion
    sur l'IP validée (adaptateur HTTP dédié) — non fait ici, signalé.
    """
    if not domain:
        return False, "Domaine vide"

    candidate = domain.strip().lower().rstrip('.')

    # 1. IP littérale
    try:
        addr = ipaddress.ip_address(candidate)
        if _ip_is_blocked(addr):
            return False, f"Adresse IP privée/réservée non autorisée : {domain}"
        return True, None
    except ValueError:
        pass  # domaine textuel — continuer

    # 2. Noms locaux et noms de services internes
    if candidate in _LOCAL_NAMES:
        return False, f"Domaine local non autorisé : {domain}"
    if candidate in _INTERNAL_NAMES or candidate.endswith('.internal'):
        return False, f"Nom de service interne non autorisé : {domain}"

    # 3. Résolution DNS — le contrôle qui manquait
    addresses = resolve_domain_ips(candidate)
    if not addresses:
        # Non résolvable : les outils ne pourront de toute façon rien joindre.
        # On laisse passer pour ne pas bloquer sur une panne DNS transitoire.
        logger.debug("is_safe_domain — %s non résolvable, autorisé par défaut", candidate)
        return True, None

    for addr in addresses:
        if _ip_is_blocked(addr):
            logger.warning(
                "SSRF bloqué — %s résout vers l'adresse interne %s", candidate, addr,
            )
            return False, (
                f"Le domaine {domain} résout vers une adresse interne "
                f"({addr}) — refusé pour prévenir les requêtes SSRF."
            )

    return True, None

DOMAIN_REGEX = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

HOST_REGEX = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d{1,5})?$'
)

ALLOWED_CRAWL_OPTIONS = {
    '--depth', '--threads', '--timeout', '--delay',
    '--max-urls', '--verbose', '--silent'
    # '--output' retiré : permettait une traversée de chemin (ex: --output ../../etc/passwd)
}


def is_valid_domain(domain: str) -> bool:
    # RFC 1035 : longueur max 253 caractères pour un FQDN
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain))


def is_valid_host(host: str) -> bool:
    """Valide un host (domaine optionnellement suivi de :port).
    Le port, si présent, doit être dans la plage valide [1, 65535].
    """
    if not HOST_REGEX.match(host):
        return False
    # Vérifier la plage du port si présent
    if ':' in host:
        try:
            port = int(host.rsplit(':', 1)[1])
            return 1 <= port <= 65535
        except (ValueError, IndexError):
            return False
    return True


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


def sanitize_crawl_options(options: list) -> tuple[list, str | None]:
    """Valide et nettoie les options passées au crawler.
    Retourne (options_valides, message_erreur_ou_None).
    """
    safe = []
    i = 0
    while i < len(options):
        opt = options[i]
        if opt in ALLOWED_CRAWL_OPTIONS:
            safe.append(opt)
            # Si l'option prend une valeur (non-flag), inclure la valeur suivante
            if i + 1 < len(options) and not options[i + 1].startswith('--'):
                val = options[i + 1]
                # Valider que la valeur est alphanumérique/numérique
                if re.match(r'^[\w.-]{1,50}$', val):
                    safe.append(val)
                    i += 2
                    continue
                else:
                    return [], f"Valeur invalide pour l'option {opt}: {val}"
        else:
            return [], f"Option non autorisée: {opt}"
        i += 1
    return safe, None
