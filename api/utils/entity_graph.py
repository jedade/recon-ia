# utils/entity_graph.py
"""
Construction du graphe d'entités depuis les résultats BRUTS d'un scan passif
(plan d'action, phase 7).

Deux étages, pour pouvoir tester l'extraction sans base de données :

  extract_graph(domain, raw_results)
      Fonction PURE : lit `scan_results` (clés d'outils de routes/recon.py) et
      retourne les entités et relations normalisées. Tolérante : un outil
      absent, en échec ou au format inattendu est simplement ignoré.

  build_graph_from_raw(domain, raw_results, scan_ref, now, recon_id=None)
      Upsert des entités (unicité type+valeur) et des relations (unicité
      source+cible+type+domaine racine) dans les tables `entity`/`relation`.
      Flush sans commit : l'appelant commite (routes/report.py, routes/graph.py).

Chaîne modélisée et types de relation
─────────────────────────────────────
  organization ─owns──────────────► domain          (O= du certificat OV/EV)
  domain       ─has_subdomain─────► subdomain       (union des outils de découverte)
  domain|sub   ─resolves_to───────► ip              (dns_records, ip_info, résolution)
  subdomain    ─observed_on───────► ip              (hostnames vus par Shodan sur l'IP)
  ip           ─announced_by──────► asn             (asn_info, ip_info)
  asn          ─operated_by───────► organization    (titulaire de l'ASN)
  domain       ─presents_certificate► certificate   (ssl_info)
  certificate  ─covers────────────► domain|sub      (SAN)
  domain       ─uses_technology───► technology      (tech_stack, waf_detection)
  ip           ─runs──────────────► technology      (CPE Shodan)
  ip           ─exposes───────────► vulnerability   (CVE Shodan InternetDB)
  ip           ─has_port──────────► port            (« ip:port », Shodan InternetDB)

InternetDB ne rattache pas une CVE à un CPE précis : la vulnérabilité est
donc liée à l'IP qui l'expose, pas à une technologie (ce serait inventer un
lien que la source ne donne pas).

Données exclues par construction (pas de PII)
─────────────────────────────────────────────
Seules des entités techniques publiques sont retenues. Les outils WHOIS/RDAP
(titulaire pouvant être une personne physique), fuites de comptes
(xposedornot), DKIM, emails DMARC… ne sont jamais lus. Toute valeur contenant
« @ » est rejetée, quel que soit le type. Les IP non routables (privées,
loopback, réservées) sont écartées : elles n'ont rien à faire dans un export
d'hôtes destiné à une phase active.
"""
import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Statuts d'outil considérés comme « observation exploitable »
OK_STATUSES = ('success', 'timeout_partial', 'no_data')

# Garde-fou : nombre maximal d'entités extraites d'un même scan
MAX_ENTITIES_PER_SCAN = 5000
# Sous-domaines simplement énumérés (crt.sh, subfinder…) : plafonnés à part
# pour laisser la place aux entités d'infrastructure (IP, ASN, certificat,
# CVE…) et aux sous-domaines résolus. Sans ce plafond, un domaine très
# énuméré (example.com : ~5 000 noms) remplissait seul le graphe.
MAX_ENUMERATED_SUBDOMAINS = 3000

_LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_ASN_RE = re.compile(r'^\s*(?:AS)?\s*(\d{1,10})\b', re.IGNORECASE)
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
_SERIAL_RE = re.compile(r'^[0-9A-Fa-f:]{1,128}$')
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')
_SPACES_RE = re.compile(r'\s+')

# Clés candidates pour la résolution DNS massive des sous-domaines (phase 5,
# format non figé au moment d'écrire ce module) : toute clé contenant
# « resol » est aussi examinée, avec plusieurs formes de données acceptées
# (voir _iter_host_ips).
_RESOLUTION_KEYS = (
    'dns_mass',  # phase 5 : {"hosts": [{"subdomain", "ips", ...}]}
    'subdomain_resolution', 'subdomains_resolution', 'subdomain_dns',
    'dns_resolution', 'resolved_subdomains', 'mass_dns', 'massdns', 'dnsx',
)

_SUBDOMAIN_TOOLS = ('crtsh', 'subfinder', 'assetfinder', 'amass', 'github',
                    'otx_passive_dns', 'urlscan_search')

# Clés d'une valeur de résolution pouvant porter des IP
_IP_FIELDS = ('ips', 'ip', 'a', 'A', 'aaaa', 'AAAA', 'addresses', 'ipv4', 'ipv6')


# ── Normalisation (partagée avec utils/scan_diff.py) ─────────────────────────

def norm_hostname(value, root: Optional[str] = None) -> Optional[str]:
    """
    Nom d'hôte en minuscules, sans point final ni joker « *. ». None s'il est
    invalide ou, quand `root` est fourni, s'il n'est ni `root` ni sous `root`.
    """
    if not isinstance(value, str):
        return None
    host = value.strip().lower().rstrip('.')
    if host.startswith('*.'):
        host = host[2:]
    if not host or len(host) > 253 or '@' in host:
        return None
    labels = host.split('.')
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    if not re.match(r'^[a-z][a-z0-9-]*$', labels[-1]):
        return None
    if root and host != root and not host.endswith('.' + root):
        return None
    return host


def norm_ip(value) -> Optional[str]:
    """Adresse IP routable sur Internet (forme canonique), sinon None."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not addr.is_global:
        return None
    return addr.compressed


def norm_asn(value) -> Optional[str]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f'AS{value}' if value > 0 else None
    if not isinstance(value, str):
        return None
    match = _ASN_RE.match(value)
    if not match or int(match.group(1)) <= 0:
        return None
    return f'AS{int(match.group(1))}'


def norm_cve(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cve = value.strip().upper()
    return cve if _CVE_RE.match(cve) else None


def norm_text(value, max_len: int = 128) -> Optional[str]:
    """Libellé court (technologie, organisation) : sans contrôle ni « @ »."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = _SPACES_RE.sub(' ', _CONTROL_RE.sub(' ', str(value))).strip()
    if not text or '@' in text:
        return None
    return text[:max_len]


def norm_port(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def certificate_id(cert: dict) -> Optional[str]:
    """Identifiant stable d'un certificat : numéro de série, sinon empreinte des champs."""
    if not isinstance(cert, dict):
        return None
    serial = cert.get('serial_number')
    if isinstance(serial, str) and _SERIAL_RE.match(serial.strip()):
        return 'serial:' + serial.strip().replace(':', '').upper()
    subject = cert.get('subject') if isinstance(cert.get('subject'), dict) else {}
    issuer = cert.get('issuer') if isinstance(cert.get('issuer'), dict) else {}
    basis = '|'.join(str(x or '') for x in (
        subject.get('commonName'), issuer.get('organizationName'),
        issuer.get('commonName'), cert.get('not_before'), cert.get('not_after')))
    if basis.strip('|'):
        return 'sha256:' + hashlib.sha256(basis.encode('utf-8')).hexdigest()[:32]
    return None


# ── Accès tolérant aux résultats d'outils ────────────────────────────────────

def tool_entry(raw: dict, key: str) -> Optional[dict]:
    entry = raw.get(key) if isinstance(raw, dict) else None
    return entry if isinstance(entry, dict) else None


def tool_ok(raw: dict, key: str) -> bool:
    entry = tool_entry(raw, key)
    return bool(entry) and entry.get('status') in OK_STATUSES


def tool_data(raw: dict, key: str, ok_only: bool = True):
    entry = tool_entry(raw, key)
    if not entry:
        return None
    if ok_only and entry.get('status') not in OK_STATUSES and 'status' in entry:
        return None
    return entry.get('data')


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, (str, int)):
        return [value]
    return []


def _ips_of(value) -> list:
    """Extrait une liste d'IP d'une valeur de forme variable (str, liste, dict)."""
    if isinstance(value, dict):
        out = []
        for key in _IP_FIELDS:
            out.extend(i for i in _as_list(value.get(key)) if isinstance(i, str))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_ips_of(item) if isinstance(item, dict) else [item])
        return out
    return _as_list(value)


def _iter_host_ips(raw: dict):
    """
    Couples (hôte, [ip]) produits par un outil de résolution DNS des
    sous-domaines. Formes acceptées pour `data` :
      {"resolved": {...}} / {"records"|"hosts"|"results"|"subdomains": ...}
      {"www.ex.com": ["1.2.3.4"], ...}
      [{"host"|"subdomain"|"name"|"hostname": "...", "ips"|"a"|"A"|"addresses"|"ip": ...}, ...]
    """
    keys = list(_RESOLUTION_KEYS) + [k for k in raw if isinstance(k, str) and 'resol' in k
                                     and k not in _RESOLUTION_KEYS]
    for key in keys:
        data = tool_data(raw, key)
        yield from _walk_resolution(data, depth=0)


def _walk_resolution(data, depth: int):
    if depth > 2 or data is None:
        return
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            host = (item.get('host') or item.get('subdomain') or item.get('name')
                    or item.get('hostname') or item.get('fqdn'))
            if isinstance(host, str):
                yield host, _ips_of(item)
        return
    if isinstance(data, dict):
        for wrapper in ('resolved', 'records', 'hosts', 'results', 'subdomains', 'data'):
            if isinstance(data.get(wrapper), (dict, list)):
                yield from _walk_resolution(data[wrapper], depth + 1)
        for host, value in data.items():
            if isinstance(host, str) and '.' in host and norm_hostname(host):
                yield host, _ips_of(value)


# ── Extraction (fonction pure) ────────────────────────────────────────────────

class _Collector:
    def __init__(self):
        self.entities = {}    # (type, valeur) -> attributs
        self.relations = {}   # ((type, valeur), (type, valeur), type_relation) -> outil

    def entity(self, etype: str, value: Optional[str], attrs: Optional[dict] = None):
        if value is None:
            return None
        key = (etype, value)
        if key not in self.entities:
            if len(self.entities) >= MAX_ENTITIES_PER_SCAN:
                return None
            self.entities[key] = {}
        if attrs:
            self.entities[key].update({k: v for k, v in attrs.items() if v is not None})
        return key

    def relation(self, source, target, rtype: str, tool: str):
        if source is None or target is None or source == target:
            return
        self.relations.setdefault((source, target, rtype), tool)


def _host_key(col: _Collector, host: str, root: str):
    return col.entity('domain' if host == root else 'subdomain', host)


def _enumerated_subdomains(raw: dict, root: str) -> list:
    """
    Sous-domaines énumérés (union de pass_recon puis outils individuels),
    normalisés, dédoublonnés et TRIÉS : [(hôte, premier outil qui l'a vu)].
    """
    seen = {}
    sources = []
    all_subs = raw.get('all_subdomains')
    if isinstance(all_subs, dict):
        sources.append(('all_subdomains', _as_list(all_subs.get('data'))))
    for key in _SUBDOMAIN_TOOLS:
        data = tool_data(raw, key)
        if isinstance(data, list):
            sources.append((key, data))
        elif isinstance(data, dict):
            sources.append((key, _as_list(data.get('subdomains'))))
    for tool, values in sources:
        for value in values:
            host = norm_hostname(value, root)
            if host and host != root and host not in seen:
                seen[host] = tool
    return sorted(seen.items())


def subdomain_names(domain, raw_results) -> set:
    """
    TOUS les sous-domaines observés d'un scan (énumérés et résolus), sans le
    plafond du graphe : base du différentiel entre deux scans
    (utils/scan_diff.py), qui doit comparer des ensembles complets.
    """
    root = norm_hostname(domain) if isinstance(domain, str) else None
    if not root or not isinstance(raw_results, dict):
        return set()
    names = {host for host, _ in _enumerated_subdomains(raw_results, root)}
    for host, _ips in _iter_host_ips(raw_results):
        h = norm_hostname(host, root)
        if h and h != root:
            names.add(h)
    return names


def extract_graph(domain, raw_results) -> dict:
    """
    Entités et relations d'un scan, normalisées et sans PII.

    Retourne {'domain', 'entities': {(type, valeur): attributs},
              'relations': {(source, cible, type): outil}}.
    """
    root = norm_hostname(domain) if isinstance(domain, str) else None
    col = _Collector()
    if not root or not isinstance(raw_results, dict):
        return {'domain': root, 'entities': col.entities, 'relations': col.relations}
    raw = raw_results
    dom = col.entity('domain', root)

    # Sous-domaines énumérés : ordre trié, donc sélection identique d'un scan
    # à l'autre quand le plafond s'applique (sinon le graphe changerait sans
    # que la cible change).
    enumerated = 0
    for host, tool in _enumerated_subdomains(raw, root):
        if enumerated >= MAX_ENUMERATED_SUBDOMAINS:
            break
        enumerated += 1
        col.relation(dom, col.entity('subdomain', host), 'has_subdomain', tool)

    # Résolution du domaine racine
    dns = tool_data(raw, 'dns_records')
    if isinstance(dns, dict):
        for ip in _as_list(dns.get('A')) + _as_list(dns.get('AAAA')):
            col.relation(dom, col.entity('ip', norm_ip(ip)), 'resolves_to', 'dns_records')

    # Résolution des sous-domaines (phase 5)
    for host, ips in _iter_host_ips(raw):
        hkey_host = norm_hostname(host, root)
        if not hkey_host:
            continue
        hkey = _host_key(col, hkey_host, root)
        if hkey_host != root:
            col.relation(dom, hkey, 'has_subdomain', 'subdomain_resolution')
        for ip in ips:
            col.relation(hkey, col.entity('ip', norm_ip(ip)), 'resolves_to', 'subdomain_resolution')

    # ip_info : IP du domaine + ASN (champ org « AS16276 OVH SAS ») + pays
    ip_info = tool_data(raw, 'ip_info')
    if isinstance(ip_info, dict):
        for entry in _as_list(ip_info.get('ips')):
            if not isinstance(entry, dict):
                continue
            ip_key = col.entity('ip', norm_ip(entry.get('ip')),
                                {'country': norm_text(entry.get('country'), 8)})
            col.relation(dom, ip_key, 'resolves_to', 'ip_info')
            org = entry.get('org')
            asn = norm_asn(org) if isinstance(org, str) and org.upper().startswith('AS') else None
            if asn:
                holder = norm_text(org.split(' ', 1)[1]) if ' ' in org.strip() else None
                asn_key = col.entity('asn', asn, {'name': holder})
                col.relation(ip_key, asn_key, 'announced_by', 'ip_info')
                col.relation(asn_key, col.entity('organization', holder), 'operated_by', 'ip_info')

    # asn_info (RIPEstat)
    asn_info = tool_data(raw, 'asn_info')
    if isinstance(asn_info, dict):
        asn = norm_asn(asn_info.get('asn'))
        holder = norm_text(asn_info.get('asn_name'))
        asn_key = col.entity('asn', asn, {'name': holder,
                                          'prefix_count': asn_info.get('prefix_count')
                                          if isinstance(asn_info.get('prefix_count'), int) else None})
        ip_key = col.entity('ip', norm_ip(asn_info.get('ip_queried')))
        col.relation(dom, ip_key, 'resolves_to', 'asn_info')
        col.relation(ip_key, asn_key, 'announced_by', 'asn_info')
        col.relation(asn_key, col.entity('organization', holder), 'operated_by', 'asn_info')

    # Certificat TLS du domaine
    cert = tool_data(raw, 'ssl_info')
    if isinstance(cert, dict) and cert:
        subject = cert.get('subject') if isinstance(cert.get('subject'), dict) else {}
        issuer = cert.get('issuer') if isinstance(cert.get('issuer'), dict) else {}
        cert_key = col.entity('certificate', certificate_id(cert), {
            'subject_cn': norm_hostname(subject.get('commonName')) or norm_text(subject.get('commonName')),
            'issuer': norm_text(issuer.get('organizationName') or issuer.get('commonName')),
            'not_before': norm_text(cert.get('not_before'), 40),
            'not_after': norm_text(cert.get('not_after'), 40),
            'san_count': cert.get('san_count') if isinstance(cert.get('san_count'), int) else None,
        })
        col.relation(dom, cert_key, 'presents_certificate', 'ssl_info')
        for san in _as_list(cert.get('san')):
            host = norm_hostname(san, root)
            if host:
                hkey = _host_key(col, host, root)
                col.relation(cert_key, hkey, 'covers', 'ssl_info')
                if host != root:
                    col.relation(dom, hkey, 'has_subdomain', 'ssl_info')
        # Organisation titulaire (certificat OV/EV : entité morale vérifiée par l'AC)
        col.relation(col.entity('organization', norm_text(subject.get('organizationName'))),
                     dom, 'owns', 'ssl_info')

    # Technologies du site
    tech = tool_data(raw, 'tech_stack')
    if isinstance(tech, dict):
        names = [tech.get('server'), tech.get('powered_by')]
        for key in ('cms', 'javascript_frameworks', 'cdn'):
            names.extend(_as_list(tech.get(key)))
        for name in names:
            col.relation(dom, col.entity('technology', norm_text(name)), 'uses_technology', 'tech_stack')
    waf = tool_data(raw, 'waf_detection')
    if isinstance(waf, dict):
        for entry in _as_list(waf.get('detected')):
            name = entry.get('name') if isinstance(entry, dict) else entry
            col.relation(dom, col.entity('technology', norm_text(name)), 'uses_technology', 'waf_detection')

    # Shodan InternetDB : ports, CPE, CVE, hostnames par IP
    shodan = tool_data(raw, 'shodan_internetdb')
    if isinstance(shodan, dict):
        enriched = {}
        for item in _as_list(shodan.get('vulns_enriched')):
            if isinstance(item, dict) and norm_cve(item.get('id')):
                enriched[norm_cve(item.get('id'))] = {
                    'cvss': item.get('cvss') if isinstance(item.get('cvss'), (int, float)) else None,
                    'epss': item.get('epss') if isinstance(item.get('epss'), (int, float)) else None,
                }
        for entry in _as_list(shodan.get('ips')):
            if not isinstance(entry, dict):
                continue
            ip = norm_ip(entry.get('ip'))
            ip_key = col.entity('ip', ip)
            if ip_key is None:
                continue
            col.relation(dom, ip_key, 'resolves_to', 'shodan_internetdb')
            for port in _as_list(entry.get('ports')):
                port = norm_port(port)
                if port:
                    col.relation(ip_key, col.entity('port', f'{ip}:{port}', {'ip': ip, 'port': port}),
                                 'has_port', 'shodan_internetdb')
            for cpe in _as_list(entry.get('cpes')):
                col.relation(ip_key, col.entity('technology', norm_text(cpe)), 'runs', 'shodan_internetdb')
            for vuln in _as_list(entry.get('vulns')):
                cve = norm_cve(vuln)
                col.relation(ip_key, col.entity('vulnerability', cve, enriched.get(cve)),
                             'exposes', 'shodan_internetdb')
            for hostname in _as_list(entry.get('hostnames')):
                host = norm_hostname(hostname, root)
                if host:
                    hkey = _host_key(col, host, root)
                    if host != root:
                        col.relation(dom, hkey, 'has_subdomain', 'shodan_internetdb')
                    col.relation(hkey, ip_key, 'observed_on', 'shodan_internetdb')

    # Pivots de la boucle agent (phase 8) : chaque résultat a le format standard
    # d'un outil (registry_key) et est rejoué par la même logique, isolément
    # (le mini-scan n'a pas de clé agent_pivots : pas de récursion).
    # ok_only=False : une boucle arrêtée sur erreur garde ses pivots réussis,
    # chacun filtré ensuite par son propre statut.
    pivots = tool_data(raw, 'agent_pivots', ok_only=False)
    if isinstance(pivots, dict):
        for item in (pivots.get('results') or [])[:50]:
            if not isinstance(item, dict) or not isinstance(item.get('result'), dict):
                continue
            key = item.get('registry_key')
            if not isinstance(key, str) or key == 'agent_pivots':
                continue
            sub = extract_graph(root, {key: item['result']})
            for ekey, attrs in sub['entities'].items():
                if ekey not in col.entities:
                    if len(col.entities) >= MAX_ENTITIES_PER_SCAN:
                        break
                    col.entities[ekey] = {}
                col.entities[ekey].update(attrs)
            for rkey, tool in sub['relations'].items():
                if rkey[0] in col.entities and rkey[1] in col.entities:
                    col.relations.setdefault(rkey, tool)

    return {'domain': root, 'entities': col.entities, 'relations': col.relations}


# ── Persistance (upsert) ──────────────────────────────────────────────────────

def _chunks(items: list, size: int = 400):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def build_graph_from_raw(domain, raw_results, scan_ref: str, now: Optional[datetime] = None,
                         recon_id: Optional[int] = None) -> dict:
    """
    Upsert du graphe d'un scan. Ne commite pas (flush uniquement).

    Retourne des compteurs : {'domain', 'entities', 'new_entities',
    'relations', 'new_relations', 'by_type'}. Un domaine invalide ou des
    résultats illisibles produisent des compteurs nuls, jamais une exception.
    """
    from database import db
    from models.entity_graph import Entity, Relation

    now = now or datetime.utcnow()
    graph = extract_graph(domain, raw_results)
    stats = {'domain': graph['domain'], 'entities': 0, 'new_entities': 0,
             'relations': 0, 'new_relations': 0, 'by_type': {}}
    if not graph['domain'] or not graph['entities']:
        return stats
    root = graph['domain']
    scan_ref = (str(scan_ref or '')[:128]) or None

    # 1. Entités : chargement groupé par type, puis création des manquantes
    by_type = {}
    for etype, value in graph['entities']:
        by_type.setdefault(etype, []).append(value)
    existing = {}
    for etype, values in by_type.items():
        for chunk in _chunks(values):
            for ent in Entity.query.filter(Entity.type == etype, Entity.value.in_(chunk)).all():
                existing[(ent.type, ent.value)] = ent

    for key, attrs in graph['entities'].items():
        ent = existing.get(key)
        if ent is None:
            ent = Entity(type=key[0], value=key[1], first_seen=now, last_seen=now,
                         attributes=json.dumps(attrs, ensure_ascii=False, sort_keys=True) if attrs else None)
            db.session.add(ent)
            existing[key] = ent
            stats['new_entities'] += 1
        else:
            if ent.last_seen is None or ent.last_seen < now:
                ent.last_seen = now
            if ent.first_seen is None or ent.first_seen > now:
                ent.first_seen = now
            if attrs:
                merged = ent.get_attributes()
                merged.update(attrs)
                ent.attributes = json.dumps(merged, ensure_ascii=False, sort_keys=True)
        stats['by_type'][key[0]] = stats['by_type'].get(key[0], 0) + 1
    stats['entities'] = len(graph['entities'])
    db.session.flush()

    # 2. Relations du domaine racine
    known = {(r.source_id, r.target_id, r.type): r
             for r in Relation.query.filter(Relation.root_domain == root).all()}
    for (source, target, rtype), tool in graph['relations'].items():
        sid, tid = existing[source].id, existing[target].id
        rel = known.get((sid, tid, rtype))
        if rel is None:
            rel = Relation(source_id=sid, target_id=tid, type=rtype, tool=tool, root_domain=root,
                           recon_id=recon_id, scan_ref=scan_ref, first_seen=now, last_seen=now)
            db.session.add(rel)
            known[(sid, tid, rtype)] = rel
            stats['new_relations'] += 1
        else:
            if rel.last_seen is None or rel.last_seen <= now:
                rel.last_seen = now
                rel.tool = tool
                rel.scan_ref = scan_ref
                if recon_id is not None:
                    rel.recon_id = recon_id
            if rel.first_seen is None or rel.first_seen > now:
                rel.first_seen = now
    stats['relations'] = len(graph['relations'])
    db.session.flush()
    logger.info('[graph] %s — %d entité(s) (%d nouvelle(s)), %d relation(s) (%d nouvelle(s)) — %s',
                root, stats['entities'], stats['new_entities'], stats['relations'],
                stats['new_relations'], scan_ref)
    return stats


# ── Lecture du sous-graphe d'un domaine ───────────────────────────────────────

def domain_entity_ids(root: str):
    """Sous-requête des id d'entités reliées au domaine racine `root`."""
    from database import db
    from models.entity_graph import Relation
    src = db.session.query(Relation.source_id.label('eid')).filter(Relation.root_domain == root)
    tgt = db.session.query(Relation.target_id.label('eid')).filter(Relation.root_domain == root)
    return src.union(tgt).subquery()


def graph_summary(root: Optional[str] = None) -> dict:
    """Compteurs par type d'entité et de relation (global ou pour un domaine)."""
    from sqlalchemy import func, select
    from database import db
    from models.entity_graph import Entity, Relation
    from models.recon import utc_iso

    ent_q = db.session.query(Entity.type, func.count(Entity.id), func.max(Entity.last_seen))
    rel_q = db.session.query(Relation.type, func.count(Relation.id))
    if root:
        ids = domain_entity_ids(root)
        ent_q = ent_q.filter(Entity.id.in_(select(ids.c.eid)))
        rel_q = rel_q.filter(Relation.root_domain == root)
    rows = ent_q.group_by(Entity.type).all()
    entities = {t: c for t, c, _ in rows}
    last_seen = max((ls for _, _, ls in rows if ls), default=None)
    relations = {t: c for t, c in rel_q.group_by(Relation.type).all()}
    return {
        'domain': root,
        'entities_by_type': entities,
        'entities_total': sum(entities.values()),
        'relations_by_type': relations,
        'relations_total': sum(relations.values()),
        'last_seen': utc_iso(last_seen),
    }


def live_hosts(root: str, since: Optional[datetime] = None) -> list:
    """
    Hôtes vivants d'un domaine d'après le graphe : nom d'hôte → IP (relations
    resolves_to / observed_on), avec les ports connus de chaque IP.
    `since` : ne garder que les observations postérieures.
    """
    from database import db
    from models.entity_graph import Entity, Relation
    from models.recon import utc_iso

    host_rels = Relation.query.filter(Relation.root_domain == root,
                                      Relation.type.in_(('resolves_to', 'observed_on')))
    port_rels = Relation.query.filter(Relation.root_domain == root, Relation.type == 'has_port')
    if since is not None:
        host_rels = host_rels.filter(Relation.last_seen >= since)
        port_rels = port_rels.filter(Relation.last_seen >= since)
    host_rels = host_rels.all()
    port_rels = port_rels.all()
    ids = {r.source_id for r in host_rels} | {r.target_id for r in host_rels} | \
          {r.target_id for r in port_rels}
    entities = {}
    for chunk in _chunks(sorted(ids)):
        for ent in Entity.query.filter(Entity.id.in_(chunk)).all():
            entities[ent.id] = ent

    ports_by_ip = {}
    for rel in port_rels:
        port_ent = entities.get(rel.target_id)
        if port_ent is None:
            continue
        port = port_ent.get_attributes().get('port')
        if port is None and ':' in port_ent.value:
            port = norm_port(port_ent.value.rsplit(':', 1)[1])
        if port:
            ports_by_ip.setdefault(rel.source_id, set()).add(int(port))

    hosts = {}
    for rel in host_rels:
        host, ip = entities.get(rel.source_id), entities.get(rel.target_id)
        if host is None or ip is None or ip.type != 'ip' or host.type not in ('domain', 'subdomain'):
            continue
        row = hosts.setdefault(host.value, {'host': host.value, 'type': host.type, 'ips': {},
                                            'last_seen': rel.last_seen})
        info = row['ips'].setdefault(ip.value, {'ip': ip.value, 'ports': set(), 'sources': set()})
        info['ports'] |= ports_by_ip.get(ip.id, set())
        info['sources'].add(rel.tool or rel.type)
        if rel.last_seen and (row['last_seen'] is None or rel.last_seen > row['last_seen']):
            row['last_seen'] = rel.last_seen

    out = []
    for name in sorted(hosts):
        row = hosts[name]
        out.append({
            'host': row['host'],
            'type': row['type'],
            'ips': [{'ip': i['ip'], 'ports': sorted(i['ports']), 'sources': sorted(i['sources'])}
                    for i in sorted(row['ips'].values(), key=lambda x: x['ip'])],
            'last_seen': utc_iso(row['last_seen']),
        })
    return out
