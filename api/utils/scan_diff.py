# utils/scan_diff.py
"""
Différentiel entre deux scans passifs du même domaine (plan d'action, B9).

  extract_snapshot(raw, domain=None) -> dict
      Empreinte technique compacte d'un scan : sous-domaines, IP, ports
      (« ip:port »), CVE, technologies, certificat TLS, SPF, DMARC, plus la
      liste des sections réellement OBSERVÉES (outil exécuté avec succès).

  diff_scans(previous_raw, current_raw, now=None, domain=None) -> dict
      Fonction PURE. Accepte des résultats bruts (`scan_results`) ou des
      empreintes déjà extraites (reconnues à la clé `snapshot_version`).

  record_scan(...)  (base de données)
      Calcule l'empreinte, la compare au scan précédent du même domaine et
      enregistre le tout dans `scan_snapshot` (voir models/scan_monitoring.py
      pour la justification du stockage en clair).

Une section n'est comparée que si elle a été observée DANS LES DEUX scans :
un outil en échec ne doit pas faire « disparaître » toutes les IP ou tous les
sous-domaines (faux positif massif). La section porte alors `compared: false`.

Format du différentiel (schema_version 1)
─────────────────────────────────────────
{
  "schema_version": 1,
  "has_previous": true,             # false = premier scan (référence)
  "previous_scan_at": "…Z" | null,  # renseigné par record_scan
  "significant": true,              # déclenche l'alerte de surveillance
  "change_count": 4,
  "subdomains":   {"compared": true, "added": [...], "removed": [...],
                   "added_count": 2, "removed_count": 0},
  "ips":          { idem },
  "ports":        { idem, valeurs « ip:port » },
  "cves":         { idem },
  "technologies": { idem },
  "certificate":  {"compared": true, "changed": false,
                   "previous": {...}|null, "current": {...}|null,
                   "days_until_expiry": 12, "expiring_soon": true, "expired": false},
  "email_security": {
      "spf":   {"compared": true, "changed": false, "previous": "…", "current": "…"},
      "dmarc": {"compared": true, "changed": true,  "previous": "…", "current": "…",
                "previous_policy": "none", "current_policy": "reject"}
  },
  "summary": ["2 nouveau(x) sous-domaine(s)", "Certificat expirant dans 12 jour(s)", …]
}

Est « significatif » : nouveau sous-domaine, nouvelle IP, nouveau port,
nouvelle CVE, certificat changé, expirant (< 30 j) ou expiré, SPF ou DMARC
modifié. Les disparitions et les changements de technologies sont comptés
dans `change_count` mais ne déclenchent pas d'alerte à eux seuls.

Les adresses email présentes dans les enregistrements SPF/DMARC (rua=, ruf=)
sont remplacées par une empreinte courte : un changement d'adresse reste
détecté, l'adresse elle-même n'est jamais recopiée.
"""
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Optional

from utils.entity_graph import (
    certificate_id, extract_graph, norm_hostname, norm_text, tool_data, tool_ok,
)

logger = logging.getLogger(__name__)

SNAPSHOT_VERSION = 1
DIFF_SCHEMA_VERSION = 1
CERT_EXPIRY_WARNING_DAYS = 30
# Plafond par liste dans le différentiel stocké (les compteurs restent exacts)
MAX_LIST_ITEMS = 500

_LIST_SECTIONS = ('subdomains', 'ips', 'ports', 'cves', 'technologies')
# Sections dont un AJOUT rend le différentiel significatif
_SIGNIFICANT_ADDITIONS = ('subdomains', 'ips', 'ports', 'cves')
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+')
_DISCOVERY_TOOLS = ('crtsh', 'subfinder', 'assetfinder', 'amass', 'github')

_LABELS = {
    'subdomains':   ('nouveau(x) sous-domaine(s)', 'sous-domaine(s) disparu(s)'),
    'ips':          ('nouvelle(s) IP', 'IP disparue(s)'),
    'ports':        ('nouveau(x) port(s) exposé(s)', 'port(s) fermé(s) ou non revu(s)'),
    'cves':         ('nouvelle(s) CVE', 'CVE non revue(s)'),
    'technologies': ('nouvelle(s) technologie(s)', 'technologie(s) non revue(s)'),
}


def _mask_emails(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return _EMAIL_RE.sub(
        lambda m: 'email#' + hashlib.sha256(m.group(0).lower().encode('utf-8')).hexdigest()[:10], text)


def _norm_record(value) -> Optional[str]:
    """Enregistrement DNS texte normalisé pour comparaison (espaces, emails masqués)."""
    if not isinstance(value, str):
        return None
    return norm_text(_mask_emails(value).replace('@', ' at '), 1024)


def _parse_not_after(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y', '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(' '.join(value.split()), fmt)
        except ValueError:
            continue
    return None


# ── Empreinte d'un scan ──────────────────────────────────────────────────────

def is_snapshot(obj) -> bool:
    return isinstance(obj, dict) and obj.get('snapshot_version') is not None


def extract_snapshot(raw, domain: Optional[str] = None) -> dict:
    """Empreinte technique compacte d'un scan (tolérante aux champs absents)."""
    raw = raw if isinstance(raw, dict) else {}
    root = norm_hostname(domain) if domain else None
    if not root:
        root = norm_hostname(raw.get('domain')) if isinstance(raw.get('domain'), str) else None

    graph = extract_graph(root, raw) if root else {'entities': {}}
    values = {}
    for etype, value in graph['entities']:
        values.setdefault(etype, set()).add(value)

    observed = {
        'subdomains': isinstance(raw.get('all_subdomains'), dict)
                      or any(tool_ok(raw, k) for k in _DISCOVERY_TOOLS),
        'ips': any(tool_ok(raw, k) for k in ('dns_records', 'ip_info', 'asn_info', 'shodan_internetdb'))
               or any(isinstance(k, str) and 'resol' in k and tool_ok(raw, k) for k in raw),
        'ports': tool_ok(raw, 'shodan_internetdb'),
        'cves': tool_ok(raw, 'shodan_internetdb'),
        'technologies': any(tool_ok(raw, k) for k in ('tech_stack', 'waf_detection', 'shodan_internetdb')),
        'certificate': tool_ok(raw, 'ssl_info') and isinstance(tool_data(raw, 'ssl_info'), dict)
                       and bool(tool_data(raw, 'ssl_info')),
        'spf': tool_ok(raw, 'email_config') or tool_ok(raw, 'spf_analysis'),
        'dmarc': tool_ok(raw, 'dmarc_check') or tool_ok(raw, 'email_config'),
    }

    certificate = None
    if observed['certificate']:
        cert = tool_data(raw, 'ssl_info')
        subject = cert.get('subject') if isinstance(cert.get('subject'), dict) else {}
        issuer = cert.get('issuer') if isinstance(cert.get('issuer'), dict) else {}
        days = cert.get('days_until_expiry')
        certificate = {
            'id': certificate_id(cert),
            'subject_cn': norm_text(subject.get('commonName')),
            'issuer': norm_text(issuer.get('organizationName') or issuer.get('commonName')),
            'not_after': norm_text(cert.get('not_after'), 40),
            'days_until_expiry': days if isinstance(days, int) and not isinstance(days, bool) else None,
        }

    email = tool_data(raw, 'email_config')
    email = email if isinstance(email, dict) else {}
    spf = email.get('spf') if isinstance(email.get('spf'), str) else None
    if spf is None:
        spf_data = tool_data(raw, 'spf_analysis')
        if isinstance(spf_data, dict) and isinstance(spf_data.get('mechanisms'), list):
            mechs = [m.get('mechanism') for m in spf_data['mechanisms']
                     if isinstance(m, dict) and m.get('domain') == root and isinstance(m.get('mechanism'), str)]
            if mechs:
                spf = 'v=spf1 ' + ' '.join(mechs)
    dmarc_data = tool_data(raw, 'dmarc_check')
    dmarc_data = dmarc_data if isinstance(dmarc_data, dict) else {}
    dmarc = dmarc_data.get('record') if isinstance(dmarc_data.get('record'), str) else None
    if dmarc is None and isinstance(email.get('dmarc'), str):
        dmarc = email.get('dmarc')
    policy = dmarc_data.get('policy') or email.get('dmarc_policy')

    return {
        'snapshot_version': SNAPSHOT_VERSION,
        'domain': root,
        'observed': observed,
        'subdomains': sorted(values.get('subdomain', ())),
        'ips': sorted(values.get('ip', ())),
        'ports': sorted(values.get('port', ())),
        'cves': sorted(values.get('vulnerability', ())),
        'technologies': sorted(values.get('technology', ())),
        'certificate': certificate,
        'spf': _norm_record(spf),
        'dmarc': _norm_record(dmarc),
        'dmarc_policy': norm_text(policy, 20),
    }


# ── Différentiel (fonction pure) ──────────────────────────────────────────────

def _list_diff(prev: dict, cur: dict, key: str) -> dict:
    if not (prev['observed'].get(key) and cur['observed'].get(key)):
        return {'compared': False, 'added': [], 'removed': [], 'added_count': 0, 'removed_count': 0}
    before, after = set(prev.get(key) or ()), set(cur.get(key) or ())
    added, removed = sorted(after - before), sorted(before - after)
    return {'compared': True, 'added': added[:MAX_LIST_ITEMS], 'removed': removed[:MAX_LIST_ITEMS],
            'added_count': len(added), 'removed_count': len(removed)}


def _cert_expiry(cert: Optional[dict], now: datetime):
    if not cert:
        return None
    expiry = _parse_not_after(cert.get('not_after'))
    if expiry is not None:
        return (expiry - now).days
    return cert.get('days_until_expiry')


def _empty_snapshot() -> dict:
    return extract_snapshot({})


def diff_scans(previous_raw, current_raw, now: Optional[datetime] = None,
               domain: Optional[str] = None) -> dict:
    """
    Compare deux scans (bruts ou empreintes). `previous_raw=None` = premier
    scan : aucun ajout/disparition n'est signalé, seule l'échéance du
    certificat courant est évaluée.
    """
    now = now or datetime.utcnow()
    has_previous = previous_raw is not None
    cur = current_raw if is_snapshot(current_raw) else extract_snapshot(current_raw, domain)
    if not has_previous:
        prev = None
    else:
        prev = previous_raw if is_snapshot(previous_raw) else extract_snapshot(
            previous_raw, domain or cur.get('domain'))
    cur.setdefault('observed', {})
    base = prev if prev is not None else _empty_snapshot()
    base.setdefault('observed', {})

    diff = {'schema_version': DIFF_SCHEMA_VERSION, 'has_previous': has_previous,
            'previous_scan_at': None, 'domain': cur.get('domain')}
    summary, significant, changes = [], False, 0

    for key in _LIST_SECTIONS:
        section = _list_diff(base, cur, key) if has_previous else \
            {'compared': False, 'added': [], 'removed': [], 'added_count': 0, 'removed_count': 0}
        diff[key] = section
        changes += section['added_count'] + section['removed_count']
        add_label, rem_label = _LABELS[key]
        if section['added_count']:
            summary.append(f"{section['added_count']} {add_label}")
            if key in _SIGNIFICANT_ADDITIONS:
                significant = True
        if section['removed_count']:
            summary.append(f"{section['removed_count']} {rem_label}")

    # Certificat : changement + échéance (évaluée même au premier scan)
    prev_cert, cur_cert = base.get('certificate'), cur.get('certificate')
    cert_compared = has_previous and bool(base['observed'].get('certificate')) \
        and bool(cur['observed'].get('certificate'))
    cert_changed = bool(cert_compared and prev_cert and cur_cert
                        and prev_cert.get('id') != cur_cert.get('id'))
    days = _cert_expiry(cur_cert, now) if cur['observed'].get('certificate') else None
    expired = days is not None and days < 0
    expiring = days is not None and 0 <= days < CERT_EXPIRY_WARNING_DAYS
    diff['certificate'] = {
        'compared': cert_compared, 'changed': cert_changed,
        'previous': prev_cert if has_previous else None, 'current': cur_cert,
        'days_until_expiry': days, 'expiring_soon': expiring, 'expired': expired,
    }
    if cert_changed:
        changes += 1
        significant = True
        summary.append('Certificat TLS changé')
    if expired:
        significant = True
        summary.append(f'Certificat TLS expiré depuis {-days} jour(s)')
    elif expiring:
        significant = True
        summary.append(f'Certificat TLS expirant dans {days} jour(s)')

    # SPF / DMARC
    email = {}
    for key, label in (('spf', 'SPF'), ('dmarc', 'DMARC')):
        compared = has_previous and bool(base['observed'].get(key)) and bool(cur['observed'].get(key))
        changed = compared and base.get(key) != cur.get(key)
        entry = {'compared': compared, 'changed': changed,
                 'previous': base.get(key) if has_previous else None, 'current': cur.get(key)}
        if key == 'dmarc':
            entry['previous_policy'] = base.get('dmarc_policy') if has_previous else None
            entry['current_policy'] = cur.get('dmarc_policy')
        email[key] = entry
        if changed:
            changes += 1
            significant = True
            if base.get(key) is None:
                summary.append(f'{label} apparu')
            elif cur.get(key) is None:
                summary.append(f'{label} supprimé')
            else:
                summary.append(f'{label} modifié')
    diff['email_security'] = email

    diff['significant'] = significant
    diff['change_count'] = changes
    diff['summary'] = summary
    return diff


# ── Persistance ───────────────────────────────────────────────────────────────

def _previous_snapshot(domain: str, exclude_id: Optional[int] = None):
    from models.scan_monitoring import ScanSnapshot
    query = ScanSnapshot.query.filter(ScanSnapshot.domain == domain)
    if exclude_id is not None:
        query = query.filter(ScanSnapshot.id != exclude_id)
    return query.order_by(ScanSnapshot.created_at.desc(), ScanSnapshot.id.desc()).first()


def record_scan(domain: str, raw_results, scan_ref: str, now: Optional[datetime] = None,
                recon_id: Optional[int] = None, cache_id: Optional[int] = None,
                source: str = 'pipeline'):
    """
    Enregistre l'empreinte d'un scan et son différentiel avec le scan
    précédent du même domaine. Upsert par `recon_id` (un dossier relancé ne
    crée pas de doublon). Flush sans commit. Retourne le ScanSnapshot.
    """
    from database import db
    from models.recon import utc_iso
    from models.scan_monitoring import ScanSnapshot

    now = now or datetime.utcnow()
    root = norm_hostname(domain)
    if not root:
        raise ValueError('Domaine invalide pour le différentiel')

    snapshot = extract_snapshot(raw_results, root)
    row = ScanSnapshot.query.filter_by(recon_id=recon_id).first() if recon_id is not None else None
    previous = _previous_snapshot(root, exclude_id=row.id if row else None)
    if previous is not None and row is not None and previous.created_at > row.created_at:
        # Relance d'un ancien dossier : comparer au scan qui le précédait
        previous = ScanSnapshot.query.filter(
            ScanSnapshot.domain == root, ScanSnapshot.id != row.id,
            ScanSnapshot.created_at <= row.created_at,
        ).order_by(ScanSnapshot.created_at.desc(), ScanSnapshot.id.desc()).first()

    diff = diff_scans(previous.get_snapshot() if previous else None, snapshot, now=now, domain=root)
    if previous is not None:
        diff['previous_scan_at'] = utc_iso(previous.created_at)
        diff['previous_snapshot_id'] = previous.id
        diff['previous_recon_id'] = previous.recon_id

    if row is None:
        row = ScanSnapshot(domain=root, recon_id=recon_id, created_at=now)
        db.session.add(row)
    row.cache_id = cache_id
    row.scan_ref = str(scan_ref or '')[:128] or f'scan:{now.isoformat()}'
    row.source = source
    row.snapshot_json = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    row.diff_json = json.dumps(diff, ensure_ascii=False, sort_keys=True)
    row.previous_snapshot_id = previous.id if previous else None
    row.significant = bool(diff['significant'])
    row.change_count = int(diff['change_count'])
    db.session.flush()
    logger.info('[diff] %s — %s : %d changement(s), significatif=%s', root, row.scan_ref,
                row.change_count, row.significant)
    return row


def diff_for_recon(recon_id: int) -> Optional[dict]:
    """
    Différentiel d'un dossier, au format ci-dessus (None si aucun). Lisible
    même après scellement : c'est le point d'entrée prévu pour la page de
    résultat et le PDF (phase 4).
    """
    from models.scan_monitoring import ScanSnapshot
    row = ScanSnapshot.query.filter_by(recon_id=recon_id).first()
    return row.get_diff() if row else None
