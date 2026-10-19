# routes/graph.py
"""
Graphe d'entités, différentiel entre scans et surveillance planifiée
(plan d'action, phase 7).

Admin uniquement (`require_auth`) :
  GET    /graph/summary                 compteurs par type (global ou ?domain=)
  GET    /graph/entities                entités paginées (?domain=&type=&q=)
  GET    /graph/live_hosts              hôtes vivants (?domain=&format=json|csv&max_age_days=)
  GET    /graph/snapshots               historique des différentiels (?domain=)
  GET    /recon/<id>/diff               différentiel d'un dossier (lisible même scellé)
  GET    /monitoring                    domaines surveillés
  POST   /monitoring                    ajouter un domaine (opt-in, désactivé par défaut)
  PATCH  /monitoring/<id>               activer/désactiver, changer l'intervalle
  DELETE /monitoring/<id>               retirer de la surveillance

Pipeline n8n (jeton de service `X-Service-Token`, ou admin) :
  GET    /monitoring/due                domaines dont le rescan est dû
  POST   /monitoring/<id>/ingest        après POST /pass_recon {domain, force_refresh}
                                        (cache mis à jour) : graphe + différentiel
                                        + alerte mail à l'admin si significatif

Le jeton de service n'ouvre PAS les routes admin (graphe, export, gestion de
la surveillance) : n8n ne peut que lister ce qui est dû et ingérer un rescan.
"""
import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, request
from flasgger import swag_from

from database import db
from models.entity_graph import ENTITY_TYPES, Entity
from models.recon import Recon, utc_iso, utc_now_iso
from models.scan_monitoring import ScanSnapshot, WatchedDomain
from utils.auth import require_auth, require_service_or_auth
from utils.entity_graph import (
    build_graph_from_raw, domain_entity_ids, graph_summary, live_hosts, norm_hostname,
)
from utils.scan_diff import record_scan
from utils.validators import is_valid_domain

logger = logging.getLogger(__name__)

graph_bp = Blueprint('graph', __name__)

# Mention portée par tout export d'hôtes vivants
LIVE_HOSTS_NOTICE = (
    "Export issu d'une reconnaissance PASSIVE (Recon-IA) : aucune de ces cibles n'a "
    "été sondée activement. Toute phase active (scan de ports, test d'intrusion) "
    "menée à partir de cette liste se fait HORS de Recon-IA et exige une "
    "autorisation écrite préalable du propriétaire des systèmes, dans le périmètre "
    "convenu. Les observations peuvent être périmées : vérifier avant usage."
)
_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _err(message: str, code: int = 400):
    return jsonify({'success': False, 'error': message}), code


def _domain_arg(required: bool = False):
    """Domaine racine passé en paramètre, normalisé. (valeur, erreur)."""
    raw = (request.args.get('domain') or '').strip().lower()
    if not raw:
        return (None, _err("Paramètre 'domain' requis")) if required else (None, None)
    domain = norm_hostname(raw)
    if not domain or not is_valid_domain(domain):
        return None, _err('Format de domaine invalide')
    return domain, None


def _page_args(default_per_page: int = 50):
    page = max(1, request.args.get('page', 1, type=int))
    per_page = max(1, min(request.args.get('per_page', default_per_page, type=int), 200))
    return page, per_page


def _csv_cell(value) -> str:
    text = '' if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


# ── Graphe ────────────────────────────────────────────────────────────────────

@graph_bp.route('/graph/summary', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Résumé du graphe d'entités (compteurs par type)",
    'parameters': [{'name': 'domain', 'in': 'query', 'type': 'string', 'required': False}],
    'responses': {200: {'description': 'Compteurs'}, 401: {'description': 'Authentification requise'}},
})
def get_graph_summary():
    domain, error = _domain_arg()
    if error:
        return error
    data = graph_summary(domain)
    query = ScanSnapshot.query
    if domain:
        query = query.filter(ScanSnapshot.domain == domain)
    data['snapshots_total'] = query.count()
    last = query.order_by(ScanSnapshot.created_at.desc(), ScanSnapshot.id.desc()).first()
    data['last_snapshot'] = last.to_dict(with_diff=False) if last else None
    if domain:
        watch = WatchedDomain.query.filter_by(domain=domain).first()
        data['monitoring'] = watch.to_dict() if watch else None
    return jsonify({'success': True, 'data': data}), 200


@graph_bp.route('/graph/entities', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Entités du graphe (paginées)",
    'parameters': [
        {'name': 'domain', 'in': 'query', 'type': 'string'},
        {'name': 'type', 'in': 'query', 'type': 'string', 'enum': list(ENTITY_TYPES)},
        {'name': 'q', 'in': 'query', 'type': 'string', 'description': 'sous-chaîne de la valeur'},
        {'name': 'page', 'in': 'query', 'type': 'integer'},
        {'name': 'per_page', 'in': 'query', 'type': 'integer', 'description': 'max 200'},
    ],
    'responses': {200: {'description': 'Liste paginée'}, 400: {'description': 'Paramètre invalide'}},
})
def list_entities():
    from sqlalchemy import func, select
    domain, error = _domain_arg()
    if error:
        return error
    etype = (request.args.get('type') or '').strip()
    if etype and etype not in ENTITY_TYPES:
        return _err(f"type invalide. Valeurs : {', '.join(ENTITY_TYPES)}")
    q = (request.args.get('q') or '').strip()[:100]
    page, per_page = _page_args()

    query = Entity.query
    if domain:
        ids = domain_entity_ids(domain)
        query = query.filter(Entity.id.in_(select(ids.c.eid)))
    if etype:
        query = query.filter(Entity.type == etype)
    if q:
        query = query.filter(func.lower(Entity.value).contains(q.lower(), autoescape=True))
    pagination = query.order_by(Entity.type, Entity.value).paginate(
        page=page, per_page=per_page, error_out=False)
    return jsonify({
        'success': True,
        'data': [e.to_dict() for e in pagination.items],
        'total': pagination.total, 'page': page, 'per_page': per_page, 'pages': pagination.pages,
    }), 200


@graph_bp.route('/graph/live_hosts', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Export des hôtes vivants d'un domaine (JSON ou CSV), admin uniquement",
    'description': LIVE_HOSTS_NOTICE,
    'parameters': [
        {'name': 'domain', 'in': 'query', 'type': 'string', 'required': True},
        {'name': 'format', 'in': 'query', 'type': 'string', 'enum': ['json', 'csv'], 'default': 'json'},
        {'name': 'max_age_days', 'in': 'query', 'type': 'integer', 'default': 90,
         'description': "ignorer les observations plus anciennes (1–3650)"},
    ],
    'responses': {200: {'description': 'Fichier'}, 400: {'description': 'Paramètre invalide'}},
})
def export_live_hosts():
    domain, error = _domain_arg(required=True)
    if error:
        return error
    fmt = (request.args.get('format') or 'json').lower()
    if fmt not in ('json', 'csv'):
        return _err("format doit valoir 'json' ou 'csv'")
    max_age = max(1, min(request.args.get('max_age_days', 90, type=int), 3650))
    since = datetime.utcnow() - timedelta(days=max_age)
    hosts = live_hosts(domain, since=since)
    generated_at = utc_now_iso()
    safe_domain = ''.join(c if c.isalnum() or c in '.-' else '_' for c in domain)
    logger.warning('[graph] export hôtes vivants — domaine=%s format=%s hôtes=%d', domain, fmt, len(hosts))

    if fmt == 'json':
        body = json.dumps({
            'notice': LIVE_HOSTS_NOTICE, 'domain': domain, 'generated_at': generated_at,
            'max_age_days': max_age, 'source': 'recon-ia passive entity graph',
            'host_count': len(hosts), 'hosts': hosts,
        }, ensure_ascii=False, indent=2)
        response = Response(body, mimetype='application/json; charset=utf-8')
        filename = f'recon_ia_hotes_vivants_{safe_domain}.json'
    else:
        buffer = io.StringIO()
        buffer.write('# ' + LIVE_HOSTS_NOTICE + '\n')
        buffer.write(f'# domaine={domain} genere_le={generated_at} max_age_days={max_age}\n')
        writer = csv.writer(buffer)
        writer.writerow(['host', 'type', 'ip', 'ports', 'sources', 'last_seen'])
        for host in hosts:
            for ip in host['ips']:
                writer.writerow([_csv_cell(v) for v in (
                    host['host'], host['type'], ip['ip'], ' '.join(str(p) for p in ip['ports']),
                    ' '.join(ip['sources']), host['last_seen'])])
        response = Response('﻿' + buffer.getvalue(), mimetype='text/csv; charset=utf-8')
        filename = f'recon_ia_hotes_vivants_{safe_domain}.csv'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    response.headers['X-Recon-IA-Notice'] = 'passive-only; active testing requires written authorization'
    return response


@graph_bp.route('/graph/snapshots', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Historique des différentiels entre scans',
    'parameters': [
        {'name': 'domain', 'in': 'query', 'type': 'string'},
        {'name': 'significant', 'in': 'query', 'type': 'string', 'enum': ['true', 'false']},
        {'name': 'page', 'in': 'query', 'type': 'integer'},
        {'name': 'per_page', 'in': 'query', 'type': 'integer'},
    ],
    'responses': {200: {'description': 'Liste paginée'}},
})
def list_snapshots():
    domain, error = _domain_arg()
    if error:
        return error
    page, per_page = _page_args(20)
    query = ScanSnapshot.query
    if domain:
        query = query.filter(ScanSnapshot.domain == domain)
    significant = request.args.get('significant')
    if significant == 'true':
        query = query.filter(ScanSnapshot.significant.is_(True))
    elif significant == 'false':
        query = query.filter(ScanSnapshot.significant.is_(False))
    elif significant is not None:
        return _err("significant doit valoir 'true' ou 'false'")
    pagination = query.order_by(ScanSnapshot.created_at.desc(), ScanSnapshot.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    items = []
    for row in pagination.items:
        item = row.to_dict(with_diff=False)
        diff = row.get_diff() or {}
        item['summary'] = diff.get('summary') or []
        item['has_previous'] = bool(diff.get('has_previous'))
        items.append(item)
    return jsonify({'success': True, 'data': items, 'total': pagination.total,
                    'page': page, 'per_page': per_page, 'pages': pagination.pages}), 200


@graph_bp.route('/graph/snapshots/<int:snapshot_id>', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Un différentiel complet",
    'parameters': [{'name': 'snapshot_id', 'in': 'path', 'type': 'integer', 'required': True}],
    'responses': {200: {'description': 'Différentiel'}, 404: {'description': 'Introuvable'}},
})
def get_snapshot(snapshot_id: int):
    row = db.session.get(ScanSnapshot, snapshot_id)
    if row is None:
        return _err('Différentiel introuvable', 404)
    return jsonify({'success': True, 'data': row.to_dict()}), 200


@graph_bp.route('/recon/<int:recon_id>/diff', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Différentiel d'un dossier avec le scan précédent du même domaine",
    'description': ("Données techniques publiques stockées en clair (models/scan_monitoring.py) : "
                    "consultable même quand le dossier est scellé."),
    'parameters': [{'name': 'recon_id', 'in': 'path', 'type': 'integer', 'required': True}],
    'responses': {200: {'description': 'Différentiel'}, 404: {'description': 'Aucun différentiel'}},
})
def get_recon_diff(recon_id: int):
    recon = db.session.get(Recon, recon_id)
    if recon is None:
        return _err('Enregistrement introuvable', 404)
    row = ScanSnapshot.query.filter_by(recon_id=recon_id).first()
    if row is None:
        return _err("Aucun différentiel pour ce dossier (rapport non encore généré, "
                    "ou dossier antérieur à la phase 7)", 404)
    return jsonify({'success': True, 'data': row.to_dict()}), 200


# ── Surveillance (gestion admin) ──────────────────────────────────────────────

def _interval(value, default=None):
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError
    days = int(value)
    if not 1 <= days <= 365:
        raise ValueError
    return days


@graph_bp.route('/monitoring', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Domaines surveillés',
    'responses': {200: {'description': 'Liste'}},
})
def list_monitoring():
    rows = WatchedDomain.query.order_by(WatchedDomain.domain).all()
    return jsonify({'success': True, 'data': [r.to_dict() for r in rows],
                    'alert_email_configured': bool(_alert_recipient())}), 200


@graph_bp.route('/monitoring', methods=['POST'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Ajouter un domaine à la surveillance (opt-in, désactivé par défaut)',
    'description': ("Le domaine doit avoir fait l'objet d'au moins un dossier vérifié et "
                    "consenti (`accord`) : la surveillance ne crée pas de nouvelle cible."),
    'parameters': [{'name': 'body', 'in': 'body', 'required': True, 'schema': {
        'type': 'object', 'required': ['domain'],
        'properties': {'domain': {'type': 'string'},
                       'interval_days': {'type': 'integer', 'default': 7},
                       'enabled': {'type': 'boolean', 'default': False}}}}],
    'responses': {201: {'description': 'Créé'}, 400: {'description': 'Invalide'},
                  409: {'description': 'Déjà surveillé ou aucun dossier consenti'}},
})
def add_monitoring():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err('Corps JSON requis')
    raw = body.get('domain')
    domain = norm_hostname(raw.strip().lower()) if isinstance(raw, str) else None
    if not domain or not is_valid_domain(domain):
        return _err('Format de domaine invalide')
    try:
        interval = _interval(body.get('interval_days'), 7)
    except (TypeError, ValueError):
        return _err('interval_days doit être un entier entre 1 et 365')
    enabled = body.get('enabled', False)
    if not isinstance(enabled, bool):
        return _err('enabled doit être un booléen')
    if WatchedDomain.query.filter_by(domain=domain).first():
        return _err('Domaine déjà surveillé', 409)
    consented = Recon.query.filter(Recon.domain == domain, Recon.accord.is_(True),
                                   Recon.verification.is_(True)).first()
    if consented is None:
        return _err("Aucun dossier vérifié et consenti pour ce domaine : surveillance refusée", 409)
    row = WatchedDomain(domain=domain, interval_days=interval, enabled=enabled)
    db.session.add(row)
    db.session.commit()
    logger.info('[monitoring] domaine ajouté — %s (actif=%s, %d j)', domain, enabled, interval)
    return jsonify({'success': True, 'data': row.to_dict()}), 201


@graph_bp.route('/monitoring/<int:watch_id>', methods=['PATCH'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Activer/désactiver la surveillance ou changer son intervalle',
    'parameters': [{'name': 'watch_id', 'in': 'path', 'type': 'integer', 'required': True},
                   {'name': 'body', 'in': 'body', 'schema': {'type': 'object', 'properties': {
                       'enabled': {'type': 'boolean'}, 'interval_days': {'type': 'integer'}}}}],
    'responses': {200: {'description': 'Mis à jour'}, 404: {'description': 'Introuvable'}},
})
def update_monitoring(watch_id: int):
    row = db.session.get(WatchedDomain, watch_id)
    if row is None:
        return _err('Domaine surveillé introuvable', 404)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err('Corps JSON requis')
    if 'enabled' in body:
        if not isinstance(body['enabled'], bool):
            return _err('enabled doit être un booléen')
        row.enabled = body['enabled']
    if 'interval_days' in body:
        try:
            row.interval_days = _interval(body['interval_days'])
        except (TypeError, ValueError):
            return _err('interval_days doit être un entier entre 1 et 365')
    db.session.commit()
    return jsonify({'success': True, 'data': row.to_dict()}), 200


@graph_bp.route('/monitoring/<int:watch_id>', methods=['DELETE'])
@require_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Retirer un domaine de la surveillance (le graphe et les différentiels restent)',
    'parameters': [{'name': 'watch_id', 'in': 'path', 'type': 'integer', 'required': True}],
    'responses': {200: {'description': 'Supprimé'}, 404: {'description': 'Introuvable'}},
})
def delete_monitoring(watch_id: int):
    row = db.session.get(WatchedDomain, watch_id)
    if row is None:
        return _err('Domaine surveillé introuvable', 404)
    db.session.delete(row)
    db.session.commit()
    return jsonify({'success': True}), 200


# ── Surveillance (pipeline n8n) ───────────────────────────────────────────────

def _alert_recipient() -> str:
    """Destinataire des alertes : l'ADMIN (jamais le demandeur)."""
    for var in ('MONITORING_ALERT_EMAIL', 'ADMIN_NOTIFICATION_EMAIL'):
        value = (os.getenv(var) or '').strip()
        if '@' in value and '\n' not in value and '\r' not in value:
            return value
    return ''


def _max_per_run() -> int:
    try:
        return max(1, min(int(os.getenv('MONITORING_MAX_PER_RUN', '5')), 50))
    except ValueError:
        return 5


@graph_bp.route('/monitoring/due', methods=['GET'])
@require_service_or_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': 'Domaines surveillés dont le rescan est dû (appelé par n8n)',
    'responses': {200: {'description': 'Liste (bornée par MONITORING_MAX_PER_RUN)'}},
})
def monitoring_due():
    now = datetime.utcnow()
    rows = WatchedDomain.query.filter(WatchedDomain.enabled.is_(True)).all()
    # Jamais rescannés d'abord, puis du plus ancien rescan au plus récent
    rows.sort(key=lambda r: (r.last_rescan_at is not None, r.last_rescan_at or datetime.min, r.id))
    due = [r for r in rows if r.is_due(now)][:_max_per_run()]
    return jsonify({'success': True, 'data': [
        {'id': r.id, 'domain': r.domain, 'interval_days': r.interval_days,
         'last_rescan_at': utc_iso(r.last_rescan_at)} for r in due]}), 200


@graph_bp.route('/monitoring/<int:watch_id>/ingest', methods=['POST'])
@require_service_or_auth
@swag_from({
    'tags': ['Graphe & surveillance'], 'security': [{'basicAuth': []}],
    'summary': "Ingérer le dernier scan en cache d'un domaine surveillé",
    'description': ("À appeler après `POST /pass_recon {domain, force_refresh: true}` (sans "
                    "recon_id) : construit le graphe et le différentiel depuis l'entrée de cache "
                    "la plus récente du domaine, puis alerte l'admin par mail si le changement est "
                    "significatif. Idempotent : une même mise à jour du cache n'est ingérée qu'une fois."),
    'parameters': [{'name': 'watch_id', 'in': 'path', 'type': 'integer', 'required': True}],
    'responses': {200: {'description': 'Ingéré (ou déjà ingéré)'}, 404: {'description': 'Introuvable'},
                  409: {'description': 'Surveillance désactivée ou aucun scan en cache'}},
})
def monitoring_ingest(watch_id: int):
    from models.pass_recon_cache import PassReconCache
    from utils.email_sender import send_monitoring_alert

    watch = db.session.get(WatchedDomain, watch_id)
    if watch is None:
        return _err('Domaine surveillé introuvable', 404)
    if not watch.enabled:
        return _err('Surveillance désactivée pour ce domaine', 409)
    entry = PassReconCache.query.filter_by(domain=watch.domain).order_by(
        PassReconCache.updated_at.desc(), PassReconCache.id.desc()).first()
    if entry is None:
        return _err('Aucun scan en cache pour ce domaine : lancez POST /pass_recon avant', 409)
    try:
        raw = entry.get_result()
    except Exception:
        return _err('Scan en cache illisible (JSON corrompu)', 409)
    if not isinstance(raw, dict):
        return _err('Scan en cache illisible', 409)

    stamp = (entry.updated_at or entry.created_at or datetime.utcnow()).strftime('%Y%m%dT%H%M%S')
    scan_ref = f'cache:{entry.id}:{stamp}'
    now = datetime.utcnow()
    already = ScanSnapshot.query.filter_by(domain=watch.domain, scan_ref=scan_ref).first()
    if already is not None:
        watch.last_rescan_at = now
        db.session.commit()
        return jsonify({'success': True, 'already_ingested': True,
                        'data': already.to_dict(with_diff=False)}), 200

    try:
        graph_stats = build_graph_from_raw(watch.domain, raw, scan_ref=scan_ref, now=now)
        snapshot = record_scan(watch.domain, raw, scan_ref=scan_ref, now=now,
                               cache_id=entry.id, source='rescan')
        watch.last_rescan_at = now
        watch.last_snapshot_id = snapshot.id
        if snapshot.significant:
            watch.last_change_at = now
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.exception('[monitoring] ingestion échouée — %s', watch.domain)
        return _err(f'Ingestion impossible : {e}', 500)

    diff = snapshot.get_diff() or {}
    alert_sent = False
    if snapshot.significant and diff.get('has_previous'):
        recipient = _alert_recipient()
        if recipient:
            alert_sent = send_monitoring_alert(recipient, watch.domain, diff, scanned_at=now)
            if alert_sent:
                watch.last_alert_at = now
                db.session.commit()
    return jsonify({'success': True, 'already_ingested': False, 'alert_sent': alert_sent,
                    'graph': graph_stats, 'data': snapshot.to_dict()}), 200
