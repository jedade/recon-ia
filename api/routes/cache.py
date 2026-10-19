# routes/cache.py
"""
Consultation admin du cache des scans (`pass_recon_cache`).

  GET /cache                    liste paginée (métadonnées, sans le résultat)
  GET /cache/<id>               une entrée avec son résultat brut complet
  GET /cache/<id>/export.json   téléchargement du résultat brut

Pourquoi (décision de l'utilisateur, 2026-10-19) : une fois un dossier
scellé, ses résultats ne sont plus lisibles côté serveur sans le code du
demandeur. Le cache, lui, conserve en clair les résultats BRUTS du scan par
domaine — données publiques de reconnaissance passive, sans analyse IA ni
donnée du demandeur. L'admin doit pouvoir les consulter depuis le dashboard.
Les entrées expirées restent en base (marquées `is_valid: false`) : elles ne
sont plus servies au pipeline, mais restent consultables.

Admin uniquement (`require_auth`) — jamais le jeton de service de n8n.
"""
import json
import logging

from flask import Blueprint, Response, jsonify, request
from flasgger import swag_from

from models.pass_recon_cache import PassReconCache
from routes.report import _safe_filename_part
from utils.auth import require_auth

logger = logging.getLogger(__name__)

cache_bp = Blueprint('cache', __name__)


@cache_bp.route('/cache', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Cache des scans'],
    'security': [{'basicAuth': []}],
    'summary': 'Lister les scans bruts en cache',
    'parameters': [
        {'name': 'page', 'in': 'query', 'type': 'integer', 'default': 1},
        {'name': 'per_page', 'in': 'query', 'type': 'integer', 'default': 20,
         'description': 'max 100'},
        {'name': 'domain', 'in': 'query', 'type': 'string',
         'description': 'Filtre par sous-chaîne de domaine'},
        {'name': 'valid', 'in': 'query', 'type': 'string', 'enum': ['true', 'false'],
         'description': 'true = non expirées, false = expirées'},
    ],
    'responses': {200: {'description': 'Liste paginée'}, 401: {'description': 'Authentification requise'}},
})
def list_cache():
    from datetime import datetime

    page = max(1, request.args.get('page', 1, type=int))
    per_page = max(1, min(request.args.get('per_page', 20, type=int), 100))
    query = PassReconCache.query
    domain = (request.args.get('domain') or '').strip().lower()
    if domain:
        query = query.filter(PassReconCache.domain.contains(domain))
    valid = request.args.get('valid')
    if valid == 'true':
        query = query.filter(PassReconCache.expires_at > datetime.utcnow())
    elif valid == 'false':
        query = query.filter(PassReconCache.expires_at <= datetime.utcnow())
    elif valid is not None:
        return jsonify({'success': False, 'error': "valid doit valoir 'true' ou 'false'"}), 400

    pagination = query.order_by(PassReconCache.updated_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    return jsonify({
        'success': True,
        'data': [entry.to_dict() for entry in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages,
    }), 200


def _load(entry_id: int):
    entry = PassReconCache.query.get_or_404(entry_id)
    try:
        result = entry.get_result()
        corrupted = False
    except Exception:
        logger.warning('[cache] result_json illisible — id=%s', entry_id)
        result, corrupted = None, True
    return entry, result, corrupted


@cache_bp.route('/cache/<int:entry_id>', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Cache des scans'],
    'security': [{'basicAuth': []}],
    'summary': "Résultat brut complet d'un scan en cache",
    'parameters': [{'name': 'entry_id', 'in': 'path', 'required': True, 'type': 'integer'}],
    'responses': {200: {'description': 'Entrée + résultat'}, 404: {'description': 'Introuvable'}},
})
def get_cache_entry(entry_id: int):
    entry, result, corrupted = _load(entry_id)
    data = entry.to_dict()
    data['result'] = result
    data['corrupted'] = corrupted
    return jsonify({'success': True, 'data': data}), 200


@cache_bp.route('/cache/<int:entry_id>/export.json', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Cache des scans'],
    'security': [{'basicAuth': []}],
    'summary': "Télécharger le résultat brut d'un scan en cache",
    'parameters': [{'name': 'entry_id', 'in': 'path', 'required': True, 'type': 'integer'}],
    'responses': {200: {'description': 'Fichier JSON'}, 404: {'description': 'Introuvable'}},
})
def export_cache_entry(entry_id: int):
    entry, result, corrupted = _load(entry_id)
    payload = {'cache': entry.to_dict(), 'corrupted': corrupted, 'scan_results': result}
    filename = f'recon_ia_scan_brut_{_safe_filename_part(entry.domain)}_{entry.id}.json'
    response = Response(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                        mimetype='application/json; charset=utf-8')
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
