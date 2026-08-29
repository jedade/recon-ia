# routes/logs.py
"""
Endpoint sécurisé de consultation des logs d'audit.

Accès restreint : authentification HTTP Basic requise.

Fonctionnalités :
  GET /logs           — liste paginée avec filtres
  GET /logs/stats     — statistiques agrégées (codes HTTP, endpoints les plus actifs)
  DELETE /logs        — purge des logs (optionnel, avec confirmation)

Filtres disponibles sur GET /logs :
  method        — GET, POST, PUT, PATCH, DELETE
  status_code   — ex: 400, 404, 500
  status_class  — 2xx, 4xx, 5xx  (filtre par centaine)
  endpoint      — sous-chaîne recherchée dans le chemin (ex: /recon)
  ip            — adresse IP exacte
  from          — date ISO 8601 de début (ex: 2025-09-13T00:00:00)
  to            — date ISO 8601 de fin
  page          — numéro de page (défaut: 1)
  per_page      — résultats par page (défaut: 50, max: 200)
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify
from flasgger import swag_from
from sqlalchemy import func

from database import db
from models.audit_log import AuditLog
from utils.auth import require_auth

logger = logging.getLogger(__name__)

logs_bp = Blueprint('logs', __name__)


# ---------------------------------------------------------------------------
# GET /logs — Liste paginée avec filtres
# ---------------------------------------------------------------------------

@logs_bp.route('/logs', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Audit - Logs'],
    'summary': 'Consulter les logs d\'audit (accès restreint)',
    'description': (
        'Retourne l\'historique paginé de toutes les requêtes HTTP enregistrées en base. '
        'Permet de surveiller l\'activité de l\'API, détecter les anomalies et auditer '
        'les accès.\n\n'
        '**Filtres disponibles** : `method`, `status_code`, `status_class` (2xx/4xx/5xx), '
        '`endpoint` (sous-chaîne), `ip`, `from` (date ISO), `to` (date ISO).'
    ),
    'parameters': [
        {'name': 'method', 'in': 'query', 'type': 'string',
         'enum': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
         'description': 'Filtrer par méthode HTTP'},
        {'name': 'status_code', 'in': 'query', 'type': 'integer',
         'description': 'Filtrer par code HTTP exact (ex: 400)'},
        {'name': 'status_class', 'in': 'query', 'type': 'string',
         'enum': ['2xx', '4xx', '5xx'],
         'description': 'Filtrer par classe de code HTTP'},
        {'name': 'endpoint', 'in': 'query', 'type': 'string',
         'description': 'Filtrer par sous-chaîne dans le chemin (ex: /recon)'},
        {'name': 'ip', 'in': 'query', 'type': 'string',
         'description': 'Filtrer par IP client exacte'},
        {'name': 'from', 'in': 'query', 'type': 'string',
         'description': 'Date de début ISO 8601 (ex: 2025-09-13T00:00:00)'},
        {'name': 'to', 'in': 'query', 'type': 'string',
         'description': 'Date de fin ISO 8601'},
        {'name': 'page', 'in': 'query', 'type': 'integer', 'default': 1},
        {'name': 'per_page', 'in': 'query', 'type': 'integer', 'default': 50,
         'description': 'Résultats par page (max 200)'},
    ],
    'responses': {
        200: {
            'description': 'Liste paginée des entrées d\'audit',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "data": [
                            {
                                "id": 42,
                                "method": "POST",
                                "endpoint": "/recon",
                                "status_code": 201,
                                "duration_ms": 145.3,
                                "ip_address": "172.20.0.1",
                                "user_agent": "curl/7.88.1",
                                "created_at": "2025-09-13T10:00:00"
                            }
                        ],
                        "total": 1, "page": 1, "per_page": 50, "pages": 1
                    }
                }
            }
        },
        400: {'description': 'Paramètre de filtre invalide'},
        401: {'description': 'Authentification requise'},
    }
})
def get_logs():
    """Retourne les logs d'audit paginés avec filtres optionnels."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    query = AuditLog.query.order_by(AuditLog.id.desc())

    # --- Filtres ---
    method = request.args.get('method', '').upper()
    if method:
        query = query.filter(AuditLog.method == method)

    status_code = request.args.get('status_code', type=int)
    if status_code is not None:
        query = query.filter(AuditLog.status_code == status_code)

    status_class = request.args.get('status_class', '')
    if status_class in ('2xx', '4xx', '5xx'):
        base = int(status_class[0]) * 100
        query = query.filter(
            AuditLog.status_code >= base,
            AuditLog.status_code < base + 100
        )

    endpoint_filter = request.args.get('endpoint', '')
    if endpoint_filter:
        query = query.filter(AuditLog.endpoint.contains(endpoint_filter))

    ip_filter = request.args.get('ip', '')
    if ip_filter:
        query = query.filter(AuditLog.ip_address == ip_filter)

    from_str = request.args.get('from', '')
    if from_str:
        try:
            from_dt = datetime.fromisoformat(from_str)
            query = query.filter(AuditLog.created_at >= from_dt)
        except ValueError:
            return jsonify({"success": False,
                            "error": "Paramètre 'from' invalide — format ISO 8601 attendu"}), 400

    to_str = request.args.get('to', '')
    if to_str:
        try:
            to_dt = datetime.fromisoformat(to_str)
            query = query.filter(AuditLog.created_at <= to_dt)
        except ValueError:
            return jsonify({"success": False,
                            "error": "Paramètre 'to' invalide — format ISO 8601 attendu"}), 400

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    logger.debug("GET /logs — %s entrées retournées (filtres: method=%r status_code=%r endpoint=%r)",
                 len(pagination.items), method or None, status_code, endpoint_filter or None)

    return jsonify({
        "success": True,
        "data": [entry.to_dict() for entry in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": per_page,
        "pages": pagination.pages,
    }), 200


# ---------------------------------------------------------------------------
# GET /logs/stats — Statistiques agrégées
# ---------------------------------------------------------------------------

@logs_bp.route('/logs/stats', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Audit - Logs'],
    'summary': 'Statistiques d\'usage et de santé de l\'API',
    'description': (
        'Retourne des métriques agrégées : répartition des codes HTTP, '
        'endpoints les plus appelés, IPs les plus actives, '
        'durée moyenne de traitement, nombre d\'erreurs.'
    ),
    'responses': {
        200: {
            'description': 'Statistiques agrégées',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "data": {
                            "total_requests": 1500,
                            "error_rate_pct": 3.2,
                            "avg_duration_ms": 120.5,
                            "by_status_class": {"2xx": 1452, "4xx": 45, "5xx": 3},
                            "top_endpoints": [
                                {"endpoint": "/recon", "count": 320},
                            ],
                            "top_ips": [
                                {"ip": "172.20.0.1", "count": 850},
                            ],
                            "top_errors": [
                                {"endpoint": "/recon", "status_code": 400, "count": 30},
                            ]
                        }
                    }
                }
            }
        },
        401: {'description': 'Authentification requise'},
    }
})
def get_logs_stats():
    """Calcule et retourne les statistiques agrégées de l'audit log."""
    total = AuditLog.query.count()

    if total == 0:
        return jsonify({
            "success": True,
            "data": {
                "total_requests": 0,
                "message": "Aucun log enregistré pour le moment."
            }
        }), 200

    # Durée moyenne
    avg_duration = db.session.query(func.avg(AuditLog.duration_ms)).scalar() or 0.0

    # Répartition par classe de statut HTTP
    status_counts = db.session.query(AuditLog.status_code, func.count()).group_by(
        AuditLog.status_code
    ).all()

    by_class = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0}
    for code, count in status_counts:
        if 200 <= code < 300:
            by_class['2xx'] += count
        elif 300 <= code < 400:
            by_class['3xx'] += count
        elif 400 <= code < 500:
            by_class['4xx'] += count
        elif 500 <= code < 600:
            by_class['5xx'] += count

    error_count = by_class['4xx'] + by_class['5xx']
    error_rate = round((error_count / total) * 100, 2) if total > 0 else 0.0

    # Top 10 endpoints
    top_endpoints = db.session.query(
        AuditLog.endpoint, func.count().label('count')
    ).group_by(AuditLog.endpoint).order_by(func.count().desc()).limit(10).all()

    # Top 5 IPs
    top_ips = db.session.query(
        AuditLog.ip_address, func.count().label('count')
    ).filter(AuditLog.ip_address.isnot(None)
    ).group_by(AuditLog.ip_address).order_by(func.count().desc()).limit(5).all()

    # Top 10 erreurs (4xx/5xx par endpoint + code)
    top_errors = db.session.query(
        AuditLog.endpoint, AuditLog.status_code, func.count().label('count')
    ).filter(AuditLog.status_code >= 400).group_by(
        AuditLog.endpoint, AuditLog.status_code
    ).order_by(func.count().desc()).limit(10).all()

    logger.info("GET /logs/stats — total=%s erreurs=%s", total, error_count)

    return jsonify({
        "success": True,
        "data": {
            "total_requests": total,
            "error_count": error_count,
            "error_rate_pct": error_rate,
            "avg_duration_ms": round(avg_duration, 2),
            "by_status_class": by_class,
            "top_endpoints": [
                {"endpoint": ep, "count": cnt} for ep, cnt in top_endpoints
            ],
            "top_ips": [
                {"ip": ip, "count": cnt} for ip, cnt in top_ips
            ],
            "top_errors": [
                {"endpoint": ep, "status_code": code, "count": cnt}
                for ep, code, cnt in top_errors
            ],
        }
    }), 200
