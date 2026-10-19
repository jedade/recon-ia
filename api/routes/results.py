# routes/results.py
"""
Consultation des résultats par le demandeur, avec le code d'accès reçu par
mail (plan d'action, phase 1 — décisions D1 à D3).

  POST /results/access        { "code": "<43 caractères>" }
      → vérifie le code, ouvre une session de consultation courte
  GET  /results/report        Authorization: Bearer <session>
      → rapport complet (provenance, scan, analyse, rapport narratif)
  GET  /results/export.json   Authorization: Bearer <session>
  GET  /results/export.csv    Authorization: Bearer <session>
  GET  /results/report.pdf    Authorization: Bearer <session>
  GET  /results/export.navigator.json   Authorization: Bearer <session>
      → layer ATT&CK Navigator (phase 4) : techniques rendues possibles
        par les constats, colorées par sévérité

Routes PUBLIQUES (pas de compte admin) : c'est le code, puis la session, qui
autorise. Règles de sécurité :
- le code ne transite que dans le CORPS d'un POST, jamais dans l'URL (qui
  finirait dans les journaux du proxy et l'en-tête Referer) ;
- un code inconnu ou mal formé reçoit la même réponse générique (pas
  d'oracle) ; seuls « expiré » et « révoqué » sont distingués, car ils
  supposent déjà la possession d'un code valide ;
- tentatives limitées par IP ; chaque accès réussi incrémente
  `access_count` / `last_access_at` (en plus de l'audit_log global, qui
  n'enregistre jamais les corps de requête) ;
- la session est revalidée à CHAQUE requête contre l'état du dossier : une
  révocation ou une expiration coupe immédiatement les sessions ouvertes ;
- le contenu n'est jamais déchiffré dans les colonnes du modèle (risque
  d'écriture du clair en base au prochain commit) : uniquement en mémoire.
"""
import io
import json
import logging
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, send_file
from flasgger import swag_from

from database import db
from extensions import limiter
from models.recon import Recon, utc_iso
from routes.report import (
    _consent_error, _safe_filename_part, build_export_csv, build_export_json, pdf_filename,
)
from utils import result_vault
from utils.attack_enablement import (
    annotate_findings, build_attack_chain, build_navigator_layer, technique_context,
)
from utils.mitre_attack import attack_version
from utils.result_vault import VaultError

logger = logging.getLogger(__name__)

results_bp = Blueprint('results', __name__)

_INVALID_CODE = "Code d'accès invalide."


def _error(message: str, status: int):
    return jsonify({'success': False, 'error': message}), status


def _state_error(recon: Recon):
    state = recon.access_state()
    if state == 'revoked':
        return _error("Ce code d'accès a été révoqué.", 403)
    if state == 'expired':
        return _error("Ce code d'accès a expiré. Relancez une analyse pour obtenir un nouveau rapport.", 410)
    if state != 'active' or recon.sealed_at is None:
        return _error(_INVALID_CODE, 401)
    return None


def _summary(recon: Recon) -> dict:
    """Métadonnées non sensibles affichées en tête de la page de résultat."""
    return {
        'domain':            recon.domain,
        'status':            recon.status,
        'security_score':    recon.security_score,
        'security_grade':    recon.security_grade,
        'completed_at':      utc_iso(recon.end_report_date or recon.completed_at),
        'access_expires_at': utc_iso(recon.access_expires_at),
    }


def _session():
    """
    Valide le jeton de session de l'en-tête Authorization.
    Retourne (recon, clé, None) ou (None, None, réponse d'erreur).
    """
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        return None, None, _error('Session de consultation requise.', 401)
    try:
        recon_id, key = result_vault.read_session(header[len('Bearer '):].strip())
    except VaultError:
        return None, None, _error('Session invalide ou expirée. Saisissez à nouveau votre code.', 401)

    recon = db.session.get(Recon, recon_id)
    if recon is None:
        return None, None, _error('Session invalide ou expirée. Saisissez à nouveau votre code.', 401)
    blocked = _state_error(recon)
    if blocked:
        return None, None, blocked
    return recon, key, None


def _unlock_or_error(recon: Recon, key: bytes):
    try:
        return result_vault.unlock(recon, key), None
    except VaultError:
        logger.error('[results] Déchiffrement impossible — recon_id=%d', recon.id)
        return None, _error('Résultats illisibles avec cette session.', 401)


# ── POST /results/access ──────────────────────────────────────────────────────

@results_bp.route('/results/access', methods=['POST'])
@limiter.limit('5 per minute; 30 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': "Ouvrir une session de consultation avec le code d'accès",
    'parameters': [{
        'name': 'body', 'in': 'body', 'required': True,
        'schema': {'type': 'object', 'required': ['code'],
                   'properties': {'code': {'type': 'string', 'description': "Code reçu par mail"}}},
    }],
    'responses': {
        200: {'description': 'Session ouverte (`session_token`, `expires_in` en secondes)'},
        401: {'description': 'Code invalide'},
        403: {'description': 'Code révoqué'},
        410: {'description': 'Code expiré'},
        429: {'description': 'Trop de tentatives'},
        503: {'description': 'Consultation indisponible (configuration serveur)'},
    },
})
def open_session():
    body = request.get_json(silent=True) or {}
    code = body.get('code')
    if isinstance(code, str):
        code = code.strip()
    if not result_vault.is_well_formed_code(code):
        return _error(_INVALID_CODE, 401)
    if not result_vault.is_configured():
        logger.error('[results] RESULTS_ACCESS_SECRET absent — consultation impossible')
        return _error('Consultation momentanément indisponible.', 503)

    recon = Recon.query.filter_by(access_token_hash=result_vault.lookup_hash(code)).first()
    if recon is None:
        logger.warning('[results] Code inconnu — IP %s', request.remote_addr)
        return _error(_INVALID_CODE, 401)
    blocked = _state_error(recon)
    if blocked:
        return blocked

    key = result_vault.derive_key(code, recon.access_salt)
    _, failed = _unlock_or_error(recon, key)
    if failed:
        return failed

    recon.access_count = (recon.access_count or 0) + 1
    recon.last_access_at = datetime.utcnow()
    db.session.commit()
    logger.info('[results] Session ouverte — recon_id=%d accès n°%d', recon.id, recon.access_count)

    return jsonify({
        'success': True,
        'data': {
            'session_token': result_vault.issue_session(recon.id, key),
            'expires_in':    result_vault.session_ttl_seconds(),
            'recon':         _summary(recon),
        },
    }), 200


# ── GET /results/report ───────────────────────────────────────────────────────

@results_bp.route('/results/report', methods=['GET'])
@limiter.limit('120 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': 'Rapport complet du dossier de la session',
    'parameters': [{'name': 'Authorization', 'in': 'header', 'required': True, 'type': 'string',
                    'description': 'Bearer <session_token>'}],
    'responses': {200: {'description': 'Rapport'}, 401: {'description': 'Session invalide'}},
})
def get_report():
    recon, key, error = _session()
    if error:
        return error
    raw, error = _unlock_or_error(recon, key)
    if error:
        return error
    body, _ = build_export_json(recon, raw)
    payload = json.loads(body)
    attack = _attack_view(payload.get('analysis_result'))
    return jsonify({'success': True, 'data': {'recon': _summary(recon), **payload, 'attack': attack}}), 200


def _attack_view(analysis) -> dict:
    """
    Vue ATT&CK de la page de résultat (phase 4). Les constats sont
    ré-annotés EN MÉMOIRE par la table déterministe (idempotent : identique à
    l'annotation faite à l'analyse, et seule source de vérité — une valeur
    stockée venant du LLM est écrasée) ; la chaîne d'attaque en est déduite.
    L'export JSON, lui, reste le jeu de données brut (même `dataset_sha256`).
    """
    if not isinstance(analysis, dict):
        return {'attack_version': attack_version(), 'chain': [], 'context': {}}
    findings = annotate_findings(analysis.get('findings') or [], {})
    analysis['findings'] = findings
    chain = build_attack_chain(findings)
    ids = [t['id'] for step in chain for t in step['techniques'] if step['stage'] != 'reconnaissance']
    return {'attack_version': attack_version(), 'chain': chain, 'context': technique_context(ids)}


# ── GET /results/export.json | export.csv | report.pdf ───────────────────────

def _attachment(body, mimetype: str, filename: str) -> Response:
    response = Response(body, mimetype=mimetype)
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@results_bp.route('/results/export.json', methods=['GET'])
@limiter.limit('60 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': 'Télécharger le jeu de données complet (JSON + provenance)',
    'parameters': [{'name': 'Authorization', 'in': 'header', 'required': True, 'type': 'string'}],
    'responses': {200: {'description': 'Fichier JSON'}, 401: {'description': 'Session invalide'},
                  403: {'description': 'Consentement absent'}},
})
def download_json():
    recon, key, error = _session()
    if error:
        return error
    blocked = _consent_error(recon)
    if blocked:
        return blocked
    raw, error = _unlock_or_error(recon, key)
    if error:
        return error
    body, filename = build_export_json(recon, raw)
    return _attachment(body, 'application/json; charset=utf-8', filename)


@results_bp.route('/results/export.csv', methods=['GET'])
@limiter.limit('60 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': 'Télécharger les constats (CSV)',
    'parameters': [{'name': 'Authorization', 'in': 'header', 'required': True, 'type': 'string'}],
    'responses': {200: {'description': 'Fichier CSV'}, 401: {'description': 'Session invalide'},
                  403: {'description': 'Consentement absent'}},
})
def download_csv():
    recon, key, error = _session()
    if error:
        return error
    blocked = _consent_error(recon)
    if blocked:
        return blocked
    raw, error = _unlock_or_error(recon, key)
    if error:
        return error
    body, filename = build_export_csv(recon, raw)
    return _attachment(body, 'text/csv; charset=utf-8', filename)


@results_bp.route('/results/export.navigator.json', methods=['GET'])
@limiter.limit('60 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': 'Télécharger le layer ATT&CK Navigator (format 4.5, enterprise-attack)',
    'description': "Techniques rendues possibles par les constats (table déterministe), colorées "
                   "par sévérité maximale, et techniques de reconnaissance (gris). À ouvrir dans "
                   "https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer).",
    'parameters': [{'name': 'Authorization', 'in': 'header', 'required': True, 'type': 'string'}],
    'responses': {200: {'description': 'Layer JSON'}, 401: {'description': 'Session invalide'},
                  403: {'description': 'Consentement absent'}},
})
def download_navigator():
    recon, key, error = _session()
    if error:
        return error
    blocked = _consent_error(recon)
    if blocked:
        return blocked
    raw, error = _unlock_or_error(recon, key)
    if error:
        return error
    try:
        analysis = json.loads(raw.get('analysis_result') or '{}')
    except (TypeError, ValueError):
        analysis = {}
    if not isinstance(analysis, dict):
        analysis = {}
    findings = annotate_findings(analysis.get('findings') or [], {})
    layer = build_navigator_layer(findings, analysis.get('mitre_attack'), recon.domain or '')
    body = json.dumps(layer, ensure_ascii=False, indent=2)
    filename = f'recon_ia_attack_navigator_{_safe_filename_part(recon.domain)}_{recon.id}.json'
    logger.info('[results] Layer Navigator — recon_id=%d techniques=%d', recon.id, len(layer['techniques']))
    return _attachment(body, 'application/json; charset=utf-8', filename)


@results_bp.route('/results/report.pdf', methods=['GET'])
@limiter.limit('60 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'summary': 'Télécharger le rapport PDF',
    'parameters': [{'name': 'Authorization', 'in': 'header', 'required': True, 'type': 'string'}],
    'responses': {200: {'description': 'Fichier PDF'}, 401: {'description': 'Session invalide'},
                  404: {'description': 'PDF absent'}},
})
def download_pdf():
    recon, key, error = _session()
    if error:
        return error
    try:
        pdf = result_vault.unlock_pdf(recon, key)
    except VaultError:
        logger.error('[results] PDF indéchiffrable — recon_id=%d', recon.id)
        return _error('Résultats illisibles avec cette session.', 401)
    if not pdf:
        return _error('Aucun rapport PDF pour ce dossier.', 404)
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=pdf_filename(recon))
