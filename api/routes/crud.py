# routes/crud.py
"""
CRUD principal pour les enregistrements de reconnaissance (Recon).

Format de réponse standardisé
──────────────────────────────
Toutes les réponses suivent l'enveloppe JSON :

  Succès  → {"success": true,  "data": {...},  "message": "..."}
  Liste   → {"success": true,  "data": [...], "total": N, "page": N, "per_page": N, "pages": N}
  Erreur  → {"success": false, "error": "message d'erreur"}

Endpoints
─────────
  POST   /recon                 Créer un enregistrement + OTP email
  POST   /verify_email          Valider l'OTP pour activer l'enregistrement
  GET    /recon                 Liste paginée
  GET    /recon/<id>            Détail (sans données sensibles)
  PUT    /recon/<id>            Mise à jour des champs d'identité
  DELETE /recon/<id>            Suppression définitive
  PATCH  /recon/<id>/result     Mise à jour des résultats n8n (scan + rapport)
  GET    /recon/<id>/report     Rapport complet avec données sensibles
"""
import os
import re
import json as _json
import logging
from datetime import datetime as _dt

from flask import Blueprint, request, jsonify
from flasgger import swag_from

from database import db
from extensions import limiter
from models.recon import Recon, utc_iso
from utils.auth import require_auth
from utils.email_sender import generate_code, send_verification_email, validate_code, send_error_notification
from utils.validators import is_valid_domain
from utils.captcha import verify_turnstile
from utils.pipeline_trigger import trigger_pipeline

logger = logging.getLogger(__name__)

crud_bp = Blueprint('crud', __name__)

# Regex email simple (non-RFC, mais suffisant pour une validation de surface)
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_ALLOWED_STATUSES = {'pending', 'running', 'success', 'failed'}

# Durée de validité d'un code OTP (secondes, configurable via .env)
_OTP_TTL = int(os.getenv('OTP_TTL_SECONDS', '600'))   # 10 min par défaut
# Tentatives incorrectes tolérées par dossier avant invalidation du code.
# La limite par IP (10/h) ne suffit pas seule : un attaquant réparti sur
# plusieurs IP pouvait essayer les 10^6 codes possibles pendant les 10 min de
# validité. 5 essais ⇒ probabilité de succès de 5/10^6 par code émis.
_OTP_MAX_ATTEMPTS = int(os.getenv('OTP_MAX_ATTEMPTS', '5'))


# ---------------------------------------------------------------------------
# POST /recon — Créer un enregistrement
# ---------------------------------------------------------------------------

@crud_bp.route('/recon', methods=['POST'])
@limiter.limit("20 per hour")
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'security': [],
    'summary': 'Créer un enregistrement de reconnaissance avec vérification email',
    'description': (
        'Crée un enregistrement avec `verification=false` et envoie un code OTP à 6 chiffres '
        'valable 10 minutes. L\'enregistrement ne devient actif qu\'après validation via '
        '`POST /verify_email`.\n\n'
        'Champ optionnel `requested_info` : description libre de l\'analyse demandée '
        '(ex. "analyser les sous-domaines et le SSL").'
    ),
    'parameters': [
        {
            'name': 'body', 'in': 'body', 'required': True,
            'schema': {
                'type': 'object',
                'required': ['domain', 'firstname', 'lastname', 'email', 'accord'],
                'properties': {
                    'domain': {'type': 'string', 'example': 'example.com'},
                    'firstname': {'type': 'string', 'example': 'Jean'},
                    'lastname': {'type': 'string', 'example': 'Dupont'},
                    'email': {'type': 'string', 'format': 'email',
                              'example': 'jean.dupont@example.com'},
                    'accord': {'type': 'boolean', 'example': True,
                               'description': 'Consentement au traitement des données'},
                    'requested_info': {'type': 'string', 'example': 'Analyse SSL et sous-domaines',
                                       'description': 'Description libre de la reconnaissance souhaitée'},
                    'turnstile_token': {'type': 'string',
                                        'description': 'Jeton Cloudflare Turnstile du formulaire '
                                                       '(obligatoire si TURNSTILE_SECRET_KEY est défini)'},
                },
                'additionalProperties': False
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Enregistrement créé — code OTP envoyé par email (ou erreur d\'envoi signalée)',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "message": "Enregistrement créé. Un code de vérification a été envoyé à votre email.",
                        "data": {
                            "id": 1,
                            "domain": "example.com",
                            "verification": False,
                            "status": "pending",
                            "start_report_date": None,
                            "end_report_date": None,
                            "execution_time": None
                        },
                        "verification_required": True
                    }
                }
            }
        },
        400: {'description': 'Champ manquant, domaine/email invalide ou email déjà enregistré'},
        429: {'description': 'Limite de 20 créations par heure atteinte'},
    }
})
def create_recon():
    """Crée un nouvel enregistrement Recon et envoie le code OTP par email."""
    data = request.get_json()
    if not data:
        logger.warning("POST /recon — corps JSON absent — IP: %s", request.remote_addr)
        return jsonify({"success": False, "error": "Données JSON requises"}), 400

    # Validation des champs obligatoires
    required = ['domain', 'firstname', 'lastname', 'email', 'accord']
    for field in required:
        if field not in data:
            logger.warning("POST /recon — champ manquant: %r — IP: %s", field, request.remote_addr)
            return jsonify({"success": False, "error": f"Champ requis manquant : {field}"}), 400

    domain = data['domain'].lower().strip()
    if not is_valid_domain(domain):
        logger.warning("POST /recon — domaine invalide: %r", data['domain'])
        return jsonify({"success": False, "error": "Format de domaine invalide"}), 400

    if not _EMAIL_RE.match(data['email']):
        logger.warning("POST /recon — email invalide: %r", data['email'])
        return jsonify({"success": False, "error": "Format d'email invalide"}), 400

    # Consentement obligatoire (2026-10-19) : auparavant `accord` devait être
    # PRÉSENT mais pouvait valoir false — le scan tournait alors quand même et
    # seul l'export final était refusé. Une collecte non consentie ne doit
    # pas démarrer du tout.
    if data.get('accord') is not True:
        return jsonify({"success": False,
                        "error": "Le consentement est requis pour lancer une analyse."}), 400

    # Anti-robot (Cloudflare Turnstile, utils/captcha.py) — avant tout envoi
    # d'email, pour qu'un script ne puisse pas inonder une boîte de codes.
    captcha_ok, captcha_error = verify_turnstile(data.get('turnstile_token'), request.remote_addr)
    if not captcha_ok:
        return jsonify({"success": False, "error": captcha_error}), 400

    # ── Anti-spam OTP ─────────────────────────────────────────────────────────
    # Chaque soumission crée désormais un NOUVEL enregistrement (voir plus bas)
    # — mais un OTP encore valide, sur N'IMPORTE LEQUEL des enregistrements déjà
    # existants pour cet email, bloque quand même un renvoi immédiat : sans ça,
    # rien n'empêcherait de spammer la boîte mail cible d'un nouveau code à
    # chaque appel.
    now = _dt.utcnow()
    pending = (
        Recon.query
        .filter_by(email=data['email'])
        .filter(Recon.otp_code.isnot(None))
        .order_by(Recon.id.desc())
        .first()
    )
    if pending:
        ref_time = pending.otp_sent_at or pending.created_at
        otp_age  = (now - ref_time).total_seconds()
        if otp_age < _OTP_TTL:
            remaining = int(_OTP_TTL - otp_age)
            logger.info(
                "POST /recon — OTP actif pour %s (expire dans %ds) — IP: %s",
                data['email'], remaining, request.remote_addr,
            )
            return jsonify({
                "success": False,
                "error": (
                    f"Un code de vérification a déjà été envoyé à cet email. "
                    f"Vérifiez votre boîte mail ou attendez encore "
                    f"{remaining // 60}m {remaining % 60:02d}s avant de réessayer."
                ),
                "retry_after_seconds": remaining,
            }), 429
        # Code expiré → rien à bloquer, on continue vers la création normale
        # (l'ancien enregistrement, lui, n'est jamais touché — voir plus bas).

    # ── Toujours créer un NOUVEL enregistrement, jamais réutiliser/écraser
    # un enregistrement existant — même pour un email et/ou un domaine déjà
    # vus (2026-07-30, remplace l'ancien mécanisme de « relance différée » à
    # enregistrement unique par email). Nécessaire pour un usage recherche :
    # relancer plusieurs fois le même domaine (test de reproductibilité,
    # comparaison de runs) doit produire plusieurs rapports DISTINCTS et
    # conservés, pas un seul rapport réécrit à chaque tentative — voir
    # CLAUDE.md §5 pour la justification complète et l'ancien design.
    code = generate_code()
    recon_record = Recon(
        domain=domain,
        firstname=data['firstname'],
        lastname=data['lastname'],
        email=data['email'],
        accord=True,
        verification=False,
        otp_code=code,
        otp_attempts=0,
        otp_sent_at=now,
        requested_info=data.get('requested_info'),
        status='pending',
    )
    db.session.add(recon_record)
    db.session.commit()
    logger.info(
        "POST /recon — enregistrement créé id=%s domain=%s email=%s",
        recon_record.id, domain, data['email'],
    )

    try:
        send_verification_email(data['email'], code)
        logger.info("POST /recon — OTP envoyé à %s", data['email'])
    except Exception as e:
        logger.error("POST /recon — échec envoi OTP à %s: %s", data['email'], e)
        return jsonify({
            "success": True,
            "message": "Enregistrement créé. Échec de l'envoi de l'email de vérification.",
            "data": recon_record.to_dict(),
            "verification_required": True,
            "email_error": "Échec de l'envoi de l'email. Contactez le support.",
        }), 201

    return jsonify({
        "success": True,
        "message": "Un code de vérification a été envoyé à votre email.",
        "data": recon_record.to_dict(),
        "verification_required": True,
    }), 201


# ---------------------------------------------------------------------------
# POST /verify_email — Valider l'OTP
# ---------------------------------------------------------------------------

@crud_bp.route('/verify_email', methods=['POST'])
@limiter.limit("10 per hour")
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'security': [],
    'summary': "Valider le code OTP et lancer l'analyse",
    'description': (
        'Route PUBLIQUE appelée par le formulaire (plus par n8n). Valide le code à 6 '
        'chiffres reçu par email. Si le code est correct et non expiré, `verification` '
        'passe à `true`, `start_report_date` est horodaté et l\'API déclenche le pipeline '
        'n8n sur le réseau interne (`pipeline_started` dans la réponse).\n\n'
        f'Le code est effacé après utilisation (usage unique), et après '
        f'{_OTP_MAX_ATTEMPTS} tentatives incorrectes sur un même dossier.'
    ),
    'parameters': [
        {
            'name': 'body', 'in': 'body', 'required': True,
            'schema': {
                'type': 'object',
                'required': ['email', 'code'],
                'properties': {
                    'email': {'type': 'string', 'format': 'email',
                              'example': 'jean.dupont@example.com'},
                    'code': {'type': 'string', 'example': '789456',
                             'description': 'Code OTP à 6 chiffres reçu par email'},
                },
                'additionalProperties': False
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Email validé — enregistrement activé et start_report_date horodaté',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "message": "Email vérifié avec succès. L'enregistrement est maintenant actif.",
                        "data": {
                            "id": 1,
                            "verification": True,
                            "start_report_date": "2025-09-13T10:00:00",
                            "end_report_date": None,
                            "execution_time": None,
                            "status": "pending"
                        }
                    }
                }
            }
        },
        400: {'description': 'Code invalide, expiré ou champs manquants'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Aucun enregistrement trouvé pour cet email'},
        429: {'description': 'Limite de 10 validations par heure atteinte'},
    }
})
def verify_email():
    """
    Valide le code OTP et active l'enregistrement.

    Logique de validation (ordre strict) :
    1. Cherche l'enregistrement par email uniquement (pas par code).
    2. Appelle validate_code() qui vérifie l'expiration puis la correspondance du code.
    3. Commit systématique si validate_code a effacé l'otp_code (succès ou expiration).
    4. En cas de succès : positionne verification=True et start_report_date=now().
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Données JSON requises"}), 400

    email = data.get('email', '').strip()
    code = str(data.get('code', '')).strip()

    if not email or not code:
        return jsonify({"success": False, "error": "Email et code sont requis"}), 400

    # Recherche du record avec un OTP actif pour cet email — plusieurs
    # enregistrements peuvent désormais exister pour le même email (voir
    # POST /recon, 2026-07-30) ; on prend le plus récent portant un OTP en
    # attente, peu importe son statut `verification`.
    recon = (
        Recon.query
        .filter_by(email=email)
        .filter(Recon.otp_code.isnot(None))
        .order_by(Recon.id.desc())
        .first()
    )
    if not recon:
        logger.warning("verify_email — aucun enregistrement en attente pour: %s", email)
        return jsonify({"success": False,
                        "error": "Aucun enregistrement en attente de vérification pour cet email"}), 404

    is_valid, message = validate_code(recon, code)

    if not is_valid:
        if recon.otp_code is not None and message == "Code incorrect":
            recon.otp_attempts = (recon.otp_attempts or 0) + 1
            if recon.otp_attempts >= _OTP_MAX_ATTEMPTS:
                recon.otp_code = None
                message = "Trop de tentatives : ce code est annulé. Soumettez à nouveau le formulaire."
                logger.warning("verify_email — code annulé après %d échecs, id=%s",
                               recon.otp_attempts, recon.id)
        # Persiste l'effacement du code (expiration, trop d'essais) et le compteur
        db.session.commit()
        logger.warning("verify_email — validation échouée pour %s: %s", email, message)
        return jsonify({"success": False, "error": message}), 400

    recon.verification = True
    recon.start_report_date = _dt.utcnow()
    db.session.commit()
    logger.info("verify_email — succès pour id=%s email=%s | start_report_date=%s",
                recon.id, email, recon.start_report_date.isoformat())

    # Déclenchement du pipeline n8n par l'API, sur le réseau interne
    # (utils/pipeline_trigger.py) — le navigateur ne parle plus à n8n.
    pipeline_started, pipeline_error = trigger_pipeline(recon.id)
    if pipeline_started:
        recon.status = 'running'
        recon.set_step('queued')
        db.session.commit()
    else:
        logger.error("verify_email — pipeline non lancé pour id=%s : %s", recon.id, pipeline_error)

    return jsonify({
        "success": True,
        "message": (
            "Email vérifié. L'analyse est lancée : vous recevrez un email avec votre code "
            "d'accès dès que le rapport sera prêt."
            if pipeline_started else
            "Email vérifié, mais le lancement de l'analyse a échoué. L'équipe a été prévenue."
        ),
        "pipeline_started": pipeline_started,
        "data": recon.to_dict(),
    }), 200


# ---------------------------------------------------------------------------
# GET /recon — Liste paginée
# ---------------------------------------------------------------------------

@crud_bp.route('/recon', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Lister tous les enregistrements (paginé)',
    'description': 'Retourne la liste paginée des enregistrements, triés par ID décroissant.',
    'parameters': [
        {'name': 'page', 'in': 'query', 'type': 'integer', 'default': 1,
         'description': 'Numéro de page'},
        {'name': 'per_page', 'in': 'query', 'type': 'integer', 'default': 20,
         'description': 'Résultats par page (max 100)'},
        {'name': 'status', 'in': 'query', 'type': 'string',
         'enum': ['pending', 'running', 'success', 'failed'],
         'description': 'Filtrer par statut d\'exécution (filtrage SQL côté serveur)'},
        {'name': 'domain', 'in': 'query', 'type': 'string',
         'description': 'Filtrer par sous-chaîne de domaine (filtrage SQL côté serveur)'},
    ],
    'responses': {
        200: {
            'description': 'Liste paginée des enregistrements',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "data": [],
                        "total": 0, "page": 1, "per_page": 20, "pages": 0
                    }
                }
            }
        },
        401: {'description': 'Authentification requise'},
    }
})
def get_recons():
    """
    Retourne la liste paginée des enregistrements Recon.

    Les filtres `status` et `domain` sont appliqués en SQL (WHERE), pas côté
    client : `total` et `pages` reflètent donc le nombre d'enregistrements
    filtrés. Filtrer côté client après pagination masquerait les résultats
    situés sur les autres pages.

    Un statut inconnu est rejeté explicitement plutôt qu'ignoré silencieusement.
    """
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status = (request.args.get('status') or '').strip().lower()
    domain = (request.args.get('domain') or '').strip().lower()

    query = Recon.query

    if domain:
        # ilike + paramètre lié par SQLAlchemy — pas de concaténation SQL.
        # Les métacaractères LIKE sont échappés pour qu'une recherche sur '%'
        # ne retourne pas la table entière.
        escaped = domain.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = query.filter(Recon.domain.ilike(f'%{escaped}%', escape='\\'))

    if status:
        if status not in _ALLOWED_STATUSES:
            return jsonify({
                "success": False,
                "error": (
                    f"Statut invalide : {status!r}. "
                    f"Valeurs acceptées : {', '.join(sorted(_ALLOWED_STATUSES))}"
                ),
            }), 400
        query = query.filter(Recon.status == status)

    pagination = query.order_by(Recon.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    logger.debug("GET /recon — page=%s per_page=%s status=%s domain=%s total=%s",
                 page, per_page, status or 'tous', domain or 'tous', pagination.total)

    return jsonify({
        "success": True,
        "data": [r.to_dict() for r in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        # pagination.per_page (et non la valeur demandée) : Flask-SQLAlchemy
        # normalise les valeurs aberrantes, la réponse doit annoncer la taille
        # de page réellement servie.
        "per_page": pagination.per_page,
        "pages": pagination.pages,
        "status_filter": status or None,
        "domain_filter": domain or None,
    }), 200


# ---------------------------------------------------------------------------
# GET /recon/<id> — Détail d'un enregistrement
# ---------------------------------------------------------------------------

@crud_bp.route('/recon/<int:id>', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Récupérer un enregistrement par ID (sans données sensibles)',
    'description': (
        'Retourne les informations publiques de l\'enregistrement. '
        '`scan_results` et `final_report` ne sont **jamais** inclus ici — '
        'utiliser `GET /recon/<id>/report` pour y accéder.'
    ),
    'parameters': [
        {'name': 'id', 'in': 'path', 'required': True, 'type': 'integer'}
    ],
    'responses': {
        200: {'description': 'Détail de l\'enregistrement'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement non trouvé'},
    }
})
def get_recon(id):
    """Retourne la vue publique d'un enregistrement (sans scan_results/final_report)."""
    recon = Recon.query.get_or_404(id)
    logger.debug("GET /recon/%s — domaine: %s", id, recon.domain)
    return jsonify({"success": True, "data": recon.to_dict()}), 200


# ---------------------------------------------------------------------------
# PUT /recon/<id> — Mise à jour des champs d'identité
# ---------------------------------------------------------------------------

@crud_bp.route('/recon/<int:id>', methods=['PUT'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Mettre à jour les champs d\'identité d\'un enregistrement',
    'description': (
        'Met à jour un ou plusieurs champs parmi : domain, firstname, lastname, email, accord, '
        'requested_info.\n\n'
        '**Note sécurité** : le champ `verification` ne peut PAS être modifié via cet endpoint — '
        'la vérification s\'effectue uniquement via `POST /verify_email`.'
    ),
    'parameters': [
        {'name': 'id', 'in': 'path', 'required': True, 'type': 'integer'}
    ],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'domain': {'type': 'string'},
                        'firstname': {'type': 'string'},
                        'lastname': {'type': 'string'},
                        'email': {'type': 'string', 'format': 'email'},
                        'accord': {'type': 'boolean'},
                        'requested_info': {'type': 'string'},
                    },
                    'additionalProperties': False
                }
            }
        }
    },
    'responses': {
        200: {'description': 'Enregistrement mis à jour'},
        400: {'description': 'Données invalides ou email déjà utilisé'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement non trouvé'},
    }
})
def update_recon(id):
    """Met à jour les champs d'identité d'un enregistrement. `verification` est ignoré."""
    recon = Recon.query.get_or_404(id)
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Données JSON requises"}), 400

    updated_fields = []

    if 'domain' in data:
        domain = data['domain'].lower().strip()
        if not is_valid_domain(domain):
            return jsonify({"success": False, "error": "Format de domaine invalide"}), 400
        recon.domain = domain
        updated_fields.append('domain')

    if 'firstname' in data:
        recon.firstname = data['firstname']
        updated_fields.append('firstname')

    if 'lastname' in data:
        recon.lastname = data['lastname']
        updated_fields.append('lastname')

    if 'email' in data:
        if not _EMAIL_RE.match(data['email']):
            return jsonify({"success": False, "error": "Format d'email invalide"}), 400
        # Pas de vérification d'unicité : un email peut désormais être partagé
        # par plusieurs enregistrements (voir CLAUDE.md §5, "Un email peut
        # lancer plusieurs scans distincts").
        recon.email = data['email']
        updated_fields.append('email')

    if 'accord' in data:
        recon.accord = bool(data['accord'])
        updated_fields.append('accord')

    if 'requested_info' in data:
        recon.requested_info = data['requested_info']
        updated_fields.append('requested_info')

    # Silencieusement ignorer 'verification' — la vérification passe par /verify_email
    if 'verification' in data:
        logger.warning("PUT /recon/%s — tentative de modification de 'verification' ignorée", id)

    db.session.commit()
    logger.info("PUT /recon/%s — champs mis à jour: %s", id, updated_fields)

    return jsonify({
        "success": True,
        "message": "Enregistrement mis à jour avec succès.",
        "data": recon.to_dict(),
    }), 200


# ---------------------------------------------------------------------------
# DELETE /recon/<id> — Suppression
# ---------------------------------------------------------------------------

@crud_bp.route('/recon/<int:id>', methods=['DELETE'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Supprimer définitivement un enregistrement',
    'parameters': [
        {'name': 'id', 'in': 'path', 'required': True, 'type': 'integer'}
    ],
    'responses': {
        200: {'description': 'Enregistrement supprimé'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement non trouvé'},
    }
})
def delete_recon(id):
    """Supprime définitivement un enregistrement et toutes ses données associées."""
    recon = Recon.query.get_or_404(id)
    domain = recon.domain
    db.session.delete(recon)
    db.session.commit()
    logger.info("DELETE /recon/%s — domain=%s supprimé", id, domain)
    return jsonify({
        "success": True,
        "message": "Enregistrement supprimé avec succès.",
        "deleted_id": id,
    }), 200


# ---------------------------------------------------------------------------
# PATCH /recon/<id>/result — Mise à jour des résultats n8n
# ---------------------------------------------------------------------------

@crud_bp.route('/recon/<int:id>/result', methods=['PATCH'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Mettre à jour les résultats d\'exécution (webhook n8n)',
    'description': (
        'Endpoint réservé au workflow n8n. Reçoit le statut, les résultats bruts '
        'OSINT (`scan_results`) et le rapport final IA (`final_report`).\n\n'
        'Ces données sensibles ne sont **jamais** retournées dans les GET standards — '
        'uniquement via `GET /recon/<id>/report`.\n\n'
        '**Statuts valides** : `pending` | `running` | `success` | `failed`\n\n'
        '`end_report_date` est positionné automatiquement à la date/heure courante.\n\n'
        '`execution_time` est calculé automatiquement depuis `start_report_date` '
        '(positionné à la vérification email) et `end_report_date`.'
    ),
    'parameters': [
        {'name': 'id', 'in': 'path', 'required': True, 'type': 'integer'}
    ],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'required': ['status'],
                    'properties': {
                        'status': {
                            'type': 'string',
                            'enum': ['pending', 'running', 'success', 'failed'],
                        },
                        'started_at': {
                            'type': 'string', 'format': 'date-time',
                            'example': '2025-09-13T10:00:00'
                        },
                        'completed_at': {
                            'type': 'string', 'format': 'date-time',
                            'example': '2025-09-13T10:00:42'
                        },
                        'scan_results': {
                            'type': 'object',
                            'description': 'Résultats OSINT bruts (objet JSON libre)'
                        },
                        'final_report': {
                            'type': 'string',
                            'description': 'Rapport final en texte généré par l\'IA'
                        }
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Résultats enregistrés — end_report_date et execution_time calculés automatiquement',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "message": "Résultats enregistrés avec succès.",
                        "data": {
                            "id": 1,
                            "status": "success",
                            "execution_time": 42.5,
                            "end_report_date": "2025-09-13T10:00:42"
                        }
                    }
                }
            }
        },
        400: {'description': 'Données invalides (statut, format date)'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement non trouvé'},
    }
})
def update_recon_result(id):
    """Reçoit et persiste les résultats d'exécution envoyés par n8n en fin de workflow."""
    recon = Recon.query.get_or_404(id)
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Données JSON requises"}), 400

    previous_status = recon.status

    status = data.get('status')
    if status and status not in _ALLOWED_STATUSES:
        return jsonify({
            "success": False,
            "error": f"Statut invalide. Valeurs acceptées : {', '.join(sorted(_ALLOWED_STATUSES))}"
        }), 400

    if status:
        recon.status = status

    if 'started_at' in data:
        try:
            recon.started_at = _dt.fromisoformat(data['started_at'])
        except (TypeError, ValueError):
            return jsonify({"success": False,
                            "error": "started_at : format ISO 8601 attendu (ex: 2025-09-13T10:00:00)"}), 400

    if 'completed_at' in data:
        try:
            recon.completed_at = _dt.fromisoformat(data['completed_at'])
        except (TypeError, ValueError):
            return jsonify({"success": False,
                            "error": "completed_at : format ISO 8601 attendu (ex: 2025-09-13T10:00:42)"}), 400

    if 'scan_results' in data:
        try:
            recon.scan_results = _json.dumps(data['scan_results'], ensure_ascii=False)
        except (TypeError, ValueError):
            return jsonify({"success": False,
                            "error": "scan_results doit être un objet JSON valide"}), 400

    if 'final_report' in data:
        if not isinstance(data['final_report'], str):
            return jsonify({"success": False,
                            "error": "final_report doit être une chaîne de caractères"}), 400
        recon.final_report = data['final_report']

    # Horodatage de fin uniquement si le workflow est terminé (success ou failed)
    # Ne pas écraser end_report_date si n8n envoie un status intermédiaire (running)
    _terminal_status = recon.status in ('success', 'failed')
    if _terminal_status:
        recon.end_report_date = _dt.utcnow()
        # Calcul automatique de execution_time depuis start_report_date
        if recon.start_report_date:
            delta = recon.end_report_date - recon.start_report_date
            recon.execution_time = round(delta.total_seconds(), 3)

    db.session.commit()
    logger.info(
        "PATCH /recon/%s/result — statut: %s→%s | durée: %ss | scan: %s | rapport: %s",
        id, previous_status, recon.status, recon.execution_time,
        "oui" if recon.scan_results else "non",
        "oui" if recon.final_report else "non",
    )

    # Notification email si le workflow passe en état d'échec
    if recon.status == 'failed' and previous_status != 'failed':
        try:
            if recon.email:
                send_error_notification(
                    to_email     = recon.email,
                    firstname    = recon.firstname or '',
                    lastname     = recon.lastname  or '',
                    domain       = recon.domain,
                    error_type   = "workflow_failed",
                    error_detail = data.get('error', ''),
                    recon_id     = recon.id,
                )
        except Exception as _mail_e:
            logger.warning("Impossible d'envoyer l'email d'erreur workflow : %s", _mail_e)

    return jsonify({
        "success": True,
        "message": "Résultats enregistrés avec succès.",
        "data": {
            "id": recon.id,
            "status": recon.status,
            "execution_time": recon.execution_time,
            "end_report_date": utc_iso(recon.end_report_date),
        },
    }), 200


# ---------------------------------------------------------------------------
# GET /recon/<id>/report — Rapport complet (données sensibles)
# ---------------------------------------------------------------------------

@crud_bp.route('/recon/<int:id>/report', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'summary': 'Récupérer le rapport complet avec résultats OSINT (données sensibles)',
    'description': (
        'Retourne l\'enregistrement complet incluant **scan_results** (résultats OSINT bruts) '
        'et **final_report** (rapport IA).\n\n'
        'Ces champs ne sont **jamais** inclus dans `GET /recon/<id>` standard.\n\n'
        '⚠️ Accès restreint — authentification requise.'
    ),
    'parameters': [
        {'name': 'id', 'in': 'path', 'required': True, 'type': 'integer'}
    ],
    'responses': {
        200: {
            'description': 'Rapport complet avec données sensibles',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "data": {
                            "id": 1,
                            "domain": "example.com",
                            "status": "success",
                            "execution_time": 42.5,
                            "requested_info": "Analyser sous-domaines et SSL",
                            "scan_results": {"subdomains": ["mail.example.com"]},
                            "final_report": "Aucune vulnérabilité critique détectée.",
                            "started_at": "2025-09-13T10:00:00",
                            "completed_at": "2025-09-13T10:00:42",
                        }
                    }
                }
            }
        },
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement non trouvé'},
    }
})
def get_recon_report(id):
    """Retourne le rapport complet avec scan_results et final_report (données sensibles)."""
    recon = Recon.query.get_or_404(id)
    logger.info("GET /recon/%s/report — domaine: %s | statut: %s", id, recon.domain, recon.status)
    return jsonify({"success": True, "data": recon.to_dict_full()}), 200
