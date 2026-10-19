# utils/retention.py
"""
Purge automatique des données personnelles et des résultats périmés
(plan d'action, phase 1 — RGPD, minimisation et limitation de conservation).

Exécutée par la boucle du watchdog (utils/stale_scan_watchdog.py) au plus
une fois par `RETENTION_INTERVAL_S`. Toutes les opérations sont
idempotentes : plusieurs workers gunicorn peuvent la lancer en même temps
sans effet de bord.

1. Résultats d'un code d'accès expiré ou révoqué depuis plus de
   `RESULTS_PURGE_GRACE_DAYS` (7 j) : le contenu chiffré est effacé (il est
   de toute façon devenu inutilisable) et l'identité du demandeur est
   anonymisée (prénom, nom, email). Les métadonnées non personnelles
   (domaine, score, durées, compteurs, statut des outils) sont conservées
   pour les statistiques agrégées du dashboard.
2. Demandes jamais vérifiées (OTP non validé) de plus de
   `UNVERIFIED_RETENTION_DAYS` (7 j) : supprimées. Elles ne contiennent que
   des données personnelles saisies dans le formulaire, sans aucun résultat.
3. Journal d'audit de plus de `AUDIT_RETENTION_DAYS` (90 j) : supprimé
   (il contient des adresses IP).

Le cache des scans (`pass_recon_cache`) n'est PAS purgé (décision de
l'utilisateur, 2026-10-19) : il ne contient que des résultats bruts de
reconnaissance passive (données publiques, sans analyse IA ni donnée du
demandeur) et doit rester consultable par l'admin (routes/cache.py), y
compris après expiration — une entrée expirée n'est simplement plus servie
au pipeline et est réécrite au prochain scan du même domaine.
"""
import logging
import os
from datetime import datetime, timedelta

from sqlalchemy import or_

logger = logging.getLogger(__name__)

ANONYMIZED_NAME = 'anonymisé'


def _days(var: str, default: int) -> int:
    return max(1, int(os.getenv(var, str(default))))


def anonymized_email(recon_id: int) -> str:
    # Domaine `.invalid` réservé (RFC 2606) : ne peut jamais recevoir de mail
    return f'purged-{recon_id}@anonymized.invalid'


def purge(now: datetime = None) -> dict:
    """Applique les règles de conservation. Retourne le nombre de lignes par règle."""
    from database import db
    from models.audit_log import AuditLog
    from models.recon import Recon

    now = now or datetime.utcnow()
    grace = now - timedelta(days=_days('RESULTS_PURGE_GRACE_DAYS', 7))
    counts = {}

    # 1. Résultats expirés/révoqués → contenu effacé + identité anonymisée
    stale = Recon.query.filter(
        Recon.sealed_at.isnot(None),
        Recon.results_purged_at.is_(None),
        or_(Recon.access_expires_at < grace, Recon.access_revoked_at < grace),
    ).all()
    for recon in stale:
        recon.sealed_bundle = None
        recon.sealed_pdf = None
        recon.firstname = ANONYMIZED_NAME
        recon.lastname = ANONYMIZED_NAME
        recon.email = anonymized_email(recon.id)
        recon.requested_info = None
        recon.results_purged_at = now
    counts['results_purged'] = len(stale)

    # 2. Demandes jamais vérifiées
    counts['unverified_deleted'] = Recon.query.filter(
        Recon.verification.is_(False),
        Recon.created_at < now - timedelta(days=_days('UNVERIFIED_RETENTION_DAYS', 7)),
    ).delete(synchronize_session=False)

    # 3. Journal d'audit (adresses IP)
    counts['audit_deleted'] = AuditLog.query.filter(
        AuditLog.created_at < now - timedelta(days=_days('AUDIT_RETENTION_DAYS', 90)),
    ).delete(synchronize_session=False)

    db.session.commit()
    if any(counts.values()):
        logger.info('[retention] purge effectuée : %s', counts)
    return counts
