# utils/stale_scan_watchdog.py
"""
Filet de sécurité contre les scans silencieusement bloqués.

Contexte (bug réel constaté le 2026-07-29) : un `POST /pass_recon` puis un
`POST /analyze/async` se sont chacun retrouvés bloqués indéfiniment (plus
d'une heure, sans aucune ligne de log) sur le domaine `isoc.bj` — la cause
exacte (probablement un appel réseau externe dont le timeout configuré n'a
pas été respecté par la bibliothèque sous-jacente) reste non identifiée avec
certitude, mais l'effet est reproductible : `recon.status` reste `running`
et `recon.current_step` reste figé indéfiniment, sans email d'échec, sans
qu'aucun mécanisme existant (ni `SCAN_DEADLINE_SECONDS`, ni le timeout
gunicorn `--timeout 300` — qui ne détecte pas un thread bloqué tant qu'un
AUTRE thread du même worker `gthread` répond encore) ne s'en aperçoive.

Plutôt que de chercher à garantir l'absence de blocage dans chaque outil/
appel réseau (47 outils + 5 backends IA, surface bien trop large), ce module
ajoute un filet de sécurité DÉTERMINISTE et indépendant de la cause : un
enregistrement `status='running'` dont `current_step` n'a pas progressé
depuis plus longtemps que la pire durée légitime déjà observée pour cette
étape est considéré bloqué, marqué `failed`, et notifié par email — exactement
comme un échec explicite l'aurait été.

Sûr en multi-worker gunicorn : chaque worker démarre sa propre copie de ce
watchdog, mais le `UPDATE ... WHERE status='running' ... RETURNING` est
atomique — un enregistrement donné n'est jamais marqué/notifié deux fois
même si plusieurs workers l'examinent au même instant (le second UPDATE
concurrent affecte 0 ligne, la condition `status='running'` ne matchant
plus).
"""
import logging
import os
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import text

logger = logging.getLogger(__name__)

# Seuils par étape (secondes) — volontairement généreux : grande marge
# au-dessus de la pire durée légitime déjà mesurée en conditions réelles,
# pour ne jamais interrompre un scan qui progresse encore lentement (ex.
# fallback Ollama Map-Reduce, ~20-25 min mesurés), seulement un cas
# réellement figé.
_STEP_TIMEOUTS_S = {
    # Pipeline déclenché par l'API (POST /verify_email → n8n) mais pas encore
    # démarré par pass_recon : n8n enchaîne en quelques secondes.
    'queued':                  int(os.getenv('WATCHDOG_QUEUED_PIPELINE_TIMEOUT_S', 900)),
    'scanning_osint':          int(os.getenv('WATCHDOG_SCANNING_TIMEOUT_S', 1200)),   # mesuré : 216-307s en usage normal
    'analyzing_ai':            int(os.getenv('WATCHDOG_ANALYZING_TIMEOUT_S', 2400)),  # mesuré : jusqu'à ~25 min (Ollama)
    # En file d'attente du verrou Ollama (utils/ollama_lock.py) — seuil au-delà
    # de OLLAMA_LOCK_ACQUIRE_TIMEOUT_S (déf. 3600s) : filet redondant au cas où
    # le TimeoutError levé par le verrou ne se propagerait pas correctement.
    'analyzing_ai_queued':     int(os.getenv('WATCHDOG_QUEUED_TIMEOUT_S', 4200)),     # 70 min
    'generating_final_report': int(os.getenv('WATCHDOG_FINAL_REPORT_TIMEOUT_S', 600)),
    'generating_pdf':          int(os.getenv('WATCHDOG_PDF_TIMEOUT_S', 600)),
}
# `current_step` encore NULL alors que status='running' (créneau entre la
# vérification email et le premier appel pass_recon) : ne devrait durer que
# quelques secondes en usage normal (n8n enchaîne immédiatement).
_NO_STEP_TIMEOUT_S = int(os.getenv('WATCHDOG_NO_STEP_TIMEOUT_S', 900))

_ERROR_TYPE_BY_STEP = {
    'queued':                  'workflow_failed',
    'scanning_osint':          'scan_failed',
    'analyzing_ai':            'analyze_failed',
    'analyzing_ai_queued':     'analyze_failed',
    'generating_final_report': 'final_report_failed',
    'generating_pdf':          'pdf_failed',
}

_CHECK_INTERVAL_S = int(os.getenv('WATCHDOG_CHECK_INTERVAL_S', 60))


def _mark_and_notify(conn, where_clause: str, params: dict, step_label) -> None:
    from utils.email_sender import send_error_notification

    rows = conn.execute(
        text(
            "UPDATE recon SET status='failed' "
            f"WHERE status='running' AND {where_clause} "
            "RETURNING id, domain, email, firstname, lastname"
        ),
        params,
    ).fetchall()
    conn.commit()

    for recon_id, domain, email, firstname, lastname in rows:
        timeout_s = params.get('timeout_s', _NO_STEP_TIMEOUT_S)
        logger.warning(
            "[watchdog] recon_id=%s bloqué à l'étape %s au-delà de %ds — marqué 'failed'",
            recon_id, step_label, timeout_s,
        )
        if not email:
            continue
        try:
            send_error_notification(
                to_email=email,
                firstname=firstname or '',
                lastname=lastname or '',
                domain=domain,
                error_type=_ERROR_TYPE_BY_STEP.get(step_label, 'workflow_failed'),
                error_detail=(
                    f"Le traitement est resté bloqué plus de {timeout_s // 60} minutes "
                    "sans progression (probablement un appel réseau externe qui n'a pas "
                    "respecté son délai d'attente) — marqué en échec automatiquement."
                ),
                recon_id=recon_id,
            )
        except Exception:
            logger.exception("[watchdog] échec notification recon_id=%s", recon_id)


def _sweep_once(app) -> None:
    from database import db

    now = datetime.utcnow()
    with app.app_context(), db.engine.connect() as conn:
        for step, timeout_s in _STEP_TIMEOUTS_S.items():
            cutoff = now - timedelta(seconds=timeout_s)
            try:
                _mark_and_notify(
                    conn,
                    "current_step = :step AND current_step_updated_at < :cutoff",
                    {"step": step, "cutoff": cutoff, "timeout_s": timeout_s},
                    step,
                )
            except Exception:
                logger.exception("[watchdog] échec du sweep pour l'étape %s", step)

        cutoff_no_step = now - timedelta(seconds=_NO_STEP_TIMEOUT_S)
        try:
            _mark_and_notify(
                conn,
                "current_step IS NULL AND updated_at < :cutoff",
                {"cutoff": cutoff_no_step, "timeout_s": _NO_STEP_TIMEOUT_S},
                None,
            )
        except Exception:
            logger.exception("[watchdog] échec du sweep (current_step NULL)")


# Purge RGPD (utils/retention.py) : greffée sur cette boucle plutôt qu'un
# second thread — même cycle de vie, même désactivation sous pytest.
_RETENTION_INTERVAL_S = int(os.getenv('RETENTION_INTERVAL_S', 3600))


def _run_retention(app) -> None:
    from utils.retention import purge
    with app.app_context():
        try:
            purge()
        except Exception:
            logger.exception("[retention] échec de la purge")
            from database import db
            db.session.rollback()


# Catalogue CISA KEV (utils/kev.py, phase 3) : même greffe que la purge. Le
# module ne retélécharge qu'au-delà de KEV_REFRESH_HOURS ; ce point d'appel
# horaire sert seulement à ce que la première analyse du jour ne paie pas le
# téléchargement. Best-effort, jamais bloquant.
_KEV_CHECK_INTERVAL_S = int(os.getenv('KEV_CHECK_INTERVAL_S', 3600))


def _run_kev_refresh() -> None:
    try:
        from utils.kev import refresh
        refresh()
    except Exception:
        logger.exception("[kev] échec du rafraîchissement (non bloquant)")


def _loop(app) -> None:
    logger.info(
        "[watchdog] démarré — intervalle=%ds, seuils=%s, sans étape=%ds, purge toutes les %ds",
        _CHECK_INTERVAL_S, _STEP_TIMEOUTS_S, _NO_STEP_TIMEOUT_S, _RETENTION_INTERVAL_S,
    )
    last_retention = 0.0
    last_kev = float("-inf")   # premier passage immédiat
    while True:
        try:
            _sweep_once(app)
        except Exception:
            logger.exception("[watchdog] erreur inattendue dans la boucle")
        if time.monotonic() - last_retention >= _RETENTION_INTERVAL_S:
            _run_retention(app)
            last_retention = time.monotonic()
        if time.monotonic() - last_kev >= _KEV_CHECK_INTERVAL_S:
            _run_kev_refresh()
            last_kev = time.monotonic()
        time.sleep(_CHECK_INTERVAL_S)


def start_watchdog(app):
    """Démarre le thread de surveillance (daemon, un par worker gunicorn)."""
    t = threading.Thread(target=_loop, args=(app,), name="stale-scan-watchdog", daemon=True)
    t.start()
    return t
