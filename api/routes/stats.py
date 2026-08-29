# routes/stats.py
"""
Agrégats globaux pour le dashboard.

  GET /recon/stats
      → KPI calculés côté serveur sur l'ENSEMBLE des enregistrements.

Pourquoi cet endpoint existe
─────────────────────────────
Le dashboard calculait auparavant ses KPI côté client à partir d'une seule page
de `GET /recon` (`per_page=200`, plafonné à 100 côté serveur). Les compteurs
présentés comme des totaux globaux ne portaient donc en réalité que sur les
100 derniers enregistrements — un biais silencieux inacceptable pour des
métriques destinées à une publication académique.

Ici, tous les comptages sont des agrégats SQL (`COUNT`/`SUM`) exécutés sur la
table entière, sans pagination.

Note sur `avg_security_score`
──────────────────────────────
`security_score` était initialement lu dans le JSON de `analysis_result`, ce
qui obligeait à transférer tous les rapports IA de la table pour n'en extraire
qu'un entier. Il est désormais dénormalisé en colonne dédiée (phase 4), et la
moyenne est un simple `AVG` SQL.

Les analyses dont la colonne n'est pas encore renseignée (antérieures au
backfill de `migrate.py`) sont exclues de la moyenne et comptées séparément
dans `unscored_analyses`, pour que l'écart soit visible et non silencieux.
"""
import json
import logging
from collections import Counter

from flask import Blueprint, jsonify
from flasgger import swag_from
from sqlalchemy import func, case

from database import db
from models.recon import Recon, utc_now_iso
from utils.auth import require_auth
from utils.mitre_attack import TECHNIQUES as _MITRE_TECHNIQUES

logger = logging.getLogger(__name__)

stats_bp = Blueprint('stats', __name__)


def _count_case(condition):
    """Compteur conditionnel portable : SUM(CASE WHEN cond THEN 1 ELSE 0 END)."""
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def _avg_security_score():
    """
    Moyenne des `security_score` sur toutes les analyses IA stockées.

    Agrégation entièrement SQL depuis la colonne dénormalisée : plus aucun
    rapport IA n'est rapatrié ni parsé côté application. Auparavant, calculer
    cette moyenne imposait de transférer l'intégralité des `analysis_result`
    de la table (plusieurs dizaines de Ko chacun) pour n'en lire qu'un entier.

    Les lignes sans score (NULL) sont ignorées par AVG/COUNT et ne sont donc
    pas comptées comme des zéros, ce qui fausserait la moyenne.
    """
    row = db.session.query(
        func.avg(Recon.security_score),
        func.count(Recon.security_score),
    ).one()

    average, count = row[0], int(row[1] or 0)
    if not count or average is None:
        return None, 0
    return round(float(average), 1), count


def _tokens_stats():
    """
    Tokens IA consommés sur l'ensemble des analyses (mesure de coût/usage).

    Agrégat SQL sur la colonne dénormalisée `tokens_total` (voir
    models/recon.py::_extract_tokens / set_analysis_result) — jamais de
    reparsing de analysis_result. Somme globale (coût réel cumulé) ET moyenne
    par analyse (comparaison entre runs) ; les analyses produites avant
    l'ajout de cette mesure (`tokens_total IS NULL`) sont ignorées par
    AVG/SUM plutôt que comptées comme des zéros, ce qui fausserait la moyenne.
    """
    row = db.session.query(
        func.coalesce(func.sum(Recon.tokens_total), 0),
        func.avg(Recon.tokens_total),
        func.count(Recon.tokens_total),
    ).one()

    total_tokens, average, count = int(row[0] or 0), row[1], int(row[2] or 0)
    return {
        'total_tokens_all_time': total_tokens,
        'avg_tokens_per_analysis': round(float(average), 0) if average is not None else None,
        'measured_analyses': count,
    }


def _traceability_stats():
    """
    Conformité outil→finding : sur tous les findings IA jamais produits, quelle
    proportion cite un `source_tool` réellement présent dans tools_executed.

    Agrégat SQL sur deux colonnes Integer dénormalisées (findings_total_count/
    findings_traceable_count) — jamais de reparsing de analysis_result. Somme
    globale des deux compteurs puis un seul ratio, pas une moyenne de ratios
    par ligne (des analyses avec des tailles de findings très différentes
    fausseraient sinon la moyenne).
    """
    row = db.session.query(
        func.coalesce(func.sum(Recon.findings_total_count), 0),
        func.coalesce(func.sum(Recon.findings_traceable_count), 0),
        func.count(Recon.findings_total_count),
    ).filter(Recon.findings_total_count.isnot(None)).one()

    total_findings, traceable_findings, analyses_checked = int(row[0]), int(row[1]), int(row[2])
    rate = round((traceable_findings / total_findings) * 100, 1) if total_findings else None
    return {
        'analyses_checked':     analyses_checked,
        'findings_total':       total_findings,
        'findings_traceable':   traceable_findings,
        'traceability_rate_pct': rate,
    }


def _mitre_coverage_stats():
    """
    Couverture MITRE ATT&CK sur l'ensemble des scans.

    `mitre_technique_count` (Integer) s'agrège en SQL pour la moyenne. Le
    détail par technique/tactique lit `mitre_technique_ids` — une petite
    liste JSON de quelques dizaines d'octets par ligne, jamais le rapport
    IA complet — avec `yield_per` pour éviter de charger toute la table
    d'un coup si elle grossit.
    """
    avg_count = (
        db.session.query(func.avg(Recon.mitre_technique_count))
        .filter(Recon.mitre_technique_count.isnot(None))
        .scalar()
    )

    rows = (
        db.session.query(Recon.mitre_technique_ids)
        .filter(Recon.mitre_technique_ids.isnot(None))
        .yield_per(500)
    )
    distinct_ids = set()
    for (ids_json,) in rows:
        try:
            distinct_ids.update(json.loads(ids_json) or [])
        except Exception:
            continue

    by_tactic = Counter()
    for tid in distinct_ids:
        meta = _MITRE_TECHNIQUES.get(tid)
        if meta:
            by_tactic[meta['tactic']] += 1

    total_known = len(_MITRE_TECHNIQUES)
    return {
        'distinct_techniques_count': len(distinct_ids),
        'distinct_techniques':       sorted(distinct_ids),
        'total_known_techniques':    total_known,
        'coverage_pct':              round(len(distinct_ids) / total_known * 100, 1) if total_known else None,
        'avg_techniques_per_scan':   round(float(avg_count), 1) if avg_count is not None else None,
        'by_tactic':                 dict(by_tactic),
    }


def _tools_reliability_stats():
    """
    Fiabilité agrégée des 47 outils OSINT passifs sur tous les scans.

    Lit `tools_status_summary` — un résumé de quelques comptes par statut
    (quelques dizaines d'octets), jamais le blob `scan_results` complet
    (potentiellement des centaines de Ko par scan avec le raw_output des
    47 outils).
    """
    rows = (
        db.session.query(Recon.tools_status_summary)
        .filter(Recon.tools_status_summary.isnot(None))
        .yield_per(500)
    )
    counts = Counter()
    scans_counted = 0
    for (summary_json,) in rows:
        try:
            parsed = json.loads(summary_json) or {}
        except Exception:
            continue
        scans_counted += 1
        for status, n in parsed.items():
            counts[status] += int(n)

    total = sum(counts.values())
    success = counts.get('success', 0)
    return {
        'scans_counted':         scans_counted,
        'total_tool_executions': total,
        'by_status':             dict(counts),
        'success_rate_pct':      round(success / total * 100, 1) if total else None,
    }


@stats_bp.route('/recon/stats', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['CRUD - Reconnaissance'],
    'security': [{'basicAuth': []}],
    'summary': 'Agrégats globaux des reconnaissances (KPI dashboard)',
    'description': (
        'Retourne les KPI calculés en SQL sur **l\'ensemble** des enregistrements, '
        'sans pagination.\n\n'
        'Remplace le calcul client qui ne portait que sur la page courante et '
        'sous-estimait silencieusement les totaux.'
    ),
    'responses': {
        200: {
            'description': 'Agrégats globaux',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "data": {
                            "total_recons": 128,
                            "pdf_generated": 91,
                            "analyses_completed": 104,
                            "in_progress": 6,
                            "by_status": {
                                "pending": 4, "running": 2,
                                "success": 118, "failed": 4,
                            },
                            "success_rate_pct": 92.2,
                            "avg_security_score": 63.4,
                            "scored_recons": 104,
                            "avg_scan_duration_s": 41.7,
                            "tokens": {
                                "total_tokens_all_time": 1245830,
                                "avg_tokens_per_analysis": 12690.0,
                                "measured_analyses": 98,
                            },
                            "compliance": {
                                "traceability": {"traceability_rate_pct": 98.5},
                                "mitre_coverage": {"distinct_techniques_count": 9, "coverage_pct": 60.0},
                                "tools_reliability": {"success_rate_pct": 87.2},
                            },
                            "computed_at": "2026-07-27T09:15:00Z",
                        },
                    }
                }
            }
        },
        401: {'description': 'Authentification requise'},
    },
})
def get_recon_stats():
    """Calcule les KPI globaux du dashboard par agrégation SQL sur toute la table."""
    row = db.session.query(
        func.count(Recon.id).label('total'),
        _count_case(Recon.pdf_report.isnot(None)).label('pdf_generated'),
        _count_case(Recon.analysis_result.isnot(None)).label('analyses_completed'),
        _count_case(Recon.status == 'pending').label('pending'),
        _count_case(Recon.status == 'running').label('running'),
        _count_case(Recon.status == 'success').label('success'),
        _count_case(Recon.status == 'failed').label('failed'),
        # execution_time = end_report_date - start_report_date, c'est-à-dire la
        # durée TOTALE du flux (validation email → PDF), attente utilisateur
        # incluse — surtout pas la durée du scan OSINT, qui se mesure entre
        # started_at et completed_at. Nommer ce KPI « durée de scan » le
        # surestimerait d'un ordre de grandeur.
        func.avg(Recon.execution_time).label('avg_flow_duration'),
    ).one()

    total = int(row.total or 0)
    pending = int(row.pending or 0)
    running = int(row.running or 0)
    success = int(row.success or 0)
    failed = int(row.failed or 0)

    # Taux de succès sur l'ensemble des enregistrements (pas sur une page)
    success_rate = round((success / total) * 100, 1) if total else 0.0

    avg_score, scored = _avg_security_score()

    # Analyses présentes mais sans score dénormalisé : elles sont exclues de la
    # moyenne. Normalement zéro après le backfill de migrate.py — on l'expose
    # plutôt que de laisser un écart silencieux dans une métrique publiée.
    unscored = int(
        db.session.query(func.count(Recon.id))
        .filter(Recon.analysis_result.isnot(None), Recon.security_score.is_(None))
        .scalar() or 0
    )
    if unscored:
        logger.warning(
            '%d analyse(s) sans security_score dénormalisé — exclues de la moyenne. '
            'Lancez migrate.py pour le backfill.', unscored,
        )

    avg_flow = row.avg_flow_duration
    avg_flow = round(float(avg_flow), 1) if avg_flow is not None else None

    # Durée moyenne du scan OSINT proprement dite (completed_at - started_at),
    # calculée uniquement sur les enregistrements où les deux bornes existent.
    scan_rows = (
        db.session.query(Recon.started_at, Recon.completed_at)
        .filter(Recon.started_at.isnot(None), Recon.completed_at.isnot(None))
        .yield_per(500)
    )
    scan_total, scan_count = 0.0, 0
    for started_at, completed_at in scan_rows:
        delta = (completed_at - started_at).total_seconds()
        if delta >= 0:
            scan_total += delta
            scan_count += 1
    avg_scan = round(scan_total / scan_count, 1) if scan_count else None

    data = {
        'total_recons':        total,
        'pdf_generated':       int(row.pdf_generated or 0),
        'analyses_completed':  int(row.analyses_completed or 0),
        'in_progress':         pending + running,
        'by_status': {
            'pending': pending,
            'running': running,
            'success': success,
            'failed':  failed,
        },
        'success_rate_pct':    success_rate,
        'avg_security_score':  avg_score,
        'scored_recons':       scored,
        'unscored_analyses':   unscored,
        'avg_scan_duration_s': avg_scan,   # completed_at - started_at
        'avg_flow_duration_s': avg_flow,   # end_report_date - start_report_date
        'tokens':              _tokens_stats(),
        # Métriques de conformité / recherche — voir docstrings des fonctions
        # dédiées pour la méthodologie de calcul de chaque bloc.
        'compliance': {
            'traceability':     _traceability_stats(),
            'mitre_coverage':   _mitre_coverage_stats(),
            'tools_reliability': _tools_reliability_stats(),
        },
        'computed_at':         utc_now_iso(),
    }

    logger.debug('GET /recon/stats — total=%s success_rate=%s avg_score=%s',
                 total, success_rate, avg_score)

    return jsonify({'success': True, 'data': data}), 200
