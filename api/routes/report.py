# routes/report.py
"""
Endpoints PDF :
  POST /recon/<id>/generate_final_report
      → Condense scan_results + analysis_result via IA
      → Stocke le rapport narratif dans recon.final_report

  POST /recon/<id>/generate_report
      → Génère le PDF depuis analysis_result (+ final_report s'il existe)
      → Stocke recon.pdf_report + envoie par email

  GET  /recon/<id>/report.pdf
      → Télécharge le PDF stocké en base

  GET  /recon/<id>/export.json
      → Dump structuré complet + empreinte de reproductibilité (SHA-256)

  GET  /recon/<id>/export.csv
      → Une ligne par finding, colonnes stables pour analyse tabulaire

  POST /recon/<id>/issue_access   (admin)
      → Réémet le code d'accès d'un dossier pas encore scellé (mail en échec)

  POST /recon/<id>/revoke_access  (admin)
      → Révoque le code d'accès d'un dossier

Coffre des résultats (2026-10-19) : en fin de pipeline, generate_report
scelle le dossier (utils/result_vault.py) et envoie le code d'accès par
mail, sans pièce jointe. Une fois scellé, les routes admin ci-dessus ne
peuvent plus lire le contenu (403) : seul le demandeur, avec son code, le
consulte via routes/results.py.

Graphe et différentiel (phase 7) : juste avant le PDF et le scellement,
generate_report alimente le graphe d'entités et enregistre le différentiel
avec le scan précédent du même domaine (`_record_graph_and_diff`, tables
entity/relation/scan_snapshot, en clair car limitées à des données
techniques publiques — voir models/scan_monitoring.py).
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

from flask import Blueprint, request, jsonify, send_file, Response
from flasgger import swag_from

from database import db
from extensions import limiter
from models.recon import Recon, utc_iso, utc_now_iso
from utils import result_vault
from utils.auth import require_auth, require_service_or_auth
from utils.pdf_generator import generate_pdf
from utils.attack_enablement import annotate_findings, attack_csv_fields
from utils.email_sender import send_results_ready_email, send_error_notification

logger = logging.getLogger(__name__)

report_bp = Blueprint('report', __name__)

# Version du schéma d'export — à incrémenter si la structure change de façon
# non rétro-compatible, pour que les jeux de données publiés restent citables.
_EXPORT_SCHEMA_VERSION = '1.0'

# Colonnes du CSV — ordre stable, contractuel pour les consommateurs (R, pandas…)
# `grounding_status` ajoutée en fin de liste (voir utils/grounding_check.py) :
# ajout rétrocompatible, ne change pas l'ordre des colonnes existantes.
_CSV_COLUMNS = [
    'finding_id', 'tool', 'tool_category', 'target', 'indicator', 'value',
    'severity', 'confidence', 'source_tool', 'source_url', 'collected_at',
    'grounding_status', 'observed_at', 'severity_rule', 'attack_enabled', 'mitigations',
]

# Marque d'ordre des octets UTF-8 — préfixe le CSV pour qu'Excel affiche
# correctement les accents des libellés français.
_UTF8_BOM = '﻿'

# Caractères autorisés dans un nom de fichier d'export.
_FILENAME_SAFE_RE = re.compile(r'[^A-Za-z0-9._-]')

# Caractères qui, en tête de cellule, font interpréter la valeur comme une
# formule par Excel/LibreOffice (CWE-1236, « CSV injection »).
_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _safe_filename_part(value: str, fallback: str = 'export') -> str:
    """
    Neutralise une portion de nom de fichier destinée à Content-Disposition.

    `recon.domain` est fourni par l'utilisateur. Il est certes validé par
    is_valid_domain() à l'écriture, mais faire reposer la sûreté d'un en-tête
    HTTP sur une validation effectuée ailleurs est fragile : on filtre donc ici
    aussi (défense en profondeur), ce qui élimine guillemets, retours à la ligne
    et tout caractère permettant d'injecter un en-tête ou de casser le quoting.
    """
    cleaned = _FILENAME_SAFE_RE.sub('_', str(value or '')).strip('._-')
    return cleaned[:100] or fallback


def _csv_safe(value):
    """
    Neutralise l'injection de formule CSV pour une ouverture dans un tableur.

    Les valeurs proviennent de sorties d'outils OSINT et de texte généré par
    l'IA : une cellule commençant par '=' serait exécutée à l'ouverture du
    fichier dans Excel. On préfixe alors une apostrophe, convention reconnue
    par les tableurs pour « traiter comme du texte ».

    Note pour l'exploitation scientifique : seule la vue CSV est ainsi
    neutralisée. L'export JSON conserve les valeurs strictement intactes et
    reste la source de référence citée par le SHA-256.
    """
    if value is None:
        return ''
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_timing(recon: Recon, analysis: dict) -> dict:
    """
    Calcule les délais à partir des horodatages stockés dans la BD.
    Retourne un dict compatible avec generate_pdf(timing=...).

    Champs calculés :
      scan_duration_s      : durée du scan OSINT (started_at → completed_at ou execution_time)
      analysis_duration_s  : durée de l'analyse IA (completed_at → analysis_generated_at)
      final_report_gen_s   : durée génération rapport final (si disponible via analysis_generated_at)
      total_duration_s     : durée totale depuis validation email (start_report_date → maintenant)

    Bug corrigé (2026-07-29) : `end_report_date` était utilisé ici comme
    marqueur de fin de SCAN, mais routes/recon.py::pass_recon ne le
    positionne plus (il représente désormais uniquement la fin de TOUT le
    flux, cohérent avec `Recon.flow_duration_s()`) — `completed_at` est le
    marqueur non ambigu de fin de scan (déjà utilisé pour `scan_duration_s`
    ci-dessus), utilisé ici en priorité.
    """
    timing: dict = {}

    # Durée scan OSINT
    if recon.started_at and recon.completed_at:
        timing['scan_duration_s'] = max(
            0.0, (recon.completed_at - recon.started_at).total_seconds()
        )
    elif recon.execution_time:
        timing['scan_duration_s'] = recon.execution_time

    # Durée analyse IA — depuis analysis_generated_at en BD (plus fiable que le champ analyzed_at du JSON)
    scan_end = recon.completed_at or recon.end_report_date
    if recon.analysis_generated_at and scan_end:
        timing['analysis_duration_s'] = max(
            0.0, (recon.analysis_generated_at - scan_end).total_seconds()
        )
    else:
        # Fallback : analyzed_at depuis le JSON de l'analyse
        analyzed_at_str = analysis.get('analyzed_at')
        if analyzed_at_str and scan_end:
            try:
                analyzed_dt = datetime.fromisoformat(
                    analyzed_at_str.replace('Z', '+00:00')
                ).replace(tzinfo=None)
                timing['analysis_duration_s'] = max(
                    0.0, (analyzed_dt - scan_end).total_seconds()
                )
            except Exception:
                pass

    # Durée totale du flux — FIGÉE (fin - début), jamais « maintenant - début ».
    # Un PDF régénéré doit afficher la même durée que le premier tirage.
    flow = recon.flow_duration_s()
    if flow is not None:
        timing['total_duration_s'] = flow

    # Horodatages absolus pour affichage
    if recon.started_at:
        timing['scan_started_at'] = recon.started_at.isoformat()
    if recon.completed_at:
        timing['scan_completed_at'] = recon.completed_at.isoformat()
    if recon.analysis_generated_at:
        timing['analysis_completed_at'] = recon.analysis_generated_at.isoformat()
    if recon.start_report_date:
        timing['flow_started_at'] = recon.start_report_date.isoformat()

    return timing


def _parse_json_text(text: Optional[str], label: str, recon_id) -> Optional[dict]:
    """Désérialise un champ JSON stocké en Text ; None si absent ou corrompu."""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        logger.warning('%s illisible (JSON corrompu) — recon_id=%s', label, recon_id,
                       exc_info=True)
        return None


def _load_analysis_from_db(recon: Recon) -> Optional[dict]:
    """Charge et désérialise analysis_result depuis la BD."""
    return _parse_json_text(recon.analysis_result, 'analysis_result', recon.id)


def _load_scan_from_db(recon: Recon) -> Optional[dict]:
    """Charge et désérialise scan_results depuis la BD."""
    return _parse_json_text(recon.scan_results, 'scan_results', recon.id)


def _raw_fields(recon: Recon) -> dict:
    """Valeurs brutes (texte) des champs exportables, depuis les colonnes en clair."""
    return {name: getattr(recon, name) for name in result_vault.BUNDLE_FIELDS}


def _sealed_error(recon: Recon):
    """
    Refuse l'accès admin au CONTENU d'un dossier scellé.

    Une fois chiffré, le contenu n'est plus lisible côté serveur sans le code
    du demandeur (décision D3) : renvoyer un 403 explicite plutôt qu'un
    « absent » trompeur, qui laisserait croire que le scan n'a rien produit.
    """
    if recon.sealed_at is not None:
        return jsonify({
            'success': False,
            'error': (
                "Résultats chiffrés : ce dossier n'est consultable qu'avec le code "
                "d'accès envoyé au demandeur (page « Voir le résultat »)."
            ),
            'results_sealed': True,
        }), 403
    return None


def _integrity_report(recon: Recon, scan_results, analysis_result, raw: Optional[dict] = None) -> dict:
    """
    Distingue « donnée absente » de « donnée présente mais illisible ».

    Sans ce bloc, un scan_results corrompu produirait un export parfaitement
    valide en apparence — scan_results: null, dataset_sha256: null, citation
    annonçant « 0 outils passifs » — c'est-à-dire un jeu de données faux
    présenté comme authentique. Inacceptable pour une donnée destinée à être
    citée : on expose explicitement l'écart.

    `raw` : valeurs brutes des champs (déchiffrées pour un dossier scellé) ;
    par défaut, les colonnes en clair du dossier.
    """
    raw = raw if raw is not None else _raw_fields(recon)
    scan_stored = raw.get('scan_results') is not None
    analysis_stored = raw.get('analysis_result') is not None
    return {
        'scan_results_stored':     scan_stored,
        'scan_results_parsed':     scan_results is not None,
        'analysis_result_stored':  analysis_stored,
        'analysis_result_parsed':  analysis_result is not None,
        'corrupted': bool(
            (scan_stored and scan_results is None)
            or (analysis_stored and analysis_result is None)
        ),
    }


def _parse_final_report(text: Optional[str]) -> Optional[dict]:
    """
    Désérialise final_report.

    Le champ est stocké en Text : soit du JSON sérialisé (rapport narratif IA
    produit par generate_final_report), soit du texte libre (ancien flux n8n).
    Retourne le dict désérialisé si possible, sinon {'text': <contenu brut>}
    pour ne jamais perdre de données à l'export.
    """
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        return {'value': parsed}
    except Exception:
        return {'text': text}


def _load_final_report_from_db(recon: Recon) -> Optional[dict]:
    """Charge final_report depuis les colonnes en clair de la BD."""
    return _parse_final_report(recon.final_report)


# ── Helpers d'export académique ───────────────────────────────────────────────

def _consent_error(recon: Recon):
    """
    Refuse l'export d'un enregistrement sans consentement enregistré.

    Ces exports sont conçus pour alimenter des jeux de données citables. Sortir
    les données d'une cible dont le demandeur n'a jamais coché `accord` (ou dont
    l'email n'a jamais été validé) reviendrait à publier une collecte non
    consentie. Retourne une réponse Flask si l'export doit être bloqué, sinon None.
    """
    if not recon.accord:
        logger.warning('[export] refusé — consentement absent recon_id=%s', recon.id)
        return jsonify({
            'success': False,
            'error': (
                "Export refusé : aucun consentement (`accord`) enregistré pour "
                "cette reconnaissance. Les exports destinés à publication "
                "requièrent un consentement explicite."
            ),
        }), 403
    return None


def _canonical_json(obj) -> str:
    """
    Sérialisation JSON canonique — clés triées, séparateurs compacts.

    Deux dictionnaires sémantiquement identiques produisent toujours la même
    chaîne, donc le même SHA-256. C'est la base de l'empreinte de
    reproductibilité citée dans les publications.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str)


def _dataset_sha256(scan_results: Optional[dict]) -> Optional[str]:
    """SHA-256 du bloc scan_results sérialisé en JSON canonique."""
    if scan_results is None:
        return None
    return hashlib.sha256(_canonical_json(scan_results).encode('utf-8')).hexdigest()


def _tools_inventory(scan_results: Optional[dict]) -> list:
    """
    Inventaire des outils réellement exécutés, extrait de scan_results.

    S'appuie sur la traçabilité `meta.tool` / `meta.category` posée en phase 2 :
    chaque entrée de scan_results portant un bloc `meta.tool` correspond à un
    outil exécuté. Les clés sans `meta` (ex: le bloc `cache`) sont ignorées.
    """
    if not isinstance(scan_results, dict):
        return []
    tools = []
    for key, value in scan_results.items():
        if not isinstance(value, dict):
            continue
        meta = value.get('meta')
        if not isinstance(meta, dict) or not meta.get('tool'):
            continue
        tools.append({
            'key':      key,
            'name':     meta.get('tool'),
            'category': meta.get('category'),
            'status':   value.get('status'),
        })
    return sorted(tools, key=lambda t: (t.get('category') or '', t['key']))


def _scan_duration_s(recon: Recon, scan_results: Optional[dict]):
    """Durée du scan : horodatages BD en priorité, repli sur le bloc cache du scan."""
    duration = recon.scan_duration_s()
    if duration is not None:
        return duration
    if isinstance(scan_results, dict):
        cache = scan_results.get('cache')
        if isinstance(cache, dict):
            return cache.get('scan_duration_s')
    return None


def _cache_hit(scan_results: Optional[dict]):
    """Indique si le scan provient du cache — info déjà posée dans scan_results.cache.hit."""
    if isinstance(scan_results, dict):
        cache = scan_results.get('cache')
        if isinstance(cache, dict):
            return cache.get('hit')
    return None


def _build_provenance(recon: Recon, scan_results, analysis_result, raw: Optional[dict] = None) -> dict:
    """Construit le bloc de provenance/reproductibilité de l'export."""
    tools = _tools_inventory(scan_results)
    analysis = analysis_result if isinstance(analysis_result, dict) else {}

    return {
        'schema_version':  _EXPORT_SCHEMA_VERSION,
        'generated_at':    utc_now_iso(),
        'recon_id':        recon.id,
        'domain':          recon.domain,
        'tools_requested': [t['key'] for t in tools],
        'tools_detail':    tools,
        'scan_duration_s': _scan_duration_s(recon, scan_results),
        'ai_backend_used': analysis.get('model_used'),
        'cache_hit':       _cache_hit(scan_results),
        'dataset_sha256':  _dataset_sha256(scan_results),
        'data_integrity':  _integrity_report(recon, scan_results, analysis_result, raw),
        'scan_started_at':   utc_iso(recon.started_at),
        'scan_completed_at': utc_iso(recon.completed_at),
        'analysis_generated_at': utc_iso(recon.analysis_generated_at),
        'methodology': (
            'Reconnaissance passive uniquement — aucune interaction intrusive '
            'avec les systèmes cibles.'
        ),
    }


def _build_citation(recon: Recon, provenance: dict) -> str:
    """
    Chaîne de citation prête à être reprise dans un article.

    Format : Recon-IA, scan of {domain}, {date UTC}, N outils passifs ({liste}),
             dataset SHA-256: {hash}
    """
    tools = provenance.get('tools_requested') or []
    scan_date = (
        provenance.get('scan_completed_at')
        or provenance.get('generated_at')
    )
    return (
        f"Recon-IA, scan of {recon.domain}, {scan_date}, "
        f"{len(tools)} outils passifs ({', '.join(tools) if tools else 'aucun'}), "
        f"dataset SHA-256: {provenance.get('dataset_sha256') or 'n/a'}"
    )


def _finding_rows(recon: Recon, scan_results, analysis_result) -> list:
    """
    Aplatit les findings de l'analyse IA en lignes tabulaires.

    Mapping (le schéma réel des findings ne porte pas toutes les colonnes
    demandées — on mappe au plus proche et on laisse vide ce qui n'existe pas
    plutôt que d'inventer une valeur) :

      finding_id    ← finding.id (ou index séquentiel de repli)
      tool          ← meta.tool de l'outil source dans scan_results
      tool_category ← meta.category de l'outil source, repli finding.category
      target        ← domaine analysé
      indicator     ← finding.title
      value         ← finding.evidence, repli finding.description
      severity      ← finding.severity
      confidence    ← finding.confidence si le modèle l'a fourni, sinon vide
                      (champ absent du schéma d'analyse — jamais fabriqué)
      source_tool   ← finding.source_tool (traçabilité phase 2)
      source_url    ← finding.web_sources, joint par « ; »
      collected_at  ← fin du scan (date de collecte de la donnée brute)
      grounding_status ← finding.grounding.status (contrôle d'ancrage automatique,
                      voir utils/grounding_check.py) — vide si l'analyse ne
                      contient pas encore ce champ (rapports générés avant son
                      introduction).
    """
    analysis = analysis_result if isinstance(analysis_result, dict) else {}
    findings = analysis.get('findings')
    if not isinstance(findings, list):
        return []

    scan = scan_results if isinstance(scan_results, dict) else {}
    collected_at = (
        utc_iso(recon.completed_at)
        or utc_iso(recon.end_report_date)
        or utc_iso(recon.analysis_generated_at)
        or ''
    )

    rows = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue

        source_tool = finding.get('source_tool') or ''
        tool_entry = scan.get(source_tool) if source_tool else None
        meta = tool_entry.get('meta') if isinstance(tool_entry, dict) else None
        meta = meta if isinstance(meta, dict) else {}

        web_sources = finding.get('web_sources')
        if isinstance(web_sources, list):
            source_url = ' ; '.join(str(u) for u in web_sources if u)
        else:
            source_url = str(web_sources or '')

        confidence = finding.get('confidence')
        # Techniques rendues possibles / mitigations : recalculées par la table
        # déterministe (phase 4), jamais reprises telles quelles du LLM.
        try:
            attack = attack_csv_fields(annotate_findings([dict(finding)], {})[0])
        except Exception:
            attack = {'attack_enabled': '', 'mitigations': ''}
        grounding = finding.get('grounding')
        grounding_status = grounding.get('status', '') if isinstance(grounding, dict) else ''

        rows.append({
            'finding_id':    finding.get('id') or f'F-{index:03d}',
            'tool':          meta.get('tool') or source_tool,
            'tool_category': meta.get('category') or finding.get('category') or '',
            'target':        recon.domain or '',
            'indicator':     finding.get('title') or '',
            'value':         finding.get('evidence') or finding.get('description') or '',
            'severity':      finding.get('severity') or '',
            'confidence':    '' if confidence is None else confidence,
            'source_tool':   source_tool,
            'source_url':    source_url,
            'collected_at':  collected_at,
            'grounding_status': grounding_status,
            'observed_at':   finding.get('observed_at') or collected_at,
            'severity_rule': finding.get('severity_rule') or '',
            'attack_enabled': attack['attack_enabled'],
            'mitigations':   attack['mitigations'],
        })
    return rows


# ── Construction des exports (partagée admin / consultation par code) ────────

def build_export_json(recon: Recon, raw: dict) -> tuple:
    """
    Construit l'export JSON à partir des valeurs brutes des champs (`raw`).
    Retourne (corps, nom_de_fichier). Partagé par l'export admin (colonnes en
    clair) et par la consultation par code (routes/results.py, valeurs
    déchiffrées) : les deux produisent un export strictement identique, donc
    le même `dataset_sha256`.
    """
    scan_results    = _parse_json_text(raw.get('scan_results'), 'scan_results', recon.id)
    analysis_result = _parse_json_text(raw.get('analysis_result'), 'analysis_result', recon.id)
    final_report    = _parse_final_report(raw.get('final_report'))

    provenance = _build_provenance(recon, scan_results, analysis_result, raw)
    payload = {
        'provenance':      provenance,
        'scan_results':    scan_results,
        'analysis_result': analysis_result,
        'final_report':    final_report,
        'citation':        _build_citation(recon, provenance),
    }
    logger.info(
        '[export.json] recon_id=%d domain=%s outils=%d sha256=%s',
        recon.id, recon.domain, len(provenance['tools_requested']),
        (provenance['dataset_sha256'] or 'n/a')[:12],
    )
    filename = f'recon_ia_export_{_safe_filename_part(recon.domain)}_{recon.id}.json'
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str), filename


def build_export_csv(recon: Recon, raw: dict) -> tuple:
    """Construit l'export CSV des findings. Retourne (corps, nom_de_fichier)."""
    scan_results    = _parse_json_text(raw.get('scan_results'), 'scan_results', recon.id)
    analysis_result = _parse_json_text(raw.get('analysis_result'), 'analysis_result', recon.id)
    rows = _finding_rows(recon, scan_results, analysis_result)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_safe(value) for key, value in row.items()})

    logger.info('[export.csv] recon_id=%d domain=%s lignes=%d', recon.id, recon.domain, len(rows))
    filename = f'recon_ia_findings_{_safe_filename_part(recon.domain)}_{recon.id}.csv'
    # BOM UTF-8 : Excel ouvre correctement les accents des libellés français
    return _UTF8_BOM + buffer.getvalue(), filename


def pdf_filename(recon: Recon) -> str:
    return f'rapport_osint_{_safe_filename_part(recon.domain)}_{recon.id}.pdf'


def _results_page_url() -> str:
    return os.getenv('RESULTS_PAGE_URL', '').strip()


def _seal_and_notify(recon: Recon, analysis: dict) -> tuple:
    """
    Scelle le dossier et envoie le code d'accès par mail.

    Le scellement n'est COMMITÉ qu'après l'envoi réussi du mail : sinon le
    code (jamais stocké) serait perdu et les résultats chiffrés illisibles à
    jamais. En cas d'échec d'envoi, la transaction est annulée — le clair est
    conservé et l'admin peut réessayer via POST /recon/<id>/issue_access.

    Retourne (email_envoyé: bool, erreur: str|None).
    """
    if not result_vault.is_configured():
        logger.error('[vault] RESULTS_ACCESS_SECRET absent — aucun code émis pour recon_id=%d',
                     recon.id)
        return False, "RESULTS_ACCESS_SECRET non configuré : code d'accès non émis"

    score = analysis.get('security_score')
    if score is None:
        score = analysis.get('risk_score')
    try:
        code = result_vault.seal_recon(recon)
        send_results_ready_email(
            to_email    = recon.email,
            firstname   = recon.firstname,
            lastname    = recon.lastname,
            domain      = recon.domain,
            access_code = code,
            expires_at  = recon.access_expires_at,
            risk_level  = analysis.get('risk_level', 'N/A'),
            risk_score  = score,
            nb_findings = len(analysis.get('findings', []) or []),
            results_url = _results_page_url(),
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error('[vault] Scellement/envoi annulé — recon_id=%d : %s', recon.id, e)
        return False, str(e)
    logger.info('[vault] Dossier scellé, code envoyé — recon_id=%d expire=%s',
                recon.id, recon.access_expires_at)
    return True, None


def _record_graph_and_diff(recon: Recon, scan_data: Optional[dict]) -> Optional[dict]:
    """
    Phase 7 : alimente le graphe d'entités et calcule le différentiel avec le
    scan précédent du même domaine, AVANT le scellement (après, le serveur ne
    peut plus relire scan_results). N'enregistre que des données techniques
    publiques (utils/entity_graph.py, utils/scan_diff.py), en clair.

    Ne bloque JAMAIS le pipeline : toute erreur est journalisée, la
    transaction de cette étape annulée, et le rapport continue sans
    différentiel. Doit être appelée quand le dossier n'a aucune modification
    en attente (le rollback ne doit rien emporter d'autre).

    Retourne un résumé {significant, change_count, has_previous, summary} ou None.
    """
    if not isinstance(scan_data, dict) or not scan_data:
        return None
    from utils.entity_graph import build_graph_from_raw
    from utils.scan_diff import record_scan
    now = datetime.utcnow()
    scan_ref = f'recon:{recon.id}'
    try:
        build_graph_from_raw(recon.domain, scan_data, scan_ref=scan_ref, now=now, recon_id=recon.id)
        snapshot = record_scan(recon.domain, scan_data, scan_ref=scan_ref, now=now,
                               recon_id=recon.id, source='pipeline')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning('[graph] graphe/différentiel non enregistrés — recon_id=%d : %s', recon.id, e)
        return None
    diff = snapshot.get_diff() or {}
    return {
        'significant':  bool(diff.get('significant')),
        'change_count': diff.get('change_count', 0),
        'has_previous': bool(diff.get('has_previous')),
        'summary':      diff.get('summary') or [],
    }


# ── POST /recon/<id>/generate_final_report ────────────────────────────────────

@report_bp.route('/recon/<int:recon_id>/generate_final_report', methods=['POST'])
@require_service_or_auth
@limiter.limit('20 per hour')
@swag_from({
    'tags': ['Rapport Final IA'],
    'security': [{'basicAuth': []}],
    'summary': 'Générer le rapport final narratif via IA',
    'description': (
        'Condense les données OSINT (`scan_results`) et l\'analyse IA (`analysis_result`) '
        'stockées en base pour produire un rapport narratif structuré.\n\n'
        'Le rapport est enregistré dans `recon.final_report` et retourné dans la réponse.\n\n'
        '**Prérequis** : l\'enregistrement doit avoir `scan_results` ET `analysis_result` '
        'en base (étapes OSINT + analyse IA déjà effectuées).\n\n'
        '**Modèle IA** : Groq par défaut, OpenRouter en fallback.\n\n'
        '⏱️ **Durée estimée** : 10–30 secondes.'
    ),
    'parameters': [
        {'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer',
         'description': 'ID de l\'enregistrement Recon'},
        {
            'name': 'body', 'in': 'body', 'required': False,
            'schema': {
                'type': 'object',
                'properties': {
                    'force_regenerate': {
                        'type': 'boolean',
                        'description': 'Forcer la régénération même si final_report existe déjà',
                        'default': False,
                    },
                },
            },
        },
    ],
    'responses': {
        200: {
            'description': 'Rapport final généré et enregistré',
            'schema': {
                'type': 'object',
                'properties': {
                    'success':      {'type': 'boolean'},
                    'data':         {'type': 'object'},
                    'cached':       {'type': 'boolean'},
                },
            },
        },
        400: {'description': 'Données manquantes (scan_results ou analysis_result absents)'},
        404: {'description': 'Enregistrement Recon introuvable'},
        500: {'description': 'Erreur génération rapport IA'},
    },
})
def generate_final_report_endpoint(recon_id: int):
    """Génère le rapport narratif IA et le stocke dans recon.final_report."""
    body             = request.get_json(silent=True) or {}
    force_regenerate = body.get('force_regenerate', False)

    recon = Recon.query.get_or_404(recon_id)
    sealed = _sealed_error(recon)
    if sealed:
        return sealed

    # Retourner le cache si déjà généré et non forcé
    if recon.final_report and not force_regenerate:
        try:
            cached = json.loads(recon.final_report)
            logger.info('[final_report] Cache hit — recon_id=%d', recon_id)
            return jsonify({
                'success':  True,
                'cached':   True,
                'recon_id': recon_id,
                'data':     cached,
            }), 200
        except Exception:
            pass  # Données corrompues → régénérer

    # Vérifier que les données sources sont présentes
    scan_results    = _load_scan_from_db(recon)
    analysis_result = _load_analysis_from_db(recon)

    if not scan_results:
        return jsonify({
            'success': False,
            'error': (
                "scan_results absent pour cet enregistrement. "
                "Effectuez d'abord la reconnaissance OSINT (POST /pass_recon) "
                "et enregistrez les résultats via PATCH /recon/<id>/result."
            ),
        }), 400

    if not analysis_result:
        return jsonify({
            'success': False,
            'error': (
                "analysis_result absent pour cet enregistrement. "
                "Effectuez d'abord l'analyse IA via POST /analyze "
                "avec recon_id={}.".format(recon_id)
            ),
        }), 400

    # Générer le rapport via IA
    recon.set_step('generating_final_report')
    db.session.commit()
    try:
        from utils.final_report_generator import generate_final_report
        final_report = generate_final_report(
            scan_results=scan_results,
            analysis_result=analysis_result,
            domain=recon.domain,
        )
    except Exception as e:
        logger.exception('[final_report] Erreur génération — recon_id=%d', recon_id)
        # Sans ceci, un échec à cette étape était totalement silencieux :
        # pas d'email, pas de changement de statut — le flux n8n restait
        # affiché « running » indéfiniment sans que l'utilisateur ni
        # l'admin ne soient prévenus (constaté en conditions réelles sur
        # un scan qui a échoué exactement ici). Miroir du pattern déjà en
        # place pour l'échec de génération PDF, plus bas dans ce fichier.
        try:
            recon.status = 'failed'
            db.session.commit()
        except Exception:
            db.session.rollback()
        try:
            if recon.email:
                send_error_notification(
                    to_email     = recon.email,
                    firstname    = recon.firstname or '',
                    lastname     = recon.lastname  or '',
                    domain       = recon.domain,
                    error_type   = "final_report_failed",
                    error_detail = "La génération du rapport final a échoué de façon inattendue.",
                    recon_id     = recon_id,
                )
        except Exception as _mail_e:
            logger.warning("Impossible d'envoyer l'email d'erreur rapport final : %s", _mail_e)
        return jsonify({
            'success': False,
            'error': f'Erreur lors de la génération du rapport final : {e}',
        }), 500

    # Persister en base
    recon.final_report = json.dumps(final_report, ensure_ascii=False)
    db.session.commit()
    logger.info(
        '[final_report] Rapport enregistré — recon_id=%d domaine=%s',
        recon_id, recon.domain,
    )

    return jsonify({
        'success':  True,
        'cached':   False,
        'recon_id': recon_id,
        'data':     final_report,
    }), 200


# ── POST /recon/<id>/generate_report ─────────────────────────────────────────

@report_bp.route('/recon/<int:recon_id>/generate_report', methods=['POST'])
@require_service_or_auth
@limiter.limit('10 per hour')
@swag_from({
    'tags': ['Rapport PDF'],
    'security': [{'basicAuth': []}],
    'summary': 'Générer, enregistrer et envoyer le rapport PDF',
    'description': (
        'Génère un rapport PDF professionnel à partir de l\'analyse IA.\n\n'
        'Si `analysis` n\'est pas fourni dans le body, il est chargé automatiquement '
        'depuis `recon.analysis_result` en base de données.\n\n'
        'Si `recon.final_report` existe, son `executive_summary` est intégré dans le PDF.\n\n'
        '⏱️ **Durée estimée** : 2–10 secondes selon le volume de données.\n\n'
        '📄 **PDF** : couverture sombre, résumé exécutif, findings color-codés par '
        'sévérité, surface d\'attaque, recommandations, métadonnées temporelles.'
    ),
    'parameters': [
        {'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer',
         'description': 'ID de l\'enregistrement Recon'},
        {
            'name': 'body', 'in': 'body', 'required': False,
            'schema': {
                'type': 'object',
                'properties': {
                    'analysis': {
                        'type': 'object',
                        'description': (
                            'Champ `data` retourné par POST /analyze. '
                            'Si absent, chargé depuis la BD (recon.analysis_result).'
                        ),
                    },
                    'send_email': {
                        'type': 'boolean',
                        'description': 'Envoyer le PDF par email (défaut: true)',
                        'default': True,
                    },
                },
            },
        },
    ],
    'responses': {
        200: {
            'description': 'PDF généré, enregistré et email envoyé',
            'schema': {
                'type': 'object',
                'properties': {
                    'success':          {'type': 'boolean'},
                    'data':             {'type': 'object'},
                },
            },
        },
        400: {'description': 'Analyse manquante en body et en base de données'},
        404: {'description': 'Enregistrement Recon introuvable'},
        500: {'description': 'Erreur génération PDF ou envoi email'},
    },
})
def generate_report(recon_id: int):
    """Génère, persiste et envoie le rapport PDF pour un enregistrement Recon."""
    body       = request.get_json(silent=True) or {}
    analysis   = body.get('analysis')
    send_email = body.get('send_email', True)

    recon = Recon.query.get_or_404(recon_id)
    sealed = _sealed_error(recon)
    if sealed:
        return sealed

    # Charger l'analyse depuis la BD si non fournie dans le body
    if not analysis or not isinstance(analysis, dict):
        analysis = _load_analysis_from_db(recon)
        if not analysis:
            return jsonify({
                'success': False,
                'error': (
                    "Paramètre 'analysis' absent et aucune analyse trouvée en base "
                    "pour recon_id={}. "
                    "Fournissez 'analysis' dans le body ou effectuez d'abord POST /analyze "
                    "avec recon_id={}.".format(recon_id, recon_id)
                ),
            }), 400
        logger.info('[generate_report] Analyse chargée depuis la BD — recon_id=%d', recon_id)

    # Intégrer le rapport final narratif si disponible
    final_report_data = None
    if recon.final_report:
        try:
            final_report_data = json.loads(recon.final_report)
            # Enrichir l'analysis avec l'executive_summary narratif du rapport final
            if final_report_data.get('executive_summary') and not analysis.get('executive_summary'):
                analysis['executive_summary'] = final_report_data['executive_summary']
            logger.info('[generate_report] Rapport final narratif intégré — recon_id=%d', recon_id)
        except Exception:
            pass

    # Graphe d'entités + différentiel avec le scan précédent (phase 7) — ICI,
    # avant toute modification du dossier dans cette requête (voir la
    # docstring : l'étape a sa propre transaction) et avant le scellement.
    # (_load_scan_from_db capture déjà toute erreur et retourne None)
    scan_data = _load_scan_from_db(recon)
    scan_diff_summary = _record_graph_and_diff(recon, scan_data)

    # ⚠️ end_report_date/execution_time DOIVENT être posés AVANT _compute_timing()
    # — corrigé (2026-07-30). Bug réel constaté sur un PDF généré : "Durée totale"
    # affichait "—" malgré un execution_time correct en base (~1min37) une fois
    # le PDF déjà produit. Cause : ces deux champs n'étaient posés qu'APRÈS avoir
    # appelé generate_pdf(timing=...) (voir plus bas) — _compute_timing() lisait
    # donc encore des valeurs NULL au moment de construire le PDF, et le "—" était
    # figé dans les octets déjà stockés (le PDF n'est jamais régénéré après coup).
    # Poser ces champs ICI (avant le calcul de timing) ne change rien à leur
    # valeur : le temps de génération du PDF lui-même est négligeable devant la
    # précision visée (secondes), et le principe "figé, jamais recalculé après
    # coup" (voir Recon.flow_duration_s()) reste respecté à l'identique.
    now = datetime.utcnow()
    if not recon.end_report_date:
        recon.end_report_date = now
    if recon.start_report_date and not recon.execution_time:
        recon.execution_time = round((now - recon.start_report_date).total_seconds(), 3)

    # Calculer les délais
    timing = _compute_timing(recon, analysis)
    logger.info(
        'generate_report — recon_id=%d domain=%s timing=%s',
        recon_id, recon.domain, timing,
    )

    # scan_data (section infrastructure du PDF) est déjà chargé plus haut.
    # Le différentiel complet du dossier est disponible pour le PDF via
    # utils.scan_diff.diff_for_recon(recon.id) (intégration : phase 4).

    # Générer le PDF
    recon.set_step('generating_pdf')
    db.session.commit()
    # Pas de fallback `except TypeError` ici : generate_pdf accepte scan_data.
    # Un tel fallback rattraperait aussi les TypeError levées À L'INTÉRIEUR du
    # générateur, réexécuterait le même code et masquerait la cause réelle.
    try:
        pdf_bytes = generate_pdf(
            analysis=analysis,
            recon=recon,
            timing=timing,
            scan_data=scan_data,
        )
    except Exception as e:
        logger.exception('Erreur génération PDF — recon_id=%d', recon_id)
        # `current_step` reste à 'generating_pdf' (montre où ça a échoué dans
        # le dashboard) ; `status` bascule à 'failed' — jusqu'ici seule la
        # notification email existait, le workflow restait affiché "running"
        # indéfiniment sans que le statut ne le reflète (même défaut déjà
        # corrigé pour generate_final_report, voir plus haut dans ce fichier).
        try:
            recon.status = 'failed'
            db.session.commit()
        except Exception:
            db.session.rollback()
        try:
            if recon.email:
                send_error_notification(
                    to_email     = recon.email,
                    firstname    = recon.firstname or '',
                    lastname     = recon.lastname  or '',
                    domain       = recon.domain,
                    error_type   = "pdf_failed",
                    error_detail = "La génération du rapport a échoué de façon inattendue.",
                    recon_id     = recon_id,
                )
        except Exception as _mail_e:
            logger.warning("Impossible d'envoyer l'email d'erreur PDF : %s", _mail_e)
        return jsonify({
            'success': False,
            'error': f'Erreur lors de la génération du PDF : {e}',
        }), 500

    # Persister en base — end_report_date/execution_time déjà posés plus haut
    # (avant _compute_timing(), voir commentaire), pas de recalcul ici.
    recon.pdf_report       = pdf_bytes
    recon.pdf_generated_at = now
    # Marquer le workflow comme terminé — c'est la dernière étape du flux n8n
    recon.status           = 'success'
    recon.set_step('completed')
    db.session.commit()
    logger.info('PDF enregistré en BD — recon_id=%d taille=%d octets statut=success',
                recon_id, len(pdf_bytes))

    # Scellement + mail « rapport prêt » avec le code d'accès (décisions D1-D3 :
    # plus de PDF joint, résultats chiffrés). Le score du mail suit la même
    # préférence que le PDF : security_score (recalculé) avant risk_score (brut
    # LLM) — voir _seal_and_notify. `send_email=false` laisse le dossier en
    # clair (usage admin/tests) : sans mail, il n'y aurait personne pour
    # détenir le code.
    email_sent  = False
    email_error = None
    if send_email:
        email_sent, email_error = _seal_and_notify(recon, analysis)

    return jsonify({
        'success': True,
        'data': {
            'recon_id':         recon_id,
            'domain':           recon.domain,
            'pdf_size_bytes':   len(pdf_bytes),
            'pdf_generated_at': now.isoformat(),
            'email_sent':       email_sent,
            'email_error':      email_error,
            'results_sealed':   recon.sealed_at is not None,
            'timing':           timing,
            'risk_level':       analysis.get('risk_level'),
            'risk_score':       analysis.get('risk_score'),
            'security_score':   analysis.get('security_score'),
            'security_grade':   analysis.get('security_grade'),
            'findings_count':   len(analysis.get('findings', []) or []),
            'has_final_report': final_report_data is not None,
            'scan_diff':        scan_diff_summary,
        },
    }), 200


# ── GET /recon/<id>/report.pdf ────────────────────────────────────────────────

@report_bp.route('/recon/<int:recon_id>/report.pdf', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Rapport PDF'],
    'security': [{'basicAuth': []}],
    'summary': 'Télécharger le rapport PDF généré',
    'parameters': [
        {'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer'},
    ],
    'responses': {
        200: {'description': 'Fichier PDF'},
        404: {'description': 'PDF non encore généré pour cet enregistrement'},
    },
})
def download_report(recon_id: int):
    """Retourne le PDF stocké en base pour cet enregistrement."""
    recon = Recon.query.get_or_404(recon_id)
    sealed = _sealed_error(recon)
    if sealed:
        return sealed

    if not recon.pdf_report:
        return jsonify({
            'success': False,
            'error': (
                "Aucun rapport PDF généré pour cet enregistrement. "
                "Appelez d'abord POST /recon/<id>/generate_report."
            ),
        }), 404

    return send_file(
        io.BytesIO(recon.pdf_report),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=pdf_filename(recon),
    )


# ── GET /recon/<id>/export.json ───────────────────────────────────────────────

@report_bp.route('/recon/<int:recon_id>/export.json', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Export académique'],
    'security': [{'basicAuth': []}],
    'summary': 'Exporter le jeu de données complet (JSON structuré + provenance)',
    'description': (
        'Dump structuré destiné à un usage en recherche publiable.\n\n'
        'Contient le bloc `provenance` (outils exécutés, durée, backend IA, '
        'empreinte SHA-256 du jeu de données), les données brutes `scan_results`, '
        'l\'analyse IA `analysis_result`, le rapport narratif `final_report`, '
        'et une chaîne `citation` prête à l\'emploi.\n\n'
        'Le `dataset_sha256` est calculé sur `scan_results` sérialisé en JSON '
        'canonique (clés triées) — il permet de vérifier qu\'un jeu de données '
        'cité n\'a pas été modifié.'
    ),
    'parameters': [
        {'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer'},
    ],
    'responses': {
        200: {'description': 'Export JSON complet'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement Recon introuvable'},
    },
})
def export_json(recon_id: int):
    """Exporte l'intégralité des données d'une reconnaissance avec sa provenance."""
    recon = Recon.query.get_or_404(recon_id)

    blocked = _consent_error(recon) or _sealed_error(recon)
    if blocked:
        return blocked

    body, filename = build_export_json(recon, _raw_fields(recon))
    response = Response(body, mimetype='application/json; charset=utf-8')
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ── GET /recon/<id>/export.csv ────────────────────────────────────────────────

@report_bp.route('/recon/<int:recon_id>/export.csv', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Export académique'],
    'security': [{'basicAuth': []}],
    'summary': 'Exporter les findings au format CSV (une ligne par observation)',
    'description': (
        'Export tabulaire des findings de l\'analyse IA.\n\n'
        'Colonnes : `finding_id, tool, tool_category, target, indicator, value, '
        'severity, confidence, source_tool, source_url, collected_at, '
        'grounding_status`.\n\n'
        '`grounding_status` (voir utils/grounding_check.py) indique si la preuve '
        'citée a été retrouvée dans la donnée brute de l\'outil source : '
        '`verified`, `evidence_not_found`, `tool_not_successful`, `unknown_tool`, '
        '`no_source_cited`, `no_evidence_text`, ou vide si l\'analyse est '
        'antérieure à l\'introduction de ce contrôle.\n\n'
        'Les colonnes absentes du schéma réel des findings (notamment '
        '`confidence`) sont laissées vides — aucune valeur n\'est fabriquée.\n\n'
        'Retourne un CSV avec en-têtes même si aucune analyse n\'existe encore.'
    ),
    'parameters': [
        {'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer'},
    ],
    'responses': {
        200: {'description': 'Fichier CSV'},
        401: {'description': 'Authentification requise'},
        404: {'description': 'Enregistrement Recon introuvable'},
    },
})
def export_csv(recon_id: int):
    """Exporte les findings d'une reconnaissance en CSV, une ligne par finding."""
    recon = Recon.query.get_or_404(recon_id)

    blocked = _consent_error(recon) or _sealed_error(recon)
    if blocked:
        return blocked

    body, filename = build_export_csv(recon, _raw_fields(recon))
    response = Response(body, mimetype='text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ── POST /recon/<id>/issue_access — réémission du code (admin) ────────────────

@report_bp.route('/recon/<int:recon_id>/issue_access', methods=['POST'])
@require_auth
@limiter.limit('10 per hour')
@swag_from({
    'tags': ['Accès aux résultats'],
    'security': [{'basicAuth': []}],
    'summary': "Émettre le code d'accès d'un dossier non encore scellé",
    'description': (
        "Rattrapage quand le mail « rapport prêt » a échoué en fin de pipeline : "
        "scelle le dossier et envoie un code d'accès au demandeur. Impossible "
        "sur un dossier déjà scellé (le serveur ne peut plus relire son contenu "
        "pour le rechiffrer avec un nouveau code)."
    ),
    'parameters': [{'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer'}],
    'responses': {
        200: {'description': 'Code émis et envoyé'},
        409: {'description': 'Dossier déjà scellé ou rapport PDF absent'},
        502: {'description': "Échec d'envoi du mail (rien n'est scellé)"},
    },
})
def issue_access(recon_id: int):
    recon = Recon.query.get_or_404(recon_id)
    if recon.sealed_at is not None:
        return jsonify({'success': False, 'error': 'Dossier déjà scellé : code non réémissible'}), 409
    if not recon.pdf_report:
        return jsonify({'success': False, 'error': 'Rapport PDF absent : terminez le pipeline avant'}), 409
    analysis = _load_analysis_from_db(recon) or {}
    sent, error = _seal_and_notify(recon, analysis)
    if not sent:
        return jsonify({'success': False, 'error': error}), 502
    return jsonify({'success': True, 'data': recon.to_dict()}), 200


# ── POST /recon/<id>/revoke_access — révocation du code (admin) ───────────────

@report_bp.route('/recon/<int:recon_id>/revoke_access', methods=['POST'])
@require_auth
@swag_from({
    'tags': ['Accès aux résultats'],
    'security': [{'basicAuth': []}],
    'summary': "Révoquer le code d'accès d'un dossier",
    'description': (
        "Rend le code inutilisable immédiatement, y compris pour les sessions "
        "de consultation déjà ouvertes (vérifié à chaque requête). Irréversible : "
        "le contenu chiffré devient définitivement illisible."
    ),
    'parameters': [{'name': 'recon_id', 'in': 'path', 'required': True, 'type': 'integer'}],
    'responses': {
        200: {'description': 'Code révoqué'},
        409: {'description': "Aucun code d'accès émis pour ce dossier"},
    },
})
def revoke_access(recon_id: int):
    recon = Recon.query.get_or_404(recon_id)
    if not recon.access_token_hash:
        return jsonify({'success': False, 'error': "Aucun code d'accès émis"}), 409
    if recon.access_revoked_at is None:
        recon.access_revoked_at = datetime.utcnow()
        db.session.commit()
        logger.warning('[vault] Code révoqué par l\'admin — recon_id=%d', recon_id)
    return jsonify({'success': True, 'data': recon.to_dict()}), 200
