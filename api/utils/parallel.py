# utils/parallel.py
"""
Exécution parallèle et résiliente des outils de reconnaissance passive.

Problème résolu
───────────────
Les outils OSINT de `routes/recon.py` sont des appels réseau (DNS, HTTP, WHOIS,
API tierces) exécutés en série : la durée du scan est la SOMME des latences,
alors que ces appels sont indépendants et passent l'essentiel de leur temps à
attendre. Ils sont I/O-bound, donc un pool de threads les parallélise
efficacement malgré le GIL.

Deux garanties de résilience
────────────────────────────
1. ISOLATION — une exception levée par un outil ne peut pas faire échouer le
   scan entier. Elle est convertie en résultat `status="error"`. Auparavant,
   une exception non rattrapée dans n'importe lequel des 47 outils renvoyait
   une 500 et faisait perdre le travail de tous les autres.
2. BORNE DE TEMPS — chaque outil a un délai maximal ; au-delà il est marqué
   `status="timeout"` et le scan continue. Un outil bloqué ne peut plus
   immobiliser l'ensemble.

Limite connue et assumée
─────────────────────────
Python ne permet pas de tuer un thread. Sur timeout, on cesse d'ATTENDRE le
résultat mais le thread sous-jacent continue jusqu'à ce que son propre appel
réseau expire. C'est acceptable ici car tous les outils passent des timeouts
explicites à requests/subprocess : le thread se termine seul peu après. Le pool
est créé avec des threads non-démons gérés par l'exécuteur, et
`shutdown(wait=False)` évite de bloquer la réponse HTTP.
"""

import concurrent.futures
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Délai par défaut d'un outil, en secondes. Volontairement généreux : certains
# outils de découverte de sous-domaines (amass) sont lents par nature.
DEFAULT_TOOL_TIMEOUT = 120

# Nombre de threads par défaut. Les tâches étant I/O-bound, on peut dépasser
# largement le nombre de cœurs ; on borne malgré tout pour ne pas ouvrir des
# dizaines de connexions simultanées vers les mêmes services tiers (risque de
# rate-limiting et de bannissement, contraire à une reconnaissance discrète).
DEFAULT_MAX_WORKERS = 8


@dataclass
class ToolTask:
    """
    Un outil à exécuter.

    key     : clé de sortie dans scan_results (ex. 'dns_records')
    fn      : callable sans argument retournant le dict de résultat de l'outil
    timeout : délai max en secondes (None → DEFAULT_TOOL_TIMEOUT)
    """
    key: str
    fn: Callable[[], Any]
    timeout: Optional[float] = None


@dataclass
class ToolOutcome:
    """Résultat d'exécution enrichi des métriques de l'orchestrateur."""
    key: str
    result: Any
    duration_s: float
    failed: bool = False
    timed_out: bool = False
    error: Optional[str] = None


def _error_result(message: str, status: str = 'error') -> dict:
    """
    Résultat d'échec au format attendu par le reste de la chaîne.

    Respecte le contrat établi en phase 2 (status / data / error / raw_output)
    afin que l'analyse IA et le PDF traitent un outil en échec exactement comme
    un outil ayant retourné une erreur métier.
    """
    return {
        'status': status,
        'data': {},
        'error': message,
        'raw_output': '',
    }


def run_tools_parallel(
    tasks: List[ToolTask],
    max_workers: int = DEFAULT_MAX_WORKERS,
    default_timeout: float = DEFAULT_TOOL_TIMEOUT,
    overall_deadline_s: Optional[float] = None,
) -> Dict[str, ToolOutcome]:
    """
    Exécute les tâches en parallèle et retourne {key: ToolOutcome}.

    Ne lève jamais : tout échec d'un outil est encapsulé dans son ToolOutcome.
    Chaque clé demandée est systématiquement présente dans le dict retourné,
    y compris en cas d'échec ou de dépassement du délai global — le format de
    sortie ne dépend donc pas des aléas d'exécution.

    overall_deadline_s : borne globale optionnelle. Les outils non terminés à
    son expiration sont marqués `timeout` sans attendre leur délai individuel.
    """
    outcomes: Dict[str, ToolOutcome] = {}
    if not tasks:
        return outcomes

    # Dédoublonnage défensif : deux tâches de même clé écraseraient leur
    # résultat de façon non déterministe selon l'ordre d'achèvement.
    seen = set()
    unique_tasks = []
    for task in tasks:
        if task.key in seen:
            logger.warning('[parallel] clé dupliquée ignorée : %s', task.key)
            continue
        seen.add(task.key)
        unique_tasks.append(task)

    started = time.perf_counter()
    workers = max(1, min(max_workers, len(unique_tasks)))

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix='osint-tool',
    )
    try:
        future_map = {}
        start_times = {}
        for task in unique_tasks:
            start_times[task.key] = time.perf_counter()
            future_map[executor.submit(_safe_call, task)] = task

        pending = set(future_map)
        while pending:
            remaining = None
            if overall_deadline_s is not None:
                remaining = overall_deadline_s - (time.perf_counter() - started)
                if remaining <= 0:
                    break

            done, pending = concurrent.futures.wait(
                pending, timeout=remaining,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                break   # délai global atteint

            for future in done:
                task = future_map[future]
                elapsed = time.perf_counter() - start_times[task.key]
                try:
                    value, error = future.result()
                except Exception as exc:                     # pragma: no cover
                    # _safe_call capture déjà tout ; filet de sécurité.
                    outcomes[task.key] = ToolOutcome(
                        key=task.key, result=_error_result(str(exc)),
                        duration_s=elapsed, failed=True, error=str(exc),
                    )
                    continue

                if error is not None:
                    logger.warning('[parallel] %s a échoué en %.1fs : %s',
                                   task.key, elapsed, error)
                    outcomes[task.key] = ToolOutcome(
                        key=task.key, result=value, duration_s=elapsed,
                        failed=True, error=error,
                    )
                else:
                    logger.debug('[parallel] %s terminé en %.1fs', task.key, elapsed)
                    outcomes[task.key] = ToolOutcome(
                        key=task.key, result=value, duration_s=elapsed,
                    )

        # Tâches restantes : délai global dépassé.
        for future in pending:
            task = future_map[future]
            future.cancel()
            elapsed = time.perf_counter() - start_times[task.key]
            logger.warning('[parallel] %s interrompu — délai global atteint (%.1fs)',
                           task.key, elapsed)
            outcomes[task.key] = ToolOutcome(
                key=task.key,
                result=_error_result(
                    'Délai global du scan atteint avant la fin de cet outil.',
                    status='timeout',
                ),
                duration_s=elapsed, failed=True, timed_out=True,
                error='deadline dépassé',
            )
    finally:
        # wait=False : ne pas retarder la réponse HTTP à cause d'un thread
        # encore bloqué sur un appel réseau qui va expirer de lui-même.
        executor.shutdown(wait=False)

    # Garantie de complétude du dict retourné.
    for task in unique_tasks:
        outcomes.setdefault(task.key, ToolOutcome(
            key=task.key,
            result=_error_result('Outil non exécuté.', status='error'),
            duration_s=0.0, failed=True, error='non exécuté',
        ))

    total = time.perf_counter() - started
    failures = sum(1 for o in outcomes.values() if o.failed)
    sequential = sum(o.duration_s for o in outcomes.values())
    logger.info(
        '[parallel] %d outils en %.1fs (cumul séquentiel %.1fs, gain ×%.1f) — %d échec(s)',
        len(outcomes), total, sequential,
        (sequential / total) if total > 0 else 1.0, failures,
    )
    return outcomes


def _safe_call(task: ToolTask):
    """
    Exécute un outil en convertissant toute exception en résultat d'erreur.

    Retourne (valeur, erreur_ou_None). Le timeout individuel est appliqué par
    l'appelant via le deadline global ; ici on garantit surtout qu'aucune
    exception ne remonte et ne tue le scan.
    """
    try:
        value = task.fn()
    except Exception as exc:
        logger.warning('[parallel] exception dans %s : %s', task.key, exc, exc_info=True)
        return _error_result(f'{type(exc).__name__}: {exc}'), str(exc)

    # Un outil doit retourner un dict avec au moins 'status'. On normalise les
    # retours inattendus plutôt que de les laisser corrompre scan_results.
    if not isinstance(value, dict):
        message = f'Résultat inattendu de type {type(value).__name__}'
        logger.warning('[parallel] %s : %s', task.key, message)
        return _error_result(message), message

    value.setdefault('status', 'success')
    return value, None
