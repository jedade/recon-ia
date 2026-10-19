# utils/pipeline_trigger.py
"""
Déclenchement du pipeline n8n par l'API (plan d'action, phase 1, S1/S2).

Avant : le navigateur appelait directement le webhook public de n8n pour
valider l'OTP, et n8n relayait vers l'API. n8n devait donc être exposé sur
Internet. Désormais le navigateur ne parle qu'à l'API : une fois l'OTP
validé (POST /verify_email), l'API appelle le webhook de n8n sur le RÉSEAU
INTERNE Docker, avec un secret partagé dans un en-tête. n8n n'a plus besoin
d'aucun port publié.

  N8N_PIPELINE_WEBHOOK_URL   ex. http://n8n:5678/webhook/recon-ia-pipeline
  N8N_WEBHOOK_SECRET         ≥ 32 caractères, vérifié par la credential
                             « Header Auth » du nœud Webhook de n8n

Le webhook répond immédiatement (le pipeline dure plusieurs minutes et
continue en arrière-plan dans n8n) : seul l'accusé de réception est attendu.
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

SECRET_HEADER = 'X-Pipeline-Secret'
_TIMEOUT_S = 10


def is_configured() -> bool:
    return bool(os.getenv('N8N_PIPELINE_WEBHOOK_URL', '').strip()) and \
        len(os.getenv('N8N_WEBHOOK_SECRET', '')) >= 32


def trigger_pipeline(recon_id: int) -> tuple:
    """Retourne (True, None) si n8n a accusé réception, sinon (False, raison)."""
    url = os.getenv('N8N_PIPELINE_WEBHOOK_URL', '').strip()
    secret = os.getenv('N8N_WEBHOOK_SECRET', '')
    if not url or len(secret) < 32:
        logger.warning('[pipeline] N8N_PIPELINE_WEBHOOK_URL / N8N_WEBHOOK_SECRET absents — '
                       'pipeline non déclenché pour recon_id=%s', recon_id)
        return False, 'Déclenchement du pipeline non configuré'
    try:
        resp = requests.post(url, json={'recon_id': int(recon_id)},
                             headers={SECRET_HEADER: secret}, timeout=_TIMEOUT_S)
    except Exception as e:
        logger.error('[pipeline] n8n injoignable pour recon_id=%s : %s', recon_id, e)
        return False, f'n8n injoignable : {e}'
    if 200 <= resp.status_code < 300:
        logger.info('[pipeline] Pipeline déclenché — recon_id=%s', recon_id)
        return True, None
    logger.error('[pipeline] n8n a refusé le déclenchement — recon_id=%s HTTP %s',
                 recon_id, resp.status_code)
    return False, f'n8n a répondu HTTP {resp.status_code}'
