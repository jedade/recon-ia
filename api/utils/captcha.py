# utils/captcha.py
"""
Vérification Cloudflare Turnstile du formulaire public (décision D6).

Le widget du formulaire (web/index.html) produit un jeton à usage unique,
envoyé avec POST /recon dans `turnstile_token`. L'API le fait valider par
Cloudflare (`siteverify`) avant de créer le dossier et d'envoyer l'OTP :
c'est ce qui empêche un script d'utiliser la plateforme pour inonder une
boîte mail de codes ou lancer des scans en masse.

Sans `TURNSTILE_SECRET_KEY` (développement local, tests), la vérification
est désactivée et un avertissement est journalisé à chaque appel. En
production, la variable DOIT être définie.
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
_TIMEOUT_S = 8


def is_enabled() -> bool:
    return bool(os.getenv('TURNSTILE_SECRET_KEY', '').strip())


def verify_turnstile(token, remote_ip: str = None) -> tuple:
    """
    Retourne (True, None) si le jeton est valide, sinon (False, raison).
    Fail closed : une erreur réseau vers Cloudflare refuse la requête.
    """
    secret = os.getenv('TURNSTILE_SECRET_KEY', '').strip()
    if not secret:
        logger.warning('[captcha] TURNSTILE_SECRET_KEY absent — vérification désactivée')
        return True, None

    if not isinstance(token, str) or not token or len(token) > 2048:
        return False, 'Vérification anti-robot manquante.'

    payload = {'secret': secret, 'response': token}
    if remote_ip:
        payload['remoteip'] = remote_ip
    try:
        resp = requests.post(SITEVERIFY_URL, data=payload, timeout=_TIMEOUT_S)
        result = resp.json()
    except Exception as e:
        logger.error('[captcha] Turnstile injoignable : %s', e)
        return False, 'Vérification anti-robot indisponible, réessayez.'

    if result.get('success') is True:
        return True, None
    logger.warning('[captcha] Jeton refusé — codes=%s IP=%s',
                   result.get('error-codes'), remote_ip)
    return False, 'Vérification anti-robot échouée, réessayez.'
