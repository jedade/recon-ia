# utils/result_vault.py
"""
Coffre des résultats d'une reconnaissance : code d'accès, chiffrement au
repos et sessions de consultation (plan d'action, phase 1, décisions D1–D3).

Principe
────────
À la fin du pipeline, un CODE D'ACCÈS aléatoire de 256 bits est généré et
envoyé par email au demandeur — c'est le seul endroit où il existe en clair.
Il sert à deux choses distinctes, qui ne doivent jamais se confondre :

1. RETROUVER le dossier : la base stocke `HMAC-SHA256(secret serveur, code)`
   (`access_token_hash`, indexé). Une fuite de la base ne donne pas le code,
   et l'empreinte ne permet pas de déchiffrer.
2. DÉCHIFFRER les résultats : `clé = HKDF-SHA256(code, sel du dossier)`.
   `scan_results`, `analysis_result`, `final_report` (regroupés dans un
   « bundle ») et le PDF sont chiffrés en AES-256-GCM avec cette clé, puis
   le clair est effacé. Le serveur ne conserve AUCUN moyen de les relire
   sans le code : un code perdu = rapport perdu (annoncé dans le mail).

Le chiffrement est authentifié avec une donnée associée (AAD) qui lie chaque
chiffré à son dossier et à son champ : recopier le chiffré d'un dossier dans
un autre, ou le PDF à la place du bundle, fait échouer le déchiffrement au
lieu de servir les données d'un tiers.

Sessions de consultation
────────────────────────
Le code n'est envoyé qu'une fois (POST /results/access). En échange, le
client reçoit un jeton de session opaque et court (1 h par défaut), chiffré
et authentifié par le serveur (Fernet). Il contient l'id du dossier et la
clé dérivée : le serveur peut ainsi déchiffrer les requêtes suivantes sans
jamais revoir le code ni stocker la clé.

Secret serveur
──────────────
`RESULTS_ACCESS_SECRET` (≥ 32 caractères) doit être STABLE et identique sur
tous les workers gunicorn : il sert à l'empreinte de recherche et aux jetons
de session. Le changer rend tous les codes émis introuvables. Il est
volontairement distinct de `SECRET_KEY`, qui retombe sur une valeur aléatoire
par processus quand il est absent — ce repli casserait silencieusement la
recherche d'un worker à l'autre. Sans ce secret, l'émission d'un code est
refusée (fail closed) plutôt que de produire un code inutilisable.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import zlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_FORMAT_VERSION = 1
_CODE_BYTES = 32                        # 256 bits d'entropie
_NONCE_BYTES = 12                       # taille recommandée pour AES-GCM
_SALT_BYTES = 16
# token_urlsafe(32) produit exactement 43 caractères base64url sans padding
ACCESS_CODE_RE = re.compile(r'^[A-Za-z0-9_-]{43}$')

BUNDLE_FIELDS = ('scan_results', 'analysis_result', 'final_report')


class VaultError(Exception):
    """Erreur de configuration ou de déchiffrement du coffre."""


def _server_secret() -> bytes:
    secret = os.getenv('RESULTS_ACCESS_SECRET', '')
    if len(secret) < 32:
        raise VaultError(
            "RESULTS_ACCESS_SECRET absent ou trop court (< 32 caractères) : "
            "impossible d'émettre ou de vérifier un code d'accès."
        )
    return secret.encode('utf-8')


def is_configured() -> bool:
    try:
        _server_secret()
        return True
    except VaultError:
        return False


def access_ttl_days() -> int:
    """Durée de validité d'un code d'accès (décision D2 : 30 jours)."""
    return max(1, min(int(os.getenv('RESULTS_ACCESS_TTL_DAYS', '30')), 365))


def session_ttl_seconds() -> int:
    return max(60, min(int(os.getenv('RESULTS_SESSION_TTL_SECONDS', '3600')), 86400))


# ── Code d'accès ──────────────────────────────────────────────────────────────

def generate_access_code() -> str:
    return secrets.token_urlsafe(_CODE_BYTES)


def is_well_formed_code(code) -> bool:
    return isinstance(code, str) and bool(ACCESS_CODE_RE.match(code))


def lookup_hash(code: str) -> str:
    """Empreinte de recherche du code (HMAC, jamais un simple SHA-256)."""
    return hmac.new(_server_secret(), code.encode('utf-8'), hashlib.sha256).hexdigest()


def new_salt() -> str:
    return secrets.token_hex(_SALT_BYTES)


def derive_key(code: str, salt_hex: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt_hex),
        info=b'recon-ia results v1',
    ).derive(code.encode('utf-8'))


# ── Chiffrement ───────────────────────────────────────────────────────────────

def _aad(recon_id: int, field: str) -> bytes:
    return f'recon-ia:v{_FORMAT_VERSION}:{recon_id}:{field}'.encode('utf-8')


def encrypt(key: bytes, plaintext: bytes, recon_id: int, field: str) -> bytes:
    nonce = secrets.token_bytes(_NONCE_BYTES)
    return bytes([_FORMAT_VERSION]) + nonce + AESGCM(key).encrypt(
        nonce, plaintext, _aad(recon_id, field))


def decrypt(key: bytes, blob: bytes, recon_id: int, field: str) -> bytes:
    if not blob or len(blob) < 1 + _NONCE_BYTES + 16 or blob[0] != _FORMAT_VERSION:
        raise VaultError("Chiffré absent ou de format inconnu")
    nonce, ciphertext = blob[1:1 + _NONCE_BYTES], blob[1 + _NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _aad(recon_id, field))
    except Exception as e:
        raise VaultError("Déchiffrement impossible (clé ou dossier incorrect)") from e


def seal_bundle(key: bytes, recon_id: int, fields: dict) -> bytes:
    """Chiffre les champs texte du dossier (valeurs brutes, telles que stockées)."""
    payload = {'v': _FORMAT_VERSION}
    payload.update({name: fields.get(name) for name in BUNDLE_FIELDS})
    raw = zlib.compress(json.dumps(payload, ensure_ascii=False).encode('utf-8'), 6)
    return encrypt(key, raw, recon_id, 'bundle')


def open_bundle(key: bytes, recon_id: int, blob: bytes) -> dict:
    raw = decrypt(key, blob, recon_id, 'bundle')
    payload = json.loads(zlib.decompress(raw).decode('utf-8'))
    return {name: payload.get(name) for name in BUNDLE_FIELDS}


# ── Scellement d'un dossier ───────────────────────────────────────────────────

def seal_recon(recon, now: Optional[datetime] = None) -> str:
    """
    Émet un code d'accès, chiffre les résultats du dossier et efface le clair.

    Modifie `recon` sans commiter : l'appelant ne commite qu'APRÈS l'envoi
    réussi du mail contenant le code (sinon le code serait perdu et les
    résultats illisibles à jamais). Retourne le code en clair.
    """
    if recon.sealed_at is not None:
        raise VaultError("Résultats déjà chiffrés : un nouveau code ne peut plus être émis")

    now = now or datetime.utcnow()
    code = generate_access_code()
    salt = new_salt()
    key = derive_key(code, salt)

    recon.sealed_bundle = seal_bundle(key, recon.id, {
        name: getattr(recon, name) for name in BUNDLE_FIELDS
    })
    pdf = recon.pdf_report
    recon.sealed_pdf = encrypt(key, pdf, recon.id, 'pdf') if pdf else None

    recon.access_salt = salt
    recon.access_token_hash = lookup_hash(code)
    recon.access_expires_at = now + timedelta(days=access_ttl_days())
    recon.access_revoked_at = None
    recon.access_count = 0
    recon.sealed_at = now

    for name in BUNDLE_FIELDS:
        setattr(recon, name, None)
    recon.pdf_report = None
    return code


def unlock(recon, key: bytes) -> dict:
    """Déchiffre le bundle d'un dossier scellé avec une clé déjà dérivée."""
    return open_bundle(key, recon.id, recon.sealed_bundle)


def unlock_pdf(recon, key: bytes) -> Optional[bytes]:
    if not recon.sealed_pdf:
        return None
    return decrypt(key, recon.sealed_pdf, recon.id, 'pdf')


# ── Sessions de consultation ──────────────────────────────────────────────────

def _fernet() -> Fernet:
    session_key = hmac.new(_server_secret(), b'recon-ia results session v1', hashlib.sha256).digest()
    return Fernet(base64.urlsafe_b64encode(session_key))


def issue_session(recon_id: int, key: bytes) -> str:
    token = json.dumps({'rid': recon_id, 'k': base64.b64encode(key).decode('ascii')})
    return _fernet().encrypt(token.encode('utf-8')).decode('ascii')


def read_session(token: str) -> Tuple[int, bytes]:
    """Retourne (recon_id, clé). Lève VaultError si invalide ou expiré."""
    try:
        raw = _fernet().decrypt(token.encode('ascii'), ttl=session_ttl_seconds())
        data = json.loads(raw)
        return int(data['rid']), base64.b64decode(data['k'])
    except (InvalidToken, ValueError, KeyError, TypeError) as e:
        raise VaultError("Session invalide ou expirée") from e
