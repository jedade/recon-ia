# tests/test_result_vault.py
"""
Tests unitaires et de sécurité du coffre des résultats
(utils/result_vault.py — plan d'action, phase 1, décision D3).
"""
import base64
import json
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from utils import result_vault as vault
from utils.result_vault import VaultError


def _recon(**overrides):
    """Dossier minimal : seuls les attributs lus/écrits par seal_recon."""
    base = dict(
        id=7, sealed_at=None,
        scan_results=json.dumps({'whois': {'status': 'success', 'data': 'MARQUEUR-SCAN'}}),
        analysis_result=json.dumps({'findings': [{'title': 'MARQUEUR-ANALYSE'}]}),
        final_report=json.dumps({'executive_summary': 'MARQUEUR-RAPPORT'}),
        pdf_report=b'%PDF-1.4 MARQUEUR-PDF',
        sealed_bundle=None, sealed_pdf=None, access_salt=None, access_token_hash=None,
        access_expires_at=None, access_revoked_at=None, access_count=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestAccessCode:
    def test_code_is_256_bits_url_safe(self):
        code = vault.generate_access_code()
        assert vault.is_well_formed_code(code)
        assert len(base64.urlsafe_b64decode(code + '=')) == 32

    def test_codes_are_unique(self):
        assert len({vault.generate_access_code() for _ in range(500)}) == 500

    @pytest.mark.parametrize('bad', [
        None, '', 'abc', 'A' * 42, 'A' * 44, 'A' * 42 + '=', 'A' * 42 + '/',
        "' OR 1=1 --" + 'A' * 32, 123,
    ])
    def test_malformed_codes_rejected(self, bad):
        assert vault.is_well_formed_code(bad) is False


@pytest.mark.security
class TestLookupHash:
    def test_hash_is_keyed(self, monkeypatch):
        code = vault.generate_access_code()
        first = vault.lookup_hash(code)
        monkeypatch.setenv('RESULTS_ACCESS_SECRET', 'un-autre-secret-serveur-de-32-caracteres!!')
        assert vault.lookup_hash(code) != first

    def test_hash_does_not_reveal_code(self):
        code = vault.generate_access_code()
        assert code not in vault.lookup_hash(code)

    def test_missing_secret_fails_closed(self, monkeypatch):
        monkeypatch.setenv('RESULTS_ACCESS_SECRET', 'trop-court')
        assert vault.is_configured() is False
        with pytest.raises(VaultError):
            vault.lookup_hash(vault.generate_access_code())
        with pytest.raises(VaultError):
            vault.issue_session(1, b'k' * 32)


@pytest.mark.security
class TestEncryption:
    def setup_method(self):
        self.code = vault.generate_access_code()
        self.salt = vault.new_salt()
        self.key = vault.derive_key(self.code, self.salt)

    def test_roundtrip(self):
        blob = vault.encrypt(self.key, b'secret', 1, 'bundle')
        assert vault.decrypt(self.key, blob, 1, 'bundle') == b'secret'

    def test_nonce_is_random(self):
        assert vault.encrypt(self.key, b'x', 1, 'f') != vault.encrypt(self.key, b'x', 1, 'f')

    def test_key_depends_on_salt(self):
        assert vault.derive_key(self.code, vault.new_salt()) != self.key

    def test_wrong_code_cannot_decrypt(self):
        blob = vault.encrypt(self.key, b'secret', 1, 'bundle')
        other = vault.derive_key(vault.generate_access_code(), self.salt)
        with pytest.raises(VaultError):
            vault.decrypt(other, blob, 1, 'bundle')

    def test_ciphertext_bound_to_record(self):
        """Recopier le chiffré d'un dossier dans un autre ne doit rien révéler."""
        blob = vault.encrypt(self.key, b'secret', 1, 'bundle')
        with pytest.raises(VaultError):
            vault.decrypt(self.key, blob, 2, 'bundle')

    def test_ciphertext_bound_to_field(self):
        blob = vault.encrypt(self.key, b'secret', 1, 'pdf')
        with pytest.raises(VaultError):
            vault.decrypt(self.key, blob, 1, 'bundle')

    def test_tampering_detected(self):
        blob = bytearray(vault.encrypt(self.key, b'secret', 1, 'bundle'))
        blob[-1] ^= 0x01
        with pytest.raises(VaultError):
            vault.decrypt(self.key, bytes(blob), 1, 'bundle')

    @pytest.mark.parametrize('blob', [None, b'', b'\x01' + b'\x00' * 10, b'\x09' + b'\x00' * 40])
    def test_garbage_rejected(self, blob):
        with pytest.raises(VaultError):
            vault.decrypt(self.key, blob, 1, 'bundle')


@pytest.mark.security
class TestSealRecon:
    def test_plaintext_erased_and_recoverable_with_code(self):
        recon = _recon()
        original = {n: getattr(recon, n) for n in vault.BUNDLE_FIELDS}
        code = vault.seal_recon(recon)

        for name in vault.BUNDLE_FIELDS:
            assert getattr(recon, name) is None
        assert recon.pdf_report is None
        for marker in (b'MARQUEUR-SCAN', b'MARQUEUR-ANALYSE', b'MARQUEUR-RAPPORT', b'MARQUEUR-PDF'):
            assert marker not in recon.sealed_bundle
            assert marker not in recon.sealed_pdf

        key = vault.derive_key(code, recon.access_salt)
        assert vault.unlock(recon, key) == original
        assert vault.unlock_pdf(recon, key) == b'%PDF-1.4 MARQUEUR-PDF'

    def test_code_never_stored(self):
        recon = _recon()
        code = vault.seal_recon(recon)
        stored = [str(v) for v in vars(recon).values()]
        assert not any(code in s for s in stored)
        assert recon.access_token_hash == vault.lookup_hash(code)

    def test_expiry_is_30_days_by_default(self):
        now = datetime(2026, 10, 19, 12, 0, 0)
        recon = _recon()
        vault.seal_recon(recon, now=now)
        assert recon.access_expires_at == now + timedelta(days=30)

    def test_cannot_seal_twice(self):
        recon = _recon()
        vault.seal_recon(recon)
        with pytest.raises(VaultError):
            vault.seal_recon(recon)

    def test_record_without_pdf(self):
        recon = _recon(pdf_report=None)
        code = vault.seal_recon(recon)
        assert recon.sealed_pdf is None
        assert vault.unlock_pdf(recon, vault.derive_key(code, recon.access_salt)) is None


@pytest.mark.security
class TestSessions:
    def test_roundtrip(self):
        key = b'k' * 32
        rid, out = vault.read_session(vault.issue_session(42, key))
        assert (rid, out) == (42, key)

    def test_token_is_opaque(self):
        key = b'clef-secrete-de-32-octets-exacte'
        token = vault.issue_session(42, key)
        assert base64.b64encode(key).decode() not in token
        assert 'rid' not in token

    def test_tampered_token_rejected(self):
        token = vault.issue_session(42, b'k' * 32)
        tampered = token[:-4] + ('AAAA' if not token.endswith('AAAA') else 'BBBB')
        with pytest.raises(VaultError):
            vault.read_session(tampered)

    def test_expired_token_rejected(self, monkeypatch):
        old = vault._fernet().encrypt_at_time(
            json.dumps({'rid': 1, 'k': base64.b64encode(b'k' * 32).decode()}).encode(),
            int(time.time()) - 7200,
        ).decode()
        with pytest.raises(VaultError):
            vault.read_session(old)

    def test_token_from_other_server_secret_rejected(self, monkeypatch):
        token = vault.issue_session(1, b'k' * 32)
        monkeypatch.setenv('RESULTS_ACCESS_SECRET', 'secret-d-un-autre-deploiement-0123456789')
        with pytest.raises(VaultError):
            vault.read_session(token)

    @pytest.mark.parametrize('token', ['', 'abc', 'é', '\x00' * 10])
    def test_garbage_rejected(self, token):
        with pytest.raises(VaultError):
            vault.read_session(token)
