# tests/test_otp.py
import pytest
from datetime import datetime, timedelta
from types import SimpleNamespace
from utils.email_sender import generate_code, validate_code


class TestGenerateCode:
    def test_length_is_6(self):
        code = generate_code()
        assert len(code) == 6

    def test_digits_only(self):
        code = generate_code()
        assert code.isdigit()

    def test_codes_are_different(self):
        codes = {generate_code() for _ in range(20)}
        assert len(codes) > 1


class TestValidateCode:
    def _make_recon(self, otp_code, created_at=None):
        """
        Stub minimal d'un Recon pour validate_code().

        Volontairement un SimpleNamespace et non un MagicMock : validate_code lit
        `otp_sent_at` en priorité sur `created_at`, et un MagicMock fabriquait
        automatiquement cet attribut sous forme de mock, ce qui faisait échouer
        la comparaison de dates (TypeError datetime > MagicMock) au lieu de
        tester la logique d'expiration.
        """
        ref = created_at or datetime.utcnow()
        return SimpleNamespace(
            id=1,
            otp_code=otp_code,
            created_at=ref,
            otp_sent_at=ref,
        )

    def test_valid_code_returns_true(self):
        recon = self._make_recon("123456")
        ok, msg = validate_code(recon, "123456")
        assert ok is True
        assert msg == "Validé"

    def test_valid_code_clears_otp(self):
        recon = self._make_recon("123456")
        validate_code(recon, "123456")
        assert recon.otp_code is None

    def test_wrong_code_returns_false(self):
        recon = self._make_recon("123456")
        ok, msg = validate_code(recon, "000000")
        assert ok is False
        assert "incorrect" in msg.lower()

    def test_expired_code_returns_false(self):
        old_time = datetime.utcnow() - timedelta(minutes=11)
        recon = self._make_recon("123456", created_at=old_time)
        ok, msg = validate_code(recon, "123456")
        assert ok is False
        assert "expiré" in msg.lower()

    def test_expired_code_clears_otp(self):
        old_time = datetime.utcnow() - timedelta(minutes=11)
        recon = self._make_recon("123456", created_at=old_time)
        validate_code(recon, "123456")
        assert recon.otp_code is None
