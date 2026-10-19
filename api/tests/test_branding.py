"""
Charte graphique ReconIA : logo dans les mails (image inline, jamais une
pièce jointe), dans le PDF, et ressources de marque présentes.
"""
import email
import os
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from utils import email_sender as es
from utils import pdf_generator as pg

API_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _FakeSMTP:
    sent = []

    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): pass
    def login(self, *a): pass

    def sendmail(self, sender, to, raw):
        _FakeSMTP.sent.append(email.message_from_string(raw))


@pytest.fixture
def outbox(monkeypatch):
    _FakeSMTP.sent = []
    monkeypatch.setattr(es.smtplib, 'SMTP', _FakeSMTP)
    monkeypatch.setattr(es, 'EMAIL_SENDER', 'noreply@example.test')
    monkeypatch.setattr(es, 'EMAIL_PASSWORD', 'x')
    monkeypatch.setattr(es, 'EMAIL_HOST', 'smtp.example.test')
    monkeypatch.setenv('SMTP_USERNAME', 'noreply@example.test')
    monkeypatch.setenv('SMTP_PASSWORD', 'x')
    return _FakeSMTP.sent


def _send_all():
    es.send_verification_email('ada@example.test', '123456')
    es.send_results_ready_email('ada@example.test', 'Ada', 'Lovelace', 'example.com',
                                'A' * 43, datetime.utcnow() + timedelta(days=30), 'HIGH', 58, 3,
                                results_url='https://recon.example.test/result.html')
    es.send_error_notification('ada@example.test', 'Ada', 'Lovelace', 'example.com',
                               error_detail='boom', recon_id=7)
    es.send_monitoring_alert('admin@example.test', 'example.com',
                             {'summary': ['1 nouveau sous-domaine'], 'subdomains': {'added': ['a.example.com']}})


def _parts(msg):
    return [p for p in msg.walk() if not p.is_multipart()]


class TestEmailBranding:
    def test_every_email_embeds_the_logo_inline(self, outbox):
        _send_all()
        assert len(outbox) == 4
        for msg in outbox:
            images = [p for p in _parts(msg) if p.get_content_type() == 'image/png']
            assert len(images) == 1, msg['Subject']
            assert images[0]['Content-ID'] == '<reconia-logo>'
            assert images[0].get_content_disposition() == 'inline'
            html = next(p for p in _parts(msg) if p.get_content_type() == 'text/html')
            body = html.get_payload(decode=True).decode('utf-8')
            assert 'cid:reconia-logo' in body
            assert '{_BRAND' not in body and 'ReconIA' in body
            assert msg['From'].startswith('ReconIA')

    @pytest.mark.security
    def test_results_email_has_no_attachment(self, outbox):
        """Décision D1 : le logo est inline, aucun fichier n'est joint."""
        _send_all()
        ready = outbox[1]
        from email.header import decode_header, make_header
        assert 'est prêt' in str(make_header(decode_header(ready['Subject'])))
        assert not [p for p in _parts(ready) if p.get_content_disposition() == 'attachment']
        assert not [p for p in _parts(ready) if p.get_content_type() == 'application/pdf']

    @pytest.mark.security
    def test_logo_is_not_loaded_from_a_remote_url(self, outbox):
        """Pas d'image distante : pas de pixel de suivi d'ouverture."""
        _send_all()
        for msg in outbox:
            html = next(p for p in _parts(msg) if p.get_content_type() == 'text/html')
            body = html.get_payload(decode=True).decode('utf-8')
            assert '<img src="http' not in body and "<img src='http" not in body

    def test_missing_logo_falls_back_to_text_only(self, outbox, monkeypatch):
        monkeypatch.setattr(es, '_BRAND_LOGO_PATH', '/nonexistent/logo.png')
        es.send_verification_email('ada@example.test', '123456')
        assert outbox and not [p for p in _parts(outbox[0]) if p.get_content_type() == 'image/png']


class TestPdfBranding:
    def test_brand_files_present(self):
        for name in ('reconia-logo-600.png', 'reconia-mark-160.png', 'reconia-logo-email.png'):
            assert os.path.isfile(os.path.join(API_DIR, 'static', 'brand', name)), name

    def test_pdf_embeds_logo_images(self):
        pdf = pg.generate_pdf({'domain': 'example.com', 'findings': [], 'security_score': 90},
                              scan_data={'domain': 'example.com'})
        assert pdf.startswith(b'%PDF')
        assert pdf.count(b'/Subtype /Image') >= 2      # logo complet + symbole de l'en-tête
        assert b'ReconIA' in pdf

    def test_pdf_survives_missing_logo(self, monkeypatch):
        monkeypatch.setattr(pg, '_BRAND_DIR', '/nonexistent')
        monkeypatch.setattr(pg, '_brand_cache', {})
        pdf = pg.generate_pdf({'domain': 'example.com', 'findings': []}, scan_data={'domain': 'example.com'})
        assert pdf.startswith(b'%PDF') and b'/Subtype /Image' not in pdf


class TestExportBranding:
    def test_publisher_block(self, monkeypatch):
        from routes.report import _publisher
        monkeypatch.setenv('RESULTS_PAGE_URL', 'https://recon.example.test/result.html')
        pub = _publisher()
        assert pub['name'] == 'ReconIA' and pub['tagline'] == 'De la donnée à la décision'
        assert pub['logo_url'] == 'https://recon.example.test/assets/brand/reconia-logo.png'

    @pytest.mark.security
    def test_publisher_ignores_non_http_url(self, monkeypatch):
        from routes.report import _publisher
        monkeypatch.setenv('RESULTS_PAGE_URL', 'javascript:alert(1)')
        assert 'logo_url' not in _publisher()

    def test_navigator_layer_is_branded(self):
        from utils.attack_enablement import build_navigator_layer
        layer = build_navigator_layer([], domain='example.com')
        assert layer['name'].startswith('ReconIA')
        assert any('De la donnée à la décision' in m['value'] for m in layer['metadata'])
