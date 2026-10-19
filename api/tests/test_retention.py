# tests/test_retention.py
"""Purge RGPD automatique (utils/retention.py — plan d'action, phase 1)."""
import json
from datetime import datetime, timedelta

import pytest

from database import db
from models.audit_log import AuditLog
from models.pass_recon_cache import PassReconCache
from models.recon import Recon
from utils import result_vault
from utils.retention import ANONYMIZED_NAME, anonymized_email, purge

pytestmark = pytest.mark.security

NOW = datetime(2026, 10, 19, 12, 0, 0)


def _sealed(expires_at, revoked_at=None, email='ada@example.com'):
    recon = Recon(domain='example.com', firstname='Ada', lastname='Lovelace', email=email,
                  accord=True, verification=True, status='success',
                  scan_results=json.dumps({'a': 1}), analysis_result='{}', pdf_report=b'%PDF',
                  requested_info='SSL', security_score=70)
    db.session.add(recon)
    db.session.commit()
    result_vault.seal_recon(recon, now=expires_at - timedelta(days=30))
    recon.access_expires_at = expires_at
    recon.access_revoked_at = revoked_at
    db.session.commit()
    return recon


def test_expired_results_purged_and_identity_anonymized(app):
    old = _sealed(NOW - timedelta(days=8))
    counts = purge(now=NOW)
    db.session.refresh(old)

    assert counts['results_purged'] == 1
    assert old.sealed_bundle is None and old.sealed_pdf is None
    assert old.firstname == old.lastname == ANONYMIZED_NAME
    assert old.email == anonymized_email(old.id)
    assert old.requested_info is None
    assert old.results_purged_at == NOW
    # Métadonnées statistiques conservées
    assert old.domain == 'example.com' and old.security_score == 70


def test_grace_period_respected(app):
    recent = _sealed(NOW - timedelta(days=3))
    active = _sealed(NOW + timedelta(days=10))
    assert purge(now=NOW)['results_purged'] == 0
    db.session.refresh(recent)
    db.session.refresh(active)
    assert recent.sealed_bundle is not None and active.sealed_bundle is not None


def test_revoked_results_purged_after_grace(app):
    revoked = _sealed(NOW + timedelta(days=20), revoked_at=NOW - timedelta(days=8))
    assert purge(now=NOW)['results_purged'] == 1
    db.session.refresh(revoked)
    assert revoked.sealed_bundle is None


def test_purge_is_idempotent(app):
    _sealed(NOW - timedelta(days=8))
    assert purge(now=NOW)['results_purged'] == 1
    assert purge(now=NOW)['results_purged'] == 0


def test_unverified_requests_deleted(app):
    stale = Recon(domain='a.tld', firstname='X', lastname='Y', email='x@a.tld', accord=True,
                  verification=False, created_at=NOW - timedelta(days=8))
    fresh = Recon(domain='b.tld', firstname='X', lastname='Y', email='x@b.tld', accord=True,
                  verification=False, created_at=NOW - timedelta(days=1))
    db.session.add_all([stale, fresh])
    db.session.commit()
    stale_id, fresh_id = stale.id, fresh.id

    assert purge(now=NOW)['unverified_deleted'] == 1
    assert db.session.get(Recon, stale_id) is None
    assert db.session.get(Recon, fresh_id) is not None


def test_old_audit_deleted_but_expired_cache_kept(app):
    """Décision 2026-10-19 : le cache brut reste en base, consultable par l'admin."""
    db.session.add_all([
        AuditLog(method='GET', endpoint='/x', status_code=200, ip_address='1.2.3.4',
                 created_at=NOW - timedelta(days=91)),
        AuditLog(method='GET', endpoint='/y', status_code=200, ip_address='1.2.3.4',
                 created_at=NOW - timedelta(days=1)),
        PassReconCache(domain='old.tld', tools_key='k', result_json='{}',
                       expires_at=NOW - timedelta(seconds=1)),
        PassReconCache(domain='new.tld', tools_key='k', result_json='{}',
                       expires_at=NOW + timedelta(days=1)),
    ])
    db.session.commit()

    counts = purge(now=NOW)
    assert counts['audit_deleted'] == 1
    assert 'cache_deleted' not in counts
    assert AuditLog.query.count() >= 1
    assert sorted(c.domain for c in PassReconCache.query.all()) == ['new.tld', 'old.tld']


def test_purged_code_can_no_longer_open_results(client, app):
    recon = Recon(domain='example.com', firstname='Ada', lastname='L', email='a@example.com',
                  accord=True, verification=True, status='success',
                  scan_results='{}', analysis_result='{}', pdf_report=b'%PDF')
    db.session.add(recon)
    db.session.commit()
    code = result_vault.seal_recon(recon)
    db.session.commit()
    recon.access_expires_at = datetime.utcnow() - timedelta(days=8)
    db.session.commit()
    purge()
    assert client.post('/results/access', json={'code': code}).status_code == 410
