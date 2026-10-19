# models/scan_monitoring.py
"""
Différentiel entre scans et surveillance planifiée (plan d'action, phase 7).

  scan_snapshot   empreinte technique compacte d'un scan (sous-domaines, IP,
                  ports, CVE, certificat, SPF/DMARC, technologies — voir
                  utils/scan_diff.py::extract_snapshot) + différentiel avec le
                  scan précédent du même domaine. Une ligne par dossier
                  (`recon_id`, pipeline) ou par rescan de surveillance
                  (`cache_id`, sans dossier).
  watched_domain  liste OPT-IN des domaines surveillés, gérée par l'admin
                  uniquement (dashboard). Désactivée par défaut.

Pourquoi le différentiel est stocké EN CLAIR (et pas dans le bundle scellé)
────────────────────────────────────────────────────────────────────────────
1. Il ne contient que des données techniques publiques, de même nature que le
   cache des scans bruts (`pass_recon_cache`), déjà conservé en clair et
   consultable par l'admin : aucune analyse IA, aucune donnée du demandeur.
2. Le scan SUIVANT doit pouvoir se comparer à celui-ci. Si l'empreinte était
   chiffrée avec le code du demandeur, le serveur ne pourrait plus jamais la
   relire et le différentiel (B9) serait impossible — de même que la
   surveillance, qui tourne sans aucun dossier.
3. Le lien dossier ↔ domaine existe déjà en clair dans `recon.domain` : la
   colonne `recon_id` n'apprend rien de plus à un lecteur de la base.
"""
import json
from datetime import datetime, timedelta

from database import db


class ScanSnapshot(db.Model):
    __tablename__ = 'scan_snapshot'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    # Un seul instantané par dossier (UNIQUE ; NULL pour un rescan sans dossier)
    recon_id = db.Column(db.Integer, db.ForeignKey('recon.id', ondelete='SET NULL'),
                         nullable=True, unique=True)
    # Entrée de cache source d'un rescan de surveillance
    cache_id = db.Column(db.Integer, nullable=True)
    # « recon:<id> » ou « cache:<id>:<horodatage de mise à jour> » — sert
    # d'idempotence : le même scan n'est jamais ingéré deux fois
    scan_ref = db.Column(db.String(128), nullable=False)
    # 'pipeline' (fin de pipeline, avant scellement) | 'rescan' (surveillance)
    source = db.Column(db.String(16), nullable=False, default='pipeline')
    snapshot_json = db.Column(db.Text, nullable=False)
    diff_json = db.Column(db.Text, nullable=True)
    previous_snapshot_id = db.Column(db.Integer, nullable=True)
    significant = db.Column(db.Boolean, nullable=False, default=False)
    change_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.Index('ix_scan_snapshot_domain_created', 'domain', 'created_at'),
        db.Index('ix_scan_snapshot_scan_ref', 'scan_ref'),
    )

    @staticmethod
    def _loads(text):
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def get_snapshot(self) -> dict:
        return self._loads(self.snapshot_json) or {}

    def get_diff(self):
        return self._loads(self.diff_json)

    def to_dict(self, with_diff: bool = True) -> dict:
        from models.recon import utc_iso
        data = {
            'id': self.id,
            'domain': self.domain,
            'recon_id': self.recon_id,
            'cache_id': self.cache_id,
            'scan_ref': self.scan_ref,
            'source': self.source,
            'previous_snapshot_id': self.previous_snapshot_id,
            'significant': bool(self.significant),
            'change_count': self.change_count or 0,
            'created_at': utc_iso(self.created_at),
        }
        if with_diff:
            data['diff'] = self.get_diff()
        return data


class WatchedDomain(db.Model):
    __tablename__ = 'watched_domain'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, unique=True)
    # Opt-in : une ligne n'est créée que par l'admin, et reste désactivée
    # tant qu'il ne l'active pas explicitement.
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    interval_days = db.Column(db.Integer, nullable=False, default=7)
    last_rescan_at = db.Column(db.DateTime, nullable=True)
    last_snapshot_id = db.Column(db.Integer, nullable=True)
    last_change_at = db.Column(db.DateTime, nullable=True)
    last_alert_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    def is_due(self, now=None) -> bool:
        """Vrai si la surveillance est active et qu'un rescan est dû."""
        if not self.enabled:
            return False
        if self.last_rescan_at is None:
            return True
        now = now or datetime.utcnow()
        return self.last_rescan_at + timedelta(days=max(1, self.interval_days or 1)) <= now

    def to_dict(self) -> dict:
        from models.recon import utc_iso
        return {
            'id': self.id,
            'domain': self.domain,
            'enabled': bool(self.enabled),
            'interval_days': self.interval_days,
            'last_rescan_at': utc_iso(self.last_rescan_at),
            'last_snapshot_id': self.last_snapshot_id,
            'last_change_at': utc_iso(self.last_change_at),
            'last_alert_at': utc_iso(self.last_alert_at),
            'is_due': self.is_due(),
            'created_at': utc_iso(self.created_at),
            'updated_at': utc_iso(self.updated_at),
        }
