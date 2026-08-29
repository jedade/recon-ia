# models/audit_log.py
"""
Modèle SQLAlchemy pour la journalisation des requêtes API en base de données.

Chaque appel HTTP enregistre : méthode, chemin, IP, code HTTP, durée, user-agent.
Cela permet de tracer toutes les actions effectuées sur l'outil et de détecter
des comportements anormaux (brute-force, utilisation abusive, etc.).

Les logs ne contiennent jamais de données sensibles (mot de passe, OTP, tokens).
"""
from datetime import datetime
from database import db


class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)

    # --- Requête HTTP ---
    # Méthode HTTP : GET, POST, PUT, PATCH, DELETE
    method = db.Column(db.String(10), nullable=False)
    # Chemin de l'endpoint (ex: /recon/1/report)
    endpoint = db.Column(db.String(255), nullable=False)
    # Code de statut HTTP retourné
    status_code = db.Column(db.Integer, nullable=False)
    # Durée de traitement en millisecondes
    duration_ms = db.Column(db.Float, nullable=True)

    # --- Client ---
    # Adresse IP du client (IPv4 ou IPv6)
    ip_address = db.Column(db.String(45), nullable=True)
    # User-Agent tronqué à 200 caractères pour éviter les injections via header
    user_agent = db.Column(db.String(200), nullable=True)

    # --- Horodatage ---
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # --- Index pour les requêtes fréquentes ---
    __table_args__ = (
        db.Index('ix_audit_log_endpoint', 'endpoint'),
        db.Index('ix_audit_log_status_code', 'status_code'),
        db.Index('ix_audit_log_ip', 'ip_address'),
    )

    def to_dict(self) -> dict:
        """Sérialise l'entrée de log pour l'API."""
        return {
            'id': self.id,
            'method': self.method,
            'endpoint': self.endpoint,
            'status_code': self.status_code,
            'duration_ms': round(self.duration_ms, 2) if self.duration_ms else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return (f"<AuditLog id={self.id} {self.method} {self.endpoint} "
                f"→ {self.status_code} ({self.duration_ms:.1f}ms)>")
