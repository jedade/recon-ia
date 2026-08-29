# models/pass_recon_cache.py
"""
Cache des résultats de reconnaissance passive (POST /pass_recon).

Objectif :
    Éviter de relancer un scan complet (5-15 min) sur un domaine déjà analysé
    récemment. Lorsqu'une entrée valide (non expirée) existe, la réponse est
    servie depuis la base en quelques millisecondes.

Stratégie de clé de cache :
    (domain, tools_key) — où tools_key est la liste triée des outils demandés,
    sérialisée en chaîne comma-separated. Deux requêtes avec les mêmes outils
    dans un ordre différent partagent la même entrée de cache.

Note RGPD :
    Seuls des résultats de reconnaissance passive portant sur des ressources
    publiques du domaine sont persistés ici — aucune donnée personnelle
    (email, identité) n'est mise en cache.

Durée d'expiration recommandée — 30 jours (CACHE_DEFAULT_TTL_DAYS) :
    - Aligné sur le cycle de recrawl Shodan (~30 jours)
    - Couvre les changements d'infrastructure courants (DNS, sous-domaines)
    - Compatible avec le principe RGPD de minimisation pour données publiques
    - Peut être réduit à 7 jours via le paramètre `cache_ttl_days` de la requête
      si des données plus fraîches sont nécessaires (ex: environnement de prod actif)

Cycle de vie :
    1. POST /pass_recon → cache MISS → scan complet → sauvegarde en cache
    2. POST /pass_recon → cache HIT  → retour immédiat + incrémente hit_count
    3. POST /pass_recon + force_refresh=true → ignore le cache → rescan + écrase
    4. expires_at < NOW() → entrée expirée → rescan + mise à jour de l'entrée
"""
import json
from datetime import datetime
from database import db

# Durée d'expiration par défaut : 30 jours
CACHE_DEFAULT_TTL_DAYS = 30


class PassReconCache(db.Model):
    __tablename__ = 'pass_recon_cache'

    id = db.Column(db.Integer, primary_key=True)

    # --- Clé de cache ---
    # Domaine scanné (minuscules, sans espaces)
    domain = db.Column(db.String(255), nullable=False)

    # Liste triée des outils demandés, sérialisée : "amass,crtsh,dns_records,ssl_info"
    tools_key = db.Column(db.String(1024), nullable=False)

    # --- Résultat ---
    # JSON complet retourné par le scan
    result_json = db.Column(db.Text, nullable=False)

    # Durée du scan original en secondes (information uniquement)
    scan_duration_s = db.Column(db.Float, nullable=True)

    # Nombre de sous-domaines uniques trouvés (accès rapide sans parser le JSON)
    subdomain_count = db.Column(db.Integer, default=0, nullable=False)

    # --- Statistiques d'utilisation ---
    # Nombre de fois que cette entrée a été servie depuis le cache
    hit_count = db.Column(db.Integer, default=0, nullable=False)
    # Dernière fois que l'entrée a été accédée depuis le cache
    last_hit_at = db.Column(db.DateTime, nullable=True)

    # --- Horodatage ---
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Mis à jour à chaque rescan (force_refresh ou expiration)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    # --- Index et contraintes ---
    __table_args__ = (
        # Un seul enregistrement par (domaine + ensemble d'outils)
        db.UniqueConstraint('domain', 'tools_key', name='uq_pass_recon_cache_domain_tools'),
        # Index principal pour la recherche cache (domain + expiration)
        db.Index('ix_pass_recon_cache_domain', 'domain'),
        db.Index('ix_pass_recon_cache_expires', 'expires_at'),
        db.Index('ix_pass_recon_cache_domain_expires', 'domain', 'expires_at'),
    )

    # ------------------------------------------------------------------
    # Méthodes utilitaires
    # ------------------------------------------------------------------

    @property
    def is_valid(self) -> bool:
        """Retourne True si l'entrée de cache n'est pas encore expirée."""
        return self.expires_at > datetime.utcnow()

    @property
    def remaining_days(self) -> int:
        """Nombre de jours restants avant expiration."""
        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.days)

    def get_result(self) -> dict:
        """Désérialise et retourne le résultat JSON stocké."""
        return json.loads(self.result_json)

    def record_hit(self) -> None:
        """Incrémente le compteur d'accès et met à jour last_hit_at."""
        self.hit_count += 1
        self.last_hit_at = datetime.utcnow()

    def to_dict(self) -> dict:
        """Métadonnées du cache (sans le résultat complet) pour les logs/API."""
        return {
            'id': self.id,
            'domain': self.domain,
            'tools_key': self.tools_key,
            'subdomain_count': self.subdomain_count,
            'scan_duration_s': round(self.scan_duration_s, 1) if self.scan_duration_s else None,
            'hit_count': self.hit_count,
            'last_hit_at': self.last_hit_at.isoformat() if self.last_hit_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'expires_at': self.expires_at.isoformat(),
            'remaining_days': self.remaining_days,
            'is_valid': self.is_valid,
        }

    def __repr__(self) -> str:
        return (
            f"<PassReconCache id={self.id} domain={self.domain!r} "
            f"tools={self.tools_key[:40]!r} expires={self.expires_at.date()} "
            f"hits={self.hit_count}>"
        )
