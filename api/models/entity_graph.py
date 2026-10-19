# models/entity_graph.py
"""
Graphe d'entités de la surface d'attaque (plan d'action, phase 7).

Deux tables :

  entity    une entité TECHNIQUE PUBLIQUE observée par un scan passif
            (domaine, sous-domaine, IP, ASN, certificat, technologie,
            vulnérabilité, port, organisation). Unicité (type, valeur) : une
            même IP vue par dix scans est une seule ligne, dont seules les
            dates de première/dernière observation évoluent.
  relation  une arête orientée source → cible (ex. sous-domaine
            `resolves_to` IP), rattachée au domaine racine du scan qui l'a
            observée (`root_domain`), avec l'outil source, la référence du
            scan (`scan_ref`, ex. « recon:12 » ou « cache:4:2026-10-19T… ») et
            les dates de première/dernière observation.

Chaîne modélisée : organisation → domaine → sous-domaine → IP → ASN →
certificat → technologie → vulnérabilité (voir utils/entity_graph.py pour
les types de relation exacts).

Ce que le graphe ne contient JAMAIS (vérifié par tests/test_phase7_security.py) :
l'identité du demandeur (nom, email), le contenu de l'analyse IA, ni les
sorties brutes des outils. Il est construit AVANT le scellement du dossier
(routes/report.py) ou depuis le cache des scans bruts, et reste en clair :
il ne contient que des données publiques de même nature que
`pass_recon_cache`.
"""
import json
from datetime import datetime

from database import db

# Types d'entités autorisés — toute autre valeur est rejetée par le constructeur.
ENTITY_TYPES = (
    'organization', 'domain', 'subdomain', 'ip', 'asn',
    'certificate', 'technology', 'vulnerability', 'port',
)


class Entity(db.Model):
    __tablename__ = 'entity'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(512), nullable=False)
    # Attributs techniques de la DERNIÈRE observation (JSON court) : échéance
    # d'un certificat, CVSS d'une CVE, nom d'un ASN… jamais de donnée personnelle.
    attributes = db.Column(db.Text, nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('type', 'value', name='uq_entity_type_value'),
        db.Index('ix_entity_type', 'type'),
        db.Index('ix_entity_last_seen', 'last_seen'),
    )

    def get_attributes(self) -> dict:
        if not self.attributes:
            return {}
        try:
            data = json.loads(self.attributes)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def to_dict(self) -> dict:
        from models.recon import utc_iso
        return {
            'id': self.id,
            'type': self.type,
            'value': self.value,
            'attributes': self.get_attributes(),
            'first_seen': utc_iso(self.first_seen),
            'last_seen': utc_iso(self.last_seen),
        }

    def __repr__(self) -> str:
        return f'<Entity {self.type}:{self.value!r}>'


class Relation(db.Model):
    __tablename__ = 'relation'

    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('entity.id', ondelete='CASCADE'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('entity.id', ondelete='CASCADE'), nullable=False)
    type = db.Column(db.String(32), nullable=False)
    # Clé de l'outil (clé de scan_results) qui a produit la DERNIÈRE observation
    tool = db.Column(db.String(64), nullable=True)
    # Domaine racine du scan : sert à extraire le sous-graphe d'un domaine
    root_domain = db.Column(db.String(255), nullable=False)
    # Dernier dossier ayant observé l'arête. SET NULL : la purge RGPD
    # (utils/retention.py) peut supprimer une demande sans casser le graphe.
    recon_id = db.Column(db.Integer, db.ForeignKey('recon.id', ondelete='SET NULL'), nullable=True)
    scan_ref = db.Column(db.String(128), nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('source_id', 'target_id', 'type', 'root_domain',
                            name='uq_relation_edge'),
        db.Index('ix_relation_root_domain', 'root_domain'),
        db.Index('ix_relation_source', 'source_id'),
        db.Index('ix_relation_target', 'target_id'),
    )

    def to_dict(self) -> dict:
        from models.recon import utc_iso
        return {
            'id': self.id,
            'source_id': self.source_id,
            'target_id': self.target_id,
            'type': self.type,
            'tool': self.tool,
            'root_domain': self.root_domain,
            'recon_id': self.recon_id,
            'scan_ref': self.scan_ref,
            'first_seen': utc_iso(self.first_seen),
            'last_seen': utc_iso(self.last_seen),
        }

    def __repr__(self) -> str:
        return f'<Relation {self.source_id} -{self.type}-> {self.target_id} ({self.root_domain})>'
