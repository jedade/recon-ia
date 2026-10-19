# models/recon.py
"""
Modèle SQLAlchemy pour un enregistrement de reconnaissance OSINT.

Champs exposés publiquement (to_dict) :
    id, domain, firstname, lastname, email, accord, verification,
    requested_info, status, execution_time, started_at, completed_at,
    start_report_date, end_report_date, created_at, updated_at

Champs sensibles (to_dict_full uniquement, endpoint /report) :
    scan_results  — résultats bruts OSINT (JSON sérialisé)
    final_report  — rapport final généré par le workflow IA/n8n

Cycle de vie d'un enregistrement :
    1. Création (POST /recon)         → status='pending', verification=False
    2. Vérification email             → verification=True,
                                        start_report_date=now()
    3. Lancement du scan par n8n      → status='running', started_at=...
    4. Résultats reçus (PATCH /result)→ status='success'|'failed',
                                        end_report_date=now(),
                                        execution_time=(end - start).total_seconds(),
                                        completed_at, scan_results, final_report

Convention d'horodatage
───────────────────────
Toutes les colonnes DateTime stockent de l'UTC **naïf** (datetime.utcnow()).
La sérialisation JSON passe systématiquement par utc_iso() qui produit de
l'ISO-8601 avec suffixe `Z` explicite — jamais d'ISO naïf ambigu, afin que
les consommateurs (dashboard, exports académiques) n'aient aucune convention
de fuseau à deviner.
"""
import json
from datetime import datetime, timezone
from database import db
from datetime import datetime as _dt


def utc_iso(dt) -> str:
    """
    Sérialise un datetime en ISO-8601 UTC avec suffixe `Z`.

    Les datetimes naïfs sont considérés comme de l'UTC (convention de stockage
    de ce modèle). Les datetimes aware sont convertis en UTC avant formatage.
    Retourne None si dt est None.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        aware = dt.replace(tzinfo=timezone.utc)
    else:
        aware = dt.astimezone(timezone.utc)
    # isoformat() produit '+00:00' — on normalise en 'Z' (forme canonique unique)
    return aware.isoformat().replace('+00:00', 'Z')


def utc_now_iso() -> str:
    """Horodatage courant en ISO-8601 UTC avec suffixe `Z`."""
    return utc_iso(_dt.utcnow())


class Recon(db.Model):
    __tablename__ = 'recon'

    # --- Identité ---
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    # PAS unique (2026-07-30, contrainte UNIQUE retirée) : un email doit
    # pouvoir lancer plusieurs scans distincts dans le temps (même domaine ou
    # non) sans écraser l'historique — indispensable pour la reproductibilité
    # scientifique (relancer le même domaine plusieurs fois doit produire
    # plusieurs rapports comparables, pas un seul réécrit à chaque fois).
    # Chaque soumission de POST /recon crée désormais systématiquement un
    # nouvel enregistrement — voir routes/crud.py::create_recon().
    email = db.Column(db.String(255), nullable=False)
    accord = db.Column(db.Boolean, default=False, nullable=False)

    # --- Vérification email OTP ---
    verification = db.Column(db.Boolean, default=False, nullable=False)
    otp_code     = db.Column(db.String(6),   nullable=True)
    otp_sent_at  = db.Column(db.DateTime,    nullable=True)   # horodatage d'envoi du code
    # Tentatives incorrectes sur le code en cours (anti brute-force réparti,
    # voir routes/crud.py::_OTP_MAX_ATTEMPTS)
    otp_attempts = db.Column(db.Integer, nullable=False, default=0)

    # --- Horodatage du cycle rapport ---
    # Rempli automatiquement à la vérification email (déclenchement du flow)
    start_report_date = db.Column(db.DateTime, nullable=True)
    # Rempli automatiquement à la réception des résultats (PATCH /result)
    end_report_date = db.Column(db.DateTime, nullable=True)

    # --- Demande de reconnaissance ---
    # Texte libre décrivant ce qui est demandé (ex: "analyse SSL + sous-domaines")
    requested_info = db.Column(db.Text, nullable=True)

    # --- Résultats sensibles — non exposés dans to_dict() ---
    # Ces colonnes sont volumineuses (rapports JSON de plusieurs dizaines de Ko,
    # PDF de plusieurs centaines de Ko) et `deferred` : SQLAlchemy ne les charge
    # PAS dans un SELECT par défaut, mais à la demande, au premier accès.
    #
    # Sans cela, GET /recon rapatriait le PDF et les trois blobs JSON de chaque
    # ligne de la page uniquement pour afficher un tableau qui n'en montre
    # aucun. Les endpoints qui ont besoin du contenu (rapport, exports, PDF) y
    # accèdent normalement — le chargement différé est transparent.
    #
    # Attention : ce différé implique une requête supplémentaire par attribut et
    # par objet. Ne jamais accéder à ces colonnes dans une boucle sur une liste
    # d'enregistrements sans `undefer()` explicite (cf. to_dict(), qui utilise
    # les colonnes dénormalisées précisément pour éviter ce piège).
    scan_results = db.deferred(db.Column(db.Text, nullable=True))
    # Rapport final généré par le workflow n8n/IA
    final_report = db.deferred(db.Column(db.Text, nullable=True))
    # Rapport PDF binaire (généré par POST /recon/<id>/generate_report)
    _pdf_report_col  = db.Column('pdf_report', db.LargeBinary, nullable=True)
    pdf_report       = db.deferred(_pdf_report_col)
    pdf_generated_at = db.Column(db.DateTime,    nullable=True)

    # Présence du PDF évaluée EN SQL (`pdf_report IS NOT NULL`), donc sans
    # transférer le binaire. Tester `self.pdf_report is not None` en Python
    # déclencherait au contraire le chargement différé du blob complet, une
    # requête par ligne — exactement ce que le `deferred` cherche à éviter.
    has_pdf = db.column_property(_pdf_report_col.isnot(None))

    # Rapport d'analyse IA (cache — POST /analyze avec recon_id)
    _analysis_result_col  = db.Column('analysis_result', db.Text, nullable=True)
    analysis_result       = db.deferred(_analysis_result_col)  # JSON sérialisé
    analysis_generated_at = db.Column(db.DateTime, nullable=True)
    analysis_expires_at   = db.Column(db.DateTime, nullable=True)

    # Idem : présence de l'analyse évaluée en SQL, sans rapatrier le rapport.
    has_analysis = db.column_property(_analysis_result_col.isnot(None))

    # --- Coffre des résultats (2026-10-19, utils/result_vault.py) ---
    # En fin de pipeline, scan_results / analysis_result / final_report sont
    # chiffrés ensemble dans `sealed_bundle` et le PDF dans `sealed_pdf`
    # (AES-256-GCM, clé dérivée du code d'accès envoyé par mail), puis les
    # colonnes en clair ci-dessus sont vidées. Le serveur ne peut plus relire
    # ces données sans le code : l'admin ne voit que les métadonnées.
    sealed_bundle = db.deferred(db.Column(db.LargeBinary, nullable=True))
    sealed_pdf    = db.deferred(db.Column(db.LargeBinary, nullable=True))
    sealed_at     = db.Column(db.DateTime, nullable=True)
    # Sel HKDF propre au dossier (hex) — pas un secret
    access_salt       = db.Column(db.String(32), nullable=True)
    # HMAC-SHA256(RESULTS_ACCESS_SECRET, code) — sert uniquement à retrouver
    # le dossier, ne permet pas de déchiffrer
    access_token_hash = db.Column(db.String(64), nullable=True, unique=True, index=True)
    access_expires_at = db.Column(db.DateTime, nullable=True)
    access_revoked_at = db.Column(db.DateTime, nullable=True)
    access_count      = db.Column(db.Integer, nullable=False, default=0)
    last_access_at    = db.Column(db.DateTime, nullable=True)
    # Purge RGPD (utils/retention.py) : contenu chiffré effacé et identité
    # anonymisée quelques jours après expiration/révocation du code
    results_purged_at = db.Column(db.DateTime, nullable=True)

    # --- Score de sécurité dénormalisé ---
    # Copie de analysis_result['security_score'] / ['security_grade'].
    #
    # Pourquoi dupliquer : ces deux valeurs sont affichées dans la liste du
    # dashboard et moyennées par GET /recon/stats. Les lire depuis le JSON
    # imposait de rapatrier puis de parser l'intégralité du rapport IA (souvent
    # plusieurs dizaines de Ko) pour deux champs — par ligne de la liste, et
    # pour toute la table dans le calcul de moyenne.
    #
    # Alimenté par set_analysis_result(), seul point d'écriture de l'analyse,
    # ce qui garantit que la copie ne diverge pas de la source.
    security_score = db.Column(db.Integer, nullable=True, index=True)
    security_grade = db.Column(db.String(2), nullable=True)

    # --- Tokens IA consommés (mesure de coût/usage, 2026-07-30) ---
    # Même principe que security_score ci-dessus : le rapport JSON complet
    # contient déjà `tokens_used` (voir routes/analyze.py::_run_backend et
    # utils/*_client.py — chaque client cumule prompt/completion/total sur
    # tout l'échange, y compris le Map-Reduce Ollama), mais dénormalisé ici
    # pour que le dashboard et GET /recon/stats n'aient pas à reparser
    # analysis_result (gros blob db.deferred) juste pour afficher un total.
    tokens_prompt     = db.Column(db.Integer, nullable=True)
    tokens_completion = db.Column(db.Integer, nullable=True)
    tokens_total      = db.Column(db.Integer, nullable=True)

    # --- Métriques de conformité dénormalisées (dashboard recherche) ---
    # Même principe que security_score ci-dessus : calculées une seule fois
    # (set_compliance_metrics() / set_tools_status_summary()) pour que
    # GET /recon/stats les agrège sans reparser scan_results/analysis_result.
    #
    # Traçabilité outil→finding : combien de findings IA référencent un
    # `source_tool` réellement présent dans tools_executed (le prompt
    # d'analyse l'impose, ceci vérifie que c'est respecté en pratique).
    findings_total_count     = db.Column(db.Integer, nullable=True)
    findings_traceable_count = db.Column(db.Integer, nullable=True)
    # Couverture MITRE ATT&CK : nombre de techniques distinctes détectées
    # (mitre_technique_ids = JSON liste des technique_id, pour l'agrégation
    # fleet-wide côté stats.py sans reparser analysis_result).
    mitre_technique_count = db.Column(db.Integer, nullable=True)
    mitre_technique_ids   = db.deferred(db.Column(db.Text, nullable=True))
    # Fiabilité des outils OSINT : {"success": 40, "error": 2, ...} — compte
    # par statut sur les 47 outils de ce scan (pas le blob scan_results complet).
    tools_status_summary = db.deferred(db.Column(db.Text, nullable=True))

    # --- Suivi d'exécution ---
    # Valeurs autorisées : pending | running | success | failed
    status = db.Column(db.String(20), nullable=False, default='pending')
    # Étape courante du pipeline pendant que status='running' (et conservée
    # telle quelle si status bascule à 'failed', pour savoir où ça a échoué) :
    # scanning_osint | analyzing_ai | generating_final_report | generating_pdf
    # | completed. Alimentée à chaque changement d'étape par les endpoints
    # concernés (pass_recon, analyze*, generate_final_report, generate_report)
    # — affichée en temps réel dans le dashboard (rafraîchi toutes les 30s)
    # plutôt que de laisser un simple "running" opaque sans indication de
    # progression pendant potentiellement plusieurs dizaines de minutes
    # (cascade IA + fallback Ollama).
    current_step = db.Column(db.String(30), nullable=True)
    current_step_updated_at = db.Column(db.DateTime, nullable=True)
    # Durée totale de l'exécution en secondes
    execution_time = db.Column(db.Float, nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # --- Horodatage ---
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Mis à jour automatiquement à chaque modification de l'enregistrement
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # ------------------------------------------------------------------
    # Sérialisation
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Métriques dérivées
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_security(analysis) -> tuple:
        """Extrait (score, grade) d'un rapport d'analyse, sans lever."""
        if not isinstance(analysis, dict):
            return None, None
        score = analysis.get('security_score')
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            score = None
        else:
            score = int(score)
        grade = analysis.get('security_grade')
        if not isinstance(grade, str):
            grade = None
        return score, grade

    @staticmethod
    def _extract_tokens(analysis) -> tuple:
        """Extrait (prompt, completion, total) de `analysis['tokens_used']`, sans lever."""
        if not isinstance(analysis, dict):
            return None, None, None
        tokens = analysis.get('tokens_used')
        if not isinstance(tokens, dict):
            return None, None, None

        def _int_or_none(v):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                return None
            return int(v)

        return (
            _int_or_none(tokens.get('prompt_tokens')),
            _int_or_none(tokens.get('completion_tokens')),
            _int_or_none(tokens.get('total_tokens')),
        )

    def set_step(self, step: str) -> None:
        """
        Positionne l'étape courante du pipeline (voir commentaire de la colonne
        `current_step`) et son horodatage — n'écrase jamais `status`, appelé en
        complément par chaque endpoint qui fait progresser le pipeline.
        """
        self.current_step = step
        self.current_step_updated_at = datetime.utcnow()

    def set_analysis_result(self, analysis, generated_at=None, expires_at=None) -> None:
        """
        Point d'écriture UNIQUE de l'analyse IA.

        Sérialise le rapport et met à jour les colonnes dénormalisées dans la
        même opération : passer par ici garantit que security_score/grade ne
        peuvent pas diverger du contenu de analysis_result.

        Accepte un dict (sérialisé ici) ou une chaîne JSON déjà sérialisée.
        """
        if isinstance(analysis, str):
            self.analysis_result = analysis
            try:
                parsed = json.loads(analysis)
            except Exception:
                parsed = None
        else:
            self.analysis_result = (
                json.dumps(analysis, ensure_ascii=False) if analysis is not None else None
            )
            parsed = analysis

        self.security_score, self.security_grade = self._extract_security(parsed)
        self.tokens_prompt, self.tokens_completion, self.tokens_total = self._extract_tokens(parsed)

        if generated_at is not None:
            self.analysis_generated_at = generated_at
        if expires_at is not None:
            self.analysis_expires_at = expires_at

    def set_compliance_metrics(self, findings, tools_executed, mitre_attack) -> None:
        """
        Calcule et dénormalise les métriques de conformité au moment où le
        rapport IA est produit (mêmes entrées que le prompt d'analyse) —
        à appeler juste après set_analysis_result(), avec les mêmes
        `findings`/`tools_executed`/`mitre_attack` que ceux du rapport.

        findings       : liste des findings du rapport (avec `source_tool`)
        tools_executed : liste de tools_executed (dicts avec clé 'tool' ou
                         chaînes) — sert à vérifier que `source_tool` désigne
                         un outil réellement exécuté, pas juste une chaîne
                         non vide.
        mitre_attack   : liste produite par utils.mitre_attack.map_tools_to_techniques
        """
        findings = findings if isinstance(findings, list) else []
        executed_keys = set()
        for t in (tools_executed or []):
            if isinstance(t, dict):
                key = t.get('tool') or t.get('source_tool') or t.get('key')
            else:
                key = t
            if key:
                executed_keys.add(key)

        self.findings_total_count = len(findings)
        self.findings_traceable_count = sum(
            1 for f in findings
            if isinstance(f, dict) and f.get('source_tool') in executed_keys
        )

        technique_ids = sorted({
            m.get('technique_id') for m in (mitre_attack or [])
            if isinstance(m, dict) and m.get('technique_id')
        })
        self.mitre_technique_count = len(technique_ids)
        self.mitre_technique_ids = json.dumps(technique_ids, ensure_ascii=False)

    def set_tools_status_summary(self, scan_results: dict, all_tools: set) -> None:
        """
        Dénormalise la répartition des statuts des 47 outils OSINT d'un scan
        (success/error/timeout/skipped/...) — à appeler juste après avoir
        construit `result` dans POST /pass_recon, avant persistance.

        Ne stocke qu'un résumé de quelques octets, jamais le blob scan_results
        complet : c'est ce résumé que /recon/stats agrège pour la fiabilité
        globale des outils, sans jamais recharger scan_results.
        """
        from collections import Counter
        counts = Counter()
        for key, value in (scan_results or {}).items():
            if key not in all_tools or not isinstance(value, dict):
                continue
            counts[value.get('status', 'unknown')] += 1
        self.tools_status_summary = json.dumps(dict(counts), ensure_ascii=False)

    def security_summary(self) -> dict:
        """
        Retourne {security_score, security_grade}.

        Lit les colonnes dénormalisées — aucun parsing JSON, et surtout aucun
        rapatriement du blob `analysis_result` : c'est ce qui permet à
        GET /recon d'inclure le score sans charger les rapports complets.

        Repli sur le parsing du JSON uniquement pour les enregistrements
        antérieurs à la migration dont les colonnes sont encore vides.
        """
        if self.security_score is not None or self.security_grade is not None:
            return {
                'security_score': self.security_score,
                'security_grade': self.security_grade,
            }

        if not self.analysis_result:
            return {'security_score': None, 'security_grade': None}
        try:
            data = json.loads(self.analysis_result)
        except Exception:
            return {'security_score': None, 'security_grade': None}
        score, grade = self._extract_security(data)
        return {'security_score': score, 'security_grade': grade}

    def scan_duration_s(self):
        """
        Durée réelle et **figée** du scan OSINT, en secondes.

        Calculée depuis les horodatages persistés (started_at → completed_at),
        avec repli sur execution_time. Ne dépend jamais de l'heure courante :
        une valeur affichée ne doit pas grandir à chaque rafraîchissement.
        """
        if self.started_at and self.completed_at:
            return max(0.0, (self.completed_at - self.started_at).total_seconds())
        return self.execution_time

    def flow_duration_s(self):
        """
        Durée totale et **figée** du flux (validation email → fin du workflow).

        C'est `fin - début`, jamais `maintenant - début` : tant que le flux
        n'est pas terminé (end_report_date absent) la valeur reste None plutôt
        que de croître indéfiniment.
        """
        if self.start_report_date and self.end_report_date:
            return max(0.0, (self.end_report_date - self.start_report_date).total_seconds())
        return None

    def access_state(self, now=None) -> str:
        """
        État du code d'accès : `none` (jamais émis), `revoked`, `expired` ou
        `active`. La révocation prime sur l'expiration.
        """
        if not self.access_token_hash:
            return 'none'
        if self.access_revoked_at is not None:
            return 'revoked'
        if self.access_expires_at is None or self.access_expires_at <= (now or _dt.utcnow()):
            return 'expired'
        return 'active'

    def to_dict(self) -> dict:
        """
        Représentation publique — sans données sensibles (scan_results, final_report).

        Utilisée par :  GET /recon, GET /recon/<id>, POST /recon, PUT /recon/<id>

        Tous les horodatages sont en ISO-8601 UTC suffixés `Z`.
        """
        sec = self.security_summary()
        return {
            'id':               self.id,
            # has_pdf / has_analysis sont des column_property évaluées en SQL :
            # aucun blob n'est rapatrié pour construire cette réponse.
            'has_pdf':              bool(self.has_pdf),
            'pdf_generated_at':     utc_iso(self.pdf_generated_at),
            'has_analysis':         bool(self.has_analysis),
            'analysis_cache_valid': (
                self.analysis_expires_at is not None and
                self.analysis_expires_at > _dt.utcnow()
            ),
            'analysis_expires_at':  utc_iso(self.analysis_expires_at),
            'domain': self.domain,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'email': self.email,
            'accord': self.accord,
            'verification': self.verification,
            'requested_info': self.requested_info,
            'status': self.status,
            'current_step': self.current_step,
            'current_step_updated_at': utc_iso(self.current_step_updated_at),
            'execution_time': self.execution_time,
            # Durées figées — calculées depuis les horodatages persistés
            'scan_duration_s': self.scan_duration_s(),
            'flow_duration_s': self.flow_duration_s(),
            # Score de sécurité inclus ici pour éviter un appel par ligne côté client
            'security_score': sec['security_score'],
            'security_grade': sec['security_grade'],
            'tokens_prompt': self.tokens_prompt,
            'tokens_completion': self.tokens_completion,
            'tokens_total': self.tokens_total,
            # Coffre : jamais le code, ni son empreinte, ni le sel
            'results_sealed': self.sealed_at is not None,
            'sealed_at': utc_iso(self.sealed_at),
            'access_state': self.access_state(),
            'access_expires_at': utc_iso(self.access_expires_at),
            'access_count': self.access_count or 0,
            'last_access_at': utc_iso(self.last_access_at),
            'results_purged_at': utc_iso(self.results_purged_at),
            'started_at': utc_iso(self.started_at),
            'completed_at': utc_iso(self.completed_at),
            'start_report_date': utc_iso(self.start_report_date),
            'end_report_date': utc_iso(self.end_report_date),
            'created_at': utc_iso(self.created_at),
            'updated_at': utc_iso(self.updated_at),
        }

    def to_dict_full(self) -> dict:
        """
        Représentation complète avec données sensibles.

        Réservée à : GET /recon/<id>/report (accès restreint, authentification requise).
        scan_results est désérialisé depuis JSON en dict Python.

        Pour un dossier scellé, les trois champs valent None : leur contenu
        n'existe plus qu'en chiffré (voir `results_sealed`).
        """
        d = self.to_dict()
        d['scan_results']            = json.loads(self.scan_results) if self.scan_results else None
        d['final_report']            = self.final_report
        d['analysis_result']         = json.loads(self.analysis_result) if self.analysis_result else None
        d['analysis_generated_at']   = utc_iso(self.analysis_generated_at)
        d['analysis_expires_at']     = utc_iso(self.analysis_expires_at)
        d['analysis_cache_valid']    = (
            self.analysis_expires_at is not None and
            self.analysis_expires_at > _dt.utcnow()
        )
        return d

    def __repr__(self) -> str:
        return f"<Recon id={self.id} domain={self.domain!r} status={self.status!r}>"
