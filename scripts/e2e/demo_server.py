# scripts/e2e/demo_server.py — API réelle (code de api/, monté en /app) avec
# un dossier SCELLÉ réaliste, pour vérifier web/result.html dans un vrai
# navigateur (scripts/e2e/run-result-page.sh). Base SQLite jetable, aucun
# appel réseau. Écrit le code d'accès dans /demo/code.txt.
#
# Les données contiennent volontairement du HTML piégé (titre et preuve d'un
# constat) : la page doit l'afficher comme du texte, jamais l'exécuter.
import json
import os
import sys

sys.path.insert(0, '/app')

os.environ.update({
    'TESTING': '1',  # pas de watchdog
    'ADMIN_EMAIL': 'admin',
    'ADMIN_PASSWORD': 'pbkdf2:sha256:1$x$y',
    'DATABASE_URL': 'sqlite:////tmp/demo.db',
    'REDIS_URL': '',
    'FLASK_ENV': 'development',
    'TRUSTED_PROXY_COUNT': '0',
    'RESULTS_ACCESS_SECRET': 'demo-results-access-secret-0123456789abcdef',
})
if os.path.exists('/tmp/demo.db'):
    os.remove('/tmp/demo.db')

from app import create_app  # noqa: E402

app = create_app()

with app.app_context():
    from database import db
    from models.recon import Recon
    from routes.recon import TOOLS_REGISTRY
    from utils import result_vault
    from utils.mitre_attack import map_tools_to_techniques

    def tool(key, status, data, raw=''):
        return {'meta': TOOLS_REGISTRY[key], 'status': status, 'data': data, 'raw_output': raw}

    scan = {
        'whois': tool('whois', 'success', {'registrar': 'OVH SAS', 'creation_date': '2011-03-02',
                                           'expiration_date': '2027-03-02', 'name_servers': ['dns1.ovh.net', 'ns1.ovh.net']},
                      'Domain Name: EXAMPLE.BJ\nRegistrar: OVH SAS\n'),
        'dns_records': tool('dns_records', 'success', {'A': ['93.184.216.34'], 'MX': ['10 mx1.example.bj'],
                                                       'TXT': ['v=spf1 include:_spf.google.com ~all']}),
        'dnssec': tool('dnssec', 'success', {'enabled': False, 'has_dnskey': False, 'has_ds': False}),
        'ssl_info': tool('ssl_info', 'success', {'issuer': "Let's Encrypt R11", 'not_after': '2026-12-30',
                                                 'protocol': 'TLSv1.3', 'san': ['example.bj', 'www.example.bj']}),
        'security_headers': tool('security_headers', 'success', {'grade': 'D', 'headers': {
            'Strict-Transport-Security': {'present': True}, 'Content-Security-Policy': {'present': False},
            'X-Frame-Options': {'present': False}}}),
        'dmarc_check': tool('dmarc_check', 'success', {'record': None, 'policy': None, 'present': False}),
        'shodan_internetdb': tool('shodan_internetdb', 'success', {'ports': [22, 80, 443], 'vulns': ['CVE-2023-48795'],
                                                                   'cpes': ['cpe:/a:openbsd:openssh:8.9']}),
        'subdomain_takeover': tool('subdomain_takeover', 'success', {'vulnerable': [], 'vulnerable_count': 0, 'checked_count': 12}),
        'headers': tool('headers', 'success', {'admin.example.bj': {'status': 'success', 'http_status': 401},
                                               'evil.example.bj': {'status': 'blocked', 'error': 'adresse interne'}}),
        'abuseipdb_check': tool('abuseipdb_check', 'skipped', {}),
        'typosquatting': tool('typosquatting', 'timeout', {}),
        'cache': {'hit': False, 'scan_duration_s': 212.4},
    }
    executed = [{'key': k, 'status': v['status']} for k, v in scan.items() if 'meta' in v]
    analysis = {
        'security_score': 58, 'security_grade': 'D+', 'risk_level': 'HIGH',
        'executive_summary': "Le domaine expose plusieurs faiblesses de configuration : absence de DMARC, "
                             "DNSSEC désactivé et en-têtes de sécurité incomplets. Un service SSH avec une "
                             "vulnérabilité connue est visible publiquement.",
        'findings': [
            {'id': 'EMAIL-001', 'severity': 'HIGH', 'title': 'Aucune politique DMARC',
             'description': "Sans DMARC, un tiers peut envoyer des mails usurpant le domaine.",
             'evidence': 'dmarc present: False', 'source_tool': 'dmarc_check',
             'recommendation': 'Publier v=DMARC1; p=quarantine puis p=reject.',
             # Champs phase 3 (règle, confiance, horodatage, références structurées)
             'severity_rule': 'dmarc_missing', 'confidence': 'high', 'observed_at': '2026-10-19T10:42:00Z',
             'references': [{'collection': 'normes', 'source': 'RFC 7489'}],
             # ID ATT&CK inventés par le LLM : la table doit les écraser (phase 4)
             'attack_enabled': [{'id': 'T9999', 'name': '<b>faux</b>'}, {'id': 'javascript:alert(1)', 'name': 'x'}],
             'grounding': {'status': 'verified'}},
            {'id': 'LEAK-001', 'severity': 'HIGH', 'title': 'Adresses du domaine présentes dans 3 fuites de données',
             'description': 'contact@ et admin@ figurent dans des fuites publiques.', 'evidence': 'breach_count: 3',
             'source_tool': 'xposedornot_breaches', 'confidence': 'medium', 'observed_at': '2026-10-19T10:40:12Z',
             'recommendation': 'Réinitialiser les mots de passe et imposer le MFA.'},
            {'id': 'ARCH-001', 'severity': 'MEDIUM', 'title': 'Fichier .env archivé par la Wayback Machine',
             'description': 'Une URL /.env a été archivée.', 'evidence': 'https://example.bj/.env (2021)',
             'source_tool': 'archive_history', 'confidence': 'low',
             'recommendation': 'Changer les secrets du fichier et bloquer son accès web.'},
            {'id': 'NET-001', 'severity': 'CRITICAL', 'title': 'SSH vulnérable à Terrapin (CVE-2023-48795)',
             'description': 'OpenSSH 8.9 exposé sur le port 22.', 'evidence': 'ports 22, CVE-2023-48795',
             'source_tool': 'shodan_internetdb', 'source_tools': ['dns_records'],
             'recommendation': "Mettre à jour OpenSSH et restreindre l'accès au port 22.", 'references': ['CVE-2023-48795']},
            {'id': 'DNS-001', 'severity': 'MEDIUM', 'title': 'DNSSEC désactivé', 'description': 'La zone n\'est pas signée.',
             'evidence': 'enabled: False', 'source_tool': 'dnssec', 'recommendation': 'Activer DNSSEC chez le registrar.'},
            {'id': 'WEB-001', 'severity': 'LOW', 'title': '<script>alert("xss")</script> CSP absente',
             'description': 'Test d\'échappement : ce titre contient du HTML.', 'evidence': '<img src=x onerror=alert(1)>',
             'source_tool': 'security_headers', 'recommendation': 'Définir une Content-Security-Policy.'},
        ],
        'strengths': ['Certificat TLS valide en TLS 1.3 (ssl_info)', 'Aucun sous-domaine vulnérable au takeover (subdomain_takeover)'],
        'immediate_actions': [{'priority': 1, 'action': 'Mettre à jour OpenSSH'}, {'priority': 2, 'action': 'Publier une politique DMARC'}],
        'attack_surface': {'total_subdomains': 14, 'exposed_services': [{'host': 'example.bj', 'service_type': 'port 22'}],
                           'technologies': ['nginx', 'WordPress'], 'cloud_providers': []},
        'mitre_attack': map_tools_to_techniques(executed),
        'grounding_check': {'total_findings': 6, 'verified': 1, 'verified_pct': 25.0,
                            'method': 'Chevauchement textuel entre la preuve et la donnée brute.'},
        'coverage_check': {'coverage_pct': 71.4, 'tools_unreferenced': ['whois', 'ssl_info'],
                           'rag_snippets_used': 3, 'rag_snippets_available': 6},
    }
    recon = Recon(domain='example.bj', firstname='Ada', lastname='Lovelace', email='ada@example.bj',
                  accord=True, verification=True, status='success', current_step='completed',
                  scan_results=json.dumps(scan), analysis_result=json.dumps(analysis),
                  final_report=json.dumps({'executive_summary': analysis['executive_summary']}),
                  pdf_report=b'%PDF-1.4 demo')
    recon.set_analysis_result(analysis)
    db.session.add(recon)
    db.session.commit()
    code = result_vault.seal_recon(recon)
    db.session.commit()
    with open('/demo/code.txt', 'w') as fh:
        fh.write(code)

app.run(host='0.0.0.0', port=8080)
