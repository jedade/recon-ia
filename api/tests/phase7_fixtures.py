# tests/phase7_fixtures.py
"""Résultats bruts de scan simulés (format de routes/recon.py) pour la phase 7."""
import copy

DOMAIN = 'example.com'
IP1 = '93.184.216.34'
IP2 = '151.101.1.69'


def raw_scan(**overrides):
    """Scan complet plausible ; `overrides` remplace des clés d'outils entières."""
    raw = {
        'all_subdomains': {'data': ['www.example.com', 'api.example.com', 'mail.example.com'],
                           'count': 3},
        'crtsh': {'status': 'success', 'meta': {'tool': 'crt.sh'},
                  'data': {'subdomains': ['www.example.com', '*.dev.example.com', 'evil.other.org'],
                           'count': 3}},
        'dns_records': {'status': 'success', 'meta': {'tool': 'dnspython'},
                        'data': {'A': [IP1, '10.0.0.5'], 'AAAA': [], 'MX': ['10 mx.example.com.']}},
        'ip_info': {'status': 'success', 'meta': {'tool': 'ipinfo'},
                    'data': {'ips': [{'ip': IP1, 'country': 'US', 'org': 'AS15133 Edgecast Inc.',
                                      'city': 'Los Angeles', 'postal': '90001'}], 'count': 1}},
        'asn_info': {'status': 'success', 'meta': {'tool': 'ripestat'},
                     'data': {'ip_queried': IP1, 'asn': 'AS15133', 'asn_name': 'EDGECAST',
                              'prefix_count': 42}},
        'ssl_info': {'status': 'success', 'meta': {'tool': 'ssl'},
                     'data': {'subject': {'commonName': 'www.example.com',
                                          'organizationName': 'Example Corp'},
                              'issuer': {'organizationName': 'DigiCert Inc', 'commonName': 'DigiCert CA'},
                              'san': ['example.com', 'www.example.com', 'shop.example.com', 'other.net'],
                              'san_count': 4, 'not_before': 'Jan  1 00:00:00 2026 GMT',
                              'not_after': 'Dec 31 23:59:59 2026 GMT', 'days_until_expiry': 70,
                              'serial_number': '0ABC1234'}},
        'email_config': {'status': 'success', 'meta': {'tool': 'dns'},
                         'data': {'mx': ['10 mx.example.com.'], 'spf': 'v=spf1 include:_spf.example.com -all',
                                  'spf_status': 'found',
                                  'dmarc': 'v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com',
                                  'dmarc_status': 'found', 'dmarc_policy': 'none'}},
        'dmarc_check': {'status': 'success', 'meta': {'tool': 'dns'},
                        'data': {'present': True, 'policy': 'none',
                                 'record': 'v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com'}},
        'tech_stack': {'status': 'success', 'meta': {'tool': 'http'},
                       'data': {'server': 'nginx/1.18.0', 'powered_by': None, 'cms': ['WordPress'],
                                'javascript_frameworks': ['jQuery'], 'cdn': []}},
        'shodan_internetdb': {'status': 'success', 'meta': {'tool': 'internetdb'},
                              'data': {'ips': [{'ip': IP1, 'status': 'success', 'ports': [80, 443],
                                                'cpes': ['cpe:/a:nginx:nginx:1.18.0'],
                                                'vulns': ['CVE-2021-23017'],
                                                'hostnames': ['www.example.com', 'cdn.thirdparty.net']}],
                                       'ports': [80, 443], 'vulns': ['CVE-2021-23017'],
                                       'vulns_enriched': [{'id': 'CVE-2021-23017', 'cvss': 7.7,
                                                           'epss': 0.02, 'summary': 'x'}]}},
        # Outils à PII potentielle : ne doivent jamais alimenter le graphe
        'whois': {'status': 'success', 'meta': {'tool': 'whois'},
                  'data': {'registrant_name': 'Jean Dupont', 'registrant_email': 'jean.dupont@gmail.com'}},
        'xposedornot_breaches': {'status': 'success', 'meta': {'tool': 'xon'},
                                 'data': {'breaches': [{'email': 'victim@example.com'}]}},
        'cache': {'hit': False},
    }
    raw = copy.deepcopy(raw)
    raw.update(copy.deepcopy(overrides))
    return raw
