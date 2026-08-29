# routes/dns_info.py
from flask import Blueprint, request, jsonify
import subprocess
import json
import re
import os
import uuid
import logging
from flasgger import swag_from
from utils.auth import require_auth
from utils.validators import is_valid_domain

logger = logging.getLogger(__name__)

dns_info_bp = Blueprint('dns_info', __name__)

@dns_info_bp.route('/dns_info', methods=['POST'])
@require_auth
def dns_info():
    """
    Collecte d'informations DNS et IP pour un domaine
    ---
    tags:
      - DNS/IP Information
    security:
      - BasicAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - domain
          properties:
            domain:
              type: string
              example: "example.com"
              description: Domaine cible pour la collecte d'informations DNS/IP
    responses:
      200:
        description: Informations DNS/IP complètes
        schema:
          type: object
          properties:
            domain:
              type: string
              description: Domaine analysé
            host:
              type: object
              description: Résultats de la commande host
            nslookup:
              type: object
              description: Résultats de la commande nslookup
            dnsrecon:
              type: object
              description: Résultats de dnsrecon
            dig_standard:
              type: object
              description: Résultats de dig standard
            dig_any:
              type: object
              description: Résultats de dig ANY
        examples:
          application/json: {
            "domain": "example.com",
            "host": {"ip": "93.184.216.34", "cname": "example.com"},
            "nslookup": {"server": "8.8.8.8", "address": "93.184.216.34"},
            "dnsrecon": {"records": [{"type": "A", "value": "93.184.216.34"}]},
            "dig_standard": {"answer": ["example.com. 300 IN A 93.184.216.34"]},
            "dig_any": {"answer": ["example.com. 300 IN A 93.184.216.34", "example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946"]}
          }
      400:
        description: Domaine manquant ou invalide
      401:
        description: Authentification requise (HTTP Basic Auth)
      500:
        description: Erreur lors de l'exécution des outils DNS
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Données JSON requises"}), 400
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Le champ 'domain' est requis"}), 400
    clean_domain = re.sub(r'^https?://|www\.', '', domain).strip('/')
    if not is_valid_domain(clean_domain):
        return jsonify({"error": "Format de domaine invalide"}), 400
    results = {
        "domain": clean_domain,
        "host": {},
        "nslookup": {},
        "dnsrecon": {},
        "dig_standard": {},
        "dig_any": {}
    }

    # 1. host utility
    try:
        host_output = subprocess.check_output(["host", clean_domain], stderr=subprocess.STDOUT, timeout=30, text=True)
        ip_match = re.search(r'has address (\d+\.\d+\.\d+\.\d+)', host_output)
        cname_match = re.search(r'is an alias for (.+)', host_output)
        results["host"] = {
            "raw": host_output,
            "ip": ip_match.group(1) if ip_match else None,
            "cname": cname_match.group(1) if cname_match else None
        }
    except subprocess.CalledProcessError as e:
        results["host"] = {"error": e.output, "raw": e.output}
    except Exception as e:
        results["host"] = {"error": str(e)}

    # 2. nslookup
    try:
        nslookup_output = subprocess.check_output(["nslookup", clean_domain], stderr=subprocess.STDOUT, timeout=30, text=True)
        server_match = re.search(r'Server:\s+([^\s]+)', nslookup_output)
        address_match = re.search(r'Address:\s+([^\s]+)', nslookup_output)
        name_match = re.search(r'Name:\s+([^\s]+)', nslookup_output)
        ip_match = re.search(r'Address:\s+([^\s]+)$', nslookup_output, re.MULTILINE)
        results["nslookup"] = {
            "raw": nslookup_output,
            "server": server_match.group(1) if server_match else None,
            "address": address_match.group(1) if address_match else None,
            "name": name_match.group(1) if name_match else None,
            "ip": ip_match.group(1) if ip_match else None
        }
    except subprocess.CalledProcessError as e:
        results["nslookup"] = {"error": e.output, "raw": e.output}
    except Exception as e:
        results["nslookup"] = {"error": str(e)}

    # 3. dnsrecon
    try:
        temp_file = f"/tmp/dnsrecon_{uuid.uuid4()}.json"
        subprocess.run(["dnsrecon", "-d", clean_domain, "-j", temp_file], check=True, timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if os.path.exists(temp_file):
            with open(temp_file, "r") as f:
                dnsrecon_data = json.load(f)
            os.remove(temp_file)
            results["dnsrecon"] = {"raw": dnsrecon_data, "records": dnsrecon_data}
        else:
            results["dnsrecon"] = {"error": "Fichier de résultat non généré"}
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else "Erreur dnsrecon"
        results["dnsrecon"] = {"error": error_msg}
    except Exception as e:
        results["dnsrecon"] = {"error": str(e)}

    # 4. dig standard
    try:
        dig_output = subprocess.check_output(["dig", clean_domain], stderr=subprocess.STDOUT, timeout=30, text=True)
        answer_section = []
        in_answer = False
        for line in dig_output.split('\n'):
            if "ANSWER SECTION:" in line:
                in_answer = True
                continue
            if in_answer and line.strip() == "":
                break
            if in_answer and line.strip():
                answer_section.append(line.strip())
        results["dig_standard"] = {"raw": dig_output, "answer": answer_section}
    except subprocess.CalledProcessError as e:
        results["dig_standard"] = {"error": e.output, "raw": e.output}
    except Exception as e:
        results["dig_standard"] = {"error": str(e)}

    # 5. dig ANY
    try:
        dig_any_output = subprocess.check_output(["dig", clean_domain, "ANY"], stderr=subprocess.STDOUT, timeout=30, text=True)
        answer_section = []
        in_answer = False
        for line in dig_any_output.split('\n'):
            if "ANSWER SECTION:" in line:
                in_answer = True
                continue
            if in_answer and line.strip() == "":
                break
            if in_answer and line.strip():
                answer_section.append(line.strip())
        results["dig_any"] = {"raw": dig_any_output, "answer": answer_section}
    except subprocess.CalledProcessError as e:
        results["dig_any"] = {"error": e.output, "raw": e.output}
    except Exception as e:
        results["dig_any"] = {"error": str(e)}

    return jsonify(results), 200