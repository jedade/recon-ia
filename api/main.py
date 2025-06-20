from flask import Flask, jsonify, request
import whois
from datetime import datetime

app = Flask(__name__)

def custom_whois(domain):
    try:
        w = whois.whois(domain)
        
        # Formatage des dates
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        
        # Structuration des données
        result = {
            "domain": domain,
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else None,
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
            "last_updated": updated_date.strftime("%Y-%m-%d") if updated_date else None,
            "registrar": w.registrar,
            "registrant_name": w.name if hasattr(w, 'name') else None,
            "registrant_organization": w.org if hasattr(w, 'org') else None,
            "registrant_country": w.country if hasattr(w, 'country') else None,
            "name_servers": list(set(w.name_servers)) if w.name_servers else [],
            "status": w.status if w.status else None,
            "emails": w.emails if hasattr(w, 'emails') else []
        }
        
        # Nettoyage des emails
        if result['emails']:
            result['emails'] = list(set(
                email.lower().strip() 
                for email in result['emails'] 
                if '@' in email
            ))
        
        return result
        
    except Exception as e:
        return {"error": str(e)}

@app.route('/whois', methods=['GET'])
def get_whois():
    """
    Endpoint de recherche WHOIS
    Retourne les informations d'enregistrement d'un domaine
    """
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Paramètre 'domain' manquant"}), 400
    
    result = custom_whois(domain)
    if "error" in result:
        return jsonify(result), 500
        
    return jsonify(result)

@app.route('/docs', methods=['GET'])
def api_docs():
    """Endpoint pour la documentation complète de l'API"""
    return jsonify({
        "api_name": "API WHOIS Domain Lookup",
        "version": "1.0",
        "endpoints": {
            "GET /whois": {
                "description": "Récupère les informations WHOIS d'un domaine",
                "parameters": {
                    "domain": {
                        "type": "string",
                        "required": True,
                        "description": "Nom de domaine à rechercher (ex: example.com)"
                    }
                },
                "exemple": "/whois?domain=google.com"
            },
            "GET /docs": {
                "description": "Documentation de l'API (cet endpoint)"
            }
        },
        "exemple_requete": "curl http://localhost:5000/whois?domain=google.com",
        "exemple_reponse": {
            "domain": "google.com",
            "creation_date": "1997-09-15",
            "expiration_date": "2028-09-14",
            "last_updated": "2019-09-09",
            "registrar": "MarkMonitor Inc.",
            "registrant_name": None,
            "registrant_organization": "Google LLC",
            "registrant_country": "US",
            "name_servers": ["ns1.google.com", "ns2.google.com"],
            "status": "clientDeleteProhibited",
            "emails": ["abusecomplaints@markmonitor.com"]
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
