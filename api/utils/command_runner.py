import subprocess
from flask import jsonify
import logging

logger = logging.getLogger(__name__)


def run_command(cmd):
    """Exécute une commande système et retourne le résultat."""
    try:
        output = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            timeout=300,
            universal_newlines=True
        )
        return jsonify({
            "result": output,
            "status": "success"
        }), 200
    except subprocess.CalledProcessError as e:
        logger.error("Commande échouée (code %s): %s", e.returncode, " ".join(cmd))
        return jsonify({
            "error": e.output,
            "return_code": e.returncode,
            "status": "error"
        }), 500
    except subprocess.TimeoutExpired:
        logger.error("Timeout pour la commande: %s", " ".join(cmd))
        return jsonify({
            "error": "Commande timeout après 5 minutes",
            "status": "timeout"
        }), 500
    except FileNotFoundError:
        logger.error("Commande introuvable: %s", cmd[0] if cmd else "")
        return jsonify({
            "error": "Outil non trouvé",
            "status": "error"
        }), 500
