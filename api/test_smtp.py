"""
Script de diagnostic SMTP — à lancer depuis le conteneur API.
Usage : python test_smtp.py <email_destinataire>
"""
import sys
import os
import smtplib

# Charger le .env
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'), override=True)
    print("[OK] .env chargé")
except Exception as e:
    print(f"[WARN] dotenv non disponible : {e}")

HOST     = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
PORT     = int(os.getenv('SMTP_PORT', 587))
USER     = os.getenv('SMTP_USERNAME', '')
PASSWORD = os.getenv('SMTP_PASSWORD', '')
TO       = sys.argv[1] if len(sys.argv) > 1 else USER

print(f"\n--- Config SMTP ---")
print(f"  HOST     : {HOST}")
print(f"  PORT     : {PORT}")
print(f"  USER     : {USER}")
print(f"  PASSWORD : {'*' * len(PASSWORD.strip())} ({len(PASSWORD.strip())} chars)")
print(f"  TO       : {TO}\n")

if not USER or not PASSWORD:
    print("[ERREUR] SMTP_USERNAME ou SMTP_PASSWORD manquant dans le .env")
    sys.exit(1)

password_clean = PASSWORD.strip()

try:
    print(f"[1/4] Connexion à {HOST}:{PORT} ...")
    with smtplib.SMTP(HOST, PORT, timeout=10) as server:
        print("[2/4] STARTTLS ...")
        server.starttls()
        print(f"[3/4] Login avec {USER} ...")
        server.login(USER, password_clean)
        print(f"[4/4] Envoi à {TO} ...")
        msg = f"Subject: Test SMTP Recon IA\nFrom: {USER}\nTo: {TO}\n\nTest de connexion SMTP OK."
        server.sendmail(USER, TO, msg)
    print("\n[SUCCES] Email envoyé !")
except smtplib.SMTPAuthenticationError as e:
    print(f"\n[ERREUR AUTH] Identifiants refusés par Gmail : {e}")
    print("  → Vérifiez que le App Password est correct et que la 2FA est activée.")
    print("  → Regénérez un App Password sur : myaccount.google.com/apppasswords")
except smtplib.SMTPConnectError as e:
    print(f"\n[ERREUR CONNEXION] Impossible de joindre {HOST}:{PORT} : {e}")
    print("  → Le réseau du conteneur bloque peut-être le port 587.")
except Exception as e:
    print(f"\n[ERREUR] {type(e).__name__}: {e}")
