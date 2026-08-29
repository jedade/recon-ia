# utils/email_sender.py
import hmac
import html as _html
import smtplib
import secrets
import string
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

EMAIL_SENDER = os.getenv('SMTP_USERNAME')
EMAIL_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_HOST = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('SMTP_PORT', 587))


def generate_code() -> str:
    """Génère un code aléatoire à 6 chiffres (cryptographiquement sûr)."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def _build_html_email(code: str) -> str:
    """Construit le corps HTML de l'email de vérification."""
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vérification Recon IA</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">

  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f0f9ff;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">

          <!-- Header / Logo -->
          <tr>
            <td align="center" style="background:linear-gradient(135deg,#0f172a,#1e293b);border-radius:16px 16px 0 0;padding:32px 40px;">
              <table cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td valign="middle" style="padding-right:14px;">
                    <!-- Logo icon -->
                    <div style="width:52px;height:52px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:12px;display:inline-block;text-align:center;line-height:52px;">
                      <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMkwyIDdMMTIgMTJMMjIgN0wxMiAyWiIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PHBhdGggZD0iTTIgMTdIMjIiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PHBhdGggZD0iTTIgMTJMMTIgMTdMMjIgMTIiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PHBhdGggZD0iTTEyIDE3VjIyIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==" width="26" height="26" alt="Recon IA" style="margin-top:13px;display:block;">
                    </div>
                  </td>
                  <td valign="middle">
                    <span style="font-size:26px;font-weight:700;color:#f1f5f9;letter-spacing:-0.5px;">
                      Recon <span style="color:#818cf8;">IA</span>
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body card -->
          <tr>
            <td style="background:#ffffff;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;padding:48px 48px 40px;">

              <!-- Badge -->
              <p style="margin:0 0 28px;text-align:center;">
                <span style="display:inline-block;background:rgba(99,102,241,0.08);color:#6366f1;font-size:13px;font-weight:600;padding:6px 16px;border-radius:100px;border:1px solid rgba(99,102,241,0.2);letter-spacing:0.5px;">
                  VERIFICATION D'IDENTITE
                </span>
              </p>

              <h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#0f172a;text-align:center;line-height:1.3;">
                Confirmez votre adresse email
              </h1>
              <p style="margin:0 0 36px;font-size:15px;color:#64748b;text-align:center;line-height:1.6;">
                Utilisez le code ci-dessous pour finaliser votre demande de reconnaissance sur la plateforme Recon IA.
              </p>

              <!-- OTP Code block -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:36px;">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border:2px solid rgba(99,102,241,0.25);border-radius:16px;padding:28px 48px;text-align:center;">
                      <p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#94a3b8;letter-spacing:2px;text-transform:uppercase;">Votre code de vérification</p>
                      <p style="margin:0;font-size:42px;font-weight:800;color:#0f172a;letter-spacing:14px;font-family:'Courier New',monospace;">{code}</p>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Expiry notice -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:32px;">
                <tr>
                  <td style="background:#fef9ec;border:1px solid #fde68a;border-radius:10px;padding:14px 18px;">
                    <table cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="padding-right:10px;font-size:18px;color:#f59e0b;" valign="top">&#9201;</td>
                        <td style="font-size:13px;color:#92400e;line-height:1.5;">
                          Ce code est valable <strong>10 minutes</strong> uniquement. Passé ce délai, vous devrez soumettre une nouvelle demande.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Security notice -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;">
                    <table cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="padding-right:10px;font-size:18px;color:#64748b;" valign="top">&#128274;</td>
                        <td style="font-size:13px;color:#475569;line-height:1.5;">
                          Si vous n'avez pas initié cette demande, ignorez cet email. Ne partagez jamais ce code avec qui que ce soit.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Divider accent -->
          <tr>
            <td style="background:linear-gradient(90deg,#6366f1,#8b5cf6,#22d3ee);height:3px;"></td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:24px 40px;text-align:center;">
              <p style="margin:0 0 6px;font-size:13px;color:#94a3b8;line-height:1.5;">
                &copy; 2026 <strong style="color:#6366f1;">Recon IA</strong> &mdash; Plateforme de Reconnaissance Passive
              </p>
              <p style="margin:0;font-size:12px;color:#cbd5e1;">
                <span style="font-family:'Courier New',monospace;">idachallenge.bj</span> &mdash; Tous droits réservés
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>"""


def send_verification_email(email: str, code: str) -> bool:
    """Envoie un email de vérification via SMTP."""
    sender = os.getenv('SMTP_USERNAME') or EMAIL_SENDER
    password = os.getenv('SMTP_PASSWORD') or EMAIL_PASSWORD

    if not all([sender, password, EMAIL_HOST]):
        raise ValueError("Variables d'environnement SMTP manquantes : SMTP_USERNAME, SMTP_PASSWORD, SMTP_SERVER")

    msg = MIMEMultipart('alternative')
    msg['From'] = f"Recon IA <{sender}>"
    msg['To'] = email
    msg['Subject'] = "Votre code de vérification Recon IA"

    # Fallback texte brut
    text_body = f"""Recon IA — Vérification d'identité

Votre code de vérification est : {code}

Ce code expire dans 10 minutes.

Si vous n'avez pas initié cette demande, ignorez cet email.

© 2026 Recon IA — idachallenge.bj
"""
    msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
    msg.attach(MIMEText(_build_html_email(code), 'html', 'utf-8'))

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, email, msg.as_string())
        logger.info("Email de vérification envoyé à %s", email)
        return True
    except Exception as e:
        logger.error("Échec d'envoi d'email à %s : %s", email, str(e))
        raise Exception(f"Impossible d'envoyer l'email : {str(e)}")


def _fmt_s(sec) -> str:
    """Formate des secondes en chaîne lisible."""
    if not sec:
        return '—'
    sec = float(sec)
    if sec < 60:
        return f'{sec:.1f}s'
    m, s = divmod(int(sec), 60)
    if m < 60:
        return f'{m}min {s:02d}s'
    h, m = divmod(m, 60)
    return f'{h}h {m:02d}min {s:02d}s'


def send_report_email(
    to_email: str,
    firstname: str,
    lastname: str,
    domain: str,
    risk_level: str,
    risk_score: int,
    pdf_bytes: bytes,
    timing: dict,
    nb_findings: int = 0,
) -> bool:
    """
    Envoie le rapport PDF par email à l'utilisateur.

    Args:
        to_email    : adresse de destination
        firstname   : prénom du demandeur
        lastname    : nom du demandeur
        domain      : domaine analysé
        risk_level  : CRITICAL | HIGH | MEDIUM | LOW
        risk_score  : 0–100
        pdf_bytes   : contenu binaire du PDF
        timing      : {scan_duration_s, analysis_duration_s, total_duration_s}
        nb_findings : nombre de findings dans le rapport
    """

    # Échappement HTML des valeurs fournies par l'utilisateur.
    # firstname / lastname / domain proviennent de POST /recon, endpoint
    # ANONYME et sans validation de format sur les noms. Interpolées telles
    # quelles dans le corps HTML, elles permettaient d'injecter un lien de
    # phishing dans un email expédié depuis un domaine authentifié SPF/DKIM.
    firstname = _html.escape(str(firstname or ''))[:64]
    lastname  = _html.escape(str(lastname or ''))[:64]
    domain    = _html.escape(str(domain or ''))[:253]
    sender   = os.getenv('SMTP_USERNAME') or EMAIL_SENDER
    password = os.getenv('SMTP_PASSWORD') or EMAIL_PASSWORD

    if not all([sender, password, EMAIL_HOST]):
        raise ValueError(
            "Variables SMTP manquantes : SMTP_USERNAME, SMTP_PASSWORD, SMTP_SERVER"
        )

    # Couleurs par niveau de risque
    risk_colors = {
        'CRITICAL': ('#ef4444', '#fef2f2'),
        'HIGH':     ('#f97316', '#fff7ed'),
        'MEDIUM':   ('#f59e0b', '#fffbeb'),
        'LOW':      ('#10b981', '#f0fdf4'),
    }
    rl = str(risk_level).upper()
    risk_fg, risk_bg = risk_colors.get(rl, ('#64748b', '#f8fafc'))

    total_s    = _fmt_s(timing.get('total_duration_s'))
    scan_s     = _fmt_s(timing.get('scan_duration_s'))
    analysis_s = _fmt_s(timing.get('analysis_duration_s'))
    now_str    = datetime.utcnow().strftime('%d/%m/%Y à %H:%M UTC')
    filename   = f'rapport_osint_{domain}.pdf'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Rapport OSINT — {domain}</title>
</head>
<body style="margin:0;padding:0;background:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;padding:36px 0;">
  <tr><td align="center">
  <table width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;">

    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#0f172a,#1e293b);border-radius:16px 16px 0 0;padding:32px 40px;text-align:center;">
        <p style="margin:0 0 4px;font-size:26px;font-weight:700;color:#f1f5f9;letter-spacing:-0.5px;">
          Recon <span style="color:#00d4ff;">IA</span>
        </p>
        <p style="margin:0;font-size:12px;color:#64748b;letter-spacing:1px;text-transform:uppercase;">
          Rapport de Sécurité OSINT
        </p>
      </td>
    </tr>

    <!-- Bande couleur risque -->
    <tr>
      <td style="background:{risk_fg};height:4px;"></td>
    </tr>

    <!-- Corps -->
    <tr>
      <td style="background:#ffffff;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;padding:40px 44px 36px;">

        <p style="margin:0 0 24px;font-size:15px;color:#1e293b;line-height:1.6;">
          Bonjour <strong>{firstname} {lastname}</strong>,
        </p>
        <p style="margin:0 0 28px;font-size:14px;color:#475569;line-height:1.7;">
          Votre rapport de sécurité OSINT pour <strong style="color:#0f172a;">{domain}</strong>
          est prêt. Il est joint à cet email au format PDF.
        </p>

        <!-- Badge risque -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:32px;">
          <tr>
            <td align="center">
              <div style="display:inline-block;background:{risk_bg};border:2px solid {risk_fg};border-radius:12px;padding:20px 40px;text-align:center;">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:{risk_fg};letter-spacing:2px;text-transform:uppercase;">
                  Niveau de risque global
                </p>
                <p style="margin:0;font-size:36px;font-weight:800;color:{risk_fg};line-height:1.1;">
                  {risk_level}
                </p>
                <p style="margin:4px 0 0;font-size:16px;color:#475569;">
                  Score : <strong style="color:{risk_fg};">{risk_score}</strong> / 100
                </p>
              </div>
            </td>
          </tr>
        </table>

        <!-- Métriques -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;">
          <tr style="background:#f8fafc;">
            <td style="padding:10px 16px;border-bottom:1px solid #e2e8f0;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Domaine analysé</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;font-family:'Courier New',monospace;">{domain}</p>
            </td>
            <td style="padding:10px 16px;border-bottom:1px solid #e2e8f0;border-left:1px solid #e2e8f0;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Findings identifiés</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;">{nb_findings} finding(s)</p>
            </td>
          </tr>
          <tr style="background:#ffffff;">
            <td style="padding:10px 16px;border-bottom:1px solid #e2e8f0;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Durée totale du processus</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;">{total_s}</p>
            </td>
            <td style="padding:10px 16px;border-bottom:1px solid #e2e8f0;border-left:1px solid #e2e8f0;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Date du rapport</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;">{now_str}</p>
            </td>
          </tr>
          <tr style="background:#f8fafc;">
            <td style="padding:10px 16px;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Durée scan OSINT</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;">{scan_s}</p>
            </td>
            <td style="padding:10px 16px;border-left:1px solid #e2e8f0;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Durée analyse IA</p>
              <p style="margin:2px 0 0;font-size:14px;font-weight:700;color:#0f172a;">{analysis_s}</p>
            </td>
          </tr>
        </table>

        <!-- Note pièce jointe -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;">
          <tr>
            <td style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:14px 18px;">
              <table cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-right:10px;font-size:20px;" valign="top">📎</td>
                  <td style="font-size:13px;color:#1e40af;line-height:1.5;">
                    Le rapport PDF complet <strong>{filename}</strong> est joint à cet email.
                    Il contient l'analyse détaillée, les recommandations priorisées et la surface
                    d'attaque identifiée.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>

        <!-- Avertissement confidentialité -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;">
              <table cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-right:10px;font-size:18px;color:#64748b;" valign="top">🔒</td>
                  <td style="font-size:12px;color:#475569;line-height:1.5;">
                    Ce rapport est <strong>confidentiel</strong>. Il contient des informations
                    sensibles sur l'infrastructure de votre domaine. Ne le partagez qu'avec les
                    personnes autorisées.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>

      </td>
    </tr>

    <!-- Bande dégradée -->
    <tr>
      <td style="background:linear-gradient(90deg,#00d4ff,#7c3aed);height:3px;"></td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:22px 40px;text-align:center;">
        <p style="margin:0 0 4px;font-size:12px;color:#94a3b8;">
          &copy; 2026 <strong style="color:#6366f1;">Recon IA</strong> &mdash; Plateforme de Reconnaissance Passive OSINT
        </p>
        <p style="margin:0;font-size:11px;color:#cbd5e1;font-family:'Courier New',monospace;">
          idachallenge.bj
        </p>
      </td>
    </tr>

  </table>
  </td></tr>
</table>
</body>
</html>"""

    text = f"""Recon IA — Rapport de Sécurité OSINT

Bonjour {firstname} {lastname},

Votre rapport de sécurité OSINT pour {domain} est prêt.

═══════════════════════════════════════
RÉSULTATS
═══════════════════════════════════════
Domaine analysé   : {domain}
Niveau de risque  : {risk_level}
Score             : {risk_score} / 100
Findings          : {nb_findings}

═══════════════════════════════════════
DÉLAIS
═══════════════════════════════════════
Durée totale      : {total_s}
Scan OSINT        : {scan_s}
Analyse IA        : {analysis_s}
Date du rapport   : {now_str}

Le rapport PDF complet est joint à cet email ({filename}).

Ce document est confidentiel — usage interne uniquement.

© 2026 Recon IA — idachallenge.bj
"""

    msg = MIMEMultipart('mixed')
    msg['From']    = f'Recon IA <{sender}>'
    msg['To']      = to_email
    msg['Subject'] = f'[Recon IA] Rapport de sécurité OSINT — {domain} — Risque {risk_level}'

    # Corps HTML + texte
    alt = MIMEMultipart('alternative')
    alt.attach(MIMEText(text, 'plain', 'utf-8'))
    alt.attach(MIMEText(html, 'html', 'utf-8'))
    msg.attach(alt)

    # Pièce jointe PDF
    pdf_part = MIMEBase('application', 'pdf')
    pdf_part.set_payload(pdf_bytes)
    encoders.encode_base64(pdf_part)
    pdf_part.add_header(
        'Content-Disposition',
        f'attachment; filename="{filename}"',
    )
    msg.attach(pdf_part)

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, to_email, msg.as_string())
        logger.info("Rapport PDF envoyé à %s pour %s", to_email, domain)
        return True
    except Exception as e:
        logger.error("Échec envoi rapport à %s : %s", to_email, e)
        raise Exception(f"Impossible d'envoyer le rapport : {e}")


def validate_code(recon, code: str) -> tuple[bool, str]:
    """
    Valide le code OTP pour un enregistrement Recon.

    Comportement :
    - Expiré (> 10 min depuis la création)  → (False, "Code expiré"),    otp_code mis à None
    - Code incorrect                         → (False, "Code incorrect"), otp_code inchangé
    - Code correct                           → (True,  "Validé"),         otp_code mis à None

    Note : l'appelant doit appeler db.session.commit() après validation (succès ou expiry).
    """
    if not recon.otp_code:
        logger.warning("Tentative de validation OTP sur enregistrement sans code — id=%s", recon.id)
        return False, "Aucun code en attente de validation"

    _otp_ttl = int(os.environ.get('OTP_TTL_SECONDS', '600'))
    _ref_time = recon.otp_sent_at if getattr(recon, 'otp_sent_at', None) else recon.created_at
    if datetime.utcnow() > _ref_time + timedelta(seconds=_otp_ttl):
        logger.info("Code OTP expiré pour l'enregistrement id=%s", recon.id)
        recon.otp_code = None
        return False, "Code expiré"

    # hmac.compare_digest : comparaison en temps constant (résistante aux timing attacks)
    if hmac.compare_digest(recon.otp_code, code):
        logger.info("Code OTP validé avec succès pour l'enregistrement id=%s", recon.id)
        recon.otp_code = None
        return True, "Validé"

    logger.warning("Code OTP incorrect pour l'enregistrement id=%s", recon.id)
    return False, "Code incorrect"


# ── Constantes ────────────────────────────────────────────────────────────────
_ADMIN_EMAIL = os.environ.get('ADMIN_NOTIFICATION_EMAIL', 'onesime.adefoulou@gmail.com')

_ERROR_LABELS = {
    "analyze_failed":       ("Échec de l'analyse IA",           "L'analyse automatique de votre domaine n'a pas pu aboutir."),
    "final_report_failed":  ("Échec du rapport final",          "La synthèse narrative de votre rapport n'a pas pu être générée."),
    "pdf_failed":           ("Échec de la génération du PDF",   "La génération de votre rapport de sécurité a échoué."),
    "scan_failed":          ("Échec de la reconnaissance",      "La phase de reconnaissance passive a rencontré une erreur."),
    "workflow_failed":      ("Erreur dans le processus",        "Une étape du processus d'analyse a rencontré une erreur inattendue."),
}


def send_error_notification(
    to_email: str,
    firstname: str,
    lastname: str,
    domain: str,
    error_type: str = "workflow_failed",
    error_detail: str = "",
    recon_id: int = None,
) -> bool:
    """
    Envoie un email professionnel à l'utilisateur lorsqu'une étape critique échoue.

    Args:
        to_email     : adresse de destination
        firstname    : prénom
        lastname     : nom
        domain       : domaine concerné
        error_type   : clé dans _ERROR_LABELS (analyze_failed | pdf_failed | scan_failed | workflow_failed)
        error_detail : message d'erreur technique (affiché de façon sobre, sans stack trace)
        recon_id     : identifiant de la demande (optionnel, pour le support)
    """

    # Échappement HTML des valeurs fournies par l'utilisateur.
    # firstname / lastname / domain proviennent de POST /recon, endpoint
    # ANONYME et sans validation de format sur les noms. Interpolées telles
    # quelles dans le corps HTML, elles permettaient d'injecter un lien de
    # phishing dans un email expédié depuis un domaine authentifié SPF/DKIM.
    firstname = _html.escape(str(firstname or ''))[:64]
    lastname  = _html.escape(str(lastname or ''))[:64]
    domain    = _html.escape(str(domain or ''))[:253]
    sender   = os.getenv('SMTP_USERNAME') or EMAIL_SENDER
    password = os.getenv('SMTP_PASSWORD') or EMAIL_PASSWORD

    if not all([sender, password, EMAIL_HOST]):
        logger.warning("send_error_notification: SMTP non configuré — email non envoyé à %s", to_email)
        return False

    label, description = _ERROR_LABELS.get(error_type, _ERROR_LABELS["workflow_failed"])
    now_str   = datetime.utcnow().strftime('%d/%m/%Y à %H:%M UTC')
    ref_str   = f"REF-{recon_id}" if recon_id else "N/A"
    # Tronquer le détail technique pour ne pas exposer d'infos sensibles
    detail_safe = (error_detail[:200] + "…") if len(error_detail) > 200 else error_detail
    detail_safe = detail_safe.replace("<", "&lt;").replace(">", "&gt;")

    # Bloc détail technique — extrait avant la f-string pour éviter les backslashes
    # dans les expressions {…} (interdit avant Python 3.12)
    detail_block = (
        '<table width="100%" cellpadding="0" cellspacing="0" border="0"'
        ' style="margin-bottom:28px;"><tr><td style="background:#f8fafc;'
        'border:1px solid #e2e8f0;border-left:3px solid #ef4444;'
        'border-radius:6px;padding:12px 16px;font-size:12px;color:#64748b;'
        'font-family:Courier New,monospace;line-height:1.5;">'
        "D&eacute;tail\u00a0: " + detail_safe + "</td></tr></table>"
    ) if detail_safe else ""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recon IA — Notification d'erreur</title>
</head>
<body style="margin:0;padding:0;background:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;padding:36px 0;">
  <tr><td align="center">
  <table width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;">

    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#0f172a,#1e293b);border-radius:16px 16px 0 0;padding:32px 40px;text-align:center;">
        <p style="margin:0 0 4px;font-size:26px;font-weight:700;color:#f1f5f9;letter-spacing:-0.5px;">
          Recon <span style="color:#00d4ff;">IA</span>
        </p>
        <p style="margin:0;font-size:12px;color:#64748b;letter-spacing:1px;text-transform:uppercase;">
          Notification de processus
        </p>
      </td>
    </tr>

    <!-- Bande rouge erreur -->
    <tr>
      <td style="background:#ef4444;height:4px;"></td>
    </tr>

    <!-- Corps -->
    <tr>
      <td style="background:#ffffff;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;padding:40px 44px 36px;">

        <!-- Icône erreur -->
        <p style="margin:0 0 20px;text-align:center;">
          <span style="display:inline-block;width:56px;height:56px;background:#fef2f2;border:2px solid #fecaca;border-radius:50%;font-size:28px;line-height:56px;text-align:center;">⚠️</span>
        </p>

        <h1 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#0f172a;text-align:center;line-height:1.3;">
          {label}
        </h1>
        <p style="margin:0 0 28px;font-size:13px;color:#94a3b8;text-align:center;">
          {now_str} &mdash; Référence : <strong style="font-family:'Courier New',monospace;">{ref_str}</strong>
        </p>

        <p style="margin:0 0 20px;font-size:15px;color:#1e293b;line-height:1.6;">
          Bonjour <strong>{firstname} {lastname}</strong>,
        </p>
        <p style="margin:0 0 28px;font-size:14px;color:#475569;line-height:1.7;">
          {description}<br>
          Votre demande concernant le domaine
          <strong style="color:#0f172a;font-family:'Courier New',monospace;">{domain}</strong>
          n'a pas pu être traitée jusqu'à son terme.
        </p>

        <!-- Détail technique discret -->
        {detail_block}

        <!-- Actions -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
          <tr>
            <td style="background:#f8fafc;padding:16px 20px;border-bottom:1px solid #e2e8f0;">
              <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:0.5px;">
                &#9654; Option 1 — Relancer la demande
              </p>
              <p style="margin:0;font-size:13px;color:#475569;line-height:1.5;">
                Connectez-vous à la plateforme et soumettez à nouveau votre demande pour le domaine
                <strong style="font-family:'Courier New',monospace;">{domain}</strong>.
                La plupart des erreurs sont transitoires et se résolvent au prochain essai.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background:#ffffff;padding:16px 20px;">
              <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:0.5px;">
                &#9654; Option 2 — Contacter l'administrateur
              </p>
              <p style="margin:0 0 10px;font-size:13px;color:#475569;line-height:1.5;">
                Si le problème persiste après plusieurs tentatives, contactez l'administrateur
                en mentionnant la référence <strong style="font-family:'Courier New',monospace;">{ref_str}</strong>
                et le domaine concerné.
              </p>
              <a href="mailto:{_ADMIN_EMAIL}?subject=Recon%20IA%20%E2%80%94%20Erreur%20{ref_str}%20%E2%80%94%20{domain}"
                 style="display:inline-block;background:#0f172a;color:#00d4ff;text-decoration:none;
                        font-size:13px;font-weight:600;padding:10px 22px;border-radius:8px;letter-spacing:0.3px;">
                ✉ Écrire à l'administrateur
              </a>
              <p style="margin:8px 0 0;font-size:12px;color:#94a3b8;">
                {_ADMIN_EMAIL}
              </p>
            </td>
          </tr>
        </table>

        <!-- Note rassurante -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 18px;">
              <table cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-right:10px;font-size:18px;" valign="top">ℹ️</td>
                  <td style="font-size:13px;color:#14532d;line-height:1.5;">
                    <strong>Aucune donnée perdue.</strong> Vos informations sont conservées.
                    Il vous suffit de relancer la demande pour obtenir votre rapport.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>

      </td>
    </tr>

    <!-- Bande dégradée -->
    <tr>
      <td style="background:linear-gradient(90deg,#00d4ff,#7c3aed);height:3px;"></td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:22px 40px;text-align:center;">
        <p style="margin:0 0 4px;font-size:12px;color:#94a3b8;">
          &copy; 2026 <strong style="color:#6366f1;">Recon IA</strong> &mdash; Plateforme de Reconnaissance Passive OSINT
        </p>
        <p style="margin:0;font-size:11px;color:#cbd5e1;font-family:'Courier New',monospace;">
          idachallenge.bj &mdash; Support : {_ADMIN_EMAIL}
        </p>
      </td>
    </tr>

  </table>
  </td></tr>
</table>
</body>
</html>"""

    text = f"""Recon IA — Notification d'erreur

Bonjour {firstname} {lastname},

{description}

Votre demande pour le domaine {domain} n'a pas pu être traitée.

Référence : {ref_str}
Date       : {now_str}
{'Détail    : ' + detail_safe if detail_safe else ''}

═══════════════════════════════════════
QUE FAIRE ?
═══════════════════════════════════════

Option 1 — Relancer la demande
Connectez-vous à la plateforme et soumettez à nouveau votre demande
pour le domaine {domain}.

Option 2 — Contacter l'administrateur
Si le problème persiste, écrivez à : {_ADMIN_EMAIL}
En mentionnant la référence {ref_str} et le domaine {domain}.

Aucune donnée n'a été perdue. Il vous suffit de relancer la demande.

© 2026 Recon IA — idachallenge.bj
Support : {_ADMIN_EMAIL}
"""

    msg = MIMEMultipart('alternative')
    msg['From']    = f'Recon IA <{sender}>'
    msg['To']      = to_email
    msg['Subject'] = f'[Recon IA] Action requise — Erreur sur {domain} ({ref_str})'

    msg.attach(MIMEText(text, 'plain', 'utf-8'))
    msg.attach(MIMEText(html,  'html',  'utf-8'))

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, to_email, msg.as_string())
        logger.info("Email d'erreur envoyé à %s — domaine=%s type=%s ref=%s",
                    to_email, domain, error_type, ref_str)
        return True
    except Exception as e:
        logger.error("Échec envoi email d'erreur à %s : %s", to_email, e)
        return False
