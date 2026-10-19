# utils/email_sender.py
import hmac
import html as _html
import smtplib
import secrets
import string
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

EMAIL_SENDER = os.getenv('SMTP_USERNAME')
EMAIL_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_HOST = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('SMTP_PORT', 587))

# ── Charte ReconIA ───────────────────────────────────────────────────────────
# Le logo est intégré au message (image « inline » référencée par cid:) et
# non chargé depuis le site : il s'affiche sans téléchargement externe et ne
# sert pas de pixel de suivi d'ouverture. Ce n'est pas une pièce jointe
# (Content-Disposition: inline) — la décision D1 (aucun rapport joint) tient.
_BRAND_LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'static', 'brand', 'reconia-logo-email.png')
_BRAND_LOGO_CID = 'reconia-logo'
_BRAND_HEADER_HTML = (
    f'<img src="cid:{_BRAND_LOGO_CID}" width="180" alt="ReconIA — De la donnée à la décision" '
    'style="display:block;margin:0 auto;border:0;outline:none;width:180px;max-width:60%;height:auto;">'
)
_BRAND_BAR_HTML = '<td style="background:linear-gradient(90deg,#0A1F44,#0B5BD3,#00C8F0);height:4px;line-height:4px;font-size:0;">&nbsp;</td>'


def _brand_logo_bytes():
    try:
        with open(_BRAND_LOGO_PATH, 'rb') as fh:
            return fh.read()
    except OSError:
        return None


def _build_message(text: str, html: str) -> MIMEMultipart:
    """
    Message multipart aux couleurs de ReconIA : texte + HTML, et le logo en
    image inline si le fichier est présent (sinon le HTML affiche son texte
    alternatif). Les en-têtes From/To/Subject sont posés par l'appelant.
    """
    alternative = MIMEMultipart('alternative')
    alternative.attach(MIMEText(text, 'plain', 'utf-8'))
    alternative.attach(MIMEText(html, 'html', 'utf-8'))
    logo = _brand_logo_bytes()
    if logo is None:
        return alternative
    related = MIMEMultipart('related')
    related.attach(alternative)
    image = MIMEImage(logo, 'png')
    image.add_header('Content-ID', f'<{_BRAND_LOGO_CID}>')
    image.add_header('Content-Disposition', 'inline', filename='reconia-logo.png')
    related.attach(image)
    return related


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
  <title>Vérification ReconIA</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">

  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f0f9ff;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">

          <!-- En-tête : logo ReconIA (image inline cid:) -->
          <tr>
            <td align="center" style="background:#ffffff;border:1px solid #e2e8f0;border-bottom:none;border-radius:16px 16px 0 0;padding:28px 40px 22px;">
              {_BRAND_HEADER_HTML}
            </td>
          </tr>
          <tr>{_BRAND_BAR_HTML}</tr>

          <!-- Body card -->
          <tr>
            <td style="background:#ffffff;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;padding:48px 48px 40px;">

              <!-- Badge -->
              <p style="margin:0 0 28px;text-align:center;">
                <span style="display:inline-block;background:rgba(11,91,211,0.08);color:#0B5BD3;font-size:13px;font-weight:600;padding:6px 16px;border-radius:100px;border:1px solid rgba(11,91,211,0.2);letter-spacing:0.5px;">
                  VERIFICATION D'IDENTITE
                </span>
              </p>

              <h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#0A1F44;text-align:center;line-height:1.3;">
                Confirmez votre adresse email
              </h1>
              <p style="margin:0 0 36px;font-size:15px;color:#64748b;text-align:center;line-height:1.6;">
                Utilisez le code ci-dessous pour finaliser votre demande de reconnaissance sur la plateforme ReconIA.
              </p>

              <!-- OTP Code block -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:36px;">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border:2px solid rgba(11,91,211,0.25);border-radius:16px;padding:28px 48px;text-align:center;">
                      <p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#94a3b8;letter-spacing:2px;text-transform:uppercase;">Votre code de vérification</p>
                      <p style="margin:0;font-size:42px;font-weight:800;color:#0A1F44;letter-spacing:14px;font-family:'Courier New',monospace;">{code}</p>
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
            <td style="background:linear-gradient(90deg,#0B5BD3,#1677F2,#00C8F0);height:3px;"></td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:24px 40px;text-align:center;">
              <p style="margin:0 0 6px;font-size:13px;color:#94a3b8;line-height:1.5;">
                &copy; 2026 <strong style="color:#0B5BD3;">ReconIA</strong> &mdash; De la donnée à la décision
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

    # Fallback texte brut
    text_body = f"""ReconIA — Vérification d'identité

Votre code de vérification est : {code}

Ce code expire dans 10 minutes.

Si vous n'avez pas initié cette demande, ignorez cet email.

© 2026 ReconIA — idachallenge.bj
"""
    msg = _build_message(text_body, _build_html_email(code))
    msg['From'] = f"ReconIA <{sender}>"
    msg['To'] = email
    msg['Subject'] = "Votre code de vérification ReconIA"

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


_ALLOWED_RISK_LEVELS = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}


def send_results_ready_email(
    to_email: str,
    firstname: str,
    lastname: str,
    domain: str,
    access_code: str,
    expires_at: datetime,
    risk_level: str,
    risk_score,
    nb_findings: int = 0,
    results_url: str = '',
) -> bool:
    """
    Annonce que le rapport est prêt et transmet le CODE D'ACCÈS — sans aucune
    pièce jointe (décision D1 du plan d'action : un mail compromis ne doit
    pas livrer le rapport à lui seul ; le PDF n'est plus joint).

    Le code n'est jamais journalisé. Il est le seul moyen de déchiffrer les
    résultats (utils/result_vault.py) : le mail le dit explicitement.

    `risk_level` vient du LLM : il est restreint à une énumération connue
    avant d'entrer dans l'objet du mail (en-tête SMTP) et dans le corps.
    """
    firstname = _html.escape(str(firstname or ''))[:64]
    lastname  = _html.escape(str(lastname or ''))[:64]
    domain    = _html.escape(str(domain or ''))[:253]
    code      = _html.escape(str(access_code))
    rl = str(risk_level or '').upper()
    rl = rl if rl in _ALLOWED_RISK_LEVELS else 'N/A'
    try:
        score = int(risk_score)
    except (TypeError, ValueError):
        score = None
    score_txt = f'{score} / 100' if score is not None else 'N/A'
    expires_txt = expires_at.strftime('%d/%m/%Y à %H:%M UTC') if expires_at else '—'
    url = results_url if str(results_url).startswith('https://') or str(results_url).startswith('http://') else ''
    url_html = _html.escape(url, quote=True)

    sender   = os.getenv('SMTP_USERNAME') or EMAIL_SENDER
    password = os.getenv('SMTP_PASSWORD') or EMAIL_PASSWORD
    if not all([sender, password, EMAIL_HOST]):
        raise ValueError("Variables SMTP manquantes : SMTP_USERNAME, SMTP_PASSWORD, SMTP_SERVER")

    link_html = (
        f'<p style="margin:0 0 24px;text-align:center;">'
        f'<a href="{url_html}" style="display:inline-block;background:#0A1F44;color:#00C8F0;'
        f'font-weight:700;text-decoration:none;padding:12px 28px;border-radius:8px;">'
        f'Voir le résultat</a></p>'
    ) if url else ''
    link_text = f"Page de consultation : {url}\n" if url else ''

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Votre rapport ReconIA est prêt</title></head>
<body style="margin:0;padding:0;background:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;padding:36px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;">
  <tr><td style="background:#ffffff;border:1px solid #e2e8f0;border-bottom:none;border-radius:16px 16px 0 0;padding:28px 40px 18px;text-align:center;">
    {_BRAND_HEADER_HTML}
    <p style="margin:14px 0 0;font-size:12px;color:#4A5872;letter-spacing:1px;text-transform:uppercase;">Votre rapport est prêt</p>
  </td></tr>
  <tr>{_BRAND_BAR_HTML}</tr>
  <tr><td style="background:#ffffff;border:1px solid #e2e8f0;border-top:none;padding:36px 44px;">
    <p style="margin:0 0 20px;font-size:15px;color:#1e293b;">Bonjour <strong>{firstname} {lastname}</strong>,</p>
    <p style="margin:0 0 24px;font-size:14px;color:#475569;line-height:1.7;">
      L'analyse de reconnaissance passive de <strong style="color:#0A1F44;">{domain}</strong> est terminée.
      Pour des raisons de sécurité, le rapport n'est pas joint à ce message : il est chiffré
      et consultable uniquement avec le code ci-dessous.
    </p>
    <p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Votre code d'accès</p>
    <p style="margin:0 0 24px;padding:16px;background:#0A1F44;color:#00C8F0;border-radius:8px;
              font-family:'Courier New',monospace;font-size:15px;word-break:break-all;text-align:center;">{code}</p>
    {link_html}
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:24px;border:1px solid #e2e8f0;border-radius:10px;">
      <tr>
        <td style="padding:10px 16px;font-size:13px;color:#475569;">Niveau de risque : <strong>{rl}</strong></td>
        <td style="padding:10px 16px;font-size:13px;color:#475569;">Score : <strong>{score_txt}</strong></td>
        <td style="padding:10px 16px;font-size:13px;color:#475569;">Constats : <strong>{int(nb_findings or 0)}</strong></td>
      </tr>
    </table>
    <p style="margin:0 0 12px;font-size:13px;color:#475569;line-height:1.6;">
      ⏳ Ce code est valable jusqu'au <strong>{expires_txt}</strong>.
    </p>
    <p style="margin:0;font-size:12px;color:#b91c1c;line-height:1.6;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;">
      🔒 Conservez ce code et ne le partagez pas : toute personne qui le détient peut lire le rapport.
      Nous ne le conservons pas — s'il est perdu, le rapport ne pourra pas être récupéré et il faudra relancer une analyse.
    </p>
  </td></tr>
  <tr><td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:18px 40px;text-align:center;">
    <p style="margin:0;font-size:12px;color:#94a3b8;">&copy; 2026 <strong style="color:#0B5BD3;">ReconIA</strong> &mdash; De la donnée à la décision</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>"""

    text = f"""ReconIA — Votre rapport est prêt

Bonjour {firstname} {lastname},

L'analyse de reconnaissance passive de {domain} est terminée.
Le rapport n'est pas joint : il est chiffré et consultable uniquement avec ce code.

Votre code d'accès :
{access_code}

{link_text}Niveau de risque : {rl} — Score : {score_txt} — Constats : {int(nb_findings or 0)}
Code valable jusqu'au {expires_txt}.

Conservez ce code et ne le partagez pas : toute personne qui le détient peut lire le rapport.
Nous ne le conservons pas. S'il est perdu, le rapport ne pourra pas être récupéré.
"""

    msg = _build_message(text, html)
    msg['From']    = f'ReconIA <{sender}>'
    msg['To']      = to_email
    msg['Subject'] = f'[ReconIA] Votre rapport pour {domain} est prêt'


    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, to_email, msg.as_string())
        logger.info("Mail « rapport prêt » envoyé à %s pour %s", to_email, domain)
        return True
    except Exception as e:
        logger.error("Échec envoi mail « rapport prêt » à %s : %s", to_email, e)
        raise Exception(f"Impossible d'envoyer le mail de résultat : {e}")


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
  <title>ReconIA — Notification d'erreur</title>
</head>
<body style="margin:0;padding:0;background:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;padding:36px 0;">
  <tr><td align="center">
  <table width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;">

    <!-- Header -->
    <tr>
      <td style="background:#ffffff;border:1px solid #e2e8f0;border-bottom:none;border-radius:16px 16px 0 0;padding:28px 40px 18px;text-align:center;">
        {_BRAND_HEADER_HTML}
        <p style="margin:14px 0 0;font-size:12px;color:#4A5872;letter-spacing:1px;text-transform:uppercase;">
          Notification de processus
        </p>
      </td>
    </tr>
    <tr>{_BRAND_BAR_HTML}</tr>

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

        <h1 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#0A1F44;text-align:center;line-height:1.3;">
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
          <strong style="color:#0A1F44;font-family:'Courier New',monospace;">{domain}</strong>
          n'a pas pu être traitée jusqu'à son terme.
        </p>

        <!-- Détail technique discret -->
        {detail_block}

        <!-- Actions -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
          <tr>
            <td style="background:#f8fafc;padding:16px 20px;border-bottom:1px solid #e2e8f0;">
              <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#0A1F44;text-transform:uppercase;letter-spacing:0.5px;">
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
              <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#0A1F44;text-transform:uppercase;letter-spacing:0.5px;">
                &#9654; Option 2 — Contacter l'administrateur
              </p>
              <p style="margin:0 0 10px;font-size:13px;color:#475569;line-height:1.5;">
                Si le problème persiste après plusieurs tentatives, contactez l'administrateur
                en mentionnant la référence <strong style="font-family:'Courier New',monospace;">{ref_str}</strong>
                et le domaine concerné.
              </p>
              <a href="mailto:{_ADMIN_EMAIL}?subject=Recon%20IA%20%E2%80%94%20Erreur%20{ref_str}%20%E2%80%94%20{domain}"
                 style="display:inline-block;background:#0A1F44;color:#00C8F0;text-decoration:none;
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
      <td style="background:linear-gradient(90deg,#00C8F0,#0B5BD3);height:3px;"></td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:22px 40px;text-align:center;">
        <p style="margin:0 0 4px;font-size:12px;color:#94a3b8;">
          &copy; 2026 <strong style="color:#0B5BD3;">ReconIA</strong> &mdash; De la donnée à la décision
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

    text = f"""ReconIA — Notification d'erreur

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

© 2026 ReconIA — idachallenge.bj
Support : {_ADMIN_EMAIL}
"""

    msg = _build_message(text, html)
    msg['From']    = f'ReconIA <{sender}>'
    msg['To']      = to_email
    msg['Subject'] = f'[ReconIA] Action requise — Erreur sur {domain} ({ref_str})'

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


def send_monitoring_alert(to_email: str, domain: str, diff: dict, scanned_at: datetime = None) -> bool:
    """
    Alerte de surveillance (plan d'action, phase 7) : changement significatif
    détecté par un rescan planifié d'un domaine surveillé.

    Destinée à l'ADMINISTRATEUR uniquement (jamais au demandeur). Le corps ne
    reprend que le résumé du différentiel (utils/scan_diff.py) et quelques
    éléments techniques publics ajoutés (sous-domaines, IP, ports, CVE), tous
    échappés : ces valeurs viennent d'outils OSINT, donc de la cible.
    Retourne False (sans lever) si le SMTP n'est pas configuré ou si l'envoi échoue.
    """
    sender   = os.getenv('SMTP_USERNAME') or EMAIL_SENDER
    password = os.getenv('SMTP_PASSWORD') or EMAIL_PASSWORD
    if not all([sender, password, EMAIL_HOST, to_email]):
        logger.warning("send_monitoring_alert: SMTP ou destinataire non configuré — alerte non envoyée")
        return False

    diff = diff if isinstance(diff, dict) else {}
    domain_txt = str(domain or '')[:253]
    domain_html = _html.escape(domain_txt)
    when = (scanned_at or datetime.utcnow()).strftime('%d/%m/%Y à %H:%M UTC')
    summary = [str(s)[:200] for s in (diff.get('summary') or []) if s][:20]

    details = []
    for key, label in (('subdomains', 'Nouveaux sous-domaines'), ('ips', 'Nouvelles IP'),
                       ('ports', 'Nouveaux ports'), ('cves', 'Nouvelles CVE')):
        section = diff.get(key) if isinstance(diff.get(key), dict) else {}
        added = [str(v)[:120] for v in (section.get('added') or [])][:15]
        if added:
            more = section.get('added_count', len(added)) - len(added)
            details.append((label, added, more if more > 0 else 0))

    summary_html = ''.join(f'<li>{_html.escape(s)}</li>' for s in summary) or '<li>—</li>'
    details_html = ''.join(
        f'<p style="margin:12px 0 4px;font-weight:600;color:#0A1F44;">{_html.escape(label)}</p>'
        f'<p style="margin:0;font-family:\'Courier New\',monospace;font-size:12px;color:#334155;">'
        f'{"<br>".join(_html.escape(v) for v in values)}'
        f'{f"<br>… et {more} autre(s)" if more else ""}</p>'
        for label, values, more in details
    )
    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>Surveillance ReconIA</title></head>
<body style="margin:0;padding:24px;background:#f0f9ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;">
<tr><td style="background:#ffffff;border-radius:12px 12px 0 0;padding:22px 32px 14px;text-align:center;">
  {_BRAND_HEADER_HTML}
  <p style="margin:12px 0 0;font-size:12px;color:#4A5872;letter-spacing:1px;text-transform:uppercase;">Surveillance</p>
</td></tr>
<tr>{_BRAND_BAR_HTML}</tr>
<tr><td style="padding:24px 32px;">
  <p style="margin:0 0 12px;font-size:14px;color:#1e293b;">Changement significatif détecté sur <strong>{domain_html}</strong>
  (rescan passif du {when}).</p>
  <ul style="margin:0 0 12px;padding-left:20px;font-size:13px;color:#475569;">{summary_html}</ul>
  {details_html}
  <p style="margin:20px 0 0;font-size:12px;color:#64748b;">Détail complet : dashboard admin, onglet « Graphe &amp; surveillance ».
  Reconnaissance passive uniquement — aucune interaction intrusive avec la cible.</p>
</td></tr></table></body></html>"""

    text_lines = [f'ReconIA — Surveillance', '',
                  f'Changement significatif détecté sur {domain_txt} (rescan passif du {when}).', '']
    text_lines += [f'- {s}' for s in summary] or ['- —']
    for label, values, more in details:
        text_lines += ['', f'{label} :'] + [f'  {v}' for v in values]
        if more:
            text_lines.append(f'  … et {more} autre(s)')
    text_lines += ['', 'Détail complet : dashboard admin, onglet « Graphe & surveillance ».']

    msg = _build_message('\n'.join(text_lines), html)
    msg['From']    = f'ReconIA <{sender}>'
    msg['To']      = to_email
    # Domaine filtré pour l'en-tête SMTP (déjà validé en amont, défense en profondeur)
    subject_domain = ''.join(c for c in domain_txt if c.isalnum() or c in '.-')
    msg['Subject'] = f'[ReconIA] Surveillance — changement sur {subject_domain}'

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, to_email, msg.as_string())
        logger.info("Alerte de surveillance envoyée — domaine=%s", subject_domain)
        return True
    except Exception as e:
        logger.error("Échec envoi alerte de surveillance (%s) : %s", subject_domain, e)
        return False
