# utils/pdf_generator.py
"""
Génération de rapports PDF OSINT — ReconIA.
Charte ReconIA : logo officiel (api/static/brand/), bleu marine, bleu roi, cyan.
"""
import io
import os
import re
from datetime import datetime
from typing import Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader

from utils import pdf_visuals as PV
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)

PAGE_W, PAGE_H = A4

# ── Palette ───────────────────────────────────────────────────────────────────
C_DARK    = colors.HexColor('#0A1F44')   # bleu marine de la charte
C_NAVY    = colors.HexColor('#0E2C5E')
C_NAVY2   = colors.HexColor('#0B1A38')
C_CYAN    = colors.HexColor('#00C8F0')   # cyan du logo
C_CYAN2   = colors.HexColor('#1677F2')
C_PURPLE  = colors.HexColor('#0B5BD3')   # bleu roi (nom historique conservé)
C_WHITE   = colors.white
C_OFF     = colors.HexColor('#f8fafc')
C_LIGHT   = colors.HexColor('#EEF3FB')
C_BORDER  = colors.HexColor('#e2e8f0')
C_TEXT    = colors.HexColor('#1e293b')
C_MUTED   = colors.HexColor('#64748b')
C_SLATE   = colors.HexColor('#475569')

SEV_C = {
    'CRITICAL': colors.HexColor('#ef4444'),
    'HIGH':     colors.HexColor('#f97316'),
    'MEDIUM':   colors.HexColor('#f59e0b'),
    'LOW':      colors.HexColor('#3b82f6'),
    'INFO':     colors.HexColor('#64748b'),
}
SEV_BG = {
    'CRITICAL': colors.HexColor('#fef2f2'),
    'HIGH':     colors.HexColor('#fff7ed'),
    'MEDIUM':   colors.HexColor('#fffbeb'),
    'LOW':      colors.HexColor('#eff6ff'),
    'INFO':     colors.HexColor('#f8fafc'),
}
RISK_C = {
    'CRITICAL': colors.HexColor('#ef4444'),
    'HIGH':     colors.HexColor('#f97316'),
    'MEDIUM':   colors.HexColor('#f59e0b'),
    'LOW':      colors.HexColor('#10b981'),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hex(c: colors.Color) -> str:
    return '#{:02x}{:02x}{:02x}'.format(
        round(c.red * 255), round(c.green * 255), round(c.blue * 255)
    )


def _safe(v: Any) -> str:
    if v is None:
        return '—'
    return str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _fmt_s(sec) -> str:
    # `sec` absent (None) → aucune donnée, "—". `sec == 0.0` → une durée
    # réellement mesurée et quasi instantanée (typiquement un cache hit), pas
    # une absence de valeur — `if not sec` les confondait (0.0 est falsy en
    # Python), constaté sur un rapport réel ("Scan OSINT : —" alors que
    # scan_duration_s valait bien 0.0, un hit de cache légitime).
    if sec is None:
        return '—'
    sec = float(sec)
    if sec <= 0:
        return '< 1s'
    if sec < 60:
        return f'{sec:.1f}s'
    m, s = divmod(int(sec), 60)
    if m < 60:
        return f'{m}min {s:02d}s'
    h, m = divmod(m, 60)
    return f'{h}h {m:02d}min {s:02d}s'


def _alt_rows(n: int, start: int = 1) -> list:
    cmds = []
    for i in range(start, n):
        cmds.append(('BACKGROUND', (0, i), (-1, i), C_OFF if i % 2 == 0 else C_WHITE))
    return cmds


def _ps(name: str, **kw) -> ParagraphStyle:
    d = dict(fontName='Helvetica', fontSize=9.5, leading=13.5, textColor=C_TEXT)
    d.update(kw)
    return ParagraphStyle(name, **d)


# ══════════════════════════════════════════════════════════════════════════════
#  LOGO RECONIA (images de la charte, api/static/brand/)
# ══════════════════════════════════════════════════════════════════════════════

# Fichiers PNG à fond transparent, générés depuis le logo officiel
# (docs/brand/make_brand.py). Absents ou illisibles : repli sur le nom en
# texte — un PDF sans logo vaut mieux qu'un rapport qui échoue.
_BRAND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'static', 'brand')
_brand_cache: dict = {}


def _brand_image(name: str):
    """ImageReader mis en cache, ou None si le fichier manque."""
    if name not in _brand_cache:
        try:
            _brand_cache[name] = ImageReader(os.path.join(_BRAND_DIR, name))
        except Exception:
            _brand_cache[name] = None
    return _brand_cache[name]


def _draw_image_fit(canvas, img, x: float, y: float, width: float) -> float:
    """Dessine `img` à la largeur donnée (transparence conservée) ; renvoie la hauteur."""
    iw, ih = img.getSize()
    h = width * ih / iw
    canvas.drawImage(img, x, y, width=width, height=h, mask='auto')
    return h


def _draw_logo_full(canvas, x: float, y: float, box_size: float,
                    font_size: float = None, text_color=None) -> float:
    """
    Symbole ReconIA + nom « Recon » (couleur `text_color`, blanc par défaut)
    et « IA » en bleu vif. (x, y) = coin inférieur gauche ; `box_size` = hauteur
    du symbole. Retourne la largeur totale occupée.
    """
    fs = font_size or box_size * 0.58
    gap = box_size * 0.28
    mark = _brand_image('reconia-mark-160.png')
    mark_w = 0.0
    if mark is not None:
        iw, ih = mark.getSize()
        mark_w = box_size * iw / ih
        canvas.drawImage(mark, x, y, width=mark_w, height=box_size, mask='auto')
    else:
        gap = 0.0

    tx = x + mark_w + gap
    ty = y + box_size * 0.5 - fs * 0.35
    canvas.setFont('Helvetica-Bold', fs)
    canvas.setFillColor(text_color or C_WHITE)
    canvas.drawString(tx, ty, 'Recon')
    recon_w = canvas.stringWidth('Recon', 'Helvetica-Bold', fs)
    canvas.setFillColor(C_CYAN)
    canvas.drawString(tx + recon_w, ty, 'IA')
    return mark_w + gap + recon_w + canvas.stringWidth('IA', 'Helvetica-Bold', fs)


def _gradient_band(canvas, x: float, y: float, w: float, h: float) -> None:
    """Bande horizontale au dégradé du logo : marine → bleu roi → cyan."""
    stops = [C_DARK, C_PURPLE, C_CYAN]
    n = 60
    for i in range(n):
        t = i / (n - 1)
        a, b, u = (stops[0], stops[1], t * 2) if t < 0.5 else (stops[1], stops[2], (t - 0.5) * 2)
        canvas.setFillColorRGB(a.red + (b.red - a.red) * u,
                               a.green + (b.green - a.green) * u,
                               a.blue + (b.blue - a.blue) * u)
        canvas.rect(x + i * w / n, y, w / n + 0.6, h, fill=1, stroke=0)


# ══════════════════════════════════════════════════════════════════════════════
#  CANVAS CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

def _page_cover(canvas, doc):
    """Page de couverture : fond clair de la charte, logo complet en haut."""
    canvas.saveState()

    canvas.setFillColor(C_WHITE)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # Triangle décoratif bas-droite, bleu très pâle
    canvas.setFillColor(C_LIGHT)
    p = canvas.beginPath()
    p.moveTo(PAGE_W * 0.55, 0)
    p.lineTo(PAGE_W, 0)
    p.lineTo(PAGE_W, PAGE_H * 0.45)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)

    # Carrés « pixels » repris du symbole, coin haut-gauche
    for (px, py, s, col) in [(1.6, 2.4, 5, '#00C8F0'), (2.6, 3.4, 7, '#19B4F0'),
                             (1.2, 4.6, 4, '#1677F2'), (3.4, 5.2, 5, '#0B5BD3'),
                             (2.2, 6.4, 3.5, '#00C8F0')]:
        canvas.setFillColor(colors.HexColor(col))
        canvas.roundRect(px * cm, PAGE_H - py * cm, s * mm, s * mm, 0.8 * mm, fill=1, stroke=0)

    # Bandes au dégradé du logo (haut 6 mm, bas 4 mm)
    _gradient_band(canvas, 0, PAGE_H - 6*mm, PAGE_W, 6*mm)
    _gradient_band(canvas, 0, 0, PAGE_W, 4*mm)

    # Logo complet (symbole + ReconIA + slogan) centré
    logo = _brand_image('reconia-logo-600.png')
    if logo is not None:
        lw = 6.2*cm
        iw, ih = logo.getSize()
        lh = lw * ih / iw
        _draw_image_fit(canvas, logo, (PAGE_W - lw) / 2, PAGE_H - 6*mm - 8*mm - lh, lw)
    else:
        w = _draw_logo_full(canvas, 0, -100, 40, text_color=C_DARK)   # mesure hors page
        _draw_logo_full(canvas, (PAGE_W - w) / 2, PAGE_H - 6*mm - 30*mm, 40, text_color=C_DARK)

    canvas.restoreState()


def _page_content(canvas, doc):
    """Pages de contenu : bandeau marine avec le logo, pied de page avec le slogan."""
    canvas.saveState()

    # ── En-tête ─────────────────────────────────────────────────────────────
    canvas.setFillColor(C_DARK)
    canvas.rect(0, PAGE_H - 14*mm, PAGE_W, 14*mm, fill=1, stroke=0)
    _gradient_band(canvas, 0, PAGE_H - 2.5*mm, PAGE_W, 2.5*mm)

    box_s = 22
    lx = 1.5*cm
    ly = PAGE_H - 14*mm + (11.5*mm - box_s) / 2
    _draw_logo_full(canvas, lx, ly, box_s, font_size=11)

    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#9DB0CF'))
    canvas.drawCentredString(PAGE_W / 2, PAGE_H - 9*mm, 'Rapport de reconnaissance passive')

    domain = getattr(doc, '_report_domain', '')
    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(C_CYAN)
    canvas.drawRightString(PAGE_W - 1.5*cm, PAGE_H - 7*mm, domain)
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(colors.HexColor('#9DB0CF'))
    canvas.drawRightString(PAGE_W - 1.5*cm, PAGE_H - 11*mm, f'Page {doc.page}')

    # ── Pied de page ────────────────────────────────────────────────────────
    canvas.setFillColor(C_OFF)
    canvas.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(1.5*cm, 10*mm, PAGE_W - 1.5*cm, 10*mm)
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(1.5*cm, 4*mm,
                      'ReconIA — De la donnée à la décision · Document confidentiel')
    canvas.setFont('Helvetica-Bold', 7)
    canvas.setFillColor(C_PURPLE)
    canvas.drawRightString(PAGE_W - 1.5*cm, 4*mm, 'idachallenge.bj')

    canvas.restoreState()


# ══════════════════════════════════════════════════════════════════════════════
#  STYLES PARAGRAPHE
# ══════════════════════════════════════════════════════════════════════════════

S = {
    # Couverture
    'cov_tag':    _ps('cov_tag',   fontSize=9,  leading=11, textColor=colors.HexColor('#64748b'),  alignment=TA_CENTER, spaceAfter=3),
    'cov_domain': _ps('cov_dom',   fontName='Helvetica-Bold', fontSize=28, leading=32, textColor=C_PURPLE, alignment=TA_CENTER, spaceAfter=4),
    'cov_sub':    _ps('cov_sub',   fontSize=11, leading=15, textColor=C_SLATE, alignment=TA_CENTER, spaceAfter=2),
    'cov_info':   _ps('cov_info',  fontSize=9.5, leading=16, textColor=C_SLATE, alignment=TA_CENTER),
    'cov_conf':   _ps('cov_conf',  fontName='Helvetica-Oblique', fontSize=8, leading=11, textColor=colors.HexColor('#334155'), alignment=TA_CENTER),
    # Titres
    'h1':         _ps('h1',        fontName='Helvetica-Bold', fontSize=16, leading=20, textColor=C_DARK,  spaceBefore=12, spaceAfter=4),
    'h2':         _ps('h2',        fontName='Helvetica-Bold', fontSize=11.5, leading=14, textColor=C_DARK, spaceBefore=9, spaceAfter=3),
    # Corps
    'body':       _ps('body',      alignment=TA_JUSTIFY, spaceAfter=5),
    'body_l':     _ps('body_l',    spaceAfter=4),
    'small':      _ps('small',     fontSize=8.5, leading=12, textColor=C_MUTED),
    'small_b':    _ps('small_b',   fontName='Helvetica-Bold', fontSize=8.5, leading=12, textColor=C_MUTED),
    'label':      _ps('label',     fontName='Helvetica-Bold', fontSize=7.5, leading=10, textColor=C_MUTED, spaceAfter=1),
    'mono':       _ps('mono',      fontName='Courier', fontSize=8.5, leading=12, textColor=C_TEXT),
    'bullet':     _ps('bullet',    leftIndent=12, spaceAfter=3),
    # Tableau header
    'th':         _ps('th',        fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=C_WHITE),
    'th_c':       _ps('th_c',      fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=C_WHITE, alignment=TA_CENTER),
    'td':         _ps('td',        fontSize=8.5, leading=12),
    'td_c':       _ps('td_c',      fontSize=8.5, leading=12, alignment=TA_CENTER),
    'td_b':       _ps('td_b',      fontName='Helvetica-Bold', fontSize=8.5, leading=12),
}

_BASE_TBL_STYLE = [
    ('GRID',          (0, 0), (-1, -1), 0.4, C_BORDER),
    ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ('TOPPADDING',    (0, 0), (-1, -1), 6),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ('LEFTPADDING',   (0, 0), (-1, -1), 8),
    ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
]


# ══════════════════════════════════════════════════════════════════════════════
#  COMPOSANTS RÉUTILISABLES
# ══════════════════════════════════════════════════════════════════════════════

def _section(title: str, icon: str = '◆') -> list:
    """En-tête de section avec accent cyan."""
    ps_icon = _ps('_si', fontName='Helvetica-Bold', fontSize=9,
                  textColor=C_CYAN, spaceAfter=0)
    ps_title = _ps('_st', fontName='Helvetica-Bold', fontSize=16,
                   leading=20, textColor=C_DARK, spaceAfter=0)
    # _safe() échappe & / < / > — sans ça, un titre contenant un "&" littéral
    # ("Corrélation MITRE ATT&CK") est interprété par le mini-parseur XML de
    # ReportLab comme le début d'une entité, et s'affiche "ATT&CK;" (le ";"
    # ajouté par le parseur en tentant de résoudre l'entité, non résolue donc
    # affichée telle quelle) — constaté sur un PDF réellement généré.
    hdr = Table(
        [[Paragraph(icon, ps_icon), Paragraph(_safe(title), ps_title)]],
        colWidths=[0.6*cm, None],
        hAlign='LEFT',
    )
    hdr.setStyle(TableStyle([
        ('VALIGN',        (0, 0), (-1, -1), 'BOTTOM'),
        ('TOPPADDING',    (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
    ]))
    return [
        Spacer(1, 6),
        hdr,
        Table([['']], colWidths=[PAGE_W - 3*cm],
              style=TableStyle([
                  ('LINEABOVE', (0, 0), (-1, 0), 2.5, C_CYAN),
                  ('TOPPADDING', (0, 0), (-1, -1), 0),
                  ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
              ])),
    ]


def _kv_table(rows: list, col1_w: float = 5*cm) -> Table:
    """Table clé / valeur avec header sombre."""
    data = [[Paragraph('Champ', S['th']), Paragraph('Valeur', S['th'])]]
    for k, v in rows:
        data.append([Paragraph(_safe(k), S['td_b']), Paragraph(_safe(v), S['td'])])
    tbl = Table(data, colWidths=[col1_w, None])
    style = list(_BASE_TBL_STYLE) + [
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
    ] + _alt_rows(len(data))
    tbl.setStyle(TableStyle(style))
    return tbl


# ══════════════════════════════════════════════════════════════════════════════
#  SECTIONS DU DOCUMENT
# ══════════════════════════════════════════════════════════════════════════════

def _build_cover(story: list, analysis: dict, recon: Any, timing: dict) -> None:
    """
    Couverture sobre, à la manière d'un rapport d'audit : identification du
    document seulement. Le score, le niveau de risque et les chiffres sont
    dans la synthèse (page 3), pas sur la page de garde.
    """
    domain = analysis.get('domain') or (recon.domain if recon else 'unknown')
    fn = _safe(getattr(recon, 'firstname', '')) if recon else ''
    ln = _safe(getattr(recon, 'lastname', '')) if recon else ''
    ref = f'RIA-{getattr(recon, "id", 0):05d}' if recon and getattr(recon, 'id', None) else '—'
    analyzed_at = analysis.get('analyzed_at', '')
    try:
        dt = datetime.fromisoformat(str(analyzed_at).replace('Z', '+00:00'))
        date_str = dt.strftime('%d/%m/%Y')
    except Exception:
        date_str = datetime.utcnow().strftime('%d/%m/%Y')

    story.append(Spacer(1, 6.6*cm))     # place du logo, dessiné par _page_cover
    story.append(Paragraph('RAPPORT DE RECONNAISSANCE PASSIVE', S['cov_tag']))
    story.append(Spacer(1, 0.25*cm))
    story.append(Paragraph('Évaluation de l\'exposition externe', _ps(
        '_cov_title', fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=C_DARK, alignment=TA_CENTER)))
    story.append(Spacer(1, 0.35*cm))
    story.append(Paragraph(_safe(domain), S['cov_domain']))
    story.append(Spacer(1, 1.1*cm))

    rows = [
        ('Préparé pour', f'{fn} {ln}'.strip() or '—'),
        ('Référence', ref),
        ('Date du rapport', date_str),
        ('Méthode', 'Reconnaissance passive (OSINT) — aucun test intrusif'),
        ('Classification', 'CONFIDENTIEL — diffusion restreinte au destinataire'),
    ]
    ps_k = _ps('_ck', fontName='Helvetica-Bold', fontSize=8.5, textColor=C_SLATE)
    ps_v = _ps('_cv', fontSize=9, textColor=C_TEXT)
    tbl = Table([[Paragraph(k.upper(), ps_k), Paragraph(_safe(v), ps_v)] for k, v in rows],
                colWidths=[4.2*cm, 9.3*cm])
    tbl.setStyle(TableStyle([
        ('LINEBELOW',     (0, 0), (-1, -2), 0.4, C_BORDER),
        ('LINEABOVE',     (0, 0), (-1, 0), 1.2, C_PURPLE),
        ('LINEBELOW',     (0, -1), (-1, -1), 1.2, C_PURPLE),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
    ]))
    wrap = Table([[tbl]], colWidths=[PAGE_W - 3*cm])
    wrap.setStyle(TableStyle([('ALIGN', (0, 0), (0, 0), 'CENTER'),
                              ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
    story.append(wrap)
    story.append(Spacer(1, 1.4*cm))
    story.append(Paragraph(
        'Ce document contient des informations sur l\'exposition de sécurité d\'un système d\'information. '
        'Il est destiné exclusivement à son destinataire et ne doit pas être diffusé sans autorisation.',
        S['cov_conf']))
    story.append(PageBreak())


_CONTENTS = [
    ('1', 'Synthèse', 'Score, niveau de risque, répartition des constats, couverture'),
    ('2', 'Exposition géographique et infrastructure', 'Localisation des serveurs, cartographie'),
    ('3', 'Présentation de l\'infrastructure', 'DNS, TLS, messagerie, web, réseau'),
    ('4', 'Constats détaillés', 'Preuve, outil source, techniques ATT&CK, recommandation'),
    ('5', 'Surface d\'attaque et MITRE ATT&CK', 'Services exposés, techniques, chaîne plausible'),
    ('6', 'Points forts et plan d\'action', 'Bonnes pratiques constatées, priorités'),
    ('7', 'Méthodologie et sources', 'Outils exécutés, limites de la collecte'),
]
_SEVERITY_SCALE = [
    ('CRITICAL', 'Critique', 'Exploitable en l\'état ou activement exploitée (ex. CVE du catalogue CISA KEV). Traitement immédiat.'),
    ('HIGH', 'Élevée', 'Expose directement à une attaque courante (usurpation d\'email, prise de contrôle de sous-domaine…). Sous 7 jours.'),
    ('MEDIUM', 'Moyenne', 'Affaiblit les défenses sans être exploitable seule. Dans le mois.'),
    ('LOW', 'Faible', 'Écart aux bonnes pratiques à faible impact. À planifier.'),
    ('INFO', 'Info', 'Information de contexte ou bonne pratique constatée.'),
]


def _build_contents(story: list) -> None:
    """Sommaire, périmètre et échelle de sévérité (page 2)."""
    story.extend(_section('Sommaire', '◆'))
    ps_n = _ps('_tn', fontName='Helvetica-Bold', fontSize=13, textColor=C_PURPLE, alignment=TA_CENTER)
    ps_t = _ps('_tt', fontName='Helvetica-Bold', fontSize=10.5, textColor=C_DARK)
    ps_d = _ps('_td', fontSize=8.5, textColor=C_MUTED)
    rows = [[Paragraph(n, ps_n), [Paragraph(_safe(t), ps_t), Paragraph(_safe(d), ps_d)]] for n, t, d in _CONTENTS]
    toc = Table(rows, colWidths=[1.2*cm, PAGE_W - 3*cm - 1.2*cm])
    toc.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, C_BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(toc)
    story.append(Spacer(1, 0.6*cm))

    story.extend(_section('Périmètre et méthode', '◆'))
    for text in (
        '<b>Objectif.</b> Mesurer ce qu\'un attaquant peut apprendre du domaine à partir de sources publiques, '
        'et en déduire les risques et les actions prioritaires.',
        '<b>Méthode.</b> Reconnaissance strictement passive : DNS public, journaux de certificats, archives du web, '
        'bases de réputation et d\'exposition, et une visite de la page d\'accueil comme un navigateur. '
        'Aucun scan de ports, aucune force brute, aucune tentative d\'exploitation.',
        '<b>Analyse.</b> La sévérité de chaque constat est fixée par des règles déterministes appliquées aux données '
        'brutes ; l\'intelligence artificielle rédige et recommande à partir des seules données collectées. '
        'Chaque constat cite l\'outil qui l\'a prouvé.',
        '<b>Limites.</b> Une reconnaissance passive ne voit que l\'exposition publique : elle ne remplace pas un test '
        'd\'intrusion autorisé. Les outils sans clé ou en échec sont listés dans la méthodologie.',
    ):
        story.append(Paragraph(text, S['body']))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph('<b>Échelle de sévérité</b>', S['h2']))
    ps_l = _ps('_sl2', fontName='Helvetica-Bold', fontSize=8.5, textColor=C_WHITE, alignment=TA_CENTER)
    rows = [[Paragraph(label, ps_l), Paragraph(_safe(desc), S['td'])] for key, label, desc in _SEVERITY_SCALE]
    scale = Table(rows, colWidths=[2.6*cm, PAGE_W - 3*cm - 2.6*cm])
    style = [('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('GRID', (0, 0), (-1, -1), 0.4, C_BORDER),
             ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]
    for i, (key, _, _) in enumerate(_SEVERITY_SCALE):
        style.append(('BACKGROUND', (0, i), (0, i), PV.SEV_COLORS[key]))
    scale.setStyle(TableStyle(style))
    story.append(scale)
    story.append(PageBreak())


def _two_cols(left, right, ratio: float = 0.5) -> Table:
    """Deux blocs côte à côte sur la largeur utile."""
    total = PAGE_W - 3*cm
    t = Table([[left, right]], colWidths=[total * ratio, total * (1 - ratio)])
    t.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'),
                           ('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                           ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
    return t


def _panel(title: str, *flowables) -> Table:
    """Encadré titré (fond clair) pour un graphique ou un bloc de chiffres."""
    ps = _ps('_pt', fontName='Helvetica-Bold', fontSize=9, textColor=C_DARK)
    content = [[Paragraph(_safe(title), ps)]] + [[f] for f in flowables if f is not None]
    t = Table(content, colWidths=[(PAGE_W - 3*cm) / 2 - 8])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_OFF), ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('LINEABOVE', (0, 0), (-1, 0), 2, C_PURPLE),
        ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t


def _build_summary(story: list, analysis: dict, scan_data: Optional[dict] = None) -> None:
    """Synthèse : jauge de score, chiffres clés, résumé, graphiques, posture."""
    story.extend(_section('Synthèse', '◆'))
    findings = analysis.get('findings', []) or []
    sec_score = analysis.get('security_score')
    sec_grade = analysis.get('security_grade') or ''
    risk_level = str(analysis.get('risk_level') or 'N/A').upper()
    scan = (scan_data or {}).get('data', scan_data) or {}

    sev_parts = PV.severity_parts(findings)
    st_parts, ok_tools, total_tools = PV.status_parts(scan)
    atk = analysis.get('attack_surface', {}) or {}

    # Jauge + chiffres clés
    rc = RISK_C.get(risk_level, C_MUTED)
    ps_k = _ps('_kk', fontSize=8, textColor=C_MUTED)
    ps_v = _ps('_kv', fontName='Helvetica-Bold', fontSize=11, textColor=C_DARK)
    facts = [
        ('Niveau de risque', f'<font color="{_hex(rc)}">{_safe(risk_level)}</font>'),
        ('Constats retenus', str(len(findings))),
        ('Dont critiques / élevés', f'{sev_parts[0][1]} / {sev_parts[1][1]}'),
        ('Sous-domaines découverts', str(atk.get('total_subdomains', 0) or 0)),
        ('Outils exploitables', f'{ok_tools} / {total_tools}' if total_tools else '—'),
    ]
    facts_tbl = Table([[Paragraph(k, ps_k), Paragraph(v, ps_v)] for k, v in facts],
                      colWidths=[4.2*cm, 4.2*cm])
    facts_tbl.setStyle(TableStyle([('LINEBELOW', (0, 0), (-1, -2), 0.4, C_BORDER),
                                   ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4)]))
    story.append(_two_cols(_panel('Score de sécurité', PV.score_gauge(sec_score, sec_grade, size=170)),
                           _panel('Chiffres clés', facts_tbl)))
    story.append(Spacer(1, 0.4*cm))

    summary = analysis.get('executive_summary')
    if summary:
        story.append(Paragraph('<b>Résumé exécutif</b>', S['h2']))
        story.append(Paragraph(_safe(summary), S['body']))
        story.append(Spacer(1, 0.3*cm))

    # Graphiques
    sev_chart = PV.donut(sev_parts, str(len(findings)), 'CONSTATS', width=235, height=110)
    cat_chart = PV.category_bars(findings, width=235)
    story.append(_two_cols(_panel('Constats par sévérité', sev_chart),
                           _panel('Constats par catégorie', cat_chart or Paragraph('Aucun constat.', S['small']))))
    story.append(Spacer(1, 0.3*cm))
    if total_tools:
        cov = PV.donut(st_parts, f'{round(100 * ok_tools / total_tools)}%', 'UTILES', width=235, height=110)
        posture = analysis.get('security_posture')
        story.append(_two_cols(_panel('Couverture de la collecte', cov),
                               _panel('Posture de sécurité', Paragraph(_safe(posture), S['small'])) if posture
                               else _panel('Lecture', Paragraph(
                                   'Le score part de 100 et diminue selon la sévérité des constats retenus. '
                                   'La couverture indique la part des outils qui ont produit des données.', S['small']))))
        story.append(Spacer(1, 0.3*cm))

    breakdown = analysis.get('security_breakdown') or {}
    if breakdown and isinstance(breakdown, dict):
        _breakdown_table(story, breakdown)
    story.append(PageBreak())


def _build_exposure_maps(story: list, analysis: dict, scan_data: Optional[dict]) -> None:
    """Carte des serveurs et cartographie de l'infrastructure (page dédiée)."""
    scan = (scan_data or {}).get('data', scan_data) or {}
    points = PV.geo_points(scan)
    domain = analysis.get('domain') or scan.get('domain') or ''
    graph = PV.infra_graph(str(domain), scan, width=PAGE_W - 3*cm, height=8.2*cm)
    if not points and graph is None:
        return
    story.extend(_section('Exposition géographique et infrastructure', '◆'))
    if points:
        story.append(Paragraph('<b>Localisation des serveurs</b>', S['h2']))
        story.append(PV.world_map(points, width=PAGE_W - 3*cm))
        story.append(Spacer(1, 0.25*cm))
        ps = S['td']
        rows = [[Paragraph(h, S['th']) for h in ('Lieu', 'Hébergeur', 'Adresses IP')]]
        for p in points[:10]:
            rows.append([
                Paragraph(_safe(', '.join(v for v in (p['city'], p['country']) if v) or '—'), ps),
                Paragraph(_safe(' · '.join(p['orgs']) or '—'), ps),
                Paragraph(_safe(', '.join(p['ips'][:4]) + (f' (+{len(p["ips"]) - 4})' if len(p['ips']) > 4 else '')), S['mono']),
            ])
        t = Table(rows, colWidths=[4.6*cm, 5.4*cm, None], repeatRows=1)
        t.setStyle(TableStyle(list(_BASE_TBL_STYLE) + [('BACKGROUND', (0, 0), (-1, 0), C_NAVY)] + _alt_rows(len(rows))))
        story.append(t)
        story.append(Spacer(1, 0.45*cm))
    if graph is not None:
        story.append(Paragraph('<b>Cartographie de l\'infrastructure</b>', S['h2']))
        story.append(Paragraph('Relations observées passivement entre le domaine, ses adresses IP (et leur hébergeur) '
                               'et ses sous-domaines actifs (12 au plus).', S['small']))
        story.append(Spacer(1, 0.15*cm))
        story.append(graph)
    story.append(PageBreak())


def _breakdown_table(story: list, breakdown: dict) -> None:
    """Tableau du score par catégorie (security_breakdown)."""
    story.append(Paragraph('<b>Score par catégorie</b>', S['h2']))
    # Détail par catégorie
    if breakdown and isinstance(breakdown, dict):
        ps_bth = _ps('_bth', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)
        ps_btd = _ps('_btd', fontSize=8, textColor=C_TEXT)
        ps_btd_c = _ps('_btdc', fontSize=8, textColor=C_TEXT, alignment=TA_CENTER)
        bkd_hdr = [Paragraph(c, ps_bth) for c in ['Catégorie', 'Score', 'Note', 'Constats', 'Critiques', 'Élevés']]
        bkd_rows = [bkd_hdr]
        for cat, val in breakdown.items():
            if not isinstance(val, dict):
                continue
            cat_score = val.get('score', 0)
            sc_col = (colors.HexColor('#ef4444') if cat_score < 40 else
                      colors.HexColor('#f59e0b') if cat_score < 60 else
                      colors.HexColor('#10b981') if cat_score >= 80 else
                      colors.HexColor('#f59e0b'))
            ps_sc_val = _ps('_bscv', fontName='Helvetica-Bold', fontSize=8,
                            textColor=sc_col, alignment=TA_CENTER)
            bkd_rows.append([
                Paragraph(_safe(str(cat)), ps_btd),
                Paragraph(str(cat_score), ps_sc_val),
                Paragraph(_safe(str(val.get('grade', '—'))), ps_btd_c),
                Paragraph(str(val.get('findings_count', 0)), ps_btd_c),
                Paragraph(str(val.get('critical', 0)), ps_btd_c),
                Paragraph(str(val.get('high', 0)), ps_btd_c),
            ])
        if len(bkd_rows) > 1:
            cw_bkd = [(PAGE_W - 3*cm) * p for p in [0.30, 0.14, 0.12, 0.18, 0.13, 0.13]]
            bkd_tbl = Table(bkd_rows, colWidths=cw_bkd)
            bkd_style = [
                ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY),
                ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_OFF]),
                ('GRID',          (0, 0), (-1, -1), 0.3, C_BORDER),
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING',    (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING',   (0, 0), (-1, -1), 5),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
            ]
            # Colorier en rouge les lignes avec critical > 0
            for ri, (cat, val) in enumerate(breakdown.items(), start=1):
                if isinstance(val, dict) and val.get('critical', 0) > 0:
                    bkd_style.append(('BACKGROUND', (0, ri), (-1, ri), colors.HexColor('#fef2f2')))
                elif isinstance(val, dict) and val.get('high', 0) > 0:
                    bkd_style.append(('BACKGROUND', (0, ri), (-1, ri), colors.HexColor('#fff7ed')))
            bkd_tbl.setStyle(TableStyle(bkd_style))
            story.append(bkd_tbl)
            story.append(Spacer(1, 0.3*cm))


_CONFIDENCE_LABEL = {'high': 'élevée', 'medium': 'moyenne', 'low': 'faible'}
_TECH_ID_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
_MIT_ID_RE = re.compile(r'^M\d{4}$')


def _ref_label(ref) -> str:
    """Référence d'un constat : chaîne (ancien format) ou {collection, source} (phase 3)."""
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        src = ref.get('source') if isinstance(ref.get('source'), str) else ''
        col = ref.get('collection') if isinstance(ref.get('collection'), str) else ''
        return f'{src} ({col})' if src and col else src
    return ''


def _attack_items(items, regex) -> list:
    """« <b>T1566</b> Phishing » pour chaque entrée {id, name} dont l'ID est valide."""
    out = []
    for it in items or []:
        if isinstance(it, dict) and isinstance(it.get('id'), str) and regex.match(it['id']):
            out.append(f"<b>{_safe(it['id'])}</b> {_safe(str(it.get('name') or '')[:120])}")
    return out[:10]


def _with_attack(analysis: dict) -> dict:
    """
    Copie de l'analyse dont les constats sont (ré)annotés par la table
    déterministe (idempotent) + chaîne d'attaque. Un échec de l'annotation
    n'empêche jamais la génération du PDF.
    """
    try:
        from utils.attack_enablement import annotate_findings, build_attack_chain
        from utils.mitre_attack import attack_version
        findings = annotate_findings(analysis.get('findings') or [], {})
        return {**analysis, 'findings': findings,
                '_attack_chain': build_attack_chain(findings), '_attack_version': attack_version()}
    except Exception:
        return analysis


def _build_findings(story: list, analysis: dict) -> None:
    findings = analysis.get('findings', []) or []
    if not findings:
        return

    story.extend(_section('Vulnérabilités & Risques Identifiés', '◆'))
    story.append(Paragraph(
        f'<b>{len(findings)}</b> finding(s) identifié(s) — classés par sévérité.',
        S['body_l'],
    ))
    story.append(Spacer(1, 0.3*cm))

    for i, f in enumerate(findings, 1):
        sev   = str(f.get('severity', 'INFO')).upper()
        sc    = SEV_C.get(sev, C_MUTED)
        sbg   = SEV_BG.get(sev, C_OFF)
        fid   = _safe(f.get('id', f'F-{i:03d}'))
        cat   = _safe(f.get('category', ''))
        title = _safe(f.get('title', 'Sans titre'))
        desc  = _safe(f.get('description', ''))
        evid  = _safe(f.get('evidence', ''))
        reco  = _safe(f.get('recommendation', ''))
        refs  = [_safe(r) for r in (_ref_label(x) for x in (f.get('references', []) or [])[:8]) if r]
        srcs  = [_safe(s) for s in (f.get('web_sources', []) or [])[:3]]

        sc_hex = _hex(sc)

        # ── Carte finding ─────────────────────────────────────────────────
        # Ligne d'en-tête : bande colorée à gauche via bordure épaisse
        hdr_ps_id  = _ps('_fi', fontName='Helvetica-Bold', fontSize=8.5, textColor=C_WHITE, alignment=TA_CENTER)
        hdr_ps_t   = _ps('_ft', fontName='Helvetica-Bold', fontSize=10, textColor=C_WHITE)
        hdr_ps_sev = _ps('_fs', fontName='Helvetica-Bold', fontSize=9, textColor=C_WHITE, alignment=TA_RIGHT)

        hdr = Table(
            [[Paragraph(fid, hdr_ps_id),
              Paragraph(title, hdr_ps_t),
              Paragraph(f'{sev}  ·  {cat}', hdr_ps_sev)]],
            colWidths=[1.6*cm, None, 4*cm],
        )
        hdr.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), sc),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',    (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
            ('LEFTPADDING',   (0, 0), (-1, -1), 9),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 9),
            ('LINEBELOW',     (0, 0), (-1, -1), 3, colors.HexColor('#00000030')),
        ]))

        # Corps
        body_rows = []
        if desc:
            body_rows.append([Paragraph('<b>Description</b>', S['label']),
                               Paragraph(desc, S['body'])])
        if evid:
            body_rows.append([Paragraph('<b>Preuve OSINT</b>', S['label']),
                               Paragraph(evid, S['mono'])])
        # Traçabilité : outil(s) OSINT à l'origine de la preuve
        src_tools = f.get('source_tools') or []
        if not isinstance(src_tools, list):
            src_tools = [src_tools]
        primary_tool = f.get('source_tool')
        ordered_tools = ([primary_tool] if primary_tool else []) + [
            t for t in src_tools if t and t != primary_tool
        ]
        ordered_tools = [_safe(t) for t in ordered_tools[:6]]
        if ordered_tools:
            body_rows.append([Paragraph('<b>Outil source</b>', S['label']),
                               Paragraph('  ·  '.join(ordered_tools), S['mono'])])
        if reco:
            body_rows.append([Paragraph(
                f'<font color="{_hex(colors.HexColor("#10b981"))}"><b>Recommandation</b></font>',
                S['label']), Paragraph(reco, S['body'])])
        # Phase 3/4 : confiance, horodatage, techniques rendues possibles,
        # mitigations (table déterministe utils/attack_enablement.py)
        conf = _CONFIDENCE_LABEL.get(str(f.get('confidence') or '').lower())
        observed = f.get('observed_at') if isinstance(f.get('observed_at'), str) else None
        if conf or observed:
            parts = []
            if conf:
                parts.append(f'Confiance : <b>{conf}</b>')
            if observed:
                parts.append(f'observé le {_safe(observed[:25])}')
            body_rows.append([Paragraph('<b>Fiabilité</b>', S['label']),
                               Paragraph('  ·  '.join(parts), S['small'])])
        enabled = _attack_items(f.get('attack_enabled'), _TECH_ID_RE)
        if enabled:
            body_rows.append([Paragraph('<b>Rend possible</b>', S['label']),
                               Paragraph('<br/>'.join(enabled), S['small'])])
        mitig = _attack_items(f.get('mitigations'), _MIT_ID_RE)
        if mitig:
            advice = f.get('mitigation_advice') if isinstance(f.get('mitigation_advice'), str) else ''
            body_rows.append([Paragraph('<b>Mitigations</b>', S['label']),
                               Paragraph('<br/>'.join(mitig) + (f'<br/><i>{_safe(advice[:600])}</i>' if advice else ''),
                                         S['small'])])
        if refs:
            body_rows.append([Paragraph('<b>Références</b>', S['label']),
                               Paragraph('  ·  '.join(refs), S['small'])])
        if srcs:
            body_rows.append([Paragraph('<b>Sources web</b>', S['label']),
                               Paragraph('<br/>'.join(srcs), S['small'])])

        block = [hdr]
        if body_rows:
            # 2.2cm était trop étroit pour "Recommandation"/"Preuve OSINT" en
            # 7.5pt gras : ReportLab les coupait au milieu du mot, faute
            # d'espace où couper proprement (repéré sur un PDF réel :
            # "Recomman" / "dation" sur deux lignes) — élargi à 2.7cm.
            btbl = Table(body_rows, colWidths=[2.7*cm, None])
            btbl.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), sbg),
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING',    (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING',   (0, 0), (-1, -1), 9),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 9),
                ('LINEBELOW',     (0, 0), (-1, -2), 0.3, C_BORDER),
                ('BOX',           (0, 0), (-1, -1), 0.4, C_BORDER),
                ('LINEBEFORE',    (0, 0), (0, -1),  3,   sc),
            ]))
            block.append(btbl)

        block.append(Spacer(1, 0.45*cm))
        story.append(KeepTogether(block))


def _build_attack_surface(story: list, analysis: dict) -> None:
    atk = analysis.get('attack_surface', {}) or {}
    if not atk:
        return

    story.extend(_section("Surface d'Attaque", '◆'))

    total_sub = atk.get('total_subdomains', 0) or 0
    techs     = atk.get('technologies', []) or []
    cloud     = atk.get('cloud_providers', []) or []
    services  = atk.get('exposed_services', []) or []

    # Compteurs
    cw_cnt = (PAGE_W - 3*cm) / 4
    cnt_cells = []
    for lbl, val in [('Sous-domaines', total_sub), ('Services exposés', len(services)),
                     ('Technologies', len(techs)), ('Cloud / Hébergeurs', len(cloud))]:
        cnt_cells.append(Table([
            [Paragraph(str(val), _ps('_cv', fontName='Helvetica-Bold', fontSize=20,
                                      textColor=C_CYAN, alignment=TA_CENTER))],
            [Paragraph(lbl, _ps('_cl', fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER))],
        ], colWidths=[cw_cnt]))

    cnt_tbl = Table([cnt_cells], colWidths=[cw_cnt] * 4)
    cnt_tbl.setStyle(TableStyle([
        ('GRID',          (0, 0), (-1, -1), 0.4, C_BORDER),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('BACKGROUND',    (0, 0), (0, 0), C_DARK),
        ('BACKGROUND',    (1, 0), (1, 0), C_OFF),
        ('BACKGROUND',    (2, 0), (2, 0), C_DARK),
        ('BACKGROUND',    (3, 0), (3, 0), C_OFF),
    ]))
    story.append(cnt_tbl)
    story.append(Spacer(1, 0.4*cm))

    if services:
        story.append(Paragraph('<b>Services exposés publiquement</b>', S['h2']))
        svc_hdr = [Paragraph(t, S['th']) for t in ['Hôte', 'Type de service', 'Risque']]
        svc_rows = [svc_hdr]
        for svc in services[:25]:
            r  = str(svc.get('risk', 'LOW')).upper()
            rc = SEV_C.get(r, C_MUTED)
            svc_rows.append([
                Paragraph(_safe(svc.get('host', '')), S['td']),
                Paragraph(_safe(svc.get('service_type', '')), S['td']),
                Paragraph(
                    f'<font color="{_hex(rc)}"><b>{r}</b></font>',
                    S['td_c'],
                ),
            ])
        svc_tbl = Table(svc_rows, colWidths=[7*cm, 6*cm, 3*cm])
        svc_style = list(_BASE_TBL_STYLE) + [
            ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ] + _alt_rows(len(svc_rows))
        svc_tbl.setStyle(TableStyle(svc_style))
        story.append(svc_tbl)
        story.append(Spacer(1, 0.4*cm))

    if techs:
        story.append(Paragraph('<b>Technologies détectées</b>', S['h2']))
        story.append(Paragraph('  ·  '.join(_safe(t) for t in techs[:30]), S['body_l']))
        story.append(Spacer(1, 0.2*cm))

    if cloud:
        story.append(Paragraph('<b>Hébergeurs / Cloud identifiés</b>', S['h2']))
        story.append(Paragraph('  ·  '.join(_safe(c) for c in cloud[:15]), S['body_l']))
        story.append(Spacer(1, 0.2*cm))


def _build_mitre_attack(story: list, analysis: dict) -> None:
    """Corrélation MITRE ATT&CK — techniques déterminées depuis les outils exécutés
    (voir utils/mitre_attack.py), pas une production libre du LLM."""
    techniques = analysis.get('mitre_attack') or []
    if not techniques:
        return

    story.extend(_section('Corrélation MITRE ATT&CK', '◆'))
    story.append(Paragraph(
        f'<b>{len(techniques)}</b> technique(s) de la matrice '
        f'<a href="https://attack.mitre.org/" color="{_hex(C_CYAN)}">ATT&amp;CK</a> '
        f'corrélée(s) aux outils de reconnaissance exécutés.',
        S['body_l'],
    ))
    story.append(Spacer(1, 0.3*cm))

    hdr = [Paragraph(t, S['th']) for t in
           ['Tactique', 'Technique', 'Outils source', 'Recommandation']]
    rows = [hdr]
    for tech in techniques:
        rows.append([
            Paragraph(_safe(tech.get('tactic', '')), S['td']),
            Paragraph(
                f"<b>{_safe(tech.get('technique_id', ''))}</b><br/>{_safe(tech.get('technique_name', ''))}",
                S['td'],
            ),
            Paragraph(_safe(', '.join(tech.get('matched_tools') or [])), S['td']),
            Paragraph(_safe(tech.get('advice', '')), S['td']),
        ])

    tbl = Table(rows, colWidths=[2.5*cm, 5*cm, 3*cm, 6*cm])
    style = list(_BASE_TBL_STYLE) + [
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
    ] + _alt_rows(len(rows))
    tbl.setStyle(TableStyle(style))
    story.append(tbl)
    story.append(Spacer(1, 0.3*cm))

    notes = [t for t in techniques if t.get('note')]
    if notes:
        for t in notes:
            story.append(Paragraph(
                f"<font color=\"{_hex(colors.HexColor('#f59e0b'))}\">⚠</font> "
                f"<b>{_safe(t.get('technique_id', ''))}</b> — {_safe(t.get('note', ''))}",
                S['bullet'],
            ))
        story.append(Spacer(1, 0.3*cm))


def _build_attack_chain(story: list, analysis: dict) -> None:
    """Chaîne d'attaque plausible (phase 4) — structure déterministe
    (utils/attack_enablement.py::build_attack_chain), pas une production du LLM."""
    chain = analysis.get('_attack_chain') or []
    if not chain:
        return

    story.extend(_section("Chaîne d'Attaque Plausible", '◆'))
    story.append(Paragraph(
        "Enchaînement que les constats rendent <b>possible</b> pour un attaquant, déduit d'une "
        "table déterministe (référentiel MITRE ATT&amp;CK Enterprise "
        f"v{_safe(analysis.get('_attack_version') or '?')}). Ce n'est pas une attaque observée.",
        S['body_l'],
    ))
    story.append(Spacer(1, 0.3*cm))

    hdr = [Paragraph(t, S['th']) for t in ['Étape', 'Tactique', 'Techniques', 'Constats']]
    rows = [hdr]
    for step in chain:
        techs = _attack_items(step.get('techniques'), _TECH_ID_RE)
        sev = str(step.get('max_severity') or 'INFO').upper()
        sc = SEV_C.get(sev, C_MUTED)
        rows.append([
            Paragraph(f"<b>{_safe(step.get('order', ''))}.</b> {_safe(step.get('label', ''))}<br/>"
                      f"<font color=\"{_hex(sc)}\"><b>{_safe(sev)}</b></font>", S['td']),
            Paragraph(f"{_safe(step.get('tactic', ''))}<br/><font name=\"Courier\">{_safe(step.get('tactic_id', ''))}</font>",
                      S['td']),
            Paragraph('<br/>'.join(techs) or '—', S['td']),
            Paragraph(_safe(', '.join(str(x) for x in (step.get('finding_ids') or [])[:12])), S['td']),
        ])

    tbl = Table(rows, colWidths=[3.4*cm, 3.2*cm, 7*cm, 2.9*cm])
    tbl.setStyle(TableStyle(list(_BASE_TBL_STYLE) + [
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
        ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
    ] + _alt_rows(len(rows))))
    story.append(tbl)
    story.append(Spacer(1, 0.4*cm))


def _build_strengths(story: list, analysis: dict) -> None:
    strengths = analysis.get('strengths', []) or []
    if not strengths:
        return
    story.extend(_section('Points Forts', '◆'))
    for s in strengths:
        story.append(Paragraph(
            f'<font color="{_hex(colors.HexColor("#10b981"))}"><b>✓</b></font>  {_safe(s)}',
            S['bullet'],
        ))
    story.append(Spacer(1, 0.3*cm))


def _build_actions(story: list, analysis: dict) -> None:
    actions = analysis.get('immediate_actions', []) or []
    if not actions:
        return
    story.extend(_section('Actions Immédiates', '◆'))

    prio_lbl = {1: ('URGENT — Maintenant', SEV_C['CRITICAL']),
                2: ('Cette semaine',        SEV_C['HIGH']),
                3: ('Ce mois',              colors.HexColor('#10b981'))}
    prio_bg  = {1: colors.HexColor('#fef2f2'),
                2: colors.HexColor('#fff7ed'),
                3: colors.HexColor('#f0fdf4')}

    for act in actions[:15]:
        prio   = int(act.get('priority', 3))
        action = _safe(act.get('action', ''))
        lbl, bc = prio_lbl.get(prio, (f'Priorité {prio}', C_MUTED))
        bg      = prio_bg.get(prio, C_OFF)

        row = Table(
            [[Paragraph(f'P{prio}', _ps('_ap', fontName='Helvetica-Bold', fontSize=12,
                                         textColor=bc, alignment=TA_CENTER)),
              Paragraph(lbl, _ps('_al', fontName='Helvetica-Bold', fontSize=8.5, textColor=bc)),
              Paragraph(action, S['body_l'])]],
            colWidths=[1*cm, 4.5*cm, None],
        )
        row.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg),
            ('LINEBEFORE',  (0, 0), (0, 0), 4, bc),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('BOX',        (0, 0), (-1, -1), 0.3, C_BORDER),
        ]))
        story.append(row)
        story.append(Spacer(1, 0.18*cm))

    story.append(Spacer(1, 0.2*cm))


def _build_metadata(story: list, analysis: dict, recon: Any, timing: dict) -> None:
    story.extend(_section('Métadonnées Techniques', '◆'))

    model    = _safe(analysis.get('model_used', '—'))
    srch     = analysis.get('searches_performed', []) or []
    anal_at  = analysis.get('analyzed_at', '—')
    try:
        anal_at = datetime.fromisoformat(
            anal_at.replace('Z', '+00:00')
        ).strftime('%d/%m/%Y %H:%M:%S UTC')
    except Exception:
        pass

    rows = [
        ('Modèle IA utilisé',          model),
        ('Recherches web effectuées',   str(len(srch))),
        ("Date d'analyse IA",           anal_at),
        ('Durée scan OSINT',            _fmt_s(timing.get('scan_duration_s'))),
        ('Durée analyse IA',            _fmt_s(timing.get('analysis_duration_s'))),
        ('Durée totale du processus',   _fmt_s(timing.get('total_duration_s'))),
    ]
    if recon:
        rows += [
            ('Enregistrement ID',  _safe(getattr(recon, 'id', '—'))),
            ('Domaine',            _safe(getattr(recon, 'domain', '—'))),
            ('Demandeur',          f"{_safe(getattr(recon,'firstname',''))} {_safe(getattr(recon,'lastname',''))}".strip()),
            ('Email',              _safe(getattr(recon, 'email', '—'))),
        ]

    story.append(_kv_table(rows))

    if srch:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph('<b>Détail des recherches web effectuées</b>', S['h2']))
        srch_hdr = [Paragraph('#', S['th_c']), Paragraph('Requête de recherche', S['th']),
                    Paragraph('Résultats', S['th_c'])]
        srch_rows = [srch_hdr]
        for j, s in enumerate(srch[:20], 1):
            srch_rows.append([
                Paragraph(str(j), S['td_c']),
                Paragraph(_safe(s.get('query', '')), S['td']),
                Paragraph(str(s.get('results_count', 0)), S['td_c']),
            ])
        st = Table(srch_rows, colWidths=[0.9*cm, None, 2.2*cm])
        srch_style = list(_BASE_TBL_STYLE) + [
            ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ] + _alt_rows(len(srch_rows))
        st.setStyle(TableStyle(srch_style))
        story.append(st)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION INFRASTRUCTURE — présentation des données brutes OSINT
# ══════════════════════════════════════════════════════════════════════════════

def _g(d: dict, *keys):
    """Accès sécurisé en profondeur dans un dict."""
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _mini_table(rows: list, col1_w: float = 4.5*cm) -> Table:
    """Table compacte clé/valeur sans header."""
    ps_k = _ps('_mk', fontName='Helvetica-Bold', fontSize=8.5, textColor=C_SLATE)
    ps_v = _ps('_mv', fontSize=8.5, textColor=C_TEXT)
    data = [[Paragraph(_safe(k), ps_k), Paragraph(_safe(v), ps_v)] for k, v in rows if v and v != '—']
    if not data:
        return None
    tbl = Table(data, colWidths=[col1_w, None])
    tbl.setStyle(TableStyle([
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('LINEBELOW',     (0, 0), (-1, -2), 0.3, C_BORDER),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_WHITE, C_OFF]),
        ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))
    return tbl


def _tool_meta(d: dict, *tool_keys) -> tuple:
    """
    Titre et légende d'une carte à partir des métadonnées RÉELLES du scan
    (``<outil>.meta.tool`` / ``<outil>.meta.description``) plutôt que de
    libellés codés en dur. Retourne (titre, légende, clés_présentes).
    """
    names, keys, caption = [], [], ''
    for k in tool_keys:
        name = _g(d, k, 'meta', 'tool')
        if not name:
            continue
        keys.append(k)
        if str(name) not in names:
            names.append(str(name))
        if not caption:
            desc = _g(d, k, 'meta', 'description')
            if desc:
                caption = str(desc)
    return ' + '.join(names), caption, keys


def _card_caption(text: str, tool_keys: list = None) -> Paragraph:
    """Légende sous l'en-tête d'une carte : description officielle de l'outil."""
    if not text:
        return None
    txt = _safe(str(text))
    if len(txt) > 300:
        txt = txt[:297] + '…'
    src = ''
    if tool_keys:
        src = ' <font name="Courier">[' + ', '.join(_safe(k) for k in tool_keys) + ']</font>'
    ps = _ps('_icap', fontSize=7.5, textColor=C_MUTED, leading=10,
             backColor=C_OFF, borderPadding=(5, 8, 5, 8))
    return Paragraph(txt + src, ps)


def _infra_card(story: list, title: str, icon: str, rows: list,
                col1_w: float = 4.5*cm, extra: list = None,
                caption: str = None, tool_keys: list = None) -> None:
    """Carte d'infrastructure avec titre coloré, légende outil et table clé/valeur."""
    ps_ct = _ps('_ict', fontName='Helvetica-Bold', fontSize=10,
                textColor=C_WHITE, spaceAfter=0)
    ps_ci = _ps('_ici', fontName='Helvetica-Bold', fontSize=10,
                textColor=C_CYAN, spaceAfter=0)
    hdr = Table(
        [[Paragraph(icon + '  ', ps_ci), Paragraph(title, ps_ct)]],
        colWidths=[0.7*cm, None],
    )
    hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), C_NAVY),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    cap = _card_caption(caption, tool_keys)
    tbl = _mini_table(rows, col1_w) if rows else None
    content = ([hdr] + ([cap] if cap is not None else [])
               + ([tbl] if tbl is not None else [])
               + [f for f in (extra or []) if f is not None])
    story.append(KeepTogether(content))
    story.append(Spacer(1, 0.35*cm))


def _pill(text: str, bg: colors.Color, fg: colors.Color = None) -> Paragraph:
    """Badge coloré inline."""
    fg_hex = _hex(fg or C_WHITE)
    bg_hex = _hex(bg)
    ps = _ps('_pill', fontSize=7.5, fontName='Helvetica-Bold',
             textColor=fg or C_WHITE,
             backColor=bg,
             borderPadding=(2, 5, 2, 5))
    return Paragraph(
        f'<font color="{fg_hex}" name="Helvetica-Bold">{_safe(text)}</font>',
        _ps('_pillp', fontSize=7.5, fontName='Helvetica-Bold',
            textColor=fg or C_WHITE, backColor=bg,
            borderPadding=(2, 5, 2, 5))
    )


def _build_infrastructure(story: list, scan_data: dict) -> None:
    """
    Section 'Présentation de l'Infrastructure' basée sur les données brutes OSINT.
    Insérée avant la section Analyse IA pour contextualiser les findings.
    """
    if not scan_data:
        return

    d = scan_data.get("data", scan_data)

    story.extend(_section('Présentation de l\'Infrastructure', '◆'))
    ps_intro = _ps('_intro', fontSize=9, textColor=C_MUTED, leading=14, spaceAfter=4)
    story.append(Paragraph(
        'Cartographie complète de l\'infrastructure cible issue de la reconnaissance passive OSINT. '
        'Ces données factuelles constituent la base de l\'analyse de sécurité.',
        ps_intro,
    ))
    story.append(Spacer(1, 0.3*cm))

    # ── 1. WHOIS / RDAP — Identité du domaine ────────────────────────────────
    whois = _g(d, 'whois', 'data') or _g(d, 'whois_info', 'data') or {}
    rdap  = _g(d, 'rdap_info', 'data') or {}
    dns_records_raw = _g(d, 'dns_records', 'data') or {}

    def _first_or_str(v):
        """Retourne le premier élément si liste, sinon la valeur directe."""
        if isinstance(v, list):
            return str(v[0]) if v else '—'
        return str(v) if v else '—'

    if whois or rdap:
        registrar_v     = _first_or_str(whois.get('registrar') or whois.get('Registrar') or '—')
        creation_v      = _first_or_str(whois.get('creation_date') or whois.get('Creation Date') or '—')
        expiration_v    = _first_or_str(whois.get('expiration_date') or whois.get('Registry Expiry Date') or '—')
        updated_v       = _first_or_str(whois.get('updated_date') or whois.get('Updated Date') or '—')
        status_raw      = whois.get('status') or whois.get('Status') or '—'
        status_v        = (_first_or_str(status_raw))[:80]
        registrant_org  = str(whois.get('registrant_org') or whois.get('Registrant Organization') or '—')
        registrant_name = str(whois.get('registrant_name') or whois.get('Registrant Name') or '—')
        registrant_email= str(whois.get('registrant_email') or whois.get('Registrant Email') or '—')
        registrant_ctry = str(whois.get('registrant_country') or whois.get('Registrant Country') or '—')
        # Serveurs NS depuis dns_records.data.NS
        ns_list         = dns_records_raw.get('NS') if isinstance(dns_records_raw, dict) else None
        ns_v            = ', '.join([str(x) for x in ns_list[:6]]) if isinstance(ns_list, list) and ns_list else '—'
        rows = [
            ('Registraire',          registrar_v),
            ('Date création',        creation_v),
            ('Date expiration',      expiration_v),
            ('Mise à jour',          updated_v),
            ('Statut',               status_v),
            ('Organisation',         registrant_org),
            ('Nom registrant',       registrant_name),
            ('Email registrant',     registrant_email),
            ('Pays registrant',      registrant_ctry),
            ('Serveurs NS',          ns_v),
        ]

        # Données RDAP normalisées (RFC 9083) — complètent le WHOIS textuel
        if rdap:
            rdap_events = rdap.get('events') if isinstance(rdap.get('events'), dict) else {}
            rdap_status = rdap.get('status') or []
            rdap_ns     = rdap.get('nameservers') or []
            rows += [
                ('Registraire (RDAP)',   str(rdap.get('registrar') or '—')),
                ('ID IANA registraire',  str(rdap.get('registrar_iana_id') or '—')),
                ('Création (RDAP)',      str(rdap_events.get('registration') or '—')),
                ('Expiration (RDAP)',    str(rdap_events.get('expiration') or '—')),
                ('Statuts EPP (RDAP)',   ', '.join(str(x) for x in rdap_status[:6]) if isinstance(rdap_status, list) and rdap_status else '—'),
                ('NS déclarés (RDAP)',   ', '.join(str(x) for x in rdap_ns[:6]) if isinstance(rdap_ns, list) and rdap_ns else '—'),
                ('DNSSEC délégué (RDAP)', 'Oui ✓' if rdap.get('dnssec_delegated') else ('Non ✗' if rdap.get('dnssec_delegated') is False else '—')),
                ('Contact abuse (RDAP)', str(rdap.get('abuse_email') or '—')),
            ]
        _t, _cap, _keys = _tool_meta(d, 'whois', 'whois_info', 'rdap_info')
        _infra_card(story, _t or 'WHOIS — Identité du Domaine', '🏢', rows,
                    caption=_cap, tool_keys=_keys)

    # ── 2. Réseau & IP ────────────────────────────────────────────────────────
    ip_info_data = _g(d, 'ip_info', 'data') or {}
    ptr_data     = _g(d, 'ptr_records', 'data') or {}
    dnsbl        = _g(d, 'dnsbl_check', 'data') or {}

    ip_list      = ip_info_data.get('ips') or []
    first_ip     = ip_list[0] if ip_list else {}
    ip_addr      = str(first_ip.get('ip') or '—') if isinstance(first_ip, dict) else '—'
    hostname_v   = str(first_ip.get('hostname') or '—') if isinstance(first_ip, dict) else '—'
    city_v       = str(first_ip.get('city') or '—') if isinstance(first_ip, dict) else '—'
    region_v     = str(first_ip.get('region') or '—') if isinstance(first_ip, dict) else '—'
    country_v    = str(first_ip.get('country') or '—') if isinstance(first_ip, dict) else '—'
    org_v        = str(first_ip.get('org') or '—') if isinstance(first_ip, dict) else '—'

    ptr_records  = ptr_data.get('records') or []
    first_ptr    = ptr_records[0] if ptr_records else {}
    ptr_v        = str(first_ptr.get('ptr') or '—') if isinstance(first_ptr, dict) else '—'
    cloud_v      = '—'
    if isinstance(first_ptr, dict) and first_ptr.get('is_cloud'):
        cloud_v  = str(first_ptr.get('cloud_provider') or 'Oui')

    dnsbl_total  = dnsbl.get('total_checks') or 0
    dnsbl_str    = (f'Propre ✓ ({dnsbl_total} listes vérifiées)' if dnsbl.get('clean')
                   else ('⚠ Listé' if dnsbl else '—'))

    net_rows = [
        ('Adresse IP',         ip_addr),
        ('Hostname',           hostname_v),
        ('Ville',              city_v),
        ('Région',             region_v),
        ('Pays réseau',        country_v),
        ('Organisation',       org_v),
        ('Cloud provider',     cloud_v),
        ('Reverse DNS (PTR)',  ptr_v),
        ('Liste noire DNSBL',  dnsbl_str),
    ]
    _t, _cap, _keys = _tool_meta(d, 'ip_info', 'ptr_records', 'asn_info', 'dnsbl_check')
    _infra_card(story, _t or 'Réseau & Adressage IP', '🌐', net_rows,
                caption=_cap, tool_keys=_keys)

    # ── 3. DNS ────────────────────────────────────────────────────────────────
    dns_records = dns_records_raw
    dnssec = _g(d, 'dnssec', 'data') or {}

    def _rec(rtype):
        v = dns_records.get(rtype) if isinstance(dns_records, dict) else None
        if isinstance(v, list):
            return ', '.join([str(x) for x in v[:5]])
        return str(v) if v else '—'

    dns_rows = [
        ('Enregistrements A',    _rec('A')),
        ('Enregistrements AAAA', _rec('AAAA')),
        ('MX (messagerie)',      _rec('MX')),
        ('NS (serveurs de noms)',_rec('NS')),
        ('TXT',                  _rec('TXT')[:200] if _rec('TXT') != '—' else '—'),
        ('CNAME',                _rec('CNAME')),
        ('SOA',                  _rec('SOA')[:120] if _rec('SOA') != '—' else '—'),
        ('DNSSEC activé',        'Oui ✓' if dnssec.get('enabled') else 'Non ✗'),
        ('Note sécurité DNS',    str(dnssec.get('security_note') or '—')[:150]),
    ]
    _t, _cap, _keys = _tool_meta(d, 'dns_records', 'dnssec')
    _infra_card(story, _t or 'DNS — Enregistrements & DNSSEC', '🔍', dns_rows,
                caption=_cap, tool_keys=_keys)

    # ── 4. SSL / TLS ──────────────────────────────────────────────────────────
    ssl_info = _g(d, 'ssl_info', 'data') or {}
    tls_conf = _g(d, 'tls_config', 'data') or {}

    subject_v   = ssl_info.get('subject') or {}
    ssl_cn      = str(subject_v.get('commonName') or '—') if isinstance(subject_v, dict) else str(subject_v or '—')
    issuer_v    = ssl_info.get('issuer') or {}
    issuer_org  = str(issuer_v.get('organizationName') or '—') if isinstance(issuer_v, dict) else '—'
    issuer_cn   = str(issuer_v.get('commonName') or '') if isinstance(issuer_v, dict) else ''
    issuer_str  = f'{issuer_org} ({issuer_cn})' if issuer_cn else issuer_org

    san_list    = ssl_info.get('san') or []
    san_v       = ', '.join([str(x) for x in san_list]) if isinstance(san_list, list) else str(san_list or '—')
    san_count   = ssl_info.get('san_count') or (len(san_list) if isinstance(san_list, list) else 0)

    days_left   = ssl_info.get('days_until_expiry')
    expired_v   = ssl_info.get('expired')
    if expired_v is True:
        cert_status = 'Expiré ✗'
    elif expired_v is False:
        cert_status = f'Valide ✓ ({days_left} jours restants)' if days_left is not None else 'Valide ✓'
    else:
        cert_status = '—'

    tls_proto   = str(ssl_info.get('tls_version') or tls_conf.get('protocol') or '—')
    cipher_raw  = tls_conf.get('cipher') or ssl_info.get('cipher')
    if isinstance(cipher_raw, dict):
        # Formaté lisiblement plutôt que le repr Python brut ("{'name': ...}")
        # constaté dans un rapport réel — voir aussi le cas DKIM plus bas.
        _bits = cipher_raw.get('bits')
        cipher_v = cipher_raw.get('name') or '—'
        if cipher_raw.get('protocol'):
            cipher_v += f" ({cipher_raw['protocol']}{f', {_bits} bits' if _bits else ''})"
    else:
        cipher_v = str(cipher_raw or '—')
    cipher_v = cipher_v[:100]

    ssl_rows = [
        ('Sujet CN',            ssl_cn[:100]),
        ('Émetteur',            issuer_str[:120]),
        ('SAN (domaines)',      (san_v[:200] if san_v != '—' else '—') + f' ({san_count} entrées)'),
        ('Valide du',           str(ssl_info.get('not_before') or '—')),
        ('Valide jusqu\'au',    str(ssl_info.get('not_after') or '—')),
        ('Statut certificat',   cert_status),
        ('Protocole TLS',       tls_proto),
        ('Cipher suite',        cipher_v),
    ]
    _t, _cap, _keys = _tool_meta(d, 'ssl_info', 'tls_config')
    _infra_card(story, _t or 'SSL / TLS — Certificat', '🔒', ssl_rows,
                caption=_cap, tool_keys=_keys)

    # ── 5. Web & Technologies ────────────────────────────────────────────────
    tech_stack  = _g(d, 'tech_stack', 'data') or {}
    waf         = _g(d, 'waf_detection', 'data') or {}
    sec_headers = _g(d, 'security_headers', 'data') or {}
    redirect    = _g(d, 'redirect_chain', 'data') or {}
    js_ep       = _g(d, 'js_endpoints', 'data') or {}

    server_v    = str(tech_stack.get('server') or '—')
    powered_v   = str(tech_stack.get('powered_by') or '—')
    cms_list    = tech_stack.get('cms') or []
    cms_v       = ', '.join([str(x) for x in cms_list]) if isinstance(cms_list, list) and cms_list else '—'
    js_fw_list  = tech_stack.get('javascript_frameworks') or []
    js_fw_v     = ', '.join([str(x) for x in js_fw_list]) if isinstance(js_fw_list, list) and js_fw_list else '—'
    cdn_list    = tech_stack.get('cdn') or []
    cdn_v       = ', '.join([str(x) for x in cdn_list]) if isinstance(cdn_list, list) and cdn_list else '—'

    waf_protected = waf.get('protected') if isinstance(waf, dict) else None
    waf_detected  = waf.get('detected') or []
    waf_server    = waf.get('server') or '—'
    if waf_protected:
        # waf_detected est une liste de dicts {"name","confidence","indicators"}
        # (routes/recon.py::_waf_detection) — extraire le nom plutôt que le
        # repr Python brut ("{'name': ...}"), même bug que cipher/DKIM ci-dessus.
        _waf_names = [
            (x.get('name') if isinstance(x, dict) else str(x)) for x in waf_detected
        ]
        waf_str = 'Protégé ✓ : ' + (', '.join(n for n in _waf_names if n) if _waf_names else 'WAF détecté')
    else:
        waf_str = f'Non protégé ✗ (serveur : {waf_server})'

    sec_grade   = str(sec_headers.get('grade') or '—')
    sec_score   = sec_headers.get('score')
    sec_max     = sec_headers.get('max_score')
    grade_str   = f'{sec_grade} ({sec_score}/{sec_max})' if sec_score is not None and sec_max is not None else sec_grade

    miss_list   = sec_headers.get('missing_headers') or []
    miss_v      = ', '.join([str(x) for x in miss_list]) if isinstance(miss_list, list) and miss_list else 'Aucun ✓'
    # BUG CORRIGÉ (2026-07-29) : `sec_headers['headers']` (routes/recon.py::
    # _security_headers) contient une entrée pour les 9 en-têtes ANALYSÉS,
    # présents ET absents (chacun avec son propre champ `present`) — pas
    # seulement ceux réellement présents. Prendre `.keys()` sans filtrer
    # listait donc les 9 en-têtes ici ET dans « Headers manquants »
    # simultanément (contradiction constatée sur un rapport réel : HSTS/CSP/…
    # affichés à la fois présents et manquants, provoquant un faux finding
    # IA « HSTS non configuré » alors que l'en-tête était bien présent).
    all_hdrs_dict     = sec_headers.get('headers') or {}
    present_hdrs_dict = (
        {k: v for k, v in all_hdrs_dict.items() if isinstance(v, dict) and v.get('present')}
        if isinstance(all_hdrs_dict, dict) else {}
    )
    present_v   = ', '.join(list(present_hdrs_dict.keys())[:10]) if present_hdrs_dict else '—'

    redir_hops     = redirect.get('hops') or '—'
    redir_final    = str(redirect.get('final_url') or '—')[:150]
    redir_v        = f'{redir_hops} hop(s) → {redir_final}'

    js_files_count    = js_ep.get('js_files_count') or 0
    js_endpoint_count = js_ep.get('endpoint_count') or (len(js_ep.get('endpoints') or []))
    js_interesting    = js_ep.get('interesting') or []
    if js_files_count == 0 and js_endpoint_count == 0:
        js_v = '—'
    else:
        js_v = f'{js_endpoint_count} endpoint(s) dans {js_files_count} fichier(s) JS'
        if js_interesting:
            js_v += f' — {len(js_interesting)} chemin(s) sensible(s)'

    # Robots.txt
    robots_d    = _g(d, 'robots_txt', 'data') or {}
    robots_stat = _g(d, 'robots_txt', 'status') or '—'
    robots_total      = robots_d.get('total_disallowed') or 0
    robots_interesting = robots_d.get('interesting_paths') or []
    if robots_stat == 'not_found':
        robots_v = 'Absent (HTTP 404)'
    elif robots_total:
        paths = [p.get('path', '') for p in robots_interesting[:5]] if isinstance(robots_interesting, list) else []
        robots_v = f'{robots_total} chemin(s) disallow'
        if paths:
            robots_v += f' — sensibles : {", ".join(paths)}'
    elif robots_stat == 'success':
        robots_v = 'Présent — aucun chemin disallow'
    else:
        robots_v = '—'

    web_rows = [
        ('Serveur',                   server_v),
        ('Propulsé par',              powered_v),
        ('CMS',                       cms_v),
        ('Frameworks JS',             js_fw_v),
        ('CDN',                       cdn_v),
        ('Pare-feu (WAF)',            waf_str[:150]),
        ('Grade headers sécurité',    grade_str),
        ('Headers manquants',         miss_v[:200]),
        ('Headers présents',          present_v[:200]),
        ('Redirections',              redir_v),
        ('Endpoints JS détectés',     js_v),
        ('Robots.txt',                robots_v[:200]),
        ('security.txt',              str(_g(d, 'security_txt', 'status') or '—')),
    ]
    _t, _cap, _keys = _tool_meta(d, 'tech_stack', 'security_headers', 'waf_detection',
                                 'redirect_chain', 'js_endpoints')
    _infra_card(story, _t or 'Web — Technologies & Configuration', '💻', web_rows,
                caption=_cap, tool_keys=_keys)

    # ── 6. Email ──────────────────────────────────────────────────────────────
    email_conf = _g(d, 'email_config', 'data') or {}
    dkim       = _g(d, 'dkim_check', 'data') or {}
    spf_a      = _g(d, 'spf_analysis', 'data') or {}

    mx_list    = email_conf.get('mx') or []
    mx_v       = ', '.join([str(x) for x in mx_list]) if isinstance(mx_list, list) else str(mx_list or '—')
    spf_val    = str(email_conf.get('spf') or '—')[:150]
    spf_status = str(email_conf.get('spf_status') or '—')
    spf_mech   = str(spf_a.get('all_mechanism') or '—')
    spf_risk   = str(spf_a.get('all_risk') or '—')
    ip4_ranges = spf_a.get('ip4_ranges') or []
    ip4_v      = ', '.join([str(x) for x in ip4_ranges[:3]]) if isinstance(ip4_ranges, list) and ip4_ranges else '—'

    dmarc_v    = str(email_conf.get('dmarc') or '—')[:150]
    dmarc_pol  = str(email_conf.get('dmarc_policy') or '—')

    dkim_found = dkim.get('found') or []
    dkim_count = dkim.get('count') or 0
    if isinstance(dkim_found, list) and dkim_found:
        def _fmt_dkim(entry):
            # Formaté lisiblement plutôt que le repr Python brut d'un dict
            # ("{'selector': 'default', ...}") constaté dans un rapport réel.
            if not isinstance(entry, dict):
                return str(entry)
            sel = entry.get('selector', '?')
            bits = []
            if entry.get('provider'):
                bits.append(str(entry['provider']))
            if entry.get('algorithm'):
                bits.append(str(entry['algorithm']))
            bits.append('clé présente' if entry.get('has_key') else 'clé absente')
            return f"{sel} ({', '.join(bits)})"
        dkim_v = ', '.join(_fmt_dkim(x) for x in dkim_found)
    else:
        dkim_v = f'Aucun sélecteur trouvé (0/{dkim_count} testés)' if dkim_count else 'Aucun sélecteur trouvé'

    email_rows = [
        ('Serveurs MX',            mx_v[:200]),
        ('SPF',                    f'{spf_val} [{spf_status}]'),
        ('Mécanisme SPF (all)',     f'{spf_mech} — risque : {spf_risk}'),
        ('IP4 ranges autorisées',  ip4_v),
        ('DMARC',                  f'{dmarc_v} [politique : {dmarc_pol}]'),
        ('DKIM sélecteurs',        dkim_v[:200]),
    ]
    _t, _cap, _keys = _tool_meta(d, 'email_config', 'spf_analysis', 'dkim_check')
    _infra_card(story, _t or 'Email — Protocoles de Sécurité', '✉', email_rows,
                caption=_cap, tool_keys=_keys)

    # ── 7. Sous-domaines ─────────────────────────────────────────────────────
    all_subs  = _g(d, 'all_subdomains', 'data') or []
    sub_count = _g(d, 'all_subdomains', 'count') or len(all_subs)
    takeover  = _g(d, 'subdomain_takeover', 'data') or {}

    vuln_count    = takeover.get('vulnerable_count') if isinstance(takeover, dict) else 0
    risk_level    = str(takeover.get('risk_level') or '—') if isinstance(takeover, dict) else '—'
    checked_count = takeover.get('checked_count') if isinstance(takeover, dict) else '—'

    sub_rows = [
        ('Total découverts',    str(sub_count)),
        ('Risques de takeover', f'{vuln_count} vulnérable(s) — niveau : {risk_level}'),
        ('Sous-domaines vérifiés', str(checked_count)),
    ]

    # Liste des sous-domaines en tableau compact
    sub_extra = []
    display_subs = [str(s) for s in all_subs[:30] if s] if isinstance(all_subs, list) else []
    if display_subs:
        ps_sub = _ps('_sub', fontSize=7.5, textColor=C_TEXT, leading=11)
        ps_th  = _ps('_subth', fontSize=7.5, fontName='Helvetica-Bold', textColor=C_WHITE)
        cols = 3
        padded = display_subs + [''] * (cols - len(display_subs) % cols if len(display_subs) % cols else 0)
        rows_data = [[Paragraph(s, ps_sub) for s in padded[i:i+cols]] for i in range(0, len(padded), cols)]
        rows_data.insert(0, [Paragraph(f'Sous-domaines découverts (premiers {len(display_subs)}/{sub_count})', ps_th)] + [Paragraph('', ps_th)] * (cols - 1))
        sub_tbl = Table(rows_data, colWidths=[(PAGE_W - 3*cm) / cols] * cols)
        sub_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY),
            ('SPAN',          (0, 0), (-1, 0)),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_OFF]),
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID',     (0, 0), (-1, -1), 0.2, C_BORDER),
        ]))
        sub_extra = [Spacer(1, 0.2*cm), sub_tbl]

    _t, _cap, _keys = _tool_meta(d, 'crtsh', 'subfinder', 'assetfinder', 'amass',
                                 'github', 'subdomain_takeover')
    _infra_card(story, f'{_t or "Sous-domaines"} ({sub_count} découverts)', '🔎', sub_rows,
                extra=sub_extra, caption=_cap, tool_keys=_keys)

    # ── 7b. En-têtes HTTP par sous-domaine ───────────────────────────────────
    headers_per_sub = _g(d, 'headers', 'data') or {}
    if isinstance(headers_per_sub, dict) and headers_per_sub:
        ps_th_s = _ps('_hth', fontSize=7.5, fontName='Helvetica-Bold', textColor=C_WHITE)
        ps_td_s = _ps('_htd', fontSize=7.5, textColor=C_TEXT, leading=10)
        col_labels = ['Sous-domaine', 'Status', 'Scheme', 'Serveur', 'HSTS', 'CSP']
        hdr_row = [Paragraph(c, ps_th_s) for c in col_labels]
        tbl_data = [hdr_row]
        for sub_name, sub_info in list(headers_per_sub.items())[:20]:
            sub_data  = (sub_info.get('data') or {}) if isinstance(sub_info, dict) else {}
            http_st   = str(sub_data.get('http_status') or sub_info.get('status', '—') if isinstance(sub_info, dict) else '—')
            scheme    = str(sub_data.get('scheme') or '—')
            server    = str(sub_data.get('Server') or sub_data.get('server') or '—')[:35]
            hdrs_low  = {k.lower(): v for k, v in sub_data.items()}
            hsts_ok   = '✓' if hdrs_low.get('strict-transport-security') else '✗'
            csp_ok    = '✓' if hdrs_low.get('content-security-policy') else '✗'
            tbl_data.append([
                Paragraph(str(sub_name)[:45], ps_td_s),
                Paragraph(http_st, ps_td_s),
                Paragraph(scheme, ps_td_s),
                Paragraph(server, ps_td_s),
                Paragraph(hsts_ok, ps_td_s),
                Paragraph(csp_ok, ps_td_s),
            ])
        if len(tbl_data) > 1:
            cw = [(PAGE_W - 3*cm) * p for p in [0.35, 0.10, 0.10, 0.25, 0.10, 0.10]]
            sub_hdr_tbl = Table(tbl_data, colWidths=cw)
            sub_hdr_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, 0), C_NAVY),
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING',    (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING',   (0, 0), (-1, -1), 4),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
                ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_WHITE, C_OFF]),
                ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ('INNERGRID',     (0, 0), (-1, -1), 0.2, C_BORDER),
            ]))
            _t, _cap, _keys = _tool_meta(d, 'headers')
            _infra_card(story, f'{_t or "En-têtes HTTP par Sous-domaine"} '
                               f'({len(headers_per_sub)} analysés)', '🌐',
                        [], extra=[Spacer(1, 0.1*cm), sub_hdr_tbl],
                        caption=_cap, tool_keys=_keys)

    # ── 8. Informations complémentaires ──────────────────────────────────────
    archive  = _g(d, 'archive_history', 'data') or {}
    favicon  = _g(d, 'favicon_hash', 'data') or {}

    # Archive web — extraction des champs imbriqués
    archive_first_date = '—'
    archive_last_date  = '—'
    archive_pages      = '—'
    archive_age        = '—'
    archive_wayback    = '—'
    if archive and isinstance(archive, dict):
        first = archive.get('first_snapshot') or {}
        last  = archive.get('last_snapshot')  or {}
        if isinstance(first, dict) and first.get('date'):
            archive_first_date = f"{first['date']} (HTTP {first.get('status', '?')})"
        if isinstance(last, dict) and last.get('date'):
            archive_last_date = f"{last['date']} (HTTP {last.get('status', '?')})"
        if archive.get('total_pages_index') is not None:
            archive_pages = str(archive['total_pages_index'])
        if archive.get('age_note'):
            archive_age = str(archive['age_note'])[:150]
        if archive.get('wayback_url'):
            archive_wayback = str(archive['wayback_url'])[:150]

    # Favicon hash
    fav_md5    = str(favicon.get('md5') or '—') if isinstance(favicon, dict) else '—'
    fav_mmh3   = str(favicon.get('murmur3') or '—') if isinstance(favicon, dict) else '—'

    # URLs historiques distinctes (Wayback CDX collapse=urlkey)
    hist_urls  = archive.get('historical_urls') if isinstance(archive, dict) else None
    hist_count = archive.get('historical_urls_count') if isinstance(archive, dict) else None
    if hist_count is None and isinstance(hist_urls, list):
        hist_count = len(hist_urls)
    archive_urls_v = '—'
    if hist_count:
        trunc = ' (limite atteinte)' if (isinstance(archive, dict)
                                         and archive.get('historical_urls_truncated')) else ''
        archive_urls_v = f'{hist_count} URL(s) distincte(s) archivée(s){trunc}'

    # Shodan InternetDB — ports / CVE observés passivement
    shodan = _g(d, 'shodan_internetdb', 'data') or {}
    sh_ports = shodan.get('ports') or []
    sh_vulns = shodan.get('vulns') or []
    sh_cpes  = shodan.get('cpes') or []
    sh_ports_v = ', '.join(str(x) for x in sh_ports[:20]) if isinstance(sh_ports, list) and sh_ports else '—'
    sh_vulns_v = ', '.join(str(x) for x in sh_vulns[:12]) if isinstance(sh_vulns, list) and sh_vulns else '—'
    sh_cpes_v  = ', '.join(str(x) for x in sh_cpes[:6])[:200] if isinstance(sh_cpes, list) and sh_cpes else '—'

    # OTX passive DNS — historique des résolutions
    otx = _g(d, 'otx_passive_dns', 'data') or {}
    otx_ips = otx.get('unique_ips') or []
    otx_v = '—'
    if otx.get('count'):
        otx_v = (f"{otx.get('count')} résolution(s) historique(s) — "
                 f"{otx.get('unique_ip_count') or len(otx_ips)} IP distincte(s)")
    otx_ips_v = ', '.join(str(x) for x in otx_ips[:10]) if isinstance(otx_ips, list) and otx_ips else '—'

    # XposedOrNot — fuites de données du domaine (remplace l'ancien HIBP)
    hibp        = _g(d, 'xposedornot_breaches', 'data') or {}
    hibp_status = _g(d, 'xposedornot_breaches', 'status')
    if hibp.get('breach_count'):
        hibp_v = (f"{hibp['breach_count']} fuite(s) — "
                  f"{hibp.get('affected_accounts', 0)} compte(s) affecté(s)")
    elif hibp_status == 'success':
        hibp_v = 'Aucune fuite connue'
    elif hibp_status:
        hibp_v = f'Non exécuté ({hibp_status})'
    else:
        hibp_v = '—'
    hibp_top = hibp.get('top_breaches') or []
    hibp_top_v = ', '.join(str(x) for x in hibp_top[:6]) if isinstance(hibp_top, list) and hibp_top else '—'

    extra_rows = [
        ('1ère archive web',   archive_first_date),
        ('Dernière archive',   archive_last_date),
        ('Pages indexées',     archive_pages),
        ('URLs historiques',   archive_urls_v),
        ('Ancienneté domaine', archive_age),
        ('URL Wayback Machine',archive_wayback),
        ('Favicon MD5',        fav_md5),
        ('Favicon MurmurH3',   fav_mmh3),
        ('Ports vus (Shodan)', sh_ports_v),
        ('CVE vues (Shodan)',  sh_vulns_v),
        ('Logiciels CPE (Shodan)', sh_cpes_v),
        ('DNS passif (OTX)',   otx_v),
        ('IP historiques (OTX)', otx_ips_v),
        ('Fuites de données (HIBP)', hibp_v),
        ('Principales fuites', hibp_top_v),
    ]
    _t, _cap, _keys = _tool_meta(d, 'archive_history', 'favicon_hash',
                                 'shodan_internetdb', 'otx_passive_dns', 'xposedornot_breaches')
    _infra_card(story, 'Informations Complémentaires', '📋', extra_rows,
                caption=_cap, tool_keys=_keys)

    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION MÉTHODOLOGIE & SOURCES — traçabilité outil → conclusion
# ══════════════════════════════════════════════════════════════════════════════

# Couleur et libellé associés à chaque statut d'exécution d'outil
_STATUS_C = {
    'success':        colors.HexColor('#10b981'),
    'timeout_partial': colors.HexColor('#f59e0b'),
    'no_data':        colors.HexColor('#64748b'),
    'not_found':      colors.HexColor('#64748b'),
    'limited':        colors.HexColor('#f59e0b'),
    'skipped':        colors.HexColor('#94a3b8'),
    'unavailable':    colors.HexColor('#94a3b8'),
    'timeout':        colors.HexColor('#f97316'),
    'not_installed':  colors.HexColor('#f97316'),
    'unreachable':    colors.HexColor('#f97316'),
    'error':          colors.HexColor('#ef4444'),
}
_STATUS_LABEL = {
    'success':         'Succès',
    'timeout_partial': 'Partiel (timeout)',
    'no_data':         'Aucune donnée',
    'not_found':       'Non trouvé',
    'limited':         'Accès limité',
    'skipped':         'Ignoré (clé absente)',
    'unavailable':     'Service indisponible',
    'timeout':         'Timeout',
    'not_installed':   'Outil non installé',
    'unreachable':     'Injoignable',
    'error':           'Erreur',
}


def _collect_tools(scan_data: dict) -> list:
    """
    Inventaire des outils réellement exécutés, lu depuis les métadonnées du scan
    (``<outil>.meta`` + ``<outil>.status``) — aucune liste codée en dur.
    """
    d = (scan_data or {}).get('data', scan_data) or {}
    tools = []
    for key, value in d.items():
        if not isinstance(value, dict):
            continue
        meta = value.get('meta')
        if not isinstance(meta, dict) or not meta.get('tool'):
            continue
        duration = (value.get('duration_s') or value.get('duration')
                    or _g(value, 'data', 'duration_s'))
        tools.append({
            'key':      str(key),
            'name':     str(meta.get('tool')),
            'category': str(meta.get('category') or '—'),
            'status':   str(value.get('status') or '—'),
            'error':    value.get('error'),
            'duration': duration,
        })
    tools.sort(key=lambda t: (t['category'], t['name']))
    return tools


def _build_methodology(story: list, scan_data: dict, timing: dict = None,
                        analysis: Optional[dict] = None) -> None:
    """
    Section « Méthodologie & Sources » — liste chaque outil OSINT exécuté,
    sa catégorie, son statut et sa durée. Base de la traçabilité entre les
    findings (champ ``source_tool``) et les outils qui les ont produits.

    ``analysis`` (optionnel, rétrocompatible) : dict complet retourné par
    /analyze — si son champ ``grounding_check`` est présent (voir
    utils/grounding_check.py), un paragraphe additif en restitue le résumé.
    """
    tools = _collect_tools(scan_data)
    if not tools:
        return

    timing = timing or {}
    d = (scan_data or {}).get('data', scan_data) or {}

    story.append(PageBreak())
    story.extend(_section('Méthodologie & Sources', '◆'))

    ok = sum(1 for t in tools if t['status'] in ('success', 'timeout_partial'))
    story.append(Paragraph(
        f'Ce rapport repose exclusivement sur de la reconnaissance <b>passive</b> : '
        f'<b>{len(tools)}</b> outils OSINT ont été exécutés, dont <b>{ok}</b> ont produit des '
        f'données exploitables. Le champ « Outil source » de chaque finding renvoie à la clé '
        f'technique listée ci-dessous, ce qui rend chaque conclusion vérifiable et reproductible.',
        S['body_l'],
    ))
    story.append(Spacer(1, 0.3*cm))

    gc = (analysis or {}).get('grounding_check')
    if isinstance(gc, dict) and gc.get('total_findings'):
        story.append(Paragraph(
            f'<b>Contrôle d\'ancrage automatique</b> : sur <b>{gc["total_findings"]}</b> finding(s), '
            f'<b>{gc.get("verified", 0)}</b> ({gc.get("verified_pct", 0)}%) ont une correspondance '
            f'textuelle vérifiée entre la preuve citée et la donnée brute de l\'outil source. '
            f'Ce contrôle est déterministe (pas un second passage IA) : il prouve l\'ancrage factuel '
            f'de la preuve, pas l\'exactitude de son interprétation — il ne garantit donc pas '
            f'l\'absence totale d\'erreur d\'analyse.',
            S['small'],
        ))
        story.append(Spacer(1, 0.3*cm))

    scan_dur = _g(d, 'cache', 'scan_duration_s') or timing.get('scan_duration_s')
    ctx_rows = [
        ('Domaine analysé',       str(d.get('domain') or '—')),
        ('Date du scan',          str(_g(d, 'cache', 'cached_at') or '—')),
        ('Outils demandés',       str(len(d.get('tools_requested') or []) or len(tools))),
        ('Outils exécutés',       str(len(tools))),
        ('Durée totale du scan',  _fmt_s(scan_dur)),
        ('Résultat servi depuis le cache',
         'Oui' if _g(d, 'cache', 'hit') else 'Non (collecte en direct)'),
    ]
    ctx_tbl = _mini_table(ctx_rows, col1_w=6*cm)
    if ctx_tbl is not None:
        story.append(ctx_tbl)
        story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph('<b>Inventaire des outils exécutés</b>', S['h2']))
    hdr = [Paragraph(t, S['th']) for t in
           ['Clé (source_tool)', 'Outil', 'Catégorie']] + \
          [Paragraph('Statut', S['th_c']), Paragraph('Durée', S['th_c'])]
    rows = [hdr]
    for t in tools:
        st_key = t['status']
        st_c   = _STATUS_C.get(st_key, C_MUTED)
        st_lbl = _STATUS_LABEL.get(st_key, st_key)
        rows.append([
            Paragraph(_safe(t['key']), S['mono']),
            Paragraph(_safe(t['name']), S['td']),
            Paragraph(_safe(t['category']), S['td']),
            Paragraph(f'<font color="{_hex(st_c)}"><b>{_safe(st_lbl)}</b></font>', S['td_c']),
            Paragraph(_fmt_s(t['duration']) if t['duration'] else '—', S['td_c']),
        ])

    tbl = Table(rows, colWidths=[3.4*cm, 4.6*cm, None, 2.9*cm, 1.6*cm], repeatRows=1)
    tbl.setStyle(TableStyle(
        list(_BASE_TBL_STYLE) + [
            ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
            ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
        ] + _alt_rows(len(rows))
    ))
    story.append(tbl)

    # Outils n'ayant produit aucune donnée — transparence sur les limites du scan
    degraded = [t for t in tools if t['status'] not in ('success', 'timeout_partial')]
    if degraded:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph('<b>Limites de la collecte</b>', S['h2']))
        for t in degraded:
            reason = _safe(str(t['error'])[:220]) if t.get('error') else \
                _safe(_STATUS_LABEL.get(t['status'], t['status']))
            story.append(Paragraph(
                f'• <b>{_safe(t["name"])}</b> (<font name="Courier">{_safe(t["key"])}</font>) — {reason}',
                S['small'],
            ))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            'Aucune conclusion du rapport ne s\'appuie sur ces outils : les données absentes '
            'sont signalées comme non collectées, jamais extrapolées.',
            S['small'],
        ))

    _build_agent_journal(story, d)


def _build_agent_journal(story: list, d: dict) -> None:
    """
    Journal des pivots choisis par la boucle agent (phase 8,
    ``scan_results["agent_pivots"]``) : chaque décision, sa raison et son
    issue, refus de périmètre compris. Rien si la boucle n'a pas tourné.
    """
    entry = d.get('agent_pivots') if isinstance(d, dict) else None
    if not isinstance(entry, dict):
        return
    data = entry.get('data') if isinstance(entry.get('data'), dict) else {}

    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph('<b>Pivots choisis par l\'agent IA</b>', S['h2']))
    if entry.get('status') == 'skipped' or data.get('status') == 'skipped':
        reason = entry.get('error') or data.get('stop_reason') or 'désactivée'
        story.append(Paragraph(f'Boucle agent non exécutée : {_safe(str(reason)[:200])}.', S['small']))
        return

    backend = data.get('backend') if isinstance(data.get('backend'), dict) else {}
    usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
    budget = data.get('budget') if isinstance(data.get('budget'), dict) else {}
    story.append(Paragraph(
        f'Modèle : <b>{_safe(backend.get("name"))}</b> ({_safe(backend.get("model"))}) · '
        f'arrêt : {_safe(data.get("stop_reason"))} · '
        f'{_safe(usage.get("pivots_executed", 0))} pivot(s) exécuté(s), '
        f'{_safe(usage.get("pivots_refused", 0))} refusé(s), '
        f'budget {_safe(budget.get("max_pivots"))} pivots / profondeur {_safe(budget.get("max_depth"))}. '
        f'L\'agent ne peut appeler que des outils passifs d\'une liste blanche, sur des cibles '
        f'déjà observées dans le périmètre déclaré.',
        S['small'],
    ))
    decisions = [x for x in (data.get('decisions') or []) if isinstance(x, dict)][:40]
    if not decisions:
        return
    story.append(Spacer(1, 0.2*cm))
    rows = [[Paragraph(t, S['th']) for t in ('#', 'Outil', 'Cible', 'Raison', 'Issue')]]
    for x in decisions:
        args = x.get('arguments') if isinstance(x.get('arguments'), dict) else {}
        target = ', '.join(f'{v}' for k, v in args.items() if k != 'reason')[:80]
        refusal = x.get('refusal') if isinstance(x.get('refusal'), dict) else None
        outcome = x.get('outcome') or '—'
        if refusal:
            outcome = f'refusé ({refusal.get("code")})'
        elif x.get('result_status'):
            outcome = f'{outcome} · {x.get("result_status")}'
        rows.append([
            Paragraph(_safe(x.get('seq')), S['td_c']),
            Paragraph(_safe(x.get('tool')), S['mono']),
            Paragraph(_safe(target), S['mono']),
            Paragraph(_safe(str(x.get('reason') or '')[:240]), S['td']),
            Paragraph(_safe(str(outcome)[:60]), S['td']),
        ])
    tbl = Table(rows, colWidths=[0.8*cm, 3*cm, 4*cm, None, 3*cm], repeatRows=1)
    tbl.setStyle(TableStyle(
        list(_BASE_TBL_STYLE) + [
            ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
            ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
        ] + _alt_rows(len(rows))
    ))
    story.append(tbl)


# ══════════════════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE PUBLIC
# ══════════════════════════════════════════════════════════════════════════════

def generate_pdf(
    analysis: dict,
    recon: Any = None,
    timing: Optional[dict] = None,
    scan_data: Optional[dict] = None,
) -> bytes:
    """
    Génère le rapport PDF ReconIA complet.

    Args:
        analysis  : dict retourné par /analyze (champ ``data``)
        recon     : objet Recon SQLAlchemy (optionnel)
        timing    : {scan_duration_s, analysis_duration_s, total_duration_s}
        scan_data : JSON brut du scan passif (recon.scan_results parsé) —
                    utilisé pour la section « Présentation de l'Infrastructure »

    Returns:
        bytes du PDF généré
    """
    if timing is None:
        timing = {}

    domain = analysis.get('domain') or (recon.domain if recon else 'unknown')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.5*cm,
        rightMargin=1.5*cm,
        topMargin=1.6*cm,       # espace pour le header des pages contenu
        bottomMargin=1.4*cm,    # espace pour le footer
        title=f'Rapport OSINT — {domain}',
        author='ReconIA',
        subject='Rapport de Sécurité OSINT',
        creator='ReconIA — De la donnée à la décision — idachallenge.bj',
    )
    # Transmettre le domaine au callback _page_content via l'objet doc
    doc._report_domain = str(domain)

    # Phase 4 : constats annotés (techniques rendues possibles, mitigations)
    # et chaîne d'attaque, recalculés par la table déterministe.
    analysis = _with_attack(analysis)

    story: list = []
    _build_cover(story, analysis, recon, timing)
    _build_contents(story)
    _build_summary(story, analysis, scan_data or {})
    _build_exposure_maps(story, analysis, scan_data or {})
    _build_infrastructure(story, scan_data or {})   # ← NOUVEAU : présentation infra avant l'analyse
    _build_findings(story, analysis)
    _build_attack_surface(story, analysis)
    _build_mitre_attack(story, analysis)
    _build_attack_chain(story, analysis)
    _build_strengths(story, analysis)
    _build_actions(story, analysis)
    _build_metadata(story, analysis, recon, timing)
    _build_methodology(story, scan_data or {}, timing, analysis)   # traçabilité outil → conclusion

    doc.build(story, onFirstPage=_page_cover, onLaterPages=_page_content)
    return buf.getvalue()
