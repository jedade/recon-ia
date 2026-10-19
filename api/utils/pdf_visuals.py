# utils/pdf_visuals.py
"""
Graphiques vectoriels du rapport PDF (ReportLab, aucune image externe) :
jauge de score, donuts (sévérités, couverture de la collecte), barres par
catégorie, carte du monde des serveurs, cartographie de l'infrastructure.

Mêmes données et mêmes règles que la page « Voir le résultat »
(web/result-visuals.js) : un rapport PDF et la page racontent la même chose.
Toutes les valeurs viennent du scan (donc de la cible) : elles ne sont
dessinées que comme texte (String), jamais interprétées.
"""
import json
import math
import os
from typing import Any, Dict, List, Optional, Tuple

from reportlab.graphics.shapes import Circle, Drawing, Group, Line, Polygon, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.graphics.shapes import STATE_DEFAULTS

# Police des dessins : Helvetica comme le reste du rapport (défaut ReportLab :
# Times-Roman, en décalage avec la mise en page).
STATE_DEFAULTS["fontName"] = "Helvetica"

# Charte ReconIA
NAVY = colors.HexColor('#0A1F44')
BLUE = colors.HexColor('#0B5BD3')
BRIGHT = colors.HexColor('#1677F2')
CYAN = colors.HexColor('#00C8F0')
MUTED = colors.HexColor('#64748b')
TEXT = colors.HexColor('#1e293b')
TRACK = colors.HexColor('#E4ECF8')
LAND = colors.HexColor('#C9D9F2')
OCEAN = colors.HexColor('#F3F7FD')

SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SEV_LABELS = {'CRITICAL': 'Critique', 'HIGH': 'Élevée', 'MEDIUM': 'Moyenne', 'LOW': 'Faible', 'INFO': 'Info'}
SEV_COLORS = {
    'CRITICAL': colors.HexColor('#DC2626'), 'HIGH': colors.HexColor('#EA580C'),
    'MEDIUM': colors.HexColor('#D97706'), 'LOW': colors.HexColor('#2563EB'),
    'INFO': colors.HexColor('#64748b'),
}
STATUS_LABELS = {
    'success': 'réussi', 'error': 'erreur', 'timeout': 'délai dépassé', 'timeout_partial': 'partiel',
    'skipped': 'ignoré', 'no_data': 'aucune donnée', 'limited': 'limité', 'unavailable': 'indisponible',
    'not_found': 'introuvable', 'unreachable': 'injoignable', 'blocked': 'bloqué',
}
_STATUS_COLORS = {
    'success': colors.HexColor('#0E9F6E'), 'timeout_partial': colors.HexColor('#D97706'),
    'limited': colors.HexColor('#D97706'), 'error': colors.HexColor('#DC2626'),
    'timeout': colors.HexColor('#DC2626'), 'unreachable': colors.HexColor('#DC2626'),
}

_LAND_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'static', 'geo', 'land-110m.json')
_land_cache: Optional[List] = None


def _short(text: Any, n: int) -> str:
    s = str(text or '')
    return s if len(s) <= n else s[:n - 1] + '…'


def score_color(score: Optional[float]) -> colors.Color:
    if score is None:
        return MUTED
    return (colors.HexColor('#0E9F6E') if score >= 80 else
            colors.HexColor('#1677F2') if score >= 60 else
            colors.HexColor('#D97706') if score >= 40 else colors.HexColor('#DC2626'))


# ── Jauge de score ───────────────────────────────────────────────────────────
def score_gauge(score: Optional[float], grade: str = '', size: float = 150) -> Drawing:
    """Demi-anneau 0–100 : piste claire, arc coloré selon le score, note au centre."""
    w, h = size, size * 0.66
    d = Drawing(w, h)
    cx, cy, r = w / 2, h * 0.18, size * 0.42
    thick = size * 0.1
    d.add(Wedge(cx, cy, r, 0, 180, radius1=r - thick, fillColor=TRACK, strokeColor=None))
    if isinstance(score, (int, float)):
        pct = max(0.0, min(100.0, float(score))) / 100
        if pct > 0:
            d.add(Wedge(cx, cy, r, 180 - 180 * pct, 180, radius1=r - thick,
                        fillColor=score_color(score), strokeColor=None))
        d.add(String(cx, cy + r * 0.32, str(int(round(score))), fontName='Helvetica-Bold',
                     fontSize=size * 0.22, fillColor=NAVY, textAnchor='middle'))
        d.add(String(cx, cy + r * 0.08, '/ 100', fontName='Helvetica', fontSize=size * 0.07,
                     fillColor=MUTED, textAnchor='middle'))
    else:
        d.add(String(cx, cy + r * 0.3, 'n/a', fontName='Helvetica-Bold', fontSize=size * 0.16,
                     fillColor=MUTED, textAnchor='middle'))
    if grade:
        d.add(String(cx, cy - size * 0.12, f'Note {grade}', fontName='Helvetica-Bold',
                     fontSize=size * 0.09, fillColor=score_color(score), textAnchor='middle'))
    d.add(String(cx - r + thick / 2, cy - size * 0.1, '0', fontSize=size * 0.055, fillColor=MUTED, textAnchor='middle'))
    d.add(String(cx + r - thick / 2, cy - size * 0.1, '100', fontSize=size * 0.055, fillColor=MUTED, textAnchor='middle'))
    return d


# ── Donut + légende ──────────────────────────────────────────────────────────
def donut(parts: List[Tuple[str, int, colors.Color]], center_value: str, center_label: str,
          width: float = 250, height: float = 120) -> Drawing:
    """Anneau des parts non nulles (sens horaire depuis midi) et légende à droite."""
    d = Drawing(width, height)
    total = sum(v for _, v, _ in parts)
    cx, cy, r = height / 2, height / 2, height * 0.44
    inner = r * 0.62
    if total <= 0:
        d.add(Wedge(cx, cy, r, 0, 360, radius1=inner, fillColor=TRACK, strokeColor=None))
    else:
        start = 90.0
        for _, value, col in parts:
            if value <= 0:
                continue
            extent = 360.0 * value / total
            d.add(Wedge(cx, cy, r, start - extent, start, radius1=inner, fillColor=col,
                        strokeColor=colors.white, strokeWidth=1.2))
            start -= extent
    d.add(String(cx, cy - 2, str(center_value), fontName='Helvetica-Bold', fontSize=16,
                 fillColor=NAVY, textAnchor='middle'))
    d.add(String(cx, cy - 13, center_label, fontSize=6.5, fillColor=MUTED, textAnchor='middle'))
    lx, ly = height + 14, height - 16
    shown = [(l, v, c) for l, v, c in parts if v > 0]
    for i, (label, value, col) in enumerate(shown[:7]):
        y = ly - i * 15
        d.add(Rect(lx, y - 1, 8, 8, fillColor=col, strokeColor=None, rx=1.5, ry=1.5))
        d.add(String(lx + 13, y, _short(label, 22), fontSize=8, fillColor=TEXT))
        d.add(String(width - 4, y, str(value), fontName='Helvetica-Bold', fontSize=8,
                     fillColor=TEXT, textAnchor='end'))
    return d


def severity_parts(findings: List[Dict]) -> List[Tuple[str, int, colors.Color]]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings or []:
        k = str((f or {}).get('severity', '')).upper()
        if k in counts:
            counts[k] += 1
    return [(SEV_LABELS[s], counts[s], SEV_COLORS[s]) for s in SEVERITIES]


def status_parts(scan: Dict) -> Tuple[List[Tuple[str, int, colors.Color]], int, int]:
    counts: Dict[str, int] = {}
    for value in (scan or {}).values():
        if isinstance(value, dict) and isinstance(value.get('meta'), dict) and value['meta'].get('tool'):
            st = str(value.get('status') or 'inconnu')
            counts[st] = counts.get(st, 0) + 1
    total = sum(counts.values())
    ok = counts.get('success', 0) + counts.get('timeout_partial', 0)
    parts = [(STATUS_LABELS.get(st, st), n, _STATUS_COLORS.get(st, MUTED))
             for st, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    return parts, ok, total


# ── Barres horizontales ──────────────────────────────────────────────────────
def category_bars(findings: List[Dict], width: float = 250, max_rows: int = 7) -> Optional[Drawing]:
    counts: Dict[str, int] = {}
    for f in findings or []:
        c = str((f or {}).get('category') or 'Autre')
        counts[c] = counts.get(c, 0) + 1
    rows = sorted(counts.items(), key=lambda kv: -kv[1])[:max_rows]
    if not rows:
        return None
    row_h = 17
    d = Drawing(width, row_h * len(rows) + 4)
    label_w, value_w = width * 0.38, 18
    track_w = width - label_w - value_w - 8
    peak = max(v for _, v in rows)
    for i, (label, value) in enumerate(rows):
        y = d.height - (i + 1) * row_h + 4
        d.add(String(0, y + 2, _short(label, 24), fontSize=8, fillColor=TEXT))
        d.add(Rect(label_w, y, track_w, 8, fillColor=TRACK, strokeColor=None, rx=4, ry=4))
        d.add(Rect(label_w, y, max(track_w * value / peak, 4), 8, fillColor=BRIGHT, strokeColor=None, rx=4, ry=4))
        d.add(String(width, y + 1, str(value), fontName='Helvetica-Bold', fontSize=8,
                     fillColor=TEXT, textAnchor='end'))
    return d


# ── Carte du monde des serveurs ──────────────────────────────────────────────
def _land_rings() -> List:
    global _land_cache
    if _land_cache is None:
        try:
            with open(_LAND_PATH, encoding='utf-8') as fh:
                _land_cache = json.load(fh).get('rings') or []
        except (OSError, ValueError):
            _land_cache = []
    return _land_cache


def geo_points(scan: Dict) -> List[Dict]:
    """Lieux distincts des IP (ip_info.loc), avec ville, pays, hébergeurs et IP."""
    entry = (scan or {}).get('ip_info')
    data = entry.get('data') if isinstance(entry, dict) else None
    ips = data.get('ips') if isinstance(data, dict) else None
    places: Dict[str, Dict] = {}
    for it in ips if isinstance(ips, list) else []:
        if not isinstance(it, dict) or not isinstance(it.get('loc'), str):
            continue
        try:
            lat, lon = (float(x) for x in it['loc'].split(',')[:2])
        except ValueError:
            continue
        if abs(lat) > 90 or abs(lon) > 180:
            continue
        key = f'{lat:.2f},{lon:.2f}'
        p = places.setdefault(key, {'lat': lat, 'lon': lon, 'city': str(it.get('city') or ''),
                                    'country': str(it.get('country') or ''), 'orgs': [], 'ips': []})
        org = str(it.get('org') or '').split(' ', 1)[-1] if str(it.get('org') or '').startswith('AS') else str(it.get('org') or '')
        if org and org not in p['orgs']:
            p['orgs'].append(org)
        if it.get('ip'):
            p['ips'].append(str(it['ip']))
    return list(places.values())


def world_map(points: List[Dict], width: float = 480) -> Optional[Drawing]:
    """Projection équirectangulaire (latitudes −58° à 84°), serveurs en cyan."""
    if not points:
        return None
    lat_min, lat_max = -58.0, 84.0
    height = width * (lat_max - lat_min) / 360.0
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=OCEAN, strokeColor=None, rx=6, ry=6))

    def xy(lon, lat):
        return (lon + 180.0) / 360.0 * width, (max(lat_min, min(lat_max, lat)) - lat_min) / (lat_max - lat_min) * height

    for lon in range(-150, 181, 30):
        x, _ = xy(lon, 0)
        d.add(Line(x, 0, x, height, strokeColor=colors.HexColor('#E3EAF6'), strokeWidth=0.4))
    for lat in (-30, 0, 30, 60):
        _, y = xy(0, lat)
        d.add(Line(0, y, width, y, strokeColor=colors.HexColor('#E3EAF6'), strokeWidth=0.4))
    for ring in _land_rings():
        if min(lat for _, lat in ring) < lat_min:
            continue          # Antarctique : hors cadre (sinon écrasé en trait horizontal)
        pts: List[float] = []
        for lon, lat in ring:
            pts.extend(xy(lon, lat))
        if len(pts) >= 6:
            d.add(Polygon(pts, fillColor=LAND, strokeColor=colors.HexColor('#B3C7E8'), strokeWidth=0.3))
    for i, p in enumerate(points[:12]):
        x, y = xy(p['lon'], p['lat'])
        d.add(Circle(x, y, 9, fillColor=CYAN, fillOpacity=0.18, strokeColor=None))
        d.add(Circle(x, y, 3.6, fillColor=CYAN, strokeColor=colors.white, strokeWidth=1.2))
        label = ', '.join(v for v in (p.get('city'), p.get('country')) if v) or f"{p['lat']:.1f}, {p['lon']:.1f}"
        anchor = 'end' if x > width * 0.7 else 'start'
        dx = -8 if anchor == 'end' else 8
        d.add(String(x + dx, y + 3 - (i % 2) * 10, _short(label, 34), fontName='Helvetica-Bold',
                     fontSize=7, fillColor=NAVY, textAnchor=anchor))
    return d


# ── Cartographie de l'infrastructure ────────────────────────────────────────
def infra_graph(domain: str, scan: Dict, width: float = 480, height: float = 300) -> Optional[Drawing]:
    """Domaine au centre, IP (et hébergeur) en premier anneau, sous-domaines actifs autour."""
    def data_of(key):
        e = (scan or {}).get(key)
        return e.get('data') if isinstance(e, dict) and isinstance(e.get('data'), dict) else {}

    ip_org: Dict[str, str] = {}
    for it in data_of('ip_info').get('ips') or []:
        if isinstance(it, dict) and it.get('ip'):
            org = str(it.get('org') or '')
            ip_org[str(it['ip'])] = org.split(' ', 1)[-1] if org.startswith('AS') else org
    root_ips = [str(x) for x in (data_of('dns_records').get('A') or []) if isinstance(x, str)]
    hosts = [hst for hst in (data_of('dns_mass').get('hosts') or [])
             if isinstance(hst, dict) and hst.get('status') == 'alive' and hst.get('subdomain')][:12]
    ordered = []
    for ip in root_ips + list(ip_org) + [str(i) for hst in hosts for i in (hst.get('ips') or [])]:
        if ip not in ordered and (':' not in ip or ip in ip_org):
            ordered.append(ip)
    ips = ordered[:8]
    if not ips and not hosts:
        return None

    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=OCEAN, strokeColor=None, rx=6, ry=6))
    cx, cy = width / 2, height / 2
    pos = {'domain': (cx, cy)}
    for i, ip in enumerate(ips):
        a = 2 * math.pi * i / max(len(ips), 1) + math.pi / 2
        pos['ip:' + ip] = (cx + math.cos(a) * width * 0.19, cy + math.sin(a) * height * 0.27)
    for i, hst in enumerate(hosts):
        a = 2 * math.pi * i / max(len(hosts), 1) + math.pi / 2 - 0.25
        pos["sub:" + hst["subdomain"]] = (cx + math.cos(a) * width * 0.41, cy - 6 + math.sin(a) * height * 0.38)

    edges = Group()
    d.add(edges)
    for ip in ips:
        (x1, y1), (x2, y2) = pos['domain'], pos['ip:' + ip]
        edges.add(Line(x1, y1, x2, y2, strokeColor=BRIGHT, strokeWidth=1.2, strokeOpacity=0.6))
    for hst in hosts:
        linked = [str(i) for i in (hst.get('ips') or []) if 'ip:' + str(i) in pos]
        for target in (['ip:' + i for i in linked] or ['domain']):
            (x1, y1), (x2, y2) = pos['sub:' + hst['subdomain']], pos[target]
            edges.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor('#94A3B8'), strokeWidth=0.8, strokeOpacity=0.7))

    def node(key, r, fill, label, sub=None, bold=False):
        x, y = pos[key]
        d.add(Circle(x, y, r, fillColor=fill, strokeColor=colors.white, strokeWidth=2))
        d.add(String(x, y - r - 9, _short(label, 26), fontName='Helvetica-Bold' if bold else 'Helvetica',
                     fontSize=8 if bold else 7, fillColor=NAVY, textAnchor='middle'))
        if sub:
            d.add(String(x, y - r - 17, _short(sub, 28), fontSize=6, fillColor=MUTED, textAnchor='middle'))

    suffix = '.' + domain if domain else ''
    for hst in hosts:
        name = hst['subdomain']
        node('sub:' + name, 5, colors.HexColor('#94A3B8'), name[:-len(suffix)] if suffix and name.endswith(suffix) else name)
    for ip in ips:
        node('ip:' + ip, 7, BRIGHT, ip, ip_org.get(ip))
    node('domain', 11, CYAN, domain or 'domaine', bold=True)
    # Légende
    for i, (label, col) in enumerate((('Domaine', CYAN), ('Adresse IP (hébergeur)', BRIGHT),
                                       ('Sous-domaine actif', colors.HexColor('#94A3B8')))):
        x = 10 + i * 130          # légende en haut à gauche, hors des nœuds
        d.add(Circle(x + 4, height - 12, 3.5, fillColor=col, strokeColor=None))
        d.add(String(x + 12, height - 14.5, label, fontSize=7, fillColor=TEXT))
    return d
