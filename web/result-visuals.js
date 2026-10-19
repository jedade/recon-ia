// web/result-visuals.js — visuels de la page « Voir le résultat » :
// graphiques (sévérités, catégories, statuts d'outils), globe de
// localisation des serveurs façon web-check, cartographie de
// l'infrastructure (domaine → sous-domaines → IP → hébergeur).
//
// Sans bibliothèque (CSP script-src 'self') : SVG construit par
// createElementNS, globe dessiné sur <canvas> en projection orthographique à
// partir de assets/geo/land-110m.json (Natural Earth, domaine public).
// Toutes les valeurs viennent du scan (donc de la cible) : texte inséré
// uniquement par textContent, jamais interprété comme du HTML.
(function () {
    'use strict';

    const NS = 'http://www.w3.org/2000/svg';
    const REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const SEV_LABELS = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Info' };
    const STATUS_LABELS = {
        success: 'réussi', error: 'erreur', timeout: 'délai dépassé', timeout_partial: 'partiel',
        skipped: 'ignoré', no_data: 'aucune donnée', limited: 'limité', unavailable: 'indisponible',
        not_found: 'introuvable', unreachable: 'injoignable', blocked: 'bloqué', not_installed: 'non installé',
    };

    // ── Petits constructeurs ────────────────────────────────────────
    function h(tag, attrs, ...children) {
        const node = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs || {})) {
            if (v === null || v === undefined || v === false) continue;
            if (k === 'class') node.className = v;
            else if (k === 'text') node.textContent = String(v);
            else if (k === 'style') node.style.cssText = String(v);
            else node.setAttribute(k, String(v));
        }
        children.flat(Infinity).forEach((c) => {
            if (c === null || c === undefined || c === false) return;
            node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
        });
        return node;
    }
    function s(tag, attrs, ...children) {
        const node = document.createElementNS(NS, tag);
        for (const [k, v] of Object.entries(attrs || {})) {
            if (v === null || v === undefined) continue;
            if (k === 'text') node.textContent = String(v);
            // CSSOM et non setAttribute('style') : la CSP bloque les attributs style
            else if (k === 'style') node.style.cssText = String(v);
            else node.setAttribute(k, String(v));
        }
        children.flat(Infinity).forEach((c) => { if (c) node.appendChild(c); });
        return node;
    }
    const cssVar = (name, fallback) => (getComputedStyle(document.documentElement).getPropertyValue(name) || '').trim() || fallback;
    const data = (scan, key) => {
        const e = scan && scan[key];
        return e && typeof e === 'object' && e.data && typeof e.data === 'object' ? e.data : null;
    };
    const truncate = (str, n) => (String(str).length > n ? String(str).slice(0, n - 1) + '…' : String(str));

    // ── Donut (sévérités, statuts) ──────────────────────────────────
    // Chaque part est un cercle en pointillé (pathLength = 100) décalé du
    // cumul précédent ; result.css anime le remplissage.
    function donut(parts, centerValue, centerLabel, ariaLabel) {
        const total = parts.reduce((a, p) => a + p.value, 0);
        const svg = s('svg', { viewBox: '0 0 120 120', class: 'donut', role: 'img', 'aria-label': ariaLabel });
        svg.appendChild(s('circle', { class: 'donut-track', cx: 60, cy: 60, r: 46, pathLength: 100 }));
        let offset = 0;
        parts.filter((p) => p.value > 0).forEach((p, i) => {
            const pct = total ? (100 * p.value) / total : 0;
            const seg = s('circle', {
                class: 'donut-seg ' + p.cls, cx: 60, cy: 60, r: 46, pathLength: 100,
                'stroke-dasharray': `${Math.max(pct - 0.6, 0.4).toFixed(2)} ${(100 - pct + 0.6).toFixed(2)}`,
                'stroke-dashoffset': (25 - offset).toFixed(2),
                style: `animation-delay:${(0.12 * i).toFixed(2)}s`,
            }, s('title', { text: `${p.label} : ${p.value}` }));
            svg.appendChild(seg);
            offset += pct;
        });
        svg.appendChild(s('text', { class: 'donut-value', x: 60, y: 60, text: centerValue }));
        svg.appendChild(s('text', { class: 'donut-label', x: 60, y: 77, text: centerLabel }));
        return svg;
    }
    function legend(parts) {
        return h('ul', { class: 'chart-legend' }, parts.filter((p) => p.value > 0).map((p) =>
            h('li', {}, h('span', { class: 'swatch ' + p.cls }), h('span', { class: 'legend-label', text: p.label }),
                h('strong', { text: p.value }))));
    }

    // ── Barres horizontales (catégories) ────────────────────────────
    function bars(rows, ariaLabel) {
        const max = Math.max(1, ...rows.map((r) => r.value));
        const list = h('ul', { class: 'hbars', 'aria-label': ariaLabel });
        rows.forEach((r, i) => {
            const fill = h('span', { class: 'hbar-fill ' + (r.cls || ''), style: `--w:${(100 * r.value / max).toFixed(1)}%;animation-delay:${(0.08 * i).toFixed(2)}s` });
            list.appendChild(h('li', {},
                h('span', { class: 'hbar-label', text: r.label, title: r.label }),
                h('span', { class: 'hbar-track' }, fill),
                h('span', { class: 'hbar-value', text: r.value })));
        });
        return list;
    }

    function chartCard(title, subtitle, ...body) {
        return h('article', { class: 'card chart-card' },
            h('h3', { text: title }), subtitle ? h('p', { class: 'chart-sub', text: subtitle }) : null, body);
    }

    // ── Données dérivées du scan ────────────────────────────────────
    function geoPoints(scan) {
        const info = data(scan, 'ip_info');
        const ips = info && Array.isArray(info.ips) ? info.ips : [];
        const byPlace = new Map();
        ips.forEach((it) => {
            if (!it || typeof it.loc !== 'string') return;
            const [lat, lon] = it.loc.split(',').map(Number);
            if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return;
            const key = lat.toFixed(2) + ',' + lon.toFixed(2);
            const place = byPlace.get(key) || { lat, lon, city: String(it.city || ''), country: String(it.country || ''), orgs: new Set(), ips: [] };
            if (it.org) place.orgs.add(String(it.org).replace(/^AS\d+\s*/, ''));
            if (it.ip) place.ips.push(String(it.ip));
            byPlace.set(key, place);
        });
        return [...byPlace.values()];
    }

    // ── Globe ───────────────────────────────────────────────────────
    let landRings = null;
    function loadLand() {
        if (landRings) return Promise.resolve(landRings);
        return fetch('assets/geo/land-110m.json', { credentials: 'omit' })
            .then((r) => (r.ok ? r.json() : { rings: [] }))
            .then((j) => { landRings = Array.isArray(j.rings) ? j.rings : []; return landRings; })
            .catch(() => { landRings = []; return landRings; });
    }

    function createGlobe(points) {
        const wrap = h('div', { class: 'globe-wrap' });
        const canvas = h('canvas', { class: 'globe', role: 'img',
            'aria-label': 'Globe : ' + points.map((p) => [p.city, p.country].filter(Boolean).join(', ')).join(' ; ') });
        wrap.appendChild(canvas);
        const ctx = canvas.getContext('2d');
        const rad = Math.PI / 180;
        const target = points[0] || { lat: 20, lon: 0 };
        let lambda = target.lon - 35;           // arrive en tournant vers le point
        let phi = Math.max(-35, Math.min(35, target.lat * 0.6));
        let size = 0, dpr = 1, raf = 0, visible = true, t0 = performance.now(), settled = REDUCED;
        if (REDUCED) lambda = target.lon;

        function resize() {
            const w = Math.min(wrap.clientWidth || 320, 420);
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            size = w;
            canvas.width = Math.round(w * dpr);
            canvas.height = Math.round(w * dpr);
            canvas.style.cssText = `width:${w}px;height:${w}px`;
        }
        function project(lon, lat, R, cx, cy) {
            const l = (lon - lambda) * rad, p = lat * rad, p0 = phi * rad;
            const cosc = Math.sin(p0) * Math.sin(p) + Math.cos(p0) * Math.cos(p) * Math.cos(l);
            let x = R * Math.cos(p) * Math.sin(l);
            let y = R * (Math.cos(p0) * Math.sin(p) - Math.sin(p0) * Math.cos(p) * Math.cos(l));
            if (cosc < 0) {                       // face cachée : ramené sur l'horizon
                const n = Math.hypot(x, y) || 1;
                x = (x / n) * R; y = (y / n) * R;
            }
            return [cx + x, cy - y, cosc >= 0];
        }
        function draw(now) {
            const R = size * 0.42, cx = size / 2, cy = size / 2;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, size, size);
            const ocean = cssVar('--globe-ocean', '#0B1A38');
            const land = cssVar('--globe-land', '#1677F2');
            const grid = cssVar('--globe-grid', 'rgba(255,255,255,.08)');
            const accent = cssVar('--globe-marker', '#00C8F0');
            // Halo + océan
            const g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.35, R * 0.1, cx, cy, R * 1.05);
            g.addColorStop(0, cssVar('--globe-ocean-light', '#12285A'));
            g.addColorStop(1, ocean);
            ctx.beginPath(); ctx.arc(cx, cy, R, 0, 2 * Math.PI); ctx.fillStyle = g; ctx.fill();
            // Graticule (méridiens et parallèles tous les 30°)
            ctx.strokeStyle = grid; ctx.lineWidth = 1;
            for (let lon = -180; lon < 180; lon += 30) line(Array.from({ length: 37 }, (_, i) => [lon, -90 + i * 5]));
            for (let lat = -60; lat <= 60; lat += 30) line(Array.from({ length: 73 }, (_, i) => [-180 + i * 5, lat]));
            function line(pts) {
                ctx.beginPath(); let pen = false;
                pts.forEach(([lo, la]) => {
                    const [x, y, vis] = project(lo, la, R, cx, cy);
                    if (!vis) { pen = false; return; }
                    if (pen) ctx.lineTo(x, y); else { ctx.moveTo(x, y); pen = true; }
                });
                ctx.stroke();
            }
            // Terres
            ctx.fillStyle = land; ctx.globalAlpha = 0.85;
            (landRings || []).forEach((ring) => {
                let any = false;
                ctx.beginPath();
                ring.forEach(([lo, la], i) => {
                    const [x, y, vis] = project(lo, la, R, cx, cy);
                    any = any || vis;
                    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
                });
                if (any) ctx.fill();
            });
            ctx.globalAlpha = 1;
            // Contour
            ctx.beginPath(); ctx.arc(cx, cy, R, 0, 2 * Math.PI);
            ctx.strokeStyle = cssVar('--globe-rim', 'rgba(0,200,240,.45)'); ctx.lineWidth = 1.5; ctx.stroke();
            // Marqueurs (pulsation)
            const pulse = REDUCED ? 0.5 : (Math.sin(now / 420) + 1) / 2;
            points.forEach((p) => {
                const [x, y, vis] = project(p.lon, p.lat, R, cx, cy);
                if (!vis) return;
                ctx.beginPath(); ctx.arc(x, y, 6 + pulse * 10, 0, 2 * Math.PI);
                ctx.fillStyle = accent; ctx.globalAlpha = 0.25 * (1 - pulse) + 0.08; ctx.fill();
                ctx.globalAlpha = 1;
                ctx.beginPath(); ctx.arc(x, y, 5, 0, 2 * Math.PI);
                ctx.fillStyle = accent; ctx.fill();
                ctx.lineWidth = 2; ctx.strokeStyle = '#FFFFFF'; ctx.stroke();
            });
        }
        function frame(now) {
            raf = 0;
            if (!settled) {
                // Rotation d'arrivée vers le premier serveur, puis rotation lente
                const k = Math.min(1, (now - t0) / 1600);
                const ease = 1 - Math.pow(1 - k, 3);
                lambda = target.lon - 35 * (1 - ease);
                if (k >= 1) settled = true;
            } else if (!REDUCED) {
                lambda += 0.04;
            }
            draw(now);
            if (!REDUCED && visible) raf = requestAnimationFrame(frame);
        }
        function start() { if (!raf) raf = requestAnimationFrame(frame); }

        loadLand().then(() => { resize(); start(); });
        window.addEventListener('resize', () => { resize(); draw(performance.now()); });
        // Pas d'animation hors écran (économie de batterie)
        if ('IntersectionObserver' in window) {
            new IntersectionObserver((entries) => {
                visible = entries.some((e) => e.isIntersecting);
                if (visible) start();
            }).observe(canvas);
        }
        // Bascule clair/sombre : redessiner avec les nouvelles couleurs
        new MutationObserver(() => draw(performance.now())).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        return wrap;
    }

    function renderGlobe(scan) {
        const points = geoPoints(scan);
        if (!points.length) return null;
        const list = h('ul', { class: 'geo-list' }, points.map((p) =>
            h('li', {},
                h('span', { class: 'geo-pin', 'aria-hidden': 'true' }),
                h('div', {},
                    h('strong', { text: [p.city, p.country].filter(Boolean).join(', ') || `${p.lat}, ${p.lon}` }),
                    h('span', { class: 'geo-meta', text: [...p.orgs].join(' · ') || 'Hébergeur inconnu' }),
                    h('span', { class: 'geo-meta mono', text: p.ips.slice(0, 4).join(' · ') + (p.ips.length > 4 ? ` (+${p.ips.length - 4})` : '') })))));
        return h('article', { class: 'card chart-card globe-card' },
            h('h3', { text: 'Localisation des serveurs' }),
            h('p', { class: 'chart-sub', text: 'Position géographique des adresses IP du domaine (source : ip_info).' }),
            h('div', { class: 'globe-layout' }, createGlobe(points), list));
    }

    // ── Cartographie de l'infrastructure ───────────────────────────
    function infraGraph(domain, scan) {
        const info = data(scan, 'ip_info');
        const ipMeta = new Map();
        (info && Array.isArray(info.ips) ? info.ips : []).forEach((it) => {
            if (it && it.ip) ipMeta.set(String(it.ip), String(it.org || '').replace(/^AS\d+\s*/, ''));
        });
        const records = data(scan, 'dns_records');
        const rootIps = records && Array.isArray(records.A) ? records.A.map(String) : [];
        const mass = data(scan, 'dns_mass');
        const hosts = (mass && Array.isArray(mass.hosts) ? mass.hosts : [])
            .filter((x) => x && x.status === 'alive' && x.subdomain).slice(0, 12);

        const ips = [...new Set([...rootIps, ...ipMeta.keys(), ...hosts.flatMap((x) => (x.ips || []).map(String))])]
            .filter((ip) => !ip.includes(':') || ipMeta.has(ip)).slice(0, 8);
        if (!ips.length && !hosts.length) return null;

        const W = 720, H = 460, cx = W / 2, cy = H / 2;
        const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'infra-graph', role: 'img',
            'aria-label': `Cartographie : ${hosts.length} sous-domaine(s) actifs, ${ips.length} adresse(s) IP` });
        const edges = s('g', { class: 'edges' });
        const nodes = s('g', { class: 'nodes' });
        svg.append(edges, nodes);

        const pos = new Map();
        pos.set('domain', [cx, cy]);
        ips.forEach((ip, i) => {
            const a = (2 * Math.PI * i) / Math.max(ips.length, 1) - Math.PI / 2;
            pos.set('ip:' + ip, [cx + Math.cos(a) * 125, cy + Math.sin(a) * 105]);
        });
        hosts.forEach((x, i) => {
            const a = (2 * Math.PI * i) / Math.max(hosts.length, 1) - Math.PI / 2 + 0.25;
            pos.set('sub:' + x.subdomain, [cx + Math.cos(a) * 285, cy + Math.sin(a) * 190]);
        });

        let n = 0;
        const edge = (from, to, cls) => {
            const [x1, y1] = pos.get(from), [x2, y2] = pos.get(to);
            edges.appendChild(s('line', { x1, y1, x2, y2, class: 'edge ' + (cls || ''), pathLength: 100,
                style: `animation-delay:${(0.04 * n++).toFixed(2)}s` }));
        };
        ips.forEach((ip) => edge('domain', 'ip:' + ip, 'edge-ip'));
        hosts.forEach((x) => {
            const linked = (x.ips || []).map(String).filter((ip) => pos.has('ip:' + ip));
            if (linked.length) linked.forEach((ip) => edge('sub:' + x.subdomain, 'ip:' + ip, 'edge-sub'));
            else edge('domain', 'sub:' + x.subdomain, 'edge-sub');
        });

        const node = (key, cls, label, sub, r) => {
            const [x, y] = pos.get(key);
            const g = s('g', { class: 'node ' + cls, transform: `translate(${x.toFixed(1)},${y.toFixed(1)})` },
                s('title', { text: [label, sub].filter(Boolean).join(' — ') }),
                s('circle', { r }),
                s('text', { class: 'node-label', y: r + 14, text: truncate(label, 24) }),
                sub ? s('text', { class: 'node-meta', y: r + 27, text: truncate(sub, 26) }) : null);
            nodes.appendChild(g);
        };
        hosts.forEach((x) => node('sub:' + x.subdomain, 'node-sub', x.subdomain.replace('.' + domain, ''), null, 8));
        ips.forEach((ip) => node('ip:' + ip, 'node-ip', ip, ipMeta.get(ip) || '', 11));
        node('domain', 'node-domain', domain, null, 18);

        const legendRow = h('ul', { class: 'chart-legend inline' },
            h('li', {}, h('span', { class: 'swatch sw-domain' }), 'Domaine'),
            h('li', {}, h('span', { class: 'swatch sw-ip' }), 'Adresse IP (hébergeur)'),
            h('li', {}, h('span', { class: 'swatch sw-sub' }), 'Sous-domaine actif'));
        return h('article', { class: 'card chart-card graph-card' },
            h('h3', { text: 'Cartographie de l\'infrastructure' }),
            h('p', { class: 'chart-sub', text: `Relations observées passivement : ${hosts.length} sous-domaine(s) actif(s) sur ${ips.length} adresse(s) IP` +
                (mass && mass.alive_count > hosts.length ? ` (12 premiers sur ${mass.alive_count})` : '') + '.' }),
            h('div', { class: 'graph-scroll' }, svg), legendRow);
    }

    // ── Section « Vue d'ensemble » ──────────────────────────────────
    function overview(report, analysis, entries) {
        const findings = Array.isArray(analysis.findings) ? analysis.findings : [];
        const scan = report.scan_results || {};
        const domain = (report.recon && report.recon.domain) || (report.provenance || {}).domain || '';

        const sevParts = SEVERITIES.map((sev) => ({
            label: SEV_LABELS[sev], cls: 'sev-fill-' + sev,
            value: findings.filter((f) => String(f.severity || '').toUpperCase() === sev).length,
        }));
        const byCat = {};
        findings.forEach((f) => { const c = String(f.category || 'Autre'); byCat[c] = (byCat[c] || 0) + 1; });
        const catRows = Object.entries(byCat).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([label, value]) => ({ label, value }));

        const statusCounts = {};
        entries.forEach(([, v]) => { const st = v.status || 'inconnu'; statusCounts[st] = (statusCounts[st] || 0) + 1; });
        const okCount = (statusCounts.success || 0) + (statusCounts.timeout_partial || 0);
        const statusParts = Object.entries(statusCounts).sort((a, b) => b[1] - a[1]).map(([st, value]) => ({
            label: STATUS_LABELS[st] || st, value, cls: 'st-fill-' + st,
        }));

        const charts = h('div', { class: 'charts-grid' },
            chartCard('Constats par sévérité', `${findings.length} constat(s) retenu(s) après contrôle des règles.`,
                h('div', { class: 'donut-row' }, donut(sevParts, findings.length, 'constats', 'Répartition des constats par sévérité'), legend(sevParts))),
            catRows.length ? chartCard('Constats par catégorie', 'Domaines de sécurité concernés.', bars(catRows, 'Constats par catégorie')) : null,
            entries.length ? chartCard('Couverture de la collecte', `${okCount} outil(s) sur ${entries.length} ont produit des données.`,
                h('div', { class: 'donut-row' }, donut(statusParts, entries.length ? Math.round(100 * okCount / entries.length) + '%' : '—', 'utiles', 'Statuts des outils'), legend(statusParts))) : null,
        );
        const globe = renderGlobe(scan);
        const graph = infraGraph(domain, scan);
        const node = h('section', { class: 'section overview' }, h('h2', { text: 'Vue d\'ensemble' }), charts,
            globe || graph ? h('div', { class: 'visual-grid' }, globe, graph) : null);
        return node;
    }

    window.ReconVisuals = { overview };
})();
