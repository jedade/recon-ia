// web/result.js — page « Voir le résultat » (plan d'action, phase 2).
//
// Parcours : code d'accès → POST /results/access → session (1 h) →
// GET /results/report → rendu ; téléchargements PDF/JSON/CSV avec la même
// session (en-tête Authorization, d'où fetch + Blob plutôt que de simples
// liens).
//
// Sécurité : tout le contenu affiché (données collectées sur des sites
// tiers, texte produit par un LLM) passe par textContent / createElement —
// JAMAIS par innerHTML. Le code d'accès ne quitte le formulaire que dans le
// corps du POST ; il n'est jamais stocké. Seul le jeton de session est
// conservé, en sessionStorage (effacé à la fermeture de l'onglet).
'use strict';

(function () {
    const CFG = window.RECON_IA_CONFIG || {};
    const API = (CFG.API_BASE || 'https://api.idachallenge.bj').replace(/\/+$/, '');
    const SESSION_KEY = 'reconia.results.session';
    const THEME_KEY = 'reconia.theme';
    const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const SEVERITY_LABELS = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Info' };
    const STATUS_LABELS = {
        success: 'réussi', error: 'erreur', timeout: 'délai dépassé', timeout_partial: 'partiel',
        skipped: 'ignoré (clé absente)', no_data: 'aucune donnée', limited: 'limité',
        unavailable: 'indisponible', not_found: 'introuvable', unreachable: 'injoignable',
        not_installed: 'non installé', blocked: 'bloqué (adresse interne)',
    };
    const CONFIDENCE_LABELS = { high: 'élevée', medium: 'moyenne', low: 'faible' };
    const TECH_RE = /^T\d{4}(\.\d{3})?$/;
    const MITIGATION_RE = /^M\d{4}$/;
    const MAX_KEYS = 30;
    const MAX_ITEMS = 25;
    const MAX_DEPTH = 3;
    const MAX_RAW = 20000;

    const $ = (id) => document.getElementById(id);

    // ── Construction sûre du DOM ─────────────────────────────────────
    function el(tag, attrs, ...children) {
        const node = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs || {})) {
            if (v === null || v === undefined || v === false) continue;
            if (k === 'class') node.className = v;
            else if (k === 'text') node.textContent = String(v);
            // CSSOM et non setAttribute('style') : la CSP (style-src 'self')
            // bloque les attributs style, pas les propriétés posées en JS.
            else if (k === 'style') node.style.cssText = String(v);
            else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
            else node.setAttribute(k, v === true ? '' : String(v));
        }
        for (const child of children.flat(Infinity)) {
            if (child === null || child === undefined || child === false) continue;
            node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return node;
    }

    // ── Stockage (peut être indisponible : navigation privée, etc.) ─
    function store(kind, key, value) {
        try {
            const s = kind === 'local' ? window.localStorage : window.sessionStorage;
            if (value === undefined) return s.getItem(key);
            if (value === null) s.removeItem(key); else s.setItem(key, value);
        } catch (e) { /* stockage indisponible : on continue sans */ }
        return null;
    }

    function getSession() {
        try {
            const raw = store('session', SESSION_KEY);
            if (!raw) return null;
            const s = JSON.parse(raw);
            if (!s.token || !s.exp || Date.now() > s.exp) { clearSession(); return null; }
            return s;
        } catch (e) { return null; }
    }
    function saveSession(token, expiresIn) {
        store('session', SESSION_KEY, JSON.stringify({ token, exp: Date.now() + (expiresIn - 30) * 1000 }));
    }
    function clearSession() { store('session', SESSION_KEY, null); }

    // ── Thème ───────────────────────────────────────────────────────
    function applyTheme(theme) {
        if (theme === 'light' || theme === 'dark') document.documentElement.setAttribute('data-theme', theme);
        else document.documentElement.removeAttribute('data-theme');
    }
    function toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme')
            || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
        const next = current === 'light' ? 'dark' : 'light';
        applyTheme(next);
        store('local', THEME_KEY, next);
    }

    // ── Appels API ──────────────────────────────────────────────────
    class ApiError extends Error {
        constructor(message, status) { super(message); this.status = status; }
    }

    async function api(path, options) {
        const session = getSession();
        const headers = Object.assign({}, (options && options.headers) || {});
        if (session && !(options && options.anonymous)) headers.Authorization = 'Bearer ' + session.token;
        const resp = await fetch(API + path, Object.assign({}, options, { headers, credentials: 'omit' }));
        if (!resp.ok) {
            let message = 'Erreur ' + resp.status;
            try { message = (await resp.json()).error || message; } catch (e) { /* corps non JSON */ }
            if (resp.status === 429) message = 'Trop de tentatives. Patientez une minute avant de réessayer.';
            throw new ApiError(message, resp.status);
        }
        return resp;
    }

    async function openSession(code) {
        const resp = await api('/results/access', {
            method: 'POST',
            anonymous: true,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
        });
        const data = (await resp.json()).data;
        saveSession(data.session_token, data.expires_in);
    }

    async function download(path, fallbackName) {
        try {
            const resp = await api(path);
            const blob = await resp.blob();
            const disposition = resp.headers.get('Content-Disposition') || '';
            const match = /filename="?([^";]+)"?/.exec(disposition);
            const url = URL.createObjectURL(blob);
            const a = el('a', { href: url, download: match ? match[1] : fallbackName });
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (e) {
            handleSessionError(e);
        }
    }

    // ── Vues ────────────────────────────────────────────────────────
    function showMessage(text, kind) {
        const m = $('access-message');
        m.textContent = text;
        m.className = 'message ' + (kind || 'error');
    }

    function showAccess(message) {
        $('report-view').classList.add('hidden');
        $('logout-btn').classList.add('hidden');
        $('access-view').classList.remove('hidden');
        if (message) showMessage(message, 'error');
        $('access-code').focus();
    }

    function handleSessionError(e) {
        if (e instanceof ApiError && [401, 403, 410].includes(e.status)) {
            clearSession();
            showAccess(e.message);
        } else {
            alert(e.message || 'Une erreur est survenue.');
        }
    }

    async function loadReport() {
        $('loading').classList.remove('hidden');
        try {
            const resp = await api('/results/report');
            const data = (await resp.json()).data;
            renderReport(data);
            $('access-view').classList.add('hidden');
            $('report-view').classList.remove('hidden');
            $('logout-btn').classList.remove('hidden');
        } catch (e) {
            handleSessionError(e);
        } finally {
            $('loading').classList.add('hidden');
        }
    }

    // ── Rendu générique d'une valeur (données d'outils) ─────────────
    function renderValue(value, depth) {
        depth = depth || 0;
        if (value === null || value === undefined || value === '') return el('span', { class: 'empty', text: '—' });
        if (Array.isArray(value)) {
            if (!value.length) return el('span', { class: 'empty', text: 'aucun' });
            const items = value.slice(0, MAX_ITEMS).map((v) => el('li', {}, renderValue(v, depth + 1)));
            if (value.length > MAX_ITEMS) items.push(el('li', { class: 'empty', text: '… ' + (value.length - MAX_ITEMS) + ' de plus' }));
            return el('ul', { class: 'vlist' }, items);
        }
        if (typeof value === 'object') {
            if (depth >= MAX_DEPTH) return el('code', { text: JSON.stringify(value).slice(0, 300) });
            const keys = Object.keys(value);
            if (!keys.length) return el('span', { class: 'empty', text: 'vide' });
            // Petit objet imbriqué de valeurs simples : une ligne compacte
            // (« present : non · valid : oui ») plutôt qu'une grille de plus,
            // illisible dans une carte étroite.
            const scalar = (v) => v === null || ['string', 'number', 'boolean'].includes(typeof v);
            if (depth >= 1 && keys.length <= 4 && keys.every((k) => scalar(value[k]))) {
                const fmt = (v) => v === null ? '—' : typeof v === 'boolean' ? (v ? 'oui' : 'non') : String(v);
                return el('span', { text: keys.map((k) => k + ' : ' + fmt(value[k])).join(' · ') });
            }
            const dl = el('dl', { class: 'kv' });
            keys.slice(0, MAX_KEYS).forEach((k) => {
                dl.appendChild(el('dt', { text: k }));
                dl.appendChild(el('dd', {}, renderValue(value[k], depth + 1)));
            });
            if (keys.length > MAX_KEYS) dl.appendChild(el('dd', { class: 'empty', text: '… ' + (keys.length - MAX_KEYS) + ' champs de plus' }));
            return dl;
        }
        if (typeof value === 'boolean') return el('span', { text: value ? 'oui' : 'non' });
        return el('span', { text: String(value) });
    }

    function statusBadge(status) {
        const s = String(status || 'inconnu');
        return el('span', { class: 'badge st-' + s, text: STATUS_LABELS[s] || s });
    }

    function severityBadge(sev) {
        const s = SEVERITIES.includes(String(sev).toUpperCase()) ? String(sev).toUpperCase() : 'INFO';
        return el('span', { class: 'badge sev-' + s, text: SEVERITY_LABELS[s] });
    }

    function section(title, ...content) {
        return el('section', { class: 'section' }, el('h2', { text: title }), content);
    }

    function openInfo(title, description, indicators) {
        $('info-title').textContent = title;
        const body = $('info-body');
        body.textContent = '';
        body.appendChild(el('p', { text: description || 'Aucune explication disponible pour cet outil.' }));
        if (indicators && (Array.isArray(indicators) ? indicators.length : Object.keys(indicators).length)) {
            body.appendChild(el('h4', { text: 'Ce que signifient les champs' }));
            body.appendChild(renderValue(indicators, 1));
        }
        $('info-modal').showModal();
    }

    function focusTool(key) {
        const card = document.getElementById('tool-' + key);
        if (!card) return;
        // La carte peut être masquée par un filtre : on réinitialise les filtres
        document.querySelectorAll('.tool-card').forEach((c) => c.classList.remove('hidden'));
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        card.classList.add('flash');
        setTimeout(() => card.classList.remove('flash'), 1600);
    }

    // ── Sections du rapport ─────────────────────────────────────────
    function gauge(score, grade) {
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 132 132');
        svg.setAttribute('class', 'gauge');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'Score de sécurité ' + (score ?? 'inconnu') + ' sur 100');
        const r = 54;
        const c = 2 * Math.PI * r;
        const pct = typeof score === 'number' ? Math.max(0, Math.min(100, score)) / 100 : 0;
        const color = pct >= 0.8 ? 'var(--ok)' : pct >= 0.6 ? 'var(--medium)' : pct >= 0.4 ? 'var(--high)' : 'var(--critical)';
        const mk = (tag, attrs) => { const n = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); return n; };
        svg.appendChild(mk('circle', { class: 'track', cx: 66, cy: 66, r }));
        svg.appendChild(mk('circle', { class: 'value', cx: 66, cy: 66, r, stroke: color, 'stroke-dasharray': `${c * pct} ${c}` }));
        const g = mk('text', { class: 'grade', x: 66, y: 70 }); g.textContent = grade || '—'; svg.appendChild(g);
        const s = mk('text', { class: 'score', x: 66, y: 92 }); s.textContent = typeof score === 'number' ? score + ' / 100' : 'n/a'; svg.appendChild(s);
        return svg;
    }

    function fmtDate(iso) {
        if (!iso) return '—';
        const d = new Date(iso);
        return isNaN(d) ? iso : d.toLocaleString('fr-FR', { dateStyle: 'long', timeStyle: 'short' });
    }

    function renderHeader(data, analysis) {
        const recon = data.recon || {};
        const score = typeof recon.security_score === 'number' ? recon.security_score : analysis.security_score;
        const grade = recon.security_grade || analysis.security_grade;
        const header = $('report-header');
        header.textContent = '';
        header.append(
            gauge(score, grade),
            el('div', { class: 'report-title' },
                el('h1', { text: recon.domain || (data.provenance || {}).domain || 'Rapport' }),
                el('p', { class: 'meta-line' }, 'Niveau de risque : ', severityBadge(analysis.risk_level || 'INFO')),
                el('p', { class: 'meta-line', text: 'Analyse terminée le ' + fmtDate(recon.completed_at
                    || (data.provenance || {}).analysis_generated_at || (data.provenance || {}).scan_completed_at) }),
                el('p', { class: 'meta-line', text: 'Accès valable jusqu\'au ' + fmtDate(recon.access_expires_at) }),
                el('p', { class: 'meta-line', text: 'Empreinte SHA-256 du jeu de données : ' + (((data.provenance || {}).dataset_sha256) || 'n/a') }),
            ),
            el('div', { class: 'downloads' },
                el('button', { class: 'primary', type: 'button', text: 'Télécharger le PDF', onclick: () => download('/results/report.pdf', 'rapport.pdf') }),
                el('button', { class: 'ghost', type: 'button', text: 'Données JSON', onclick: () => download('/results/export.json', 'rapport.json') }),
                el('button', { class: 'ghost', type: 'button', text: 'Constats CSV', onclick: () => download('/results/export.csv', 'constats.csv') }),
                el('button', { class: 'ghost', type: 'button', id: 'navigator-btn', text: 'Layer ATT&CK Navigator',
                    title: 'À ouvrir dans ATT&CK Navigator (Open Existing Layer)',
                    onclick: () => download('/results/export.navigator.json', 'attack_navigator.json') }),
            ),
        );
    }

    function renderSummary(analysis, finalReport) {
        const text = (finalReport && finalReport.executive_summary) || analysis.executive_summary;
        const surface = analysis.attack_surface || {};
        const fsum = analysis.findings || [];
        const tiles = el('div', { class: 'tiles' },
            [['Constats', fsum.length],
             ['Sous-domaines', surface.total_subdomains ?? '—'],
             ['Services exposés', (surface.exposed_services || []).length],
             ['Technologies', (surface.technologies || []).length],
             ['Points forts', (analysis.strengths || []).length]]
                .map(([lbl, num]) => el('div', { class: 'card tile' }, el('div', { class: 'num', text: num }), el('div', { class: 'lbl', text: lbl }))));
        return section('Résumé', tiles, text ? el('div', { class: 'card', style: null }, el('p', { text })) : null);
    }

    function renderReliability(analysis) {
        const g = analysis.grounding_check;
        const c = analysis.coverage_check;
        if (!g && !c) return null;
        const cards = [];
        if (g) cards.push(el('div', { class: 'card' },
            el('h3', { text: 'Preuves vérifiées' }),
            el('p', { text: (g.verified ?? 0) + ' constat(s) sur ' + (g.total_findings ?? 0) + ' ont une preuve retrouvée dans la donnée brute de l\'outil cité' + (g.verified_pct != null ? ' (' + g.verified_pct + ' %).' : '.') }),
            el('p', { class: 'muted small', text: g.method || '' })));
        if (c) cards.push(el('div', { class: 'card' },
            el('h3', { text: 'Couverture de l\'analyse' }),
            el('p', { text: (c.coverage_pct != null ? c.coverage_pct + ' %' : 'n/a') + ' des outils ayant produit des données sont exploités par l\'analyse.' }),
            (c.tools_unreferenced || []).length ? el('p', { class: 'small' }, 'Non exploités : ', (c.tools_unreferenced || []).map((k, i) =>
                [i ? ', ' : '', el('button', { class: 'link-btn', type: 'button', text: k, onclick: () => focusTool(k) })])) : null,
            el('p', { class: 'muted small', text: 'Extraits de référence (OWASP, RFC…) cités : ' + (c.rag_snippets_used ?? 0) + ' / ' + (c.rag_snippets_available ?? 0) })));
        return section('Fiabilité de l\'analyse', el('div', { class: 'grid-2' }, cards));
    }

    function renderFindings(analysis) {
        const findings = (analysis.findings || []).slice().sort((a, b) =>
            SEVERITIES.indexOf(String(a.severity).toUpperCase()) - SEVERITIES.indexOf(String(b.severity).toUpperCase()));
        if (!findings.length) return section('Constats', el('p', { class: 'empty', text: 'Aucun constat.' }));

        const list = el('div', {});
        const counts = {};
        findings.forEach((f) => { const s = String(f.severity).toUpperCase(); counts[s] = (counts[s] || 0) + 1; });
        let active = null;
        const chips = el('div', { class: 'chips' });
        const apply = () => {
            list.querySelectorAll('.finding').forEach((n) => n.classList.toggle('hidden', !!active && n.dataset.sev !== active));
            chips.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', (c.dataset.sev || null) === active));
        };
        chips.appendChild(el('button', { class: 'ghost chip active', type: 'button', text: 'Tous (' + findings.length + ')', onclick: () => { active = null; apply(); } }));
        SEVERITIES.filter((s) => counts[s]).forEach((s) => chips.appendChild(
            el('button', { class: 'ghost chip', type: 'button', 'data-sev': s, text: SEVERITY_LABELS[s] + ' (' + counts[s] + ')', onclick: () => { active = s; apply(); } })));

        findings.forEach((f) => {
            const sev = SEVERITIES.includes(String(f.severity).toUpperCase()) ? String(f.severity).toUpperCase() : 'INFO';
            const dl = el('dl', {});
            const row = (label, node) => { if (node) { dl.appendChild(el('dt', { text: label })); dl.appendChild(el('dd', {}, node)); } };
            row('Description', f.description ? el('span', { text: f.description }) : null);
            row('Preuve', f.evidence ? el('pre', { text: String(f.evidence) }) : null);
            row('Recommandation', f.recommendation ? el('span', { text: f.recommendation }) : null);
            const tools = [f.source_tool].concat(f.source_tools || []).filter((t, i, a) => t && a.indexOf(t) === i);
            row('Outil source', tools.length ? el('span', {}, tools.map((t, i) => [i ? ', ' : '', el('button', { class: 'link-btn', type: 'button', text: t, onclick: () => focusTool(t) })])) : null);
            row('Références', referencesNode(f.references));
            if (f.grounding && f.grounding.status) row('Contrôle de preuve', el('span', { text: f.grounding.status === 'verified' ? 'preuve retrouvée dans les données' : f.grounding.status }));
            // hasOwnProperty : « constructor », « __proto__ »… ne sont pas des niveaux
            const conf = typeof f.confidence === 'string' && Object.prototype.hasOwnProperty.call(CONFIDENCE_LABELS, f.confidence) ? f.confidence : null;
            row('Confiance', conf ? el('span', { class: 'badge conf-' + conf, text: CONFIDENCE_LABELS[conf] }) : null);
            row('Observé le', typeof f.observed_at === 'string' && f.observed_at ? el('span', { text: fmtDate(f.observed_at) }) : null);
            row('Rend possible', attackList(f.attack_enabled, TECH_RE, techniqueUrl));
            row('Mitigations', attackList(f.mitigations, MITIGATION_RE, mitigationUrl));
            row('Mesure', typeof f.mitigation_advice === 'string' && f.mitigation_advice ? el('span', { text: f.mitigation_advice }) : null);
            list.appendChild(el('article', { class: 'card finding sev-' + sev, 'data-sev': sev, 'data-fid': typeof f.id === 'string' ? f.id : '' },
                el('div', { class: 'finding-head' }, severityBadge(sev), el('span', { class: 'fid', text: f.id || '' }), el('h3', { text: f.title || 'Constat' })),
                dl));
        });
        return section('Constats', chips, list);
    }

    function renderStrengthsAndActions(analysis) {
        const strengths = analysis.strengths || [];
        const actions = (analysis.immediate_actions || []).slice().sort((a, b) => (a.priority || 9) - (b.priority || 9));
        if (!strengths.length && !actions.length) return null;
        const prio = { 1: 'Immédiat', 2: 'Cette semaine', 3: 'Ce mois' };
        return section('Points forts et actions', el('div', { class: 'grid-2' },
            strengths.length ? el('div', { class: 'card' }, el('h3', { text: 'Points forts' }), el('ul', { class: 'vlist' }, strengths.map((s) => el('li', { text: s })))) : null,
            actions.length ? el('div', { class: 'card' }, el('h3', { text: 'Actions prioritaires' }), el('ul', { class: 'vlist' },
                actions.map((a) => el('li', {}, el('strong', { text: (prio[a.priority] || 'Plus tard') + ' — ' }), a.action || '')))) : null));
    }

    // ── ATT&CK : techniques rendues possibles, mitigations, chaîne ──
    // Les ID sont revalidés côté navigateur avant de construire un lien :
    // seul un ID au format ATT&CK strict devient une URL attack.mitre.org.
    function techniqueUrl(id) { return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'; }
    function mitigationUrl(id) { return 'https://attack.mitre.org/mitigations/' + id + '/'; }

    function attackList(items, re, urlOf) {
        const valid = (Array.isArray(items) ? items : []).filter((t) => t && typeof t.id === 'string' && re.test(t.id));
        if (!valid.length) return null;
        return el('span', { class: 'atk-list' }, valid.map((t) =>
            el('span', { class: 'atk-chip' },
                el('a', { href: urlOf(t.id), target: '_blank', rel: 'noopener noreferrer', text: t.id }),
                ' ' + (typeof t.name === 'string' ? t.name : ''))));
    }

    // Références : chaînes (ancien format) ou {collection, source} (phase 3)
    function referencesNode(refs) {
        if (!Array.isArray(refs) || !refs.length) return null;
        const parts = refs.map((r) => {
            if (typeof r === 'string') return r;
            if (r && typeof r === 'object') {
                const src = typeof r.source === 'string' ? r.source : '';
                const col = typeof r.collection === 'string' ? r.collection : '';
                return src ? (col ? src + ' (' + col + ')' : src) : '';
            }
            return '';
        }).filter(Boolean);
        return parts.length ? el('span', { text: parts.join(' · ') }) : null;
    }

    function focusFinding(fid) {
        const card = [...document.querySelectorAll('article.finding')].find((n) => n.dataset.fid === fid);
        if (!card) return;
        card.classList.remove('hidden');
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        card.classList.add('flash');
        setTimeout(() => card.classList.remove('flash'), 1600);
    }

    // Relations `uses` d'ATT&CK : contexte général sur la technique, jamais
    // une attribution ni une menace avérée pour ce domaine.
    function groupsNote(ctx) {
        if (!ctx || typeof ctx.groups_count !== 'number' || ctx.groups_count <= 0) return null;
        const sample = (Array.isArray(ctx.groups_sample) ? ctx.groups_sample : []).filter((g) => typeof g === 'string').slice(0, 3);
        return el('div', { class: 'muted small', text: 'Contexte : technique employée par ' + ctx.groups_count + ' groupe(s) connu(s)'
            + (sample.length ? ' (ex. ' + sample.join(', ') + ')' : '') + ' — information générale, pas une menace avérée.' });
    }

    function renderAttackChain(attack) {
        const chain = (attack && Array.isArray(attack.chain)) ? attack.chain : [];
        if (!chain.length) return null;
        // Map sans prototype : un ID « __proto__ » ne peut rien atteindre
        const context = Object.assign(Object.create(null), (attack && attack.context && typeof attack.context === 'object') ? attack.context : {});
        const steps = chain.map((step) => {
            const techniques = (Array.isArray(step.techniques) ? step.techniques : [])
                .filter((t) => t && typeof t.id === 'string' && TECH_RE.test(t.id));
            return el('li', { class: 'card chain-step' },
                el('div', { class: 'chain-head' },
                    el('span', { class: 'chain-num', text: String(step.order || '') }),
                    el('h3', { text: step.label || step.tactic || '' }),
                    severityBadge(step.max_severity)),
                el('p', { class: 'muted small', text: (step.tactic || '') + (step.tactic_id ? ' · ' + step.tactic_id : '') }),
                el('ul', { class: 'vlist chain-techs' }, techniques.map((t) => el('li', {},
                    el('a', { href: techniqueUrl(t.id), target: '_blank', rel: 'noopener noreferrer', text: t.id }),
                    ' ' + (t.name || '') + ' ',
                    (t.finding_ids || []).length ? el('span', { class: 'small' }, '— ', (t.finding_ids || []).map((fid, i) =>
                        [i ? ', ' : '', el('button', { class: 'link-btn', type: 'button', text: String(fid), onclick: () => focusFinding(String(fid)) })])) : null,
                    groupsNote(context[t.id])))));
        });
        return section('Chaîne d\'attaque plausible',
            el('p', { class: 'muted small', text: 'Scénario déduit de façon déterministe des constats (table Recon-IA, référentiel ATT&CK Enterprise v'
                + ((attack && attack.attack_version) || '?') + ') : il décrit ce qu\'une exposition PERMET, pas une attaque observée.' }),
            el('ol', { class: 'chain' }, steps));
    }

    function renderMitre(analysis) {
        const techniques = analysis.mitre_attack || [];
        if (!techniques.length) return null;
        const rows = techniques.map((t) => {
            const id = String(t.technique_id || '');
            const href = TECH_RE.test(id) ? techniqueUrl(id) : null;
            // data-label : affiché à la place de l'en-tête sur petit écran
            return el('tr', {},
                el('td', { 'data-label': 'Technique' }, href ? el('a', { href, target: '_blank', rel: 'noopener noreferrer', text: id }) : id),
                el('td', { 'data-label': 'Nom', text: t.technique_name || '' }),
                el('td', { 'data-label': 'Tactique', text: t.tactic || '' }),
                el('td', { 'data-label': 'Outils', text: (t.matched_tools || []).join(', ') }),
                el('td', { 'data-label': 'Recommandation', text: t.advice || '' }));
        });
        return section('MITRE ATT&CK — informations qu\'un attaquant peut collecter', el('div', { class: 'card', style: 'overflow-x:auto' },
            el('table', { class: 'data' },
                el('thead', {}, el('tr', {}, ['Technique', 'Nom', 'Tactique', 'Outils', 'Recommandation'].map((h) => el('th', { text: h })))),
                el('tbody', {}, rows))));
    }

    function toolEntries(scan) {
        return Object.entries(scan || {})
            .filter(([, v]) => v && typeof v === 'object' && v.meta && v.meta.tool)
            .sort((a, b) => (a[1].meta.category || '').localeCompare(b[1].meta.category || '') || a[0].localeCompare(b[0]));
    }

    function renderToolStatus(entries) {
        if (!entries.length) return null;
        const counts = {};
        entries.forEach(([, v]) => { counts[v.status || 'inconnu'] = (counts[v.status || 'inconnu'] || 0) + 1; });
        const bar = el('div', { class: 'status-bar', role: 'img', 'aria-label': 'Répartition des statuts des outils' },
            Object.entries(counts).map(([s, n]) => el('span', { class: 'st-' + s, style: 'width:' + (100 * n / entries.length) + '%', title: (STATUS_LABELS[s] || s) + ' : ' + n })));
        const legend = el('div', { class: 'chips' }, Object.entries(counts).map(([s, n]) => el('span', {}, statusBadge(s), ' ' + n)));
        const pills = el('div', { class: 'tool-list' }, entries.map(([k, v]) =>
            el('button', { class: 'tool-pill st-' + (v.status || ''), type: 'button', title: v.meta.tool, onclick: () => focusTool(k) },
                el('span', { class: 'dot' }), el('span', { style: 'color:var(--text)', text: k }))));
        return section('Exécution des ' + entries.length + ' outils', el('div', { class: 'card' }, bar, legend, pills));
    }

    function renderToolCards(entries) {
        if (!entries.length) return null;
        const grid = el('div', { class: 'masonry' });
        const categories = [...new Set(entries.map(([, v]) => v.meta.category).filter(Boolean))];
        let activeCat = null;
        const search = el('input', { type: 'search', placeholder: 'Rechercher un outil…', 'aria-label': 'Rechercher un outil' });
        const chips = el('div', { class: 'chips' });
        // Filtre corrigé par rapport à web-check : on compare chaque carte à la
        // catégorie SÉLECTIONNÉE (web-check comparait les cartes entre elles).
        const apply = () => {
            const q = search.value.trim().toLowerCase();
            grid.querySelectorAll('.tool-card').forEach((card) => {
                const okCat = !activeCat || card.dataset.cat === activeCat;
                const okText = !q || card.dataset.search.includes(q);
                card.classList.toggle('hidden', !(okCat && okText));
            });
            chips.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', (c.dataset.cat || null) === activeCat));
        };
        search.addEventListener('input', apply);
        chips.appendChild(el('button', { class: 'ghost chip active', type: 'button', text: 'Toutes', onclick: () => { activeCat = null; apply(); } }));
        categories.forEach((cat) => chips.appendChild(el('button', { class: 'ghost chip', type: 'button', 'data-cat': cat, text: cat, onclick: () => { activeCat = cat; apply(); } })));

        entries.forEach(([key, v]) => {
            const raw = typeof v.raw_output === 'string' ? v.raw_output : '';
            grid.appendChild(el('article', {
                class: 'card tool-card', id: 'tool-' + key, 'data-cat': v.meta.category || '',
                'data-search': (key + ' ' + v.meta.tool + ' ' + (v.meta.category || '')).toLowerCase(),
            },
                el('div', { class: 'tool-card-head' },
                    el('h3', { text: v.meta.tool }),
                    el('button', { class: 'ghost', type: 'button', 'aria-label': 'Explication de l\'outil ' + v.meta.tool, text: '?',
                        onclick: () => openInfo(v.meta.tool, v.meta.description, v.meta.indicators) })),
                el('p', { class: 'cat' }, (v.meta.category || '') + ' · ', statusBadge(v.status), ' · ', el('code', { text: key })),
                v.error ? el('p', { class: 'small st-error', text: String(v.error) }) : null,
                renderValue(v.data),
                raw ? el('details', {}, el('summary', { text: 'Sortie brute' }),
                    el('pre', { text: raw.length > MAX_RAW ? raw.slice(0, MAX_RAW) + '\n… (tronqué, voir l\'export JSON)' : raw })) : null));
        });
        return section('Résultats par outil', el('div', { class: 'toolbar' }, search), chips, grid);
    }

    function renderReport(data) {
        const analysis = data.analysis_result || {};
        const finalReport = data.final_report || null;
        const entries = toolEntries(data.scan_results);
        renderHeader(data, analysis);
        const container = $('report-sections');
        container.textContent = '';
        [
            renderSummary(analysis, finalReport),
            renderReliability(analysis),
            renderFindings(analysis),
            renderStrengthsAndActions(analysis),
            renderAttackChain(data.attack),
            renderMitre(analysis),
            renderToolStatus(entries),
            renderToolCards(entries),
            section('Méthodologie', el('div', { class: 'card' },
                el('p', { text: ((data.provenance || {}).methodology) || 'Reconnaissance passive uniquement.' }),
                data.citation ? el('p', { class: 'muted small', text: 'Citation : ' + data.citation }) : null)),
        ].forEach((node) => { if (node) container.appendChild(node); });
        document.title = (data.recon && data.recon.domain ? data.recon.domain + ' — ' : '') + 'Résultat Recon IA';
    }

    // ── Démarrage ───────────────────────────────────────────────────
    function init() {
        applyTheme(store('local', THEME_KEY));
        $('theme-toggle').addEventListener('click', toggleTheme);
        $('logout-btn').addEventListener('click', () => { clearSession(); $('report-sections').textContent = ''; showAccess(); });
        $('toggle-code').addEventListener('click', () => {
            const input = $('access-code');
            input.type = input.type === 'password' ? 'text' : 'password';
        });

        $('access-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = $('access-code');
            const code = input.value.trim();
            if (!/^[A-Za-z0-9_-]{43}$/.test(code)) {
                showMessage('Le code doit contenir 43 caractères (lettres, chiffres, « - » et « _ »).', 'error');
                return;
            }
            const btn = $('access-submit');
            btn.disabled = true;
            try {
                await openSession(code);
                input.value = '';  // le code ne reste pas dans la page
                $('access-message').className = 'message hidden';
                await loadReport();
            } catch (err) {
                showMessage(err.message || 'Impossible d\'ouvrir le rapport.', 'error');
            } finally {
                btn.disabled = false;
            }
        });

        if (getSession()) loadReport(); else showAccess();
    }

    document.addEventListener('DOMContentLoaded', init);
})();
