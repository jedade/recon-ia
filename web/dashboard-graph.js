// web/dashboard-graph.js — onglet « Graphe & surveillance » et section
// « Différentiel » du détail d'un dossier (plan d'action, phase 7).
//
// CSP : fichier externe, aucun style/script inline. Tout le contenu venant de
// l'API (valeurs issues des outils OSINT, donc de la cible) est rendu via
// textContent / createElement, jamais innerHTML. Les appels passent par les
// helpers de session exposés par dashboard.html (window.ReconDash).
(function () {
    'use strict';

    const TYPE_LABELS = {
        domain: 'Domaines', subdomain: 'Sous-domaines', ip: 'IP', port: 'Ports',
        asn: 'ASN', organization: 'Organisations', certificate: 'Certificats',
        technology: 'Technologies', vulnerability: 'CVE',
    };
    const SECTION_LABELS = {
        subdomains: 'Sous-domaines', ips: 'IP', ports: 'Ports (ip:port)',
        cves: 'CVE', technologies: 'Technologies',
    };

    let _loaded = false;
    let _domain = '';
    let _page = 1;
    let _pages = 1;

    const dash = () => window.ReconDash;
    const $ = (id) => document.getElementById(id);

    function el(tag, opts, children) {
        const node = document.createElement(tag);
        if (opts) {
            if (opts.cls) node.className = opts.cls;
            if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
            if (opts.title) node.title = opts.title;
            if (opts.data) Object.keys(opts.data).forEach(k => { node.dataset[k] = opts.data[k]; });
        }
        (children || []).forEach(c => { if (c) node.appendChild(c); });
        return node;
    }

    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    function fmt(iso) { return iso ? dash().formatDate(iso) : '—'; }

    function messageRow(tbody, cols, text) {
        clear(tbody);
        const td = el('td', { cls: 'empty-state', text });
        td.colSpan = cols;
        tbody.appendChild(el('tr', null, [td]));
    }

    function handleError(err, target, cols) {
        if (err && err.message === '401') { dash().onUnauthorized(); return; }
        const text = 'Erreur : ' + (err && err.message ? err.message : 'inconnue');
        if (target && cols) messageRow(target, cols, text);
        else if (target) { clear(target); target.appendChild(el('p', { cls: 'g7-error', text })); }
    }

    function button(label, action, id, extraCls) {
        return el('button', { cls: 'btn-icon g7-btn' + (extraCls ? ' ' + extraCls : ''), text: label,
                              data: { action, id: String(id) } });
    }

    /* ── Graphe ─────────────────────────────────────────────── */
    async function loadSummary() {
        const counters = $('graph-counters');
        const qs = _domain ? '?domain=' + encodeURIComponent(_domain) : '';
        try {
            const resp = await dash().apiFetch('/graph/summary' + qs);
            const d = resp.data || {};
            clear(counters);
            const byType = d.entities_by_type || {};
            const cards = [['Entités', d.entities_total || 0], ['Relations', d.relations_total || 0],
                ['Différentiels', d.snapshots_total || 0]];
            Object.keys(TYPE_LABELS).forEach(t => cards.push([TYPE_LABELS[t], byType[t] || 0]));
            cards.forEach(([label, value]) => {
                counters.appendChild(el('div', { cls: 'stat-card g7-stat' }, [
                    el('div', { cls: 'stat-info' }, [
                        el('div', { cls: 'stat-value', text: value }),
                        el('div', { cls: 'stat-label', text: label }),
                    ]),
                ]));
            });
            const exportOk = !!_domain;
            $('btn-graph-export-csv').disabled = !exportOk;
            $('btn-graph-export-json').disabled = !exportOk;
        } catch (err) {
            handleError(err, counters);
        }
    }

    async function loadEntities(page) {
        _page = page || 1;
        const tbody = $('graph-entities-tbody');
        const params = new URLSearchParams({ page: _page, per_page: 50 });
        if (_domain) params.set('domain', _domain);
        const type = $('graph-type-filter').value;
        const q = $('graph-entity-q').value.trim();
        if (type) params.set('type', type);
        if (q) params.set('q', q);
        try {
            const resp = await dash().apiFetch('/graph/entities?' + params.toString());
            const items = resp.data || [];
            _pages = Math.max(resp.pages || 1, 1);
            $('graph-entities-count').textContent = `${resp.total || 0} entité(s)`;
            $('graph-page-info').textContent = `${resp.page} / ${_pages}`;
            $('btn-graph-prev').disabled = resp.page <= 1;
            $('btn-graph-next').disabled = resp.page >= _pages;
            if (!items.length) { messageRow(tbody, 5, 'Aucune entité'); return; }
            clear(tbody);
            items.forEach(e => {
                const attrs = e.attributes && Object.keys(e.attributes).length
                    ? Object.entries(e.attributes).map(([k, v]) => `${k}=${v}`).join(' · ') : '—';
                tbody.appendChild(el('tr', null, [
                    el('td', { text: TYPE_LABELS[e.type] || e.type }),
                    el('td', { cls: 'g7-mono', text: e.value }),
                    el('td', { cls: 'g7-dim', text: attrs }),
                    el('td', { text: fmt(e.first_seen) }),
                    el('td', { text: fmt(e.last_seen) }),
                ]));
            });
        } catch (err) {
            handleError(err, tbody, 5);
        }
    }

    async function exportLiveHosts(format) {
        if (!_domain) return;
        try {
            const blob = await dash().apiFetchBinary(
                `/graph/live_hosts?domain=${encodeURIComponent(_domain)}&format=${format}`);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `recon_ia_hotes_vivants_${_domain.replace(/[^a-z0-9.-]/gi, '_')}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (err) {
            if (err && err.message === '401') { dash().onUnauthorized(); return; }
            $('graph-export-notice').textContent = 'Export impossible : ' + err.message;
        }
    }

    /* ── Différentiels ──────────────────────────────────────── */
    async function loadSnapshots() {
        const tbody = $('graph-snapshots-tbody');
        const params = new URLSearchParams({ per_page: 20 });
        if (_domain) params.set('domain', _domain);
        const sig = $('graph-snap-significant').value;
        if (sig) params.set('significant', sig);
        try {
            const resp = await dash().apiFetch('/graph/snapshots?' + params.toString());
            const items = resp.data || [];
            if (!items.length) { messageRow(tbody, 7, 'Aucun différentiel enregistré'); return; }
            clear(tbody);
            items.forEach(s => {
                const origin = s.source === 'rescan' ? 'Rescan (surveillance)'
                    : (s.recon_id ? `Dossier #${s.recon_id}` : 'Pipeline');
                const summary = s.has_previous ? ((s.summary || []).join(' · ') || 'Aucun changement')
                    : 'Premier scan (référence)';
                const changes = el('td', { text: String(s.change_count || 0) });
                if (s.significant) changes.appendChild(el('span', { cls: 'g7-badge g7-badge-warn', text: 'significatif' }));
                tbody.appendChild(el('tr', null, [
                    el('td', { cls: 'g7-dim', text: s.id }),
                    el('td', { cls: 'g7-mono', text: s.domain }),
                    el('td', { text: origin }),
                    el('td', { text: fmt(s.created_at) }),
                    changes,
                    el('td', { text: summary }),
                    el('td', null, [button('Détail', 'snapshot-open', s.id)]),
                ]));
            });
        } catch (err) {
            handleError(err, tbody, 7);
        }
    }

    async function openSnapshot(id) {
        const box = $('graph-snapshot-detail');
        try {
            const resp = await dash().apiFetch(`/graph/snapshots/${id}`);
            clear(box);
            box.appendChild(buildDiffSection(resp.data && resp.data.diff, `Différentiel #${id} — ${resp.data.domain}`));
        } catch (err) {
            handleError(err, box);
        }
    }

    /**
     * Section DOM d'un différentiel (format documenté dans api/utils/scan_diff.py).
     * Réutilisée par l'onglet et par le détail d'un dossier.
     */
    function buildDiffSection(diff, title) {
        const section = el('div', { cls: 'modal-section g7-diff' });
        section.appendChild(el('div', { cls: 'modal-section-title', text: title || 'Différentiel avec le scan précédent' }));
        if (!diff) {
            section.appendChild(el('p', { cls: 'g7-dim', text: 'Aucun différentiel disponible.' }));
            return section;
        }
        const head = el('p', { cls: 'g7-diff-head' });
        if (!diff.has_previous) {
            head.textContent = 'Premier scan de ce domaine : sert de référence aux prochains.';
        } else {
            head.textContent = `Comparé au scan du ${fmt(diff.previous_scan_at)} — ${diff.change_count || 0} changement(s).`;
            if (diff.significant) head.appendChild(el('span', { cls: 'g7-badge g7-badge-warn', text: 'significatif' }));
        }
        section.appendChild(head);

        const summary = diff.summary || [];
        if (summary.length) {
            section.appendChild(el('ul', { cls: 'g7-list' }, summary.map(s => el('li', { text: s }))));
        }

        const cert = diff.certificate || {};
        if (cert.current || cert.changed) {
            const parts = [];
            if (cert.current) parts.push(`Certificat : ${cert.current.issuer || '?'} — expire ${cert.current.not_after || '?'}`);
            if (cert.days_until_expiry !== null && cert.days_until_expiry !== undefined) parts.push(`${cert.days_until_expiry} jour(s) restants`);
            if (cert.changed) parts.push('changé depuis le scan précédent');
            section.appendChild(el('p', { cls: cert.expired || cert.expiring_soon ? 'g7-warn' : 'g7-dim', text: parts.join(' · ') }));
        }
        const mail = diff.email_security || {};
        ['spf', 'dmarc'].forEach(k => {
            const e = mail[k];
            if (e && e.changed) {
                section.appendChild(el('p', { cls: 'g7-warn', text: `${k.toUpperCase()} : « ${e.previous || 'absent'} » → « ${e.current || 'absent'} »` }));
            }
        });

        if (diff.has_previous) {
            Object.keys(SECTION_LABELS).forEach(key => {
                const s = diff[key];
                if (!s) return;
                if (!s.compared) {
                    section.appendChild(el('p', { cls: 'g7-dim', text: `${SECTION_LABELS[key]} : non comparé (outil indisponible dans l'un des scans)` }));
                    return;
                }
                if (!s.added_count && !s.removed_count) return;
                const details = el('details', { cls: 'g7-details' });
                details.appendChild(el('summary', { text: `${SECTION_LABELS[key]} : +${s.added_count} / −${s.removed_count}` }));
                if ((s.added || []).length) details.appendChild(el('p', { cls: 'g7-mono g7-added', text: '+ ' + s.added.join('  + ') }));
                if ((s.removed || []).length) details.appendChild(el('p', { cls: 'g7-mono g7-removed', text: '− ' + s.removed.join('  − ') }));
                section.appendChild(details);
            });
        }
        return section;
    }

    async function renderReconDiff(reconId, container) {
        if (!container || !Number.isInteger(reconId)) return;
        const holder = el('div', { cls: 'g7-diff-holder' });
        holder.dataset.reconId = String(reconId);
        container.appendChild(holder);
        try {
            const resp = await dash().apiFetch(`/recon/${reconId}/diff`);
            if (!holder.isConnected) return;
            holder.appendChild(buildDiffSection(resp.data && resp.data.diff));
        } catch (err) {
            if (err && err.message === '401') { dash().onUnauthorized(); return; }
            // 404 = pas encore de différentiel (rapport non généré ou dossier ancien)
            holder.appendChild(buildDiffSection(null));
        }
    }

    /* ── Surveillance ───────────────────────────────────────── */
    async function loadMonitoring() {
        const tbody = $('monitor-tbody');
        try {
            const resp = await dash().apiFetch('/monitoring');
            const items = resp.data || [];
            if (!resp.alert_email_configured) {
                $('monitor-notice').textContent = "Attention : aucun destinataire d'alerte configuré "
                    + '(MONITORING_ALERT_EMAIL ou ADMIN_NOTIFICATION_EMAIL). Les différentiels restent enregistrés.';
            }
            if (!items.length) { messageRow(tbody, 7, 'Aucun domaine surveillé'); return; }
            clear(tbody);
            items.forEach(w => {
                const state = el('td', null, [el('span', {
                    cls: 'g7-badge ' + (w.enabled ? 'g7-badge-ok' : 'g7-badge-off'),
                    text: w.enabled ? (w.is_due ? 'active — rescan dû' : 'active') : 'désactivée',
                })]);
                tbody.appendChild(el('tr', null, [
                    el('td', { cls: 'g7-mono', text: w.domain }),
                    state,
                    el('td', { text: `${w.interval_days} j` }),
                    el('td', { text: fmt(w.last_rescan_at) }),
                    el('td', { text: fmt(w.last_change_at) }),
                    el('td', { text: fmt(w.last_alert_at) }),
                    el('td', null, [
                        button(w.enabled ? 'Désactiver' : 'Activer', w.enabled ? 'monitor-off' : 'monitor-on', w.id),
                        button('Retirer', 'monitor-delete', w.id, 'g7-btn-danger'),
                    ]),
                ]));
            });
        } catch (err) {
            handleError(err, tbody, 7);
        }
    }

    async function addMonitoring() {
        const domain = $('monitor-domain').value.trim().toLowerCase();
        const interval = parseInt($('monitor-interval').value, 10);
        if (!domain) return;
        try {
            await dash().apiSend('POST', '/monitoring', { domain, interval_days: interval || 7, enabled: false });
            $('monitor-domain').value = '';
            loadMonitoring();
        } catch (err) {
            if (err && err.message === '401') { dash().onUnauthorized(); return; }
            $('monitor-notice').textContent = 'Ajout impossible : ' + err.message;
        }
    }

    async function monitorAction(action, id) {
        try {
            if (action === 'monitor-on' || action === 'monitor-off') {
                await dash().apiSend('PATCH', `/monitoring/${id}`, { enabled: action === 'monitor-on' });
            } else if (action === 'monitor-delete') {
                if (!confirm('Retirer ce domaine de la surveillance ? (le graphe et les différentiels sont conservés)')) return;
                await dash().apiSend('DELETE', `/monitoring/${id}`);
            }
            loadMonitoring();
        } catch (err) {
            if (err && err.message === '401') { dash().onUnauthorized(); return; }
            $('monitor-notice').textContent = 'Action impossible : ' + err.message;
        }
    }

    /* ── Cycle de vie ───────────────────────────────────────── */
    function loadAll() {
        _domain = $('graph-domain').value.trim().toLowerCase();
        loadSummary();
        loadEntities(1);
        loadSnapshots();
        loadMonitoring();
    }

    function open() {
        if (!dash()) return;
        if (!_loaded) { _loaded = true; loadAll(); }
    }

    function reset() {
        _loaded = false; _domain = ''; _page = 1; _pages = 1;
        ['graph-entities-tbody', 'graph-snapshots-tbody', 'monitor-tbody'].forEach(id => {
            const t = $(id); if (t) messageRow(t, t.closest('table').querySelectorAll('th').length, '—');
        });
        const box = $('graph-snapshot-detail'); if (box) clear(box);
    }

    function bind() {
        if (!$('tab-graph')) return;
        $('btn-graph-load').addEventListener('click', loadAll);
        $('graph-domain').addEventListener('keydown', e => { if (e.key === 'Enter') loadAll(); });
        $('btn-graph-entities').addEventListener('click', () => loadEntities(1));
        $('graph-type-filter').addEventListener('change', () => loadEntities(1));
        $('graph-entity-q').addEventListener('keydown', e => { if (e.key === 'Enter') loadEntities(1); });
        $('btn-graph-prev').addEventListener('click', () => { if (_page > 1) loadEntities(_page - 1); });
        $('btn-graph-next').addEventListener('click', () => { if (_page < _pages) loadEntities(_page + 1); });
        $('btn-graph-export-csv').addEventListener('click', () => exportLiveHosts('csv'));
        $('btn-graph-export-json').addEventListener('click', () => exportLiveHosts('json'));
        $('btn-graph-snapshots').addEventListener('click', loadSnapshots);
        $('graph-snap-significant').addEventListener('change', loadSnapshots);
        $('btn-monitor-add').addEventListener('click', addMonitoring);
        $('graph-snapshots-tbody').addEventListener('click', e => {
            const b = e.target.closest('[data-action="snapshot-open"]');
            const id = b ? parseInt(b.dataset.id, 10) : NaN;
            if (Number.isInteger(id)) openSnapshot(id);
        });
        $('monitor-tbody').addEventListener('click', e => {
            const b = e.target.closest('[data-action]');
            const id = b ? parseInt(b.dataset.id, 10) : NaN;
            if (Number.isInteger(id)) monitorAction(b.dataset.action, id);
        });
    }

    bind();
    window.ReconGraph = Object.freeze({ open, reset, renderReconDiff, buildDiffSection });
})();
