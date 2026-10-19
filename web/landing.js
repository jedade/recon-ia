// web/landing.js — page d'accueil ReconIA : menu, formulaire en deux étapes
// (demande + code de vérification), widget Turnstile.
//
// Le formulaire ne parle QU'À L'API : la vérification du code déclenche
// elle-même le pipeline n8n sur le réseau interne. API_BASE et la clé
// Turnstile viennent de config.js (DASHBOARD_API_BASE / TURNSTILE_SITE_KEY,
// .env racine), injecté au démarrage du conteneur `web`.
// ⚠️ Visible côté client : jamais de secret ici. La protection anti-abus
// est côté API (captcha, limites de débit, OTP).
//
// Rendu exclusivement par textContent / createElement : aucun contenu venu
// de l'API n'est interprété comme du HTML.
(function () {
    'use strict';

    const CONFIG = window.RECON_IA_CONFIG || {};
    const API_BASE = CONFIG.API_BASE || 'https://api.idachallenge.bj';
    const RECON_API_URL = API_BASE + '/recon';
    const VERIFY_API_URL = API_BASE + '/verify_email';
    const TURNSTILE_SITE_KEY = CONFIG.TURNSTILE_SITE_KEY || '';

    const SUBMIT_COOLDOWN_MS = 30000;   // 30 s entre deux demandes (confort ; l'API limite aussi)
    let submitCooldownUntil = 0;

    const $ = (id) => document.getElementById(id);

    function el(tag, opts, children) {
        const node = document.createElement(tag);
        if (opts && opts.className) node.className = opts.className;
        if (opts && opts.text) node.textContent = opts.text;
        if (opts && opts.href) node.setAttribute('href', opts.href);
        (children || []).forEach((c) => node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
        return node;
    }

    // ── Turnstile (chargé à la demande, seulement si une clé est configurée) ──
    let turnstileToken = '';
    let turnstileWidgetId = null;
    function setupTurnstile() {
        if (!TURNSTILE_SITE_KEY) return;
        window.onTurnstileLoad = function () {
            turnstileWidgetId = window.turnstile.render('#turnstile-widget', {
                sitekey: TURNSTILE_SITE_KEY,
                language: 'fr',
                // Format normal = 300 px de large : trop pour un écran de 320 px
                size: window.matchMedia('(max-width: 380px)').matches ? 'compact' : 'normal',
                callback: function (token) { turnstileToken = token; },
                'expired-callback': function () { turnstileToken = ''; },
                'error-callback': function () { turnstileToken = ''; },
            });
        };
        const s = document.createElement('script');
        s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad';
        s.async = true;
        s.defer = true;
        document.head.appendChild(s);
    }
    function resetTurnstile() {
        turnstileToken = '';
        if (window.turnstile && turnstileWidgetId !== null) window.turnstile.reset(turnstileWidgetId);
    }

    // ── Messages ────────────────────────────────────────────────────────
    function showMessage(nodes, type, permanent) {
        const box = $('form-message');
        box.textContent = '';
        box.className = 'form-message ' + (type || 'error');
        const icon = el('i', { className: type === 'success' ? 'fas fa-circle-check' : 'fas fa-circle-exclamation' });
        icon.setAttribute('aria-hidden', 'true');
        box.appendChild(icon);
        const body = el('div');
        (Array.isArray(nodes) ? nodes : [nodes]).forEach((n) => body.appendChild(typeof n === 'string' ? document.createTextNode(n) : n));
        box.appendChild(body);
        box.hidden = false;
        box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        if (!permanent && type === 'success') setTimeout(() => { box.hidden = true; }, 8000);
    }
    function hideMessage() { $('form-message').hidden = true; }

    function setLoading(button, loading) {
        button.disabled = loading;
        button.querySelector('.btn-text').hidden = loading;
        button.querySelector('.btn-loading').hidden = !loading;
    }

    function setStep(n) {
        $('fs-1').classList.toggle('active', n === 1);
        $('fs-2').classList.toggle('active', n === 2);
    }

    // ── Appels API ──────────────────────────────────────────────────────
    async function readJson(response) {
        const text = await response.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* corps non JSON */ }
        return { data, text };
    }

    // Étape 1 — créer la demande et envoyer le code de vérification par email
    async function createRecon(form) {
        const fd = new FormData(form);
        const response = await fetch(RECON_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                firstname: (fd.get('first-name') || '').trim(),
                lastname: (fd.get('last-name') || '').trim(),
                domain: (fd.get('domain-to-test') || '').trim().toLowerCase(),
                email: (fd.get('contact-email') || '').trim(),
                accord: fd.get('ownership-confirmation') === 'on',
                turnstile_token: turnstileToken || undefined,
            }),
        });
        const { data, text } = await readJson(response);
        if (!response.ok) {
            throw new Error((data && (data.message || data.error)) || text || ('HTTP ' + response.status));
        }
        return data;
    }

    // Étape 2 — vérifier le code ; l'API lance elle-même l'analyse.
    // 200 = vérifié, 400/404/429 = refusé avec un message explicite.
    async function verifyCode(code, email) {
        const response = await fetch(VERIFY_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, email }),
        });
        const { data } = await readJson(response);
        return {
            ok: response.ok && data && data.success === true,
            pipelineStarted: !!(data && data.pipeline_started === true),
            message: (data && (data.error || data.message)) || null,
        };
    }

    // ── Formulaire en deux étapes ───────────────────────────────────────
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

    function setupForms() {
        const mainForm = $('main-form');
        const verifyForm = $('verification-form');
        const submitMain = $('submit-main-btn');
        const submitVerify = $('submit-verification-btn');
        if (!mainForm || !verifyForm) return;

        mainForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fd = new FormData(mainForm);
            const first = (fd.get('first-name') || '').trim();
            const last = (fd.get('last-name') || '').trim();
            const domain = (fd.get('domain-to-test') || '').trim().toLowerCase();
            const email = (fd.get('contact-email') || '').trim();

            if (!first || !last || !domain || !email) return showMessage('Veuillez remplir tous les champs requis.', 'error');
            if (!fd.get('ownership-confirmation')) return showMessage('Vous devez confirmer être autorisé à analyser ce domaine.', 'error');
            if (!EMAIL_RE.test(email)) return showMessage('Veuillez saisir une adresse email valide.', 'error');
            if (!DOMAIN_RE.test(domain)) return showMessage('Format de domaine invalide. Exemple : exemple.bj', 'error');

            const now = Date.now();
            if (now < submitCooldownUntil) {
                return showMessage('Merci de patienter ' + Math.ceil((submitCooldownUntil - now) / 1000) + ' seconde(s) avant une nouvelle demande.', 'error');
            }
            submitCooldownUntil = now + SUBMIT_COOLDOWN_MS;

            setLoading(submitMain, true);
            try {
                await createRecon(mainForm);
                mainForm.hidden = true;
                verifyForm.hidden = false;
                setStep(2);
                showMessage('Un code de vérification a été envoyé à votre adresse email. Veuillez le saisir ci-dessous.', 'success', true);
                $('verification-code').focus();
            } catch (error) {
                // Les messages de l'API sont rédigés pour l'utilisateur
                // (consentement, anti-robot, délai entre deux codes).
                submitCooldownUntil = 0;
                showMessage((error && error.message) || 'Une erreur est survenue. Veuillez réessayer.', 'error');
            } finally {
                resetTurnstile();   // un jeton Turnstile ne sert qu'une fois
                setLoading(submitMain, false);
            }
        });

        $('back-to-main-btn').addEventListener('click', () => {
            verifyForm.hidden = true;
            mainForm.hidden = false;
            setStep(1);
            hideMessage();
        });

        verifyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = $('verification-code').value.trim();
            const email = $('contact-email').value.trim();
            if (!code) return showMessage('Veuillez saisir le code de vérification.', 'error');

            setLoading(submitVerify, true);
            try {
                const result = await verifyCode(code, email);
                if (result.ok && !result.pipelineStarted) {
                    verifyForm.hidden = true;
                    showMessage(result.message || "Email vérifié, mais l'analyse n'a pas pu être lancée. L'équipe a été prévenue.", 'error', true);
                } else if (result.ok) {
                    verifyForm.hidden = true;
                    showMessage([
                        el('h3', { text: 'Analyse lancée !' }),
                        el('p', {}, [
                            'Dès que le rapport sera prêt (en général moins de 30 minutes), vous recevrez un email contenant un ',
                            el('strong', { text: "code d'accès" }),
                            '. Saisissez-le sur la page ',
                            el('a', { href: 'result.html', text: 'Voir le résultat' }),
                            ' pour consulter et télécharger le rapport (PDF, JSON, CSV).',
                        ]),
                    ], 'success', true);
                } else {
                    showMessage(result.message || 'Le code de vérification est incorrect. Veuillez réessayer.', 'error');
                }
            } catch (error) {
                showMessage('Une erreur est survenue lors de la vérification du code. Veuillez réessayer.', 'error');
            } finally {
                setLoading(submitVerify, false);
            }
        });
    }

    // ── Navigation ──────────────────────────────────────────────────────
    function setupNav() {
        const toggle = $('menu-toggle');
        const nav = $('main-nav');
        const header = $('site-header');
        if (toggle && nav) {
            const close = () => { nav.classList.remove('open'); toggle.setAttribute('aria-expanded', 'false'); };
            toggle.addEventListener('click', () => {
                const open = nav.classList.toggle('open');
                toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
            nav.querySelectorAll('a').forEach((a) => a.addEventListener('click', close));
            document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
        }
        if (header) {
            const onScroll = () => header.classList.toggle('scrolled', window.scrollY > 8);
            window.addEventListener('scroll', onScroll, { passive: true });
            onScroll();
        }
        const year = $('year');
        if (year) year.textContent = String(new Date().getFullYear());
    }

    // ── Animations ──────────────────────────────────────────────────────
    const REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Apparition au défilement : les éléments .reveal reçoivent « in » en
    // entrant dans l'écran, avec un léger décalage entre voisins d'une grille.
    function setupReveal() {
        const items = Array.from(document.querySelectorAll('.reveal'));
        items.forEach((node) => {
            if (node.hasAttribute('data-delay')) return;
            const siblings = Array.from(node.parentElement.children).filter((c) => c.classList.contains('reveal'));
            const idx = siblings.indexOf(node);
            if (idx > 0) node.setAttribute('data-delay', String(Math.min(idx, 4)));
        });
        const show = (node) => {
            node.classList.add('in');
            // Une fois apparu, l'élément reprend ses transitions de survol
            setTimeout(() => node.classList.add('done'), 1200);
        };
        if (REDUCED || !('IntersectionObserver' in window)) { items.forEach(show); return; }
        const io = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) { show(entry.target); io.unobserve(entry.target); }
            });
        }, { rootMargin: '0px 0px -8% 0px', threshold: 0.12 });
        items.forEach((node) => io.observe(node));
    }

    // Compteurs : de 0 à la valeur affichée (texte final déjà dans le HTML)
    function setupCounters() {
        if (REDUCED) return;
        document.querySelectorAll('[data-count]').forEach((node) => {
            const target = parseInt(node.getAttribute('data-count'), 10);
            if (!Number.isFinite(target)) return;
            const delay = node.classList.contains('score-value') ? 900 : 500;
            const duration = 1600;
            node.textContent = '0';
            setTimeout(() => {
                const start = performance.now();
                const step = (now) => {
                    const t = Math.min(1, (now - start) / duration);
                    const eased = 1 - Math.pow(1 - t, 3);
                    node.textContent = String(Math.round(target * eased));
                    if (t < 1) requestAnimationFrame(step);
                };
                requestAnimationFrame(step);
            }, delay);
        });
    }

    function init() {
        setupNav();
        setupForms();
        setupTurnstile();
        setupReveal();
        setupCounters();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
