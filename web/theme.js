// web/theme.js — thème clair / sombre commun à toutes les pages ReconIA.
//
// Chargé de façon SYNCHRONE dans <head>, avant les feuilles de style : il pose
// data-theme="light|dark" sur <html> avant le premier rendu (pas de flash).
// Choix mémorisé sous la clé « reconia.theme » (même clé que result.js) ;
// sans choix, le thème du système est suivi, y compris s'il change.
// Les boutons portant l'attribut data-theme-toggle basculent le thème.
(function () {
    'use strict';
    var KEY = 'reconia.theme';
    var root = document.documentElement;
    var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    // « js » : les styles qui masquent avant animation ne s'appliquent que si
    // les scripts tournent (sinon le contenu resterait invisible).
    root.classList.add('js');

    function stored() {
        try {
            var v = window.localStorage.getItem(KEY);
            return v === 'light' || v === 'dark' ? v : null;
        } catch (e) { return null; }   // stockage indisponible (navigation privée…)
    }
    function system() { return media && media.matches ? 'dark' : 'light'; }

    function apply(theme) {
        root.setAttribute('data-theme', theme);
        var buttons = document.querySelectorAll('[data-theme-toggle]');
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
            buttons[i].setAttribute('aria-label', theme === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre');
            buttons[i].setAttribute('title', theme === 'dark' ? 'Thème clair' : 'Thème sombre');
        }
    }

    apply(stored() || system());

    if (media && media.addEventListener) {
        media.addEventListener('change', function () { if (!stored()) apply(system()); });
    }

    function toggle() {
        var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        // Transition douce des couleurs pendant la bascule uniquement
        root.classList.add('theme-switching');
        apply(next);
        try { window.localStorage.setItem(KEY, next); } catch (e) { /* ignoré */ }
        window.setTimeout(function () { root.classList.remove('theme-switching'); }, 400);
    }

    document.addEventListener('click', function (e) {
        var btn = e.target && e.target.closest ? e.target.closest('[data-theme-toggle]') : null;
        if (btn) { e.preventDefault(); toggle(); }
    });
    document.addEventListener('DOMContentLoaded', function () { apply(root.getAttribute('data-theme')); });

    window.ReconTheme = { toggle: toggle, current: function () { return root.getAttribute('data-theme'); } };
})();
