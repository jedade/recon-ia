// scripts/e2e/page_check.mjs — contrôle visuel rapide d'une page statique
// dans Chrome headless (protocole DevTools, sans dépendance npm) :
// débordement horizontal, violations CSP, exceptions JS, images cassées,
// capture d'écran. Bureau et mobile, thème clair et sombre.
//
// Usage : node page_check.mjs <url> <dossier de sortie> <chrome> [nom]
// Code de sortie 1 si un contrôle échoue.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const [,, PAGE_URL, OUT, CHROME, NAME = "page"] = process.argv;
mkdirSync(join(OUT, 'profile-check'), { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=9338', `--user-data-dir=${join(OUT, 'profile-check')}`,
  '--no-first-run', '--disable-gpu', 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 40; i++) { try { targets = await (await fetch('http://127.0.0.1:9338/json')).json(); if (targets.length) break; } catch { } await sleep(250); }
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let seq = 0; const pending = new Map(); let problems = [];
ws.addEventListener('message', (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.exceptionThrown') problems.push('exception : ' + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
  if (msg.method === 'Log.entryAdded' && /Content Security Policy/.test(msg.params.entry.text)) problems.push('CSP : ' + msg.params.entry.text.slice(0, 220));
});
const send = (method, params = {}) => new Promise((res) => { const n = ++seq; pending.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); });
const evaluate = async (e) => (await send('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true })).result?.result?.value;
await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');

let ok = true;
// Gamme d'écrans : petits et grands téléphones, tablette, portable, bureau.
// VIEWPORTS=320,768 (largeurs) restreint la liste.
const ALL_VARIANTS = [
  { label: '320-clair', width: 320, height: 640, mobile: true, scheme: 'light' },
  { label: '375-sombre', width: 375, height: 740, mobile: true, scheme: 'dark' },
  { label: '414-clair', width: 414, height: 896, mobile: true, scheme: 'light' },
  { label: '768-sombre', width: 768, height: 1024, mobile: true, scheme: 'dark' },
  { label: '1024-clair', width: 1024, height: 768, mobile: false, scheme: 'light' },
  { label: '1440-sombre', width: 1440, height: 900, mobile: false, scheme: 'dark' },
];
const only = (process.env.VIEWPORTS || '').split(',').filter(Boolean).map(Number);
const variants = only.length ? ALL_VARIANTS.filter((v) => only.includes(v.width)) : ALL_VARIANTS;
for (const v of variants) {
  problems = [];
  await send('Emulation.setDeviceMetricsOverride', { width: v.width, height: v.height, deviceScaleFactor: 1, mobile: v.mobile });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: v.scheme }] });
  await send('Page.navigate', { url: PAGE_URL });
  for (let i = 0; i < 60; i++) { if (await evaluate(`document.readyState === 'complete'`)) break; await sleep(250); }
  await sleep(1200);
  // Défilement progressif : déclenche les apparitions au défilement (.reveal)
  await evaluate(`(async () => {
    const h = document.documentElement.scrollHeight;
    for (let y = 0; y < h; y += Math.round(innerHeight * 0.6)) { scrollTo({ top: y, behavior: 'instant' }); await new Promise(r => setTimeout(r, 150)); }
    scrollTo({ top: h, behavior: 'instant' }); await new Promise(r => setTimeout(r, 400));
    scrollTo({ top: 0, behavior: 'instant' }); await new Promise(r => setTimeout(r, 900)); return 1;
  })()`);
  const hiddenReveal = await evaluate(`[...document.querySelectorAll('.reveal:not(.in)')].map(e => e.tagName.toLowerCase() + '.' + e.className.split(' ')[0] + '@' + Math.round(e.getBoundingClientRect().top + scrollY)).join(' ')`);
  if (hiddenReveal) problems.push(`.reveal jamais affichés : ${hiddenReveal}`);
  const r = await evaluate(`(() => {
    const vw = document.documentElement.clientWidth;
    const wide = [...document.querySelectorAll('body *')].filter(e => {
      const b = e.getBoundingClientRect();
      // Hors écran à gauche en entier (lien d’évitement, menu replié) : volontaire
      return b.width > 0 && b.right > 0 && (b.right > vw + 1 || b.left < -1);
    }).filter(e => !e.closest('[hidden]')).slice(0, 6).map(e => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (e.className && typeof e.className === 'string' ? '.' + e.className.split(' ')[0] : '') + ' ' + Math.round(e.getBoundingClientRect().right));
    const broken = [...document.images].filter(i => i.complete && i.naturalWidth === 0).map(i => i.getAttribute('src'));
    const visible = (e) => { const b = e.getBoundingClientRect(); const cs = getComputedStyle(e);
      return b.width > 0 && b.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && !e.closest('[hidden], .hidden, dialog:not([open])'); };
    const label = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (typeof e.className === 'string' && e.className ? '.' + e.className.trim().split(/s+/)[0] : '');
    // Texte lisible : < 11 px sur un élément qui porte directement du texte
    const tiny = [...document.querySelectorAll('body *')].filter(e => visible(e)
      && [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 1)
      && parseFloat(getComputedStyle(e).fontSize) < 11).map(e => label(e) + ' ' + getComputedStyle(e).fontSize);
    // Cibles tactiles (écrans tactiles) : boutons et liens hors texte courant < 32 px
    const small = ${v.mobile} ? [...document.querySelectorAll('button, a, input, select, summary, [role=button]')].filter(e => {
      if (!visible(e) || e.closest('p, li > p, td, dd, figcaption, .faq details p')) return false;
      if (e.matches('input[type=checkbox], input[type=radio]')) return false;
      const b = e.getBoundingClientRect(); return b.height < 32 || b.width < 32;
    }).map(e => { const b = e.getBoundingClientRect(); return label(e) + ' ' + Math.round(b.width) + 'x' + Math.round(b.height); }) : [];
    const uniq = (a) => [...new Set(a)];
    return { scroll: document.documentElement.scrollWidth, vw, wide, broken, tiny: uniq(tiny).slice(0, 8), small: uniq(small).slice(0, 10) };
  })()`);
  const overflow = r.scroll > r.vw + 1;
  const pass = !overflow && r.broken.length === 0 && problems.length === 0;
  ok = ok && pass;
  console.log(`${pass ? '✓' : '✗'} ${NAME} ${v.label} — largeur ${r.scroll}/${r.vw}` +
    (overflow ? ` débordement : ${r.wide.join(', ')}` : '') +
    (r.broken.length ? ` images cassées : ${r.broken.join(', ')}` : '') +
    (problems.length ? ` | ${problems.join(' | ')}` : ''));
  if (r.tiny.length) console.log(`    ⚠ texte < 11 px : ${r.tiny.join(', ')}`);
  if (r.small.length) console.log(`    ⚠ cibles tactiles < 32 px : ${r.small.join(', ')}`);
  const { result } = await send('Page.getLayoutMetrics');
  const h = Math.min(Math.ceil(result.cssContentSize.height), v.width < 700 ? 8000 : 5200);
  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: v.width, height: h, scale: 1 } });
  writeFileSync(join(OUT, `${NAME}-${v.label}.png`), Buffer.from(shot.result.data, 'base64'));
}
// Bouton de thème : bascule, mémorisation, et même thème sur une autre page
const hasToggle = await evaluate(`!!document.querySelector('[data-theme-toggle]')`);
if (hasToggle) {
  const before = await evaluate(`document.documentElement.getAttribute('data-theme')`);
  await evaluate(`document.querySelector('[data-theme-toggle]').click(); 1`);
  await sleep(500);
  const after = await evaluate(`document.documentElement.getAttribute('data-theme')`);
  const saved = await evaluate(`localStorage.getItem('reconia.theme')`);
  await send('Page.navigate', { url: new URL("docs.html", PAGE_URL).href });
  for (let i = 0; i < 40; i++) { if (await evaluate(`document.readyState === 'complete'`)) break; await sleep(250); }
  const elsewhere = await evaluate(`document.documentElement.getAttribute('data-theme')`);
  const pass = before && after && before !== after && saved === after && elsewhere === after;
  ok = ok && pass;
  console.log(`${pass ? '✓' : '✗'} ${NAME} bouton de thème — ${before} → ${after}, mémorisé « ${saved} », docs.html en « ${elsewhere} »`);
  await evaluate(`localStorage.removeItem('reconia.theme'); 1`);
}
ws.close(); chrome.kill();
process.exit(ok ? 0 : 1);
