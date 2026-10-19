// scripts/e2e/dashboard.mjs — dashboard admin sur la stack réelle (Chrome
// headless) : connexion, onglet « Scans bruts (cache) », détail d'un scan,
// détail d'un dossier scellé (section coffre, pas de téléchargement, accès au
// scan brut du même domaine).
//
// Usage : node dashboard.mjs <dossier de sortie> <chemin de Chrome>
// Variables : SITE, API_PUBLIC (URL de l'API vue par le navigateur),
// ADMIN_EMAIL, ADMIN_PASSWORD. Code de sortie 1 si une vérification échoue.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const [,, OUT, CHROME] = process.argv;
const SITE = process.env.SITE || 'http://localhost';
const API_PUBLIC = process.env.API_PUBLIC || 'http://api.localhost';
mkdirSync(join(OUT, 'profile-dash'), { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=9336', `--user-data-dir=${join(OUT, 'profile-dash')}`,
  '--no-first-run', '--disable-gpu', '--window-size=1440,900', 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 40; i++) { try { targets = await (await fetch('http://127.0.0.1:9336/json')).json(); if (targets.length) break; } catch { } await sleep(250); }
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let seq = 0; const pending = new Map(); const problems = [];
ws.addEventListener('message', (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.exceptionThrown') problems.push('exception : ' + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
  if (msg.method === 'Log.entryAdded' && /Content Security Policy/.test(msg.params.entry.text)) problems.push('CSP : ' + msg.params.entry.text);
  if (msg.method === 'Page.javascriptDialogOpening') { problems.push('dialogue : ' + msg.params.message); send('Page.handleJavaScriptDialog', { accept: true }); }
});
function send(method, params = {}) { return new Promise((res) => { const n = ++seq; pending.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); }); }
const evaluate = async (e) => (await send('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true })).result?.result?.value;
async function shot(name) {
  if (!(await noOverflow(name))) problems.push('débordement horizontal : ' + name);
  const { result } = await send('Page.getLayoutMetrics');
  const h = Math.min(Math.ceil(result.cssContentSize.height), 4000);
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: VW, height: h, scale: 1 } });
  writeFileSync(join(OUT, name), Buffer.from(r.result.data, 'base64'));
}
const results = [];
const check = (name, ok, detail) => { results.push(!!ok); console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`); };

await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');
// WIDTH=375|768… : largeur d'écran émulée (tactile sous 900 px)
const VW = Number(process.env.WIDTH || 1440);
await send('Emulation.setDeviceMetricsOverride', { width: VW, height: VW < 900 ? 844 : 900, deviceScaleFactor: 1, mobile: VW < 900 });
const overflowChecks = [];
async function noOverflow(label) {
  const r = await evaluate(`(() => { const vw = document.documentElement.clientWidth;
    const wide = [...document.querySelectorAll("body *")].filter(e => { const b = e.getBoundingClientRect();
      return b.width > 0 && b.right > vw + 1 && !e.closest(".table-wrap, .dash-tabs"); })
      .slice(0, 5).map(e => e.tagName.toLowerCase() + (e.id ? "#" + e.id : "") + "." + String(e.className).split(" ")[0] + " " + Math.round(e.getBoundingClientRect().right));
    return { w: document.documentElement.scrollWidth, vw, wide }; })()`);
  overflowChecks.push(`${label} ${r.w}/${r.vw}`);
  if (r.w > r.vw + 1) problems.push(`${label} : ${r.wide.join(", ")}`);
  return r.w <= r.vw + 1;
}
// THEME=light|dark : thème imposé avant le premier rendu (clé de theme.js)
if (process.env.THEME) {
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source: `try { localStorage.setItem('reconia.theme', ${JSON.stringify(process.env.THEME)}); } catch (e) {}`,
  });
}
await send('Page.navigate', { url: `${SITE}/dashboard.html` });
// Attendre la fin du chargement : les feuilles de style externes (polices,
// icônes) retardent l'exécution du script ; soumettre avant ferait partir le
// formulaire en navigation native.
for (let i = 0; i < 60; i++) { if (await evaluate(`document.readyState === 'complete'`)) break; await sleep(250); }
await sleep(500);
await evaluate(`document.getElementById('api-url').value = ${JSON.stringify(API_PUBLIC)};
  document.getElementById('api-email').value = ${JSON.stringify(process.env.ADMIN_EMAIL || '')};
  document.getElementById('api-pass').value = ${JSON.stringify(process.env.ADMIN_PASSWORD || '')};
  document.getElementById('login-form').requestSubmit(); 1`);
await sleep(4000);
check('connexion admin', await evaluate(`getComputedStyle(document.getElementById('login-screen')).display === 'none'`));

// Liste des dossiers : cadenas pour un dossier scellé
const sealedRow = await evaluate(`(() => { const lock = document.querySelector('#recon-tbody .fa-lock');
  return lock ? lock.parentElement.getAttribute('title') : null; })()`);
check('dossier scellé affiché avec un cadenas', sealedRow, sealedRow || '');

// Détail du dossier scellé
const sealedId = await evaluate(`(() => { const lock = document.querySelector('#recon-tbody .fa-lock');
  return lock ? lock.closest('tr').querySelector('[data-action="open"]').dataset.id : null; })()`);
await evaluate(`openModal(${Number(sealedId)}); 1`);
await sleep(2500);
const modal = await evaluate(`({
  vault: document.getElementById('modal-body').textContent.includes('Coffre des résultats'),
  noFakeEmpty: !document.getElementById('modal-body').textContent.includes('Aucune analyse IA disponible'),
  jsonHidden: document.getElementById('modal-btn-json').style.display === 'none',
  csvHidden: document.getElementById('modal-btn-csv').style.display === 'none',
  pdfHidden: document.getElementById('modal-btn-dl').style.display === 'none',
  cacheBtn: !!document.getElementById('modal-cache-btn'),
  revokeBtn: !!document.getElementById('modal-revoke-btn'),
})`);
check('détail scellé : section « Coffre des résultats »', modal.vault);
check('détail : aucune durée négative', await evaluate(`[...document.querySelectorAll('.timing-chip .tc-val')]
  .every(e => !/^[-−]/.test(e.textContent.trim()))`));
check('détail scellé : pas de faux « Aucune analyse IA »', modal.noFakeEmpty);
check('détail scellé : aucun téléchargement proposé', modal.jsonHidden && modal.csvHidden && modal.pdfHidden);
check('détail scellé : boutons « scan brut » et « révoquer »', modal.cacheBtn && modal.revokeBtn);
await shot('dash-01-dossier-scelle.png');

// Accès au scan brut du même domaine depuis le dossier scellé
await evaluate(`document.getElementById('modal-cache-btn').click(); 1`);
await sleep(3000);
const fromVault = await evaluate(`({ title: document.getElementById('modal-subtitle').textContent,
  tools: document.querySelectorAll('#modal-body details.tool-raw').length,
  json: document.getElementById('modal-btn-json').style.display !== 'none' })`);
check('scan brut ouvert depuis le dossier scellé', /Scan brut en cache/.test(fromVault.title) && fromVault.tools > 0,
  `${fromVault.tools} outils, export JSON ${fromVault.json ? 'disponible' : 'absent'}`);
await shot('dash-02-scan-brut.png');
await evaluate(`document.getElementById('modal-close').click(); 1`);

// Onglet « Scans bruts (cache) »
await evaluate(`document.querySelector('.dash-tab[data-tab="cache"]').click(); 1`);
await sleep(2500);
const tab = await evaluate(`({ rows: document.querySelectorAll('#cache-tbody tr [data-action="cache-open"].btn-eye').length,
  count: document.getElementById('cache-count').textContent })`);
check('onglet « Scans bruts (cache) » rempli', tab.rows > 0, tab.count);
await evaluate(`document.getElementById('filter-cache-valid').value = 'false'; document.getElementById('btn-apply-cache-filters').click(); 1`);
await sleep(1500);
const expiredFilter = await evaluate(`document.getElementById('cache-count').textContent`);
check('filtre « expirées » appliqué', /scan/.test(expiredFilter), expiredFilter);
await shot('dash-03-onglet-cache.png');

// Phase 7 — section « Différentiel » dans le détail du dossier scellé
await evaluate(`openModal(${Number(sealedId)}); 1`);
await sleep(2500);
check('détail : section différentiel (phase 7)', await evaluate(
  `!!document.querySelector('#modal-body .g7-diff-holder .g7-diff')`));
await evaluate(`document.getElementById('modal-close').click(); 1`);

// Phase 7 — onglet « Graphe & surveillance »
await evaluate(`document.querySelector('.dash-tab[data-tab="graph"]').click(); 1`);
await sleep(2500);
const graphTab = await evaluate(`({
  counters: document.querySelectorAll('#graph-counters .stat-card').length,
  monitor: document.querySelectorAll('#monitor-tbody tr').length,
  exportDisabled: document.getElementById('btn-graph-export-csv').disabled,
})`);
check('onglet graphe : compteurs par type', graphTab.counters >= 10, `${graphTab.counters} cartes`);
check('onglet graphe : export désactivé sans domaine', graphTab.exportDisabled);
check('onglet graphe : tableau de surveillance rendu', graphTab.monitor > 0);
await shot('dash-04-onglet-graphe.png');

check('aucune exception, violation CSP ni dialogue', problems.length === 0, problems.join(' | '));
ws.close(); chrome.kill();
process.exit(results.every(Boolean) ? 0 : 1);
