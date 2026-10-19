// scripts/e2e/result_page.mjs — vérifie web/result.html dans un VRAI
// navigateur (Chrome headless piloté par le protocole DevTools, sans
// dépendance npm : Node ≥ 22 fournit fetch et WebSocket).
//
// Lancé par scripts/e2e/run-result-page.sh, qui démarre l'API de
// démonstration (demo_server.py, dossier scellé réaliste) et un serveur
// statique pour la page. Ce test a trouvé des défauts invisibles aux tests
// pytest : éléments affichés « [object HTMLButtonElement] », bouton de filtre
// illisible, débordement horizontal sur mobile, directive CSP ignorée.
//
// Usage : node result_page.mjs <dossier de travail> <chemin de Chrome>
// Sortie : captures 01/02/03-*.png dans le dossier de travail + rapport JSON ;
// code de sortie 1 si une vérification échoue.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const DIR = process.argv[2];
const CHROME = process.argv[3];
const PAGE = 'http://localhost:18081/result.html';
const code = readFileSync(join(DIR, 'code.txt'), 'utf8').trim();
const profile = join(DIR, 'profile');
mkdirSync(profile, { recursive: true });

const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=9333', `--user-data-dir=${profile}`,
  '--no-first-run', '--disable-gpu', '--window-size=1366,900', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let targets;
for (let i = 0; i < 40; i++) {
  try { targets = await (await fetch('http://127.0.0.1:9333/json')).json(); if (targets.length) break; } catch { }
  await sleep(250);
}
const target = targets.find((t) => t.type === 'page');
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));

let id = 0;
const pending = new Map();
const events = { console: [], errors: [], dialogs: [], csp: [] };
ws.addEventListener('message', (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.consoleAPICalled') events.console.push(msg.params.type + ': ' + msg.params.args.map((a) => a.value ?? a.description).join(' '));
  if (msg.method === 'Runtime.exceptionThrown') events.errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  if (msg.method === 'Log.entryAdded') { const e = msg.params.entry; (e.text.includes('Content Security Policy') ? events.csp : events.console).push(e.level + ': ' + e.text); }
  if (msg.method === 'Page.javascriptDialogOpening') { events.dialogs.push(msg.params.message); send('Page.handleJavaScriptDialog', { accept: true }); }
});
function send(method, params = {}) {
  return new Promise((resolve) => { const n = ++id; pending.set(n, resolve); ws.send(JSON.stringify({ id: n, method, params })); });
}
const evaluate = async (expr) => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;

async function shot(name, width, height) {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 600 });
  await sleep(500);
  const { result } = await send('Page.getLayoutMetrics');
  const h = Math.min(Math.ceil(result.cssContentSize.height), 6000);
  const shotRes = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
    clip: { x: 0, y: 0, width, height: h, scale: 1 } });
  writeFileSync(join(DIR, name), Buffer.from(shotRes.result.data, 'base64'));
}

await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');
await send('Page.navigate', { url: PAGE });
await sleep(1500);
await shot('01-acces.png', 1366, 900);

// Code faux → message d'erreur générique
await evaluate(`document.getElementById('access-code').value='${'A'.repeat(43)}'; document.getElementById('access-form').requestSubmit(); 1`);
await sleep(1200);
const wrongMsg = await evaluate(`document.getElementById('access-message').textContent`);

// Bon code
await evaluate(`document.getElementById('access-code').value='${code}'; document.getElementById('access-form').requestSubmit(); 1`);
await sleep(2500);
const state = await evaluate(`({
  reportVisible: !document.getElementById('report-view').classList.contains('hidden'),
  codeCleared: document.getElementById('access-code').value === '',
  findings: document.querySelectorAll('.finding').length,
  toolCards: document.querySelectorAll('.tool-card').length,
  mitreRows: document.querySelectorAll('table.data tbody tr').length,
  injectedScripts: document.querySelectorAll('#report-sections script, #report-sections img').length,
  xssTitleShownAsText: [...document.querySelectorAll('.finding h3')].some(h => h.textContent.includes('<script>')),
  sessionStored: !!sessionStorage.getItem('reconia.results.session'),
  codeInStorage: JSON.stringify(sessionStorage).includes(${JSON.stringify(code)}) || JSON.stringify(localStorage).includes(${JSON.stringify(code)}),
  // Phase 4 : techniques rendues possibles, mitigations, chaîne d'attaque
  chainSteps: document.querySelectorAll('ol.chain > li.chain-step').length,
  attackChips: [...document.querySelectorAll('.finding .atk-chip a')].map(a => a.textContent),
  attackHrefsOk: [...document.querySelectorAll('.atk-chip a, .chain-techs a')].every(a => /^https:\\/\\/attack\\.mitre\\.org\\/(techniques|mitigations)\\/[TM]\\d{4}(\\/\\d{3})?\\/$/.test(a.href)),
  fakeTechniqueShown: document.body.innerText.includes('T9999') || document.body.innerText.includes('javascript:alert'),
  confidenceBadges: document.querySelectorAll('.finding .badge.conf-high, .finding .badge.conf-medium, .finding .badge.conf-low').length,
  structuredRefShown: document.body.innerText.includes('RFC 7489 (normes)'),
  navigatorButton: !!document.getElementById('navigator-btn'),
})`);
const objectLeak = await evaluate('document.body.innerText.includes("[object ")');
await shot('02-rapport-bureau.png', 1366, 900);

// Filtre de sévérité + filtre de catégorie + recherche
const filters = await evaluate(`(() => {
  const chip = [...document.querySelectorAll('.chips .chip')].find(c => c.dataset.sev === 'CRITICAL');
  chip.click();
  const visibleFindings = [...document.querySelectorAll('.finding')].filter(f => !f.classList.contains('hidden')).length;
  const cat = [...document.querySelectorAll('.chips .chip')].find(c => c.dataset.cat === 'Email / Messagerie');
  cat && cat.click();
  const visibleTools = [...document.querySelectorAll('.tool-card')].filter(c => !c.classList.contains('hidden')).length;
  return { visibleFindings, visibleTools, emailCategoryFound: !!cat };
})()`);

// Téléchargement PDF avec la session (même requête que le bouton)
const pdf = await evaluate(`(async () => {
  const s = JSON.parse(sessionStorage.getItem('reconia.results.session'));
  const r = await fetch('http://localhost:18080/results/report.pdf', { headers: { Authorization: 'Bearer ' + s.token } });
  return { status: r.status, type: r.headers.get('Content-Type'), start: (await r.text()).slice(0, 8) };
})()`);

// Layer ATT&CK Navigator avec la session (même requête que le bouton) + sans session
const navigator = await evaluate(`(async () => {
  const s = JSON.parse(sessionStorage.getItem('reconia.results.session'));
  const r = await fetch('http://localhost:18080/results/export.navigator.json', { headers: { Authorization: 'Bearer ' + s.token } });
  const layer = await r.json();
  const anon = await fetch('http://localhost:18080/results/export.navigator.json');
  return { status: r.status, anonStatus: anon.status, layer: layer.versions && layer.versions.layer, domain: layer.domain,
           techniques: (layer.techniques || []).map(t => t.techniqueID + ':' + t.score) };
})()`);

await evaluate(`[...document.querySelectorAll('.chips .chip')].forEach(c => { if (c.textContent.startsWith('Tous') || c.textContent === 'Toutes') c.click(); }); 1`);
await shot('03-rapport-mobile.png', 390, 844);
const mobileWidth = await evaluate('document.documentElement.scrollWidth');

// Fermeture de session
await send('Emulation.setDeviceMetricsOverride', { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
const logout = await evaluate(`document.getElementById('logout-btn').click(); ({ access: !document.getElementById('access-view').classList.contains('hidden'), session: sessionStorage.getItem('reconia.results.session') })`);

const report = { mobileWidth, wrongMsg, state, filters, pdf, navigator, logout, events };
console.log(JSON.stringify(report, null, 2));

const checks = {
  'code faux → message générique': wrongMsg === "Code d'accès invalide.",
  'bon code → rapport affiché': state.reportVisible,
  'champ du code vidé après usage': state.codeCleared,
  'code jamais stocké dans le navigateur': !state.codeInStorage,
  'constats rendus': state.findings > 0,
  'cartes d\'outils rendues': state.toolCards > 0,
  'aucun élément HTML injecté depuis les données': state.injectedScripts === 0,
  'HTML piégé affiché comme du texte': state.xssTitleShownAsText,
  'aucune boîte de dialogue (alert XSS)': events.dialogs.length === 0,
  'aucune exception JavaScript': events.errors.length === 0,
  'aucune violation CSP': events.csp.length === 0,
  'filtre de sévérité': filters.visibleFindings === 1,
  'filtre de catégorie': filters.emailCategoryFound && filters.visibleTools >= 1,
  'téléchargement PDF avec la session': pdf.status === 200 && pdf.start.startsWith('%PDF'),
  'pas de débordement horizontal à 390 px': mobileWidth <= 390,
  'chaîne d\'attaque plausible affichée': state.chainSteps >= 2,
  'techniques rendues possibles affichées (T1566, T1078, T1552.001)': ['T1566', 'T1078', 'T1552.001'].every(t => state.attackChips.includes(t)),
  'mitigations affichées (M1054)': state.attackChips.includes('M1054'),
  'liens ATT&CK construits depuis des ID valides': state.attackHrefsOk,
  'ID ATT&CK du LLM écartés (T9999)': !state.fakeTechniqueShown,
  'confiance affichée': state.confidenceBadges >= 3,
  'références structurées affichées': state.structuredRefShown,
  'bouton layer Navigator': state.navigatorButton,
  'layer Navigator 4.5 téléchargeable avec la session': navigator.status === 200 && navigator.layer === '4.5' && navigator.domain === 'enterprise-attack' && navigator.techniques.includes('T1566:3'),
  'layer Navigator refusé sans session': navigator.anonStatus === 401,
  'fermeture de session': logout.access && logout.session === null,
  '« [object » jamais affiché': !objectLeak,
};
let failed = 0;
for (const [name, ok] of Object.entries(checks)) {
  console.log(`${ok ? '✓' : '✗'} ${name}`);
  if (!ok) failed++;
}
ws.close();
chrome.kill();
process.exit(failed ? 1 : 0);
