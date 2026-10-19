// scripts/e2e/full_flow.mjs — parcours COMPLET sur la stack réelle
// (docker compose + Caddy + n8n + Mailpit), piloté dans Chrome headless.
//
//   formulaire (vrai widget Turnstile) → OTP lu dans Mailpit → vérification
//   → pipeline n8n réel (scan, analyse IA, PDF, scellement) → mail « rapport
//   prêt » lu dans Mailpit → code saisi sur result.html → rapport + PDF.
//
// Usage : node full_flow.mjs <dossier de sortie> <chemin de Chrome>
// Variables : SITE (http://localhost:8088), API_ADMIN (http://localhost:8080),
//   MAILPIT (http://localhost:8026), ADMIN_AUTH (« email:motdepasse »),
//   DOMAIN (example.com), PIPELINE_TIMEOUT_S (3600).
// Code de sortie 1 si une étape échoue.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const OUT = process.argv[2];
const CHROME = process.argv[3];
const SITE = process.env.SITE || 'http://localhost:8088';
const API_ADMIN = process.env.API_ADMIN || 'http://localhost:8080';
const MAILPIT = process.env.MAILPIT || 'http://localhost:8026';
const ADMIN_AUTH = 'Basic ' + Buffer.from(process.env.ADMIN_AUTH || '').toString('base64');
const DOMAIN = process.env.DOMAIN || 'example.com';
const EMAIL = `e2e-${Date.now()}@example.test`;
const PIPELINE_TIMEOUT_S = Number(process.env.PIPELINE_TIMEOUT_S || 3600);
mkdirSync(join(OUT, 'profile'), { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok });
  log(`${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  return ok;
}

// ── Mailpit ──────────────────────────────────────────────────────────
async function waitMail(subjectPart, timeoutS = 120) {
  for (let i = 0; i < timeoutS; i++) {
    const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent('to:' + EMAIL)}`)).json();
    const msg = (list.messages || []).find((m) => (m.Subject || '').includes(subjectPart));
    if (msg) return (await fetch(`${MAILPIT}/api/v1/message/${msg.ID}`)).json();
    await sleep(1000);
  }
  return null;
}

// ── Chrome / DevTools ────────────────────────────────────────────────
const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=9334', `--user-data-dir=${join(OUT, 'profile')}`,
  '--no-first-run', '--disable-gpu', '--window-size=1366,900', 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 40; i++) {
  try { targets = await (await fetch('http://127.0.0.1:9334/json')).json(); if (targets.length) break; } catch { }
  await sleep(250);
}
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let seq = 0;
const pending = new Map();
const events = { errors: [], csp: [], dialogs: [] };
ws.addEventListener('message', (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.exceptionThrown') events.errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  if (msg.method === 'Log.entryAdded' && msg.params.entry.text.includes('Content Security Policy')) events.csp.push(msg.params.entry.text);
  if (msg.method === 'Page.javascriptDialogOpening') { events.dialogs.push(msg.params.message); send('Page.handleJavaScriptDialog', { accept: true }); }
});
function send(method, params = {}) {
  return new Promise((resolve) => { const n = ++seq; pending.set(n, resolve); ws.send(JSON.stringify({ id: n, method, params })); });
}
const evaluate = async (expr) => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
// Attendre la fin du chargement : soumettre un formulaire avant que son script
// soit attaché le ferait partir en navigation native (bloquée par la CSP).
async function goto(url) {
  await send('Page.navigate', { url });
  for (let i = 0; i < 80; i++) { await sleep(250); if (await evaluate(`document.readyState === 'complete'`)) break; }
  await sleep(500);
}
async function shot(name) {
  const { result } = await send('Page.getLayoutMetrics');
  const h = Math.min(Math.ceil(result.cssContentSize.height), 5000);
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: 1366, height: h, scale: 1 } });
  writeFileSync(join(OUT, name), Buffer.from(r.result.data, 'base64'));
}
await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');

let exitCode = 0;
try {
  // 1. Formulaire public + Turnstile réel (clé de test Cloudflare)
  await goto(`${SITE}/`);
  let token = '';
  for (let i = 0; i < 30 && !token; i++) {
    token = await evaluate(`(document.querySelector('[name="cf-turnstile-response"]') || {}).value || ''`);
    if (!token) await sleep(1000);
  }
  check('widget Turnstile chargé et jeton obtenu', token, token ? token.slice(0, 12) + '…' : 'aucun jeton');
  await evaluate(`(() => {
    const set = (id, v) => { document.getElementById(id).value = v; };
    set('first-name', 'Ada'); set('last-name', 'Lovelace');
    set('domain-to-test', ${JSON.stringify(DOMAIN)}); set('contact-email', ${JSON.stringify(EMAIL)});
    document.getElementById('ownership-confirmation').checked = true;
    document.getElementById('main-form').requestSubmit();
  })()`);
  // L'API répond après l'envoi SMTP de l'OTP : attendre l'étape 2 (20 s max).
  let step2 = false;
  for (let i = 0; i < 40 && !step2; i++) {
    await sleep(500);
    step2 = await evaluate(`getComputedStyle(document.getElementById('verification-form')).display !== 'none'`);
  }
  check('formulaire accepté (captcha vérifié côté API)', step2,
    await evaluate(`document.getElementById('form-message').textContent.trim()`));
  await shot('flow-01-formulaire.png');

  // 2. OTP reçu par mail
  const otpMail = await waitMail('');
  const otp = otpMail && ((otpMail.Text || '').match(/\b(\d{6})\b/) || [])[1];
  check('mail OTP reçu (SMTP réel vers Mailpit)', otp, otpMail ? otpMail.Subject : 'aucun mail');

  // 3. Vérification → l'API déclenche n8n
  await evaluate(`document.getElementById('verification-code').value = ${JSON.stringify(otp || '')};
                  document.getElementById('verification-form').requestSubmit(); 1`);
  await sleep(4000);
  const launched = await evaluate(`document.getElementById('form-message').textContent`);
  check('OTP validé et analyse lancée', /Analyse lancée/.test(launched || ''), (launched || '').trim().slice(0, 80));
  await shot('flow-02-analyse-lancee.png');

  // 4. Pipeline n8n réel, suivi côté admin
  const list = await (await fetch(`${API_ADMIN}/recon?per_page=5`, { headers: { Authorization: ADMIN_AUTH } })).json();
  const recon = (list.data || []).find((r) => r.email === EMAIL);
  check('dossier créé en base', recon, recon ? `recon_id=${recon.id}` : '');
  let final = null;
  const t0 = Date.now();
  let lastStep = '';
  while (recon && (Date.now() - t0) / 1000 < PIPELINE_TIMEOUT_S) {
    final = (await (await fetch(`${API_ADMIN}/recon/${recon.id}`, { headers: { Authorization: ADMIN_AUTH } })).json()).data;
    if (final.current_step !== lastStep) { lastStep = final.current_step; log(`  étape : ${lastStep} (statut ${final.status})`); }
    if (['success', 'failed'].includes(final.status) && (final.results_sealed || final.status === 'failed')) break;
    await sleep(10000);
  }
  check('pipeline n8n terminé avec succès', final && final.status === 'success',
    final ? `statut=${final.status} étape=${final.current_step} en ${Math.round((Date.now() - t0) / 1000)} s` : '');
  check('résultats scellés en base', final && final.results_sealed && final.access_state === 'active');

  // 5. Mail « rapport prêt » : code d'accès, aucune pièce jointe
  const readyMail = await waitMail('est prêt', 120);
  const code = readyMail && ((readyMail.Text || '').match(/\b([A-Za-z0-9_-]{43})\b/) || [])[1];
  check('mail « rapport prêt » reçu avec un code', code, readyMail ? readyMail.Subject : 'aucun mail');
  check('aucune pièce jointe dans le mail', readyMail && (readyMail.Attachments || []).length === 0);

  // 6. Consultation par code
  await goto(`${SITE}/result.html`);
  await evaluate(`document.getElementById('access-code').value = ${JSON.stringify(code || '')};
                  document.getElementById('access-form').requestSubmit(); 1`);
  await sleep(5000);
  const report = await evaluate(`({
    visible: !document.getElementById('report-view').classList.contains('hidden'),
    domain: (document.querySelector('.report-title h1') || {}).textContent,
    tools: document.querySelectorAll('.tool-card').length,
    findings: document.querySelectorAll('.finding').length,
  })`);
  check('rapport affiché sur result.html', report.visible && report.domain === DOMAIN,
    `${report.tools} cartes d'outils, ${report.findings} constats`);
  await shot('flow-03-resultat.png');
  const pdf = await evaluate(`(async () => {
    const s = JSON.parse(sessionStorage.getItem('reconia.results.session'));
    const r = await fetch(window.RECON_IA_CONFIG.API_BASE + '/results/report.pdf', { headers: { Authorization: 'Bearer ' + s.token } });
    const b = new Uint8Array(await r.arrayBuffer());
    return { status: r.status, size: b.length, magic: String.fromCharCode(...b.slice(0, 5)) };
  })()`);
  check('PDF déchiffré téléchargé via Caddy', pdf.status === 200 && pdf.magic === '%PDF-', `${pdf.size} octets`);

  // 7. Admin : contenu illisible, cache brut lisible
  const sealedPdf = await fetch(`${API_ADMIN}/recon/${recon.id}/report.pdf`, { headers: { Authorization: ADMIN_AUTH } });
  check('admin : PDF du dossier scellé refusé (403)', sealedPdf.status === 403);
  const cache = await (await fetch(`${API_ADMIN}/cache?domain=${DOMAIN}`, { headers: { Authorization: ADMIN_AUTH } })).json();
  check('admin : scan brut consultable dans le cache', (cache.data || []).some((c) => c.domain === DOMAIN));

  check('aucune exception JavaScript', events.errors.length === 0, events.errors.join(' | '));
  check('aucune violation CSP', events.csp.length === 0, events.csp.join(' | '));
} catch (e) {
  check('exécution du scénario', false, e.stack);
} finally {
  writeFileSync(join(OUT, 'full_flow_events.json'), JSON.stringify(events, null, 2));
  exitCode = results.some((r) => !r.ok) ? 1 : 0;
  log(`${results.filter((r) => r.ok).length}/${results.length} vérifications réussies`);
  ws.close();
  chrome.kill();
  process.exit(exitCode);
}
