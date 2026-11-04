'use strict';

// Drives the real page in headless Chromium: the account and device panel, and the behaviour around it that
// must not change (saved products, the 20-label trial, printing, export via AndroidBridge, transfer, Stripe).
// Skipped when no browser is found; set CHROME_PATH to point at one.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

function findChrome() {
  const candidates = [process.env.CHROME_PATH, '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const playwright = path.join(os.homedir(), '.cache', 'ms-playwright');
  if (fs.existsSync(playwright)) {
    for (const dir of fs.readdirSync(playwright).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse()) {
      candidates.push(path.join(playwright, dir, 'chrome-linux64', 'chrome'), path.join(playwright, dir, 'chrome-linux', 'chrome'));
    }
  }
  return candidates.find((p) => p && fs.existsSync(p));
}

const chromePath = findChrome();
const skip = !chromePath && 'no Chromium found';
const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const appScript = html.slice(html.indexOf("var KEY='pharmacy-labels-v2'"));
const I18N = require('node:vm').runInNewContext(`(${appScript.slice(appScript.indexOf('var I18N=') + 9, appScript.indexOf('function contentLang('))
  .trim().replace(/;$/, '')})`);
const en = I18N.en;
const PORT = 31896;
const DEBUG_PORT = 31897;
const origin = `http://127.0.0.1:${PORT}`;
const STORAGE_KEY = 'pharmacy-labels-v2';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let server, chrome, ws, profile, dataDir, serverModule;
let seq = 0;
const pending = new Map();
const problems = [];
const consoleText = [];
const requests = [];
const sent = [];

function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function ev(expression) {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  return result.result.value;
}

async function waitFor(expression, timeout = 8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await ev(expression).catch(() => false)) return;
    await sleep(50);
  }
  const state = await ev(`JSON.stringify({ account: document.getElementById('account-status')?.textContent,
    message: document.getElementById('account-message')?.textContent, chip: document.getElementById('billing-chip')?.textContent })`)
    .catch((error) => error.message);
  throw new Error(`timed out waiting for ${expression}; page: ${state}; errors: ${JSON.stringify(problems)}; requests: ${JSON.stringify(requests.map((r) => `${r.method} ${new URL(r.url).pathname}`))}`);
}

async function navigate(url) {
  await ev('window.__previousPage = true').catch(() => {});
  await send('Page.navigate', { url });
  await waitFor(`!window.__previousPage && document.readyState !== 'loading'`, 20000);
}

// Loads the app and waits until billing and the account panel have both settled.
async function load(query = '') {
  await navigate(`${origin}/${query}`);
  await waitFor(`document.getElementById('billing-chip').textContent !== '20/20' || document.getElementById('billing-status').textContent !== ''`);
  await waitFor(`!document.getElementById('account-panel').hidden`);
}

const text = (id) => ev(`document.getElementById(${JSON.stringify(id)}).textContent`);
const hidden = (id) => ev(`document.getElementById(${JSON.stringify(id)}).hidden`);
const click = (id) => ev(`document.getElementById(${JSON.stringify(id)}).click()`);
const type = (id, value) => ev(`(() => { const el = document.getElementById(${JSON.stringify(id)}); el.value = ${JSON.stringify(value)};
  el.dispatchEvent(new Event('input', { bubbles: true })); })()`);
const requestsTo = (pathname, method) => requests.filter((r) => new URL(r.url).pathname === pathname && (!method || r.method === method));
const fill = (key, data = {}) => en[key].replace(/\{(\w+)\}/g, (_, k) => String(data[k]));
const count = (sql, ...args) => serverModule.db.prepare(sql).get(...args).n;

async function block(patterns) {
  await send('Network.setBlockedURLs', { urls: patterns });
}

const mailCount = (email) => sent.filter((m) => m.to === email).length;

// Waits for the mail sent after `before` mails to this address had arrived, and reads its code.
async function mailedCode(email, before) {
  for (let i = 0; i < 200; i++) {
    await serverModule.processOutbox();
    const mails = sent.filter((m) => m.to === email);
    if (mails.length > before) return mails[mails.length - 1].text.match(/verification code is: (\d{8})/)[1];
    await sleep(10);
  }
  throw new Error(`no code mailed to ${email}`);
}

async function signUp(email) {
  await type('account-email', email);
  const before = mailCount(email);
  await click('btn-account-code');
  await waitFor(`!document.getElementById('account-code-step').hidden`);
  const code = await mailedCode(email, before);
  await type('account-code', code);
  await click('btn-account-signup');
  await waitFor(`document.getElementById('account-status').textContent.startsWith('Signed in as')`);
  return code;
}

before(async () => {
  if (!chromePath) return;
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-account-ui-'));
  Object.assign(process.env, { SESSION_SECRET: 'account-ui-secret-with-at-least-32-characters', PUBLIC_APP_URL: origin, DATA_DIR: dataDir });
  // No Stripe key: checkout answers 503 locally, so nothing can reach Stripe.
  for (const name of ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'SMTP_HOST']) delete process.env[name];
  serverModule = require('../server');
  serverModule.mailer.configured = true;
  serverModule.mailer.send = async (message) => { sent.push(message); };
  server = await new Promise((resolve) => { const l = serverModule.app.listen(PORT, '127.0.0.1', () => resolve(l)); });
  profile = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-chrome-account-'));
  chrome = spawn(chromePath, ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
  let target;
  for (let i = 0; i < 100 && !target; i++) {
    await sleep(100);
    try { target = (await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`)).json()).find((t) => t.type === 'page'); } catch {}
  }
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve) => ws.addEventListener('open', resolve));
  ws.addEventListener('message', ({ data }) => {
    const m = JSON.parse(data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Runtime.exceptionThrown') problems.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === 'Runtime.consoleAPICalled') consoleText.push(m.params.args.map((a) => a.value ?? a.description).join(' '));
    if (m.method === 'Network.requestWillBeSent') requests.push({ url: m.params.request.url, method: m.params.request.method });
  });
  await send('Runtime.enable');
  await send('Page.enable');
  await send('Network.enable');
  // Requests go straight to the network, so blocked URLs below apply to every fetch the page makes.
  await send('Network.setBypassServiceWorker', { bypass: true });
  await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*']);
});

after(async () => {
  if (ws) ws.close();
  if (chrome) { chrome.kill(); await sleep(300); }
  if (server) server.close();
  if (serverModule) serverModule.db.close();
  for (const dir of [profile, dataDir]) if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('saved products survive loading the page with the new panel', { skip }, async () => {
  const products = [
    { id: 'p1', name: 'Paracetamol 500', price: '2500', code: 'PARA-000001', exp: '2027-05', batch: 'B1' },
    { id: 'p2', name: 'باراسيتامول', price: '1000', code: 'BARA-000002', exp: '', batch: '' }
  ];
  await navigate(`${origin}/api/health`);
  await ev(`localStorage.setItem(${JSON.stringify(STORAGE_KEY)}, ${JSON.stringify(JSON.stringify({ settings: { lang: 'en' }, products }))})`);
  await load();
  assert.deepEqual(await ev(`[...document.querySelectorAll('#reg-body tr[data-id]')].map((tr) => tr.dataset.id)`), ['p1', 'p2']);
  await sleep(400); // past persist()'s debounce
  const stored = JSON.parse(await ev(`localStorage.getItem(${JSON.stringify(STORAGE_KEY)})`));
  assert.deepEqual(stored.products, products, 'products are kept exactly');
  assert.equal(await ev(`Object.keys(localStorage).some((k) => /account|device|token/i.test(k))`), false, 'the account adds nothing to localStorage');
});

test('a first visit creates exactly one anonymous session, so billing and the account share it', { skip }, async () => {
  await send('Network.clearBrowserCookies');
  const before = count('SELECT COUNT(*) AS n FROM app_sessions');
  await load();
  assert.equal(count('SELECT COUNT(*) AS n FROM app_sessions') - before, 1);
});

test('the trial stays at 20 labels: printing reserves on the server, export uses AndroidBridge, the limit locks as before', { skip }, async () => {
  await load();
  assert.equal(await text('billing-chip'), '20/20');
  assert.equal(await text('billing-status'), fill('freeRemaining', { n: 20, limit: 20 }));

  await ev(`window.__printed = 0; window.print = () => { window.__printed += 1; }`);
  await click('btn-print');
  await waitFor(`window.__printed === 1`);
  assert.equal(await text('billing-chip'), '19/20');
  assert.equal(requestsTo('/api/labels/reserve', 'POST').length, 1);

  await ev(`window.__saved = []; window.AndroidBridge = { saveXlsx: (name, data) => window.__saved.push([name, data.length]) }`);
  await click('btn-export');
  const saved = await ev('window.__saved');
  assert.equal(saved.length, 1);
  assert.match(saved[0][0], /\.xlsx$/);
  assert.ok(saved[0][1] > 100, 'a base64 workbook is handed to the bridge');

  // Use the rest of the trial, then the page locks exactly as it did before.
  assert.equal(await ev(`fetch('/api/labels/reserve', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ count: 19 }) }).then((r) => r.status)`), 200);
  await load();
  assert.equal(await text('billing-chip'), '0/20');
  assert.equal(await text('billing-status'), fill('lockedPlan', { price: 5 }));
  for (const id of ['btn-print', 'btn-test', 'btn-export', 'btn-import', 'btn-save']) assert.equal(await ev(`document.getElementById('${id}').disabled`), true, id);
  assert.equal(await hidden('transfer-box'), false);
  // An account does not change that.
  assert.equal(await hidden('account-signin'), false);
});

test('transfer and Stripe checkout keep their requests and messages', { skip }, async () => {
  await load();
  await type('transfer-email', 'transfer-buyer@example.com');
  await click('btn-transfer-request');
  await waitFor(`document.getElementById('transfer-status').textContent !== ''`);
  assert.equal(await text('transfer-status'), fill('transferSent', { minutes: 10 }));
  assert.equal(await hidden('transfer-code-step'), false);
  assert.equal(requestsTo('/api/license/transfer/request', 'POST').length, 1);

  await click('btn-unlock');
  await waitFor(`document.getElementById('toast').textContent === ${JSON.stringify(en.unlockFail)}`);
  assert.equal(requestsTo('/api/checkout', 'POST').length, 1);

  await load('?checkout_session_id=cs_test_account_ui&checkout=success');
  await waitFor(`!location.search.includes('checkout_session_id')`);
  assert.equal(requestsTo('/api/checkout/complete', 'POST').length, 1);
  assert.equal(await ev('location.search'), '');
});

test('signing up shows the account, registers a device only on request, and never shows the code', { skip }, async () => {
  await load();
  assert.equal(await text('account-status'), en.acctSignedOut);
  assert.equal(await hidden('account-signin'), false);
  assert.equal(await hidden('account-code-step'), true);
  assert.equal(await hidden('account-signed'), true);
  assert.equal(requestsTo('/device-key.js').length, 0, 'the device script is not loaded for a signed-out page');

  // A burst of clicks sends one request: the button is disabled before the first one leaves.
  await type('account-email', 'ui-user@example.com');
  const before = requestsTo('/api/email-verification/request', 'POST').length;
  const mailsBefore = mailCount('ui-user@example.com');
  await ev(`(() => { const b = document.getElementById('btn-account-code'); b.click(); b.click(); b.click(); })()`);
  await waitFor(`!document.getElementById('account-code-step').hidden`);
  assert.equal(requestsTo('/api/email-verification/request', 'POST').length - before, 1);
  assert.equal(await text('account-message'), fill('acctCodeSent', { minutes: 10 }));
  const code = await mailedCode('ui-user@example.com', mailsBefore);
  assert.equal(mailCount('ui-user@example.com'), mailsBefore + 1, 'one code mailed');

  await type('account-code', '00000000' === code ? '11111111' : '00000000');
  await click('btn-account-signup');
  await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.acct_verification_failed)}`);
  await type('account-code', code);
  await click('btn-account-signup');
  await waitFor(`document.getElementById('account-status').textContent.startsWith('Signed in as')`);
  assert.equal(await text('account-status'), fill('acctSignedIn', { email: 'ui***@e***.com' }));
  assert.equal(await text('account-message'), en.acctCreated);
  assert.equal(await text('device-state'), en.devNone);
  assert.equal(await hidden('btn-device-register'), false);
  assert.equal(await hidden('btn-device-verify'), true);

  // Signed in, but nothing was registered, generated or loaded without the user asking.
  assert.equal(count('SELECT COUNT(*) AS n FROM devices'), 0);
  assert.equal(requestsTo('/device-key.js').length, 0);
  assert.equal(await ev(`indexedDB.databases().then((dbs) => dbs.some((d) => d.name === 'product-labels-device'))`), false);
  await load();
  assert.equal(count('SELECT COUNT(*) AS n FROM devices'), 0, 'reloading does not register either');

  // Declining the confirmation does nothing.
  await ev('window.confirm = () => false');
  await click('btn-device-register');
  await sleep(200);
  assert.equal(requestsTo('/api/devices/challenge').length, 0);

  await ev('window.confirm = () => true');
  await click('btn-device-register');
  await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.devRegistered)}`);
  assert.equal(await text('device-state'), en.devThis);
  assert.equal(await hidden('btn-device-register'), true);
  assert.equal(count('SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NULL'), 1);

  await load();
  await waitFor(`document.getElementById('device-state').textContent === ${JSON.stringify(en.devThis)}`);
  await click('btn-device-verify');
  await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.devVerified)}`);

  // Nothing about the account touches billing: still the free plan.
  assert.match(await text('billing-title'), new RegExp(en.freePlan));
  assert.equal(count('SELECT COUNT(*) AS n FROM license_certificates') + count('SELECT COUNT(*) AS n FROM trials'), 0);

  const page = await ev('document.body.innerText');
  assert.ok(!page.includes(code), 'the code is not shown');
  assert.ok(!consoleText.join('\n').includes(code), 'the code is not logged');
  assert.equal(await ev(`document.cookie`), '', 'session and account cookies stay HttpOnly');

  await click('btn-account-logout');
  await waitFor(`document.getElementById('account-status').textContent === ${JSON.stringify(en.acctSignedOut)}`);
  assert.equal(await text('account-message'), en.acctLoggedOut);
  assert.deepEqual(problems, []);
});

test('login for an address without an account explains what to do; the other device case is shown', { skip }, async () => {
  await load();
  await type('account-email', 'nobody-here@example.com');
  const before = mailCount('nobody-here@example.com');
  await click('btn-account-code');
  await waitFor(`!document.getElementById('account-code-step').hidden`);
  await type('account-code', await mailedCode('nobody-here@example.com', before));
  await click('btn-account-login');
  await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.acct_account_not_found)}`);
  assert.equal(await hidden('account-code-step'), true, 'the spent code is not offered again');
  assert.equal(count("SELECT COUNT(*) AS n FROM accounts WHERE email_masked = 'no***@e***.com'"), 0);

  // The first account of this browser owns its key; another account's device elsewhere reads as "another device".
  const other = serverModule.db.prepare('SELECT id FROM accounts').get().id;
  await signUp('second-ui@example.com');
  const accountId = serverModule.db.prepare("SELECT id FROM accounts WHERE email_masked = 'se***@e***.com'").get().id;
  assert.notEqual(accountId, other);
  serverModule.db.prepare(`INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at, last_validated_at)
    VALUES ('elsewhere', ?, 'some-other-thumbprint', '{}', 1, 1)`).run(accountId);
  await load();
  await waitFor(`document.getElementById('device-state').textContent === ${JSON.stringify(en.devOther)}`);
  assert.equal(await hidden('btn-device-register'), true);
  assert.equal(await hidden('btn-device-verify'), true);
  await click('btn-account-logout');
  await waitFor(`document.getElementById('account-status').textContent === ${JSON.stringify(en.acctSignedOut)}`);
});

test('an unreachable account service or server shows a message and leaves the page working', { skip }, async () => {
  try {
    await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*', '*/api/account*']);
    await load();
    assert.equal(await text('account-status'), en.acctUnavailable);
    assert.equal(await hidden('account-signin'), true);
    assert.equal(await hidden('account-signed'), true);
    assert.match(await text('billing-chip'), /^\d+\/20$/, 'billing is unaffected');

    await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*', '*/api/*']);
    await navigate(`${origin}/`);
    await waitFor(`!document.getElementById('account-panel').hidden`);
    assert.equal(await text('account-status'), en.acctUnavailable);
    assert.equal(await text('billing-chip'), '—');
    assert.equal(await text('billing-status'), en.serviceUnavailable);
    assert.ok(await ev(`document.querySelectorAll('#reg-body tr[data-id]').length`) >= 2, 'saved products are still listed');
  } finally {
    await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*']);
  }
  assert.deepEqual(problems, []);
});

test('a device script that fails to load leaves the page usable and can be retried', { skip }, async () => {
  await load();
  await signUp('script-fail@example.com');
  assert.equal(await text('device-state'), en.devNone);
  await ev('window.confirm = () => true');
  try {
    await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*', '*device-key.js*']);
    await click('btn-device-register');
    await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.devScriptFailed)}`);
    assert.equal(await ev(`typeof window.ProductLabelsDevice`), 'undefined');
    for (const id of ['btn-device-register', 'btn-account-logout']) assert.equal(await ev(`document.getElementById('${id}').disabled`), false, id);
    assert.ok(await ev(`document.querySelectorAll('#reg-body tr[data-id]').length`) >= 2);
  } finally {
    await block(['*fonts.googleapis.com*', '*fonts.gstatic.com*']);
  }
  const accountId = serverModule.db.prepare("SELECT id FROM accounts WHERE email_masked = 'sc***@e***.com'").get().id;
  assert.equal(count('SELECT COUNT(*) AS n FROM devices WHERE account_id = ?', accountId), 0);
  // The failed load is not cached: the next attempt loads the script and reaches the server. This browser
  // profile's key already belongs to the account from the earlier test, so the server refuses it here.
  await click('btn-device-register');
  await waitFor(`document.getElementById('account-message').textContent !== ${JSON.stringify(en.devScriptFailed)}`);
  await waitFor(`document.getElementById('account-message').textContent === ${JSON.stringify(en.acct_key_unavailable)}`);
  assert.deepEqual(problems, []);
});

test('on file:// (the Android asset) the account panel stays hidden and nothing is requested', { skip }, async () => {
  const before = requests.length;
  await navigate(`file://${path.join(root, 'index.html')}`);
  await sleep(1500);
  assert.equal(await ev('location.protocol'), 'file:');
  assert.equal(await hidden('account-panel'), true);
  const made = requests.slice(before).map((r) => r.url);
  assert.ok(!made.some((url) => /\/api\/(account|devices|email-verification)|device-key\.js/.test(url)), JSON.stringify(made));
  assert.equal(await text('billing-status'), en.serviceUnavailable, 'billing behaves as it already did without a server');
  assert.deepEqual(problems, []);
});
