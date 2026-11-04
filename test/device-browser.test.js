'use strict';

// Runs device-key.js in headless Chromium against the real server routes: real WebCrypto, real IndexedDB.
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
const PORT = 31892;
const DEBUG_PORT = 31893;
const origin = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let server, chrome, ws, profile, dataDir, serverModule;
let seq = 0;
const pending = new Map();
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

async function open() {
  await ev('window.__previousPage = true').catch(() => {});
  await send('Page.navigate', { url: `${origin}/api/health` });
  for (let i = 0; i < 100; i++) {
    if (await ev(`!window.__previousPage && document.readyState === 'complete'`).catch(() => false)) break;
    await sleep(50);
  }
  await ev(`new Promise((resolve, reject) => { const s = document.createElement('script'); s.src = '/device-key.js';
    s.onload = resolve; s.onerror = reject; document.head.appendChild(s); })`);
}

const pagePost = (pathname, body) => ev(`fetch(${JSON.stringify(pathname)}, { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: ${JSON.stringify(JSON.stringify(body))} }).then(async (r) => ({ status: r.status, body: await r.json() }))`);

before(async () => {
  if (!chromePath) return;
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-device-ui-'));
  Object.assign(process.env, {
    SESSION_SECRET: 'device-browser-secret-with-at-least-32-chars', PUBLIC_APP_URL: origin, DATA_DIR: dataDir,
    STRIPE_SECRET_KEY: 'sk_test_device_browser', STRIPE_WEBHOOK_SECRET: 'whsec_device_browser'
  });
  delete process.env.SMTP_HOST;
  serverModule = require('../server');
  serverModule.mailer.configured = true;
  serverModule.mailer.send = async (message) => { sent.push(message); };
  server = await new Promise((resolve) => { const l = serverModule.app.listen(PORT, '127.0.0.1', () => resolve(l)); });
  profile = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-chrome-device-'));
  chrome = spawn(chromePath, ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
  let target;
  for (let i = 0; i < 100 && !target; i++) {
    await sleep(100);
    try { target = (await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`)).json()).find((t) => t.type === 'page'); } catch {}
  }
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve) => ws.addEventListener('open', resolve));
  ws.addEventListener('message', ({ data }) => {
    const m = JSON.parse(data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  });
  await send('Runtime.enable');
  await send('Page.enable');
});

after(async () => {
  if (ws) ws.close();
  if (chrome) { chrome.kill(); await sleep(300); }
  if (server) server.close();
  if (serverModule) serverModule.db.close();
  for (const dir of [profile, dataDir]) if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('in a real browser the device key is non-extractable, survives a reload and proves possession', { skip: !chromePath && 'no Chromium found' }, async () => {
  await open();
  const email = 'browser-device@example.com';
  assert.equal((await pagePost('/api/email-verification/request', { email })).status, 202);
  for (let i = 0; i < 200 && !sent.length; i++) {
    await serverModule.processOutbox();
    await sleep(10);
  }
  const code = sent[0].text.match(/verification code is: (\d{8})/)[1];
  assert.equal((await pagePost('/api/account/signup', { email, code })).status, 201);

  const registered = await ev(`(async () => {
    const keys = ProductLabelsDevice.createDeviceKeys();
    const result = await keys.register();
    const { privateKey, publicKey } = await keys.keyPair();
    let exported = 'refused';
    try { await crypto.subtle.exportKey('jwk', privateKey); exported = 'exported'; } catch {}
    return { result, thumbprint: await keys.thumbprint(), extractable: privateKey.extractable, exported,
      usages: privateKey.usages, algorithm: privateKey.algorithm, publicExtractable: publicKey.extractable,
      cookieVisible: document.cookie.includes('product_labels') };
  })()`);
  assert.equal(registered.result.status, 201, JSON.stringify(registered.result.body));
  assert.equal(registered.result.body.keyThumbprint, registered.thumbprint);
  assert.equal(registered.extractable, false);
  assert.equal(registered.exported, 'refused');
  assert.deepEqual(registered.usages, ['sign']);
  assert.deepEqual(registered.algorithm, { name: 'ECDSA', namedCurve: 'P-256' });
  assert.equal(registered.publicExtractable, true);
  assert.equal(registered.cookieVisible, false, 'session and account cookies stay HttpOnly');

  // After a reload the same key comes back from IndexedDB and signs a fresh challenge.
  await sleep(5);
  await open();
  const proved = await ev(`(async () => {
    const keys = ProductLabelsDevice.createDeviceKeys();
    return { result: await keys.verify(), thumbprint: await keys.thumbprint() };
  })()`);
  assert.equal(proved.result.status, 200, JSON.stringify(proved.result.body));
  assert.equal(proved.thumbprint, registered.thumbprint);

  const devices = serverModule.db.prepare('SELECT key_thumbprint, public_key_jwk FROM devices').all();
  assert.equal(devices.length, 1);
  assert.equal(devices[0].key_thumbprint, registered.thumbprint);
  assert.ok(!Object.hasOwn(JSON.parse(devices[0].public_key_jwk), 'd'));
});

test('offline, the real service worker serves device-key.js from its cache and never HTML for a script', { skip: !chromePath && 'no Chromium found' }, async () => {
  await send('Page.navigate', { url: `${origin}/` });
  // The page registers sw.js on load; reload once the worker is active so the page is controlled by it.
  await ev(`new Promise((resolve) => { const wait = () => navigator.serviceWorker ? navigator.serviceWorker.ready.then(resolve) : setTimeout(wait, 50); wait(); })`);
  await send('Page.reload');
  for (let i = 0; i < 100 && !(await ev('Boolean(navigator.serviceWorker && navigator.serviceWorker.controller)').catch(() => false)); i++) await sleep(50);
  assert.equal(await ev(`navigator.serviceWorker.controller.scriptURL`), `${origin}/sw.js`);
  assert.deepEqual(await ev(`caches.keys()`), ['product-labels-v11']);
  assert.equal(await ev(`caches.open('product-labels-v11').then((c) => c.match('/device-key.js')).then((r) => Boolean(r))`), true);
  assert.equal(await ev(`caches.open('product-labels-v11').then((c) => c.match('/license-client.js')).then((r) => Boolean(r))`), true);

  // A real outage: DevTools' offline emulation does not reach the worker's own fetches, so stop the server.
  await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  server = null;
  {
    const offline = await ev(`(async () => {
      const outcome = (p) => p.then(async (r) => ({ status: r.status, type: r.headers.get('content-type'), body: (await r.text()).slice(0, 60) }),
        (e) => ({ error: e.name }));
      return {
        script: await outcome(fetch('/device-key.js')),
        missing: await outcome(fetch('/missing-file.js')),
        api: await outcome(fetch('/api/health'))
      };
    })()`);
    assert.equal(offline.script.status, 200);
    assert.match(offline.script.type, /javascript/);
    assert.match(offline.script.body, /use strict/);
    assert.deepEqual(offline.missing, { error: 'TypeError' }, 'an uncached script fails instead of returning index.html');
    assert.deepEqual(offline.api, { error: 'TypeError' }, 'API calls are never answered from a cache');
  }
});
