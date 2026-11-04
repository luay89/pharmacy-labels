'use strict';

// Drives the real page in headless Chromium over the DevTools protocol.
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
const pageHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const appScript = pageHtml.slice(pageHtml.indexOf("var KEY='pharmacy-labels-v2'"));
const I18N = require('node:vm').runInNewContext(`(${appScript.slice(appScript.indexOf('var I18N=') + 9, appScript.indexOf('function contentLang('))
  .trim().replace(/;$/, '')})`);
const PORT = 31890;
const DEBUG_PORT = 31891;
const origin = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let server, chrome, ws, profile, dataDir;
let seq = 0;
const pending = new Map();
const problems = [];

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
    await sleep(100);
  }
  const state = await ev(`JSON.stringify({ ready: document.readyState, chip: document.getElementById('billing-chip')?.textContent,
    status: document.getElementById('billing-status')?.textContent })`).catch((error) => error.message);
  throw new Error(`timed out waiting for ${expression}; page: ${state}; page errors: ${JSON.stringify(problems)}`);
}

async function load() {
  await ev('window.__previousPage = true').catch(() => {});
  await send('Page.navigate', { url: `${origin}/` });
  // Once parsing is done the app script has run and set the chip to "—"; it shows the free count after
  // /api/session answers. The load event is not awaited: a slow font stylesheet can hold it back.
  await waitFor(`!window.__previousPage && document.readyState !== 'loading' && document.getElementById('billing-chip').textContent === '20/20'`, 20000);
}

async function key(keyName, code, keyCode) {
  for (const type of ['keyDown', 'keyUp']) {
    await send('Input.dispatchKeyEvent', { type, key: keyName, code, windowsVirtualKeyCode: keyCode });
  }
}

async function clickAt(x, y) {
  for (const type of ['mousePressed', 'mouseReleased']) {
    await send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
  }
}

const dialogOpen = () => ev(`document.getElementById('buy-dialog').open`);
const setLanguage = (lang) => ev(`(() => { const s = document.getElementById('language-select'); s.value = '${lang}';
  s.dispatchEvent(new Event('change')); return new Promise((r) => setTimeout(r, 400)); })()`);

before(async () => {
  if (!chromePath) return;
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-ui-'));
  Object.assign(process.env, {
    SESSION_SECRET: 'ui-browser-secret-with-at-least-32-chars', PUBLIC_APP_URL: origin, DATA_DIR: dataDir,
    STRIPE_SECRET_KEY: 'sk_test_ui_browser', STRIPE_WEBHOOK_SECRET: 'whsec_ui_browser'
  });
  delete process.env.SMTP_HOST;
  const { app } = require('../server');
  server = await new Promise((resolve) => { const l = app.listen(PORT, '127.0.0.1', () => resolve(l)); });
  profile = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-chrome-'));
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
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') problems.push(m.params.args.map((a) => a.value ?? a.description).join(' '));
  });
  await send('Runtime.enable');
  await send('Page.enable');
  // Keep the test off the internet: the font stylesheet blocks the app script until it loads or fails.
  await send('Network.enable');
  await send('Network.setBlockedURLs', { urls: ['*fonts.googleapis.com*', '*fonts.gstatic.com*'] });
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
});

after(async () => {
  if (ws) ws.close();
  if (chrome) { chrome.kill(); await sleep(300); }
  if (server) server.close();
  for (const dir of [profile, dataDir]) if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('first visit is in English and the purchase button sits at the top', { skip: !chromePath && 'no Chromium found' }, async () => {
  await load();
  const page = await ev(`(() => {
    const b = document.getElementById('btn-buy-help').getBoundingClientRect();
    const h1 = document.querySelector('h1').getBoundingClientRect();
    const sel = document.getElementById('theme-select').getBoundingClientRect();
    const overlap = (a, c) => a.left < c.right && c.left < a.right && a.top < c.bottom && c.top < a.bottom;
    return { lang: document.documentElement.lang, dir: document.documentElement.dir, title: document.title,
      h1: document.querySelector('h1 span').textContent, select: document.getElementById('language-select').value,
      button: document.getElementById('btn-buy-help').textContent, top: b.top, visible: b.width > 0 && b.height > 0,
      overlaps: overlap(b, h1) || overlap(b, sel), unlock: document.getElementById('btn-unlock').textContent,
      preset: document.getElementById('s-preset').selectedOptions[0].textContent };
  })()`);
  assert.deepEqual({ ...page, top: undefined }, {
    lang: 'en', dir: 'ltr', title: 'Product Labels', h1: 'Product Labels', select: 'en', button: 'Buy / Purchase',
    top: undefined, visible: true, overlaps: false, unlock: 'One-time purchase (5$)', preset: '40 × 30 mm'
  });
  assert.ok(page.top < 120, `button too low: ${page.top}`);
  assert.equal(await ev(`/[\\u0600-\\u06FF]/.test(document.querySelector('.wrap').innerText.replace(/العربية|اردو/g, ''))`), false,
    'no Arabic text should remain in the English interface');
});

test('the help dialog opens, closes with Escape, the backdrop and the close buttons', { skip: !chromePath && 'no Chromium found' }, async () => {
  await ev(`document.getElementById('btn-buy-help').click()`);
  assert.equal(await dialogOpen(), true);
  const content = await ev(`({ headings: [...document.querySelectorAll('#buy-dialog h3')].map((h) => h.textContent),
    steps: document.querySelectorAll('#buy-dialog li').length, empty: [...document.querySelectorAll('#buy-dialog [data-i18n]')].filter((e) => !e.textContent.trim()).length,
    support: document.getElementById('help-support').textContent, go: !document.getElementById('buy-go').hidden,
    focused: document.activeElement.id })`);
  assert.deepEqual(content.headings, ['Accounts and device licenses', 'Purchase and Activation', 'Keep Your Purchase Email', 'Transfer to Another Device', 'Troubleshooting']);
  assert.equal(content.empty, 0);
  assert.ok(content.steps >= 13);
  assert.match(content.support, /Reply to your purchase confirmation email/);
  assert.equal(content.go, true);
  assert.equal(content.focused, 'buy-close');

  await key('Escape', 'Escape', 27);
  await sleep(100);
  assert.equal(await dialogOpen(), false);
  assert.equal(await ev(`document.activeElement.id`), 'btn-buy-help');

  await ev(`document.getElementById('btn-buy-help').click()`);
  await clickAt(4, 4);
  await sleep(100);
  assert.equal(await dialogOpen(), false, 'click on the backdrop closes');

  await ev(`document.getElementById('btn-buy-help').click()`);
  const box = await ev(`(() => { const r = document.querySelector('#buy-dialog .dlg-body').getBoundingClientRect(); return { x: r.left + 30, y: r.top + 30 }; })()`);
  await clickAt(box.x, box.y);
  await sleep(100);
  assert.equal(await dialogOpen(), true, 'click inside keeps it open');
  await ev(`document.getElementById('buy-close-x').click()`);
  assert.equal(await dialogOpen(), false);
  await ev(`document.getElementById('btn-buy-help').click(); document.getElementById('buy-close').click()`);
  assert.equal(await dialogOpen(), false);
});

test('the chosen language persists across reloads and unknown values fall back to English', { skip: !chromePath && 'no Chromium found' }, async () => {
  await setLanguage('ar');
  const ar = await ev(`({ lang: document.documentElement.lang, dir: document.documentElement.dir,
    button: document.getElementById('btn-buy-help').textContent, unlock: document.getElementById('btn-unlock').textContent })`);
  assert.deepEqual(ar, { lang: 'ar', dir: 'rtl', button: 'شراء الترخيص', unlock: 'شراء لمرة واحدة (5$)' });
  await ev(`document.getElementById('btn-buy-help').click()`);
  assert.equal(await ev(`document.querySelector('#buy-dialog [data-i18n="helpA"]').textContent`), 'الشراء والتفعيل');
  await ev(`document.getElementById('buy-close').click()`);

  await load();
  assert.deepEqual(await ev(`[document.documentElement.lang, document.documentElement.dir, document.getElementById('language-select').value]`), ['ar', 'rtl', 'ar']);

  await setLanguage('ur');
  assert.deepEqual(await ev(`[document.documentElement.lang, document.documentElement.dir, document.getElementById('language-select').value,
    document.getElementById('btn-buy-help').textContent]`), ['ur', 'rtl', 'ur', I18N.ur.buyBtn], 'Urdu is translated and right-to-left');

  await ev(`(() => { const s = JSON.parse(localStorage.getItem('pharmacy-labels-v2')); s.settings.lang = '__proto__';
    localStorage.setItem('pharmacy-labels-v2', JSON.stringify(s)); })()`);
  await load();
  assert.deepEqual(await ev(`[document.documentElement.lang, document.getElementById('language-select').value]`), ['en', 'en']);

  await ev(`localStorage.setItem('pharmacy-labels-v2', '{not json')`);
  await load();
  assert.deepEqual(await ev(`[document.documentElement.lang, document.getElementById('language-select').value]`), ['en', 'en']);
});

test('every language renders its own texts, direction and currency example', { skip: !chromePath && 'no Chromium found' }, async () => {
  for (const lang of Object.keys(I18N)) {
    await setLanguage(lang);
    const d = I18N[lang];
    const page = await ev(`(() => {
      const text = (id) => document.getElementById(id).textContent;
      const emptyKeys = [...document.querySelectorAll('[data-i18n]')].filter((e) => !e.textContent.trim()).map((e) => e.dataset.i18n);
      return { lang: document.documentElement.lang, dir: document.documentElement.dir, title: document.title,
        buy: text('btn-buy-help'), unlock: text('btn-unlock'), heading: document.querySelector('[data-i18n="appTitle"]').textContent,
        currency: document.getElementById('f-currency').placeholder, saveBtn: text('btn-save'), emptyKeys,
        preset: document.getElementById('s-preset').selectedOptions[0].textContent };
    })()`);
    assert.deepEqual(page, {
      lang, dir: ['ar', 'ur'].includes(lang) ? 'rtl' : 'ltr', title: d.appTitle, buy: d.buyBtn,
      unlock: d.unlockBtn.replace('{price}', '5'), heading: d.appTitle, currency: d.currencyPh, saveBtn: d.saveBtn,
      emptyKeys: [], preset: d.presetMm.replace('{w}', '40').replace('{h}', '30')
    }, lang);
    await ev(`document.getElementById('btn-buy-help').click()`);
    assert.equal(await ev(`document.querySelector('#buy-dialog [data-i18n="helpAccountTitle"]').textContent`), d.helpAccountTitle, `${lang} account help heading`);
    assert.equal(await ev(`document.querySelector('#buy-dialog [data-i18n="helpA"]').textContent`), d.helpA, `${lang} dialog`);
    await ev(`document.getElementById('buy-close').click()`);
  }
  await setLanguage('en');
});

test('small screens keep the button visible without horizontal scrolling', { skip: !chromePath && 'no Chromium found' }, async () => {
  await send('Emulation.setDeviceMetricsOverride', { width: 360, height: 740, deviceScaleFactor: 2, mobile: true });
  for (const lang of Object.keys(I18N)) {
    await setLanguage(lang);
    await ev(`document.getElementById('btn-buy-help').click()`);
    const m = await ev(`(() => { const b = document.getElementById('btn-buy-help').getBoundingClientRect();
      const d = document.getElementById('buy-dialog').getBoundingClientRect();
      return { scroll: document.documentElement.scrollWidth, width: innerWidth, buttonRight: b.right, buttonLeft: b.left,
        dialogLeft: d.left, dialogRight: d.right, dialogBottom: d.bottom, height: innerHeight }; })()`);
    assert.ok(m.scroll <= m.width, `${lang}: page scrolls sideways (${m.scroll} > ${m.width})`);
    assert.ok(m.buttonLeft >= 0 && m.buttonRight <= m.width, `${lang}: button off screen`);
    assert.ok(m.dialogLeft >= 0 && m.dialogRight <= m.width && m.dialogBottom <= m.height, `${lang}: dialog off screen`);
    if (process.env.UI_SCREENSHOT_DIR) {
      const shot = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(path.join(process.env.UI_SCREENSHOT_DIR, `mobile-dialog-${lang}.png`), Buffer.from(shot.data, 'base64'));
    }
    await ev(`document.getElementById('buy-close').click()`);
  }
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  assert.deepEqual(problems, []);
});
