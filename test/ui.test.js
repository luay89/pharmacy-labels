'use strict';

// Static checks of index.html: translations, default language, purchase help markup.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const appScript = html.slice(html.indexOf("var KEY='pharmacy-labels-v2'"));
const I18N = vm.runInNewContext(`(${appScript.slice(appScript.indexOf('var I18N=') + 9, appScript.indexOf('function contentLang('))
  .trim().replace(/;$/, '')})`);

function constant(name) {
  const match = appScript.match(new RegExp(`${name}=([^,;]+)`));
  return match && vm.runInNewContext(match[1]);
}

test('the Android asset is an exact copy of the web page', () => {
  assert.equal(fs.readFileSync(path.join(root, 'android/app/src/main/assets/index.html'), 'utf8'), html);
});

test('English is the default and saved languages are validated', () => {
  assert.match(html, /<html lang="en" dir="ltr">/);
  assert.equal(constant('DEFAULT_LANG'), 'en');
  assert.match(appScript, /theme:'system',lang:DEFAULT_LANG\}/);
  assert.match(appScript, /if\(SUPPORTED_LANGS\.indexOf\(s\.settings\.lang\)<0\)s\.settings\.lang=DEFAULT_LANG;/);
  const options = [...html.matchAll(/<option value="([a-z]{2})">/g)].map((m) => m[1]);
  assert.deepEqual(options, JSON.parse(appScript.match(/SUPPORTED_LANGS=(\[[^\]]+\])/)[1].replace(/'/g, '"')));
  assert.equal(appScript.match(/RTL_LANGS=(\[[^\]]+\])/)[1], "['ar','ur']");
});

const LANGS = JSON.parse(appScript.match(/SUPPORTED_LANGS=(\[[^\]]+\])/)[1].replace(/'/g, '"'));

test('every language in the selector has a complete dictionary with the same placeholders', () => {
  assert.deepEqual(Object.keys(I18N).sort(), [...LANGS].sort());
  const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
  for (const lang of LANGS) {
    assert.deepEqual(Object.keys(I18N[lang]).sort(), Object.keys(I18N.en).sort(), `${lang} keys`);
    for (const key of Object.keys(I18N.en)) {
      assert.deepEqual(placeholders(I18N[lang][key]), placeholders(I18N.en[key]), `${lang}.${key}`);
    }
  }
});

test('every language is really translated and quotes its own button names in the help', () => {
  const fill = (s) => s.replace(/\{price\}/g, '5');
  for (const lang of LANGS.filter((l) => l !== 'en')) {
    const d = I18N[lang];
    const same = Object.keys(I18N.en).filter((key) => d[key] === I18N.en[key]);
    // Only genuinely identical words (e.g. "Normal", "Code", the "{w} × {h} mm" pattern) may match English.
    assert.ok(same.length <= 6, `${lang} copies English for: ${same.join(', ')}`);
    for (const [text, label] of [['helpA1', 'unlockBtn'], ['helpA1', 'helpGo'], ['helpC1', 'transferSummary'],
      ['helpC2', 'transferRequestBtn'], ['helpC4', 'transferConfirmBtn']]) {
      assert.ok(fill(d[text]).includes(fill(d[label])), `${lang}.${text} must quote ${lang}.${label}`);
    }
    for (const key of ['xp1', 'xp2', 'xp3', 'xp4', 'xp5']) {
      assert.equal((d[key].match(/<b>/g) || []).length, (d[key].match(/<\/b>/g) || []).length, `${lang}.${key}`);
      assert.doesNotMatch(d[key], /<(?!\/?b>)/, `${lang}.${key} only uses <b>`);
    }
  }
});

test('each language shows its own currency example and states the price in US dollars', () => {
  const examples = LANGS.map((lang) => I18N[lang].currencyPh);
  assert.equal(new Set(examples).size, LANGS.length, 'every language has its own currency example');
  const local = { zh: /元|¥/, hi: /₹/, es: /€/, fr: /€/, pt: /R\$/, ur: /روپے/, ru: /₽/, ja: /円|¥/, de: /€/, ar: /د\.ع/, en: /USD/ };
  for (const lang of LANGS) assert.match(I18N[lang].currencyPh, local[lang], lang);
  // The license is charged in USD by Stripe: every language must say so, never a converted amount.
  const usd = { zh: /美元/, hi: /USD/, es: /US\$/, fr: /\$ US/, pt: /US\$/, ur: /امریکی ڈالر/, ru: /USD/, ja: /米ドル/, de: /US-\$/, ar: /\$/, en: /\$/ };
  for (const lang of LANGS) {
    for (const key of ['unlockBtn', 'lockedPlan', 'helpIntro', 'helpA1']) {
      assert.match(I18N[lang][key], usd[lang], `${lang}.${key}`);
      assert.match(I18N[lang][key], /\{price\}/, `${lang}.${key}`);
    }
  }
});

test('every translation key used by the page exists', () => {
  const used = new Set();
  for (const m of html.matchAll(/data-i18n(?:-html)?="(\w+)"/g)) used.add(m[1]);
  for (const m of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of m[1].split(';')) used.add(pair.split(':')[1]);
  }
  for (const m of appScript.matchAll(/\bt\('(\w+)'/g)) used.add(m[1]);
  for (const m of appScript.matchAll(/\['(?:btn-)?transfer-[\w-]+','(\w+)'\]/g)) used.add(m[1]);
  for (const m of appScript.matchAll(/t\(S\.\w+(?:===?[^?]+)?\?'(\w+)':'(\w+)'/g)) used.add(m[1]).add(m[2]);
  assert.ok(used.size > 100, `only ${used.size} keys found`);
  for (const key of used) {
    for (const lang of LANGS) assert.ok(I18N[lang][key], `missing ${lang}.${key}`);
  }
});

test('the purchase button sits in the header and opens a complete help dialog', () => {
  const header = html.slice(html.indexOf('<header>'), html.indexOf('</header>'));
  assert.match(header, /<div class="head-tools">\s*<button type="button" class="primary" id="btn-buy-help"[^>]*>Buy \/ Purchase<\/button>/);
  assert.equal(I18N.en.buyBtn, 'Buy / Purchase');
  const dialog = html.slice(html.indexOf('<dialog id="buy-dialog"'), html.indexOf('</dialog>'));
  const sections = [...dialog.matchAll(/<h3 id="help-\w" data-i18n="(\w+)">/g)].map((m) => I18N.en[m[1]]);
  assert.deepEqual(sections, ['Purchase and Activation', 'Keep Your Purchase Email', 'Transfer to Another Device', 'Troubleshooting']);
  assert.match(dialog, /id="buy-close-x" aria-label="Close"/);
  assert.match(dialog, /id="buy-close"/);
  assert.match(html, /\.wrap,\.toast,dialog\{display:none!important\}/, 'dialog must not print');
});

test('help text matches the server transfer rules', () => {
  assert.equal(constant('TRANSFER_CODE_MINUTES') * 60_000, vm.runInNewContext(server.match(/TRANSFER_CODE_TTL_MS = ([^;]+);/)[1]));
  assert.equal(constant('TRANSFER_CODE_ATTEMPTS'), Number(server.match(/TRANSFER_CODE_MAX_ATTEMPTS = (\d+);/)[1]));
  assert.equal(constant('UNLOCK_PRICE_USD') * 100, Number(server.match(/PRICE_CENTS = (\d+);/)[1]));
  assert.match(server, /consumeRateLimit\.immediate\(`transfer-request:email:\$\{emailHash\}`, 3, HOUR\)/);
  assert.match(I18N.en.helpD2, /up to 3 times per hour/);
  for (const lang of ['en', 'ar']) {
    for (const key of ['helpA3', 'helpB1', 'helpC3', 'helpC5', 'helpC6']) assert.ok(I18N[lang][key].length > 20, `${lang}.${key}`);
  }
  assert.doesNotMatch(JSON.stringify(I18N), /sk_(test|live)_|whsec_|SMTP_PASS/);
});

test('the account panel is hidden by default and the device script is never a static tag', () => {
  assert.match(html, /<div class="panel" id="account-panel"[^>]* hidden>/);
  assert.doesNotMatch(html, /<script[^>]*device-key\.js/);
  assert.match(appScript, /function accountSupported\(\)\{return location\.protocol==='http:'\|\|location\.protocol==='https:'\}/);
  // Every account error the server can return has its own message in every language.
  for (const error of ['invalid_email', 'email_not_allowed', 'email_unavailable', 'rate_limited', 'invalid_code', 'verification_failed',
    'account_not_found', 'account_unavailable', 'not_authenticated', 'device_limit_reached', 'key_unavailable', 'device_not_registered', 'proof_failed']) {
    for (const lang of LANGS) assert.ok(I18N[lang][`acct_${error}`], `${lang}.acct_${error}`);
  }
});

test('the account UI escapes product identifiers and exposes the second-factor controls', () => {
  assert.match(appScript, /data-id="'\+esc\(p\.id\)\+'/);
  assert.match(html, /id="btn-account-totp"/);
  assert.match(appScript, /api\/account\/mfa\/verify/);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
});
