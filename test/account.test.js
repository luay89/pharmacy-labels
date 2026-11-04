'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-account-'));
const webhookSecret = 'whsec_test_secret';
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31882';
process.env.DATA_DIR = dataDir;
process.env.STRIPE_SECRET_KEY = 'sk_test_123456789';
process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
process.env.TRUST_PROXY = '1';
delete process.env.SMTP_HOST;

// No SMTP connection can be opened from this file: any transport creation fails the run.
const nodemailer = require('nodemailer');
let transportsCreated = 0;
nodemailer.createTransport = () => {
  transportsCreated += 1;
  throw new Error('real SMTP transport must not be created in tests');
};

const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const logs = [];
const originalConsole = { log: console.log, warn: console.warn, error: console.error };
for (const level of Object.keys(originalConsole)) {
  console[level] = (...args) => logs.push(args.map(String).join(' '));
}

const { app, db, mailer, clock, processOutbox } = require('../server');
const origin = process.env.PUBLIC_APP_URL;
const sent = [];
mailer.configured = true;
mailer.send = async (message) => { sent.push(message); };
const realNow = clock.now;
const issuedCodes = [];
const issuedTokens = [];
let server;
let ipCounter = 0;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31882, '127.0.0.1', () => resolve(listener));
  });
});

after(async () => {
  Object.assign(console, originalConsole);
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ACCOUNT_MAX_AGE = 30 * 24 * 60 * 60;

async function newClient() {
  const ip = `192.0.2.${++ipCounter}`;
  const response = await fetch(`${origin}/api/session`, { headers: { 'X-Forwarded-For': ip } });
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { ip, cookie, account: '', id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

// Sends the browser's cookies and keeps the account cookie the server sets or clears, like a browser would.
async function api(client, method, pathname, body, extraHeaders = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Cookie: [client.cookie, client.account].filter(Boolean).join('; '),
      Origin: origin,
      'X-Forwarded-For': client.ip,
      ...extraHeaders
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const setCookies = response.headers.getSetCookie();
  for (const header of setCookies) {
    const [pair] = header.split(';');
    if (pair.startsWith('product_labels_account=')) {
      client.account = /Max-Age=0/.test(header) ? '' : pair;
      if (client.account) issuedTokens.push(pair.split('=')[1]);
    }
  }
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null, setCookies };
}

async function waitForMail(to, count) {
  for (let i = 0; i < 200; i++) {
    await processOutbox();
    const matching = sent.filter((message) => message.to === to);
    if (matching.length >= count) return matching[count - 1];
    await sleep(10);
  }
  throw new Error(`Expected ${count} email(s) to ${to}`);
}

async function mailedCode(client, email) {
  const to = email.trim().toLowerCase();
  const before = sent.filter((message) => message.to === to).length;
  const response = await api(client, 'POST', '/api/email-verification/request', { email });
  assert.equal(response.status, 202);
  const code = (await waitForMail(to, before + 1)).text.match(/verification code is: (\d{8})/)[1];
  issuedCodes.push(code);
  return code;
}

function withClock(offsetMs, fn) {
  clock.now = () => realNow() + offsetMs;
  return Promise.resolve().then(fn).finally(() => { clock.now = realNow; });
}

const signup = (client, email, code, extra = {}) => api(client, 'POST', '/api/account/signup', { email, code, ...extra });
const login = (client, email, code, extra = {}) => api(client, 'POST', '/api/account/login', { email, code, ...extra });
const whoami = async (client) => (await api(client, 'GET', '/api/account')).body;
const wrongCode = (code) => (code === '00000000' ? '11111111' : '00000000');
const count = (table) => db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
const accountSessionsOf = (accountId) => db.prepare('SELECT * FROM account_sessions WHERE account_id = ? ORDER BY created_at').all(accountId);
const latestCode = (sessionId) => db.prepare('SELECT * FROM account_codes WHERE app_session_id = ? ORDER BY id DESC LIMIT 1').get(sessionId);
// The account of this browser's live sign-in, read on the server side.
const accountIdOf = (client) => db.prepare(
  'SELECT account_id FROM account_sessions WHERE app_session_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC LIMIT 1'
).get(client.id)?.account_id ?? null;

function totp(secret, now = realNow()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of secret) {
    value = (value << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));
  const digest = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

async function newAccount(email) {
  const client = await newClient();
  const code = await mailedCode(client, email);
  const response = await signup(client, email, code);
  assert.equal(response.status, 201);
  return client;
}

test('signup with a verified email creates one account and a sign-in bound to this browser', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'New.User@Example.com');
  const audits = count('audit_events');
  const response = await signup(client, ' new.user@EXAMPLE.com ', code);
  assert.equal(response.status, 201);
  assert.deepEqual(response.body, { authenticated: true, created: true, emailMasked: 'ne***@e***.com' });

  // Only the account cookie is set; the anonymous session (and any legacy license on it) keeps its id.
  assert.equal(response.setCookies.length, 1);
  const cookie = response.setCookies[0];
  assert.match(cookie, /^product_labels_account=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=2592000$/);
  assert.doesNotMatch(cookie, /Secure/, 'no Secure flag over plain HTTP (set over HTTPS)');
  assert.deepEqual(await whoami(client), { authenticated: true, emailMasked: 'ne***@e***.com' });

  const account = db.prepare('SELECT * FROM accounts').all().find((row) => row.email_masked === 'ne***@e***.com');
  assert.match(account.id, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(account.email_hash, latestCode(client.id).email_hash, 'same normalized keyed hash as the code');
  assert.equal(account.status, 'active');
  const [session] = accountSessionsOf(account.id);
  const token = client.account.split('=')[1];
  assert.notEqual(session.token_hash, token, 'only a hash of the token is stored');
  assert.match(session.token_hash, /^[0-9a-f]{64}$/);
  assert.equal(session.app_session_id, client.id);
  assert.equal(session.expires_at - session.created_at, ACCOUNT_MAX_AGE * 1000);
  assert.notEqual(latestCode(client.id).consumed_at, null);

  const events = db.prepare('SELECT event, outcome, account_id, device_id, ip_hash FROM audit_events ORDER BY id').all().slice(audits);
  assert.deepEqual(events.map((e) => [e.event, e.outcome, e.account_id]), [['account_created', 'ok', account.id], ['signup', 'ok', account.id]]);
  assert.ok(events.every((e) => /^[0-9a-f]{64}$/.test(e.ip_hash) && e.device_id === null));
  const auditText = JSON.stringify(db.prepare('SELECT * FROM audit_events').all());
  assert.doesNotMatch(auditText, /@|192\.0\.2/);
  assert.ok(!auditText.includes(code) && !auditText.includes(token), 'no code or token in the audit trail');
});

test('signup without a verified code creates nothing', async () => {
  const client = await newClient();
  const accounts = count('accounts');
  const unrequested = await signup(client, 'unverified@example.com', '12345678');
  assert.equal(unrequested.status, 403);
  assert.deepEqual(unrequested.body, { error: 'verification_failed' });
  assert.equal((await signup(client, 'unverified@example.com', undefined)).status, 400);
  assert.equal((await signup(client, 'not-an-email', '12345678')).status, 400);
  assert.deepEqual((await signup(client, 'x@mailinator.com', '12345678')).body, { error: 'email_not_allowed' });

  const code = await mailedCode(client, 'unverified@example.com');
  assert.equal((await signup(client, 'unverified@example.com', wrongCode(code))).status, 403);
  assert.equal((await signup(client, 'someone.else@example.com', code)).status, 403, 'the code belongs to one address');
  const stranger = await newClient();
  assert.equal((await signup(stranger, 'unverified@example.com', code)).status, 403, 'and to one browser');
  assert.equal(count('accounts'), accounts);
  assert.deepEqual(await whoami(client), { authenticated: false });
  assert.equal(client.account, '');
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'signup' AND outcome = 'bad_code' AND account_id IS NULL").get().n >= 4);
});

test('expired, consumed and locked codes cannot create an account or sign in', async () => {
  const accounts = count('accounts');
  const client = await newClient();
  const expiring = await mailedCode(client, 'stale@example.com');
  await withClock(10 * 60 * 1000, async () => assert.equal((await signup(client, 'stale@example.com', expiring)).status, 403));
  assert.equal((await signup(client, 'stale@example.com', expiring)).status, 403, 'an expired code stays dead');

  const used = await newClient();
  const usedCode = await mailedCode(used, 'used@example.com');
  assert.equal((await api(used, 'POST', '/api/email-verification/verify', { email: 'used@example.com', code: usedCode })).status, 200);
  assert.equal((await signup(used, 'used@example.com', usedCode)).status, 403, 'a code consumed by plain verification is gone');

  const locked = await newClient();
  const lockedCode = await mailedCode(locked, 'locked@example.com');
  for (let i = 0; i < 5; i++) assert.equal((await login(locked, 'locked@example.com', wrongCode(lockedCode))).status, 403);
  assert.equal((await signup(locked, 'locked@example.com', lockedCode)).status, 403);
  assert.equal(count('accounts'), accounts);
});

test('a second signup for the same address signs in to the existing account instead of duplicating it', async () => {
  const first = await newAccount('dup@example.com');
  const accountId = accountIdOf(first);
  const accounts = count('accounts');
  await withClock(61 * 1000, async () => {
    const second = await newClient();
    const response = await signup(second, 'DUP@example.com', await mailedCode(second, 'dup@example.com'));
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { authenticated: true, created: false, emailMasked: 'du***@e***.com' });
    assert.equal(accountIdOf(second), accountId);
  });
  assert.equal(count('accounts'), accounts);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'account_created' AND account_id = ?").get(accountId).n, 1);
});

test('concurrent signups end on exactly one account, and one code signs in only once', async () => {
  const a = await newClient();
  const b = await newClient();
  const codeA = await mailedCode(a, 'race@example.com');
  const codeB = await withClock(61 * 1000, () => mailedCode(b, 'race@example.com'));
  const accounts = count('accounts');
  const results = await Promise.all([signup(a, 'race@example.com', codeA), signup(b, 'race@example.com', codeB)]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 201]);
  assert.equal(count('accounts'), accounts + 1);
  assert.equal(accountIdOf(a), accountIdOf(b));

  const c = await newClient();
  const codeC = await withClock(122 * 1000, () => mailedCode(c, 'race@example.com'));
  const doubles = await Promise.all(Array.from({ length: 5 }, () => login(c, 'race@example.com', codeC)));
  assert.equal(doubles.filter((r) => r.status === 200).length, 1);
  assert.ok(doubles.filter((r) => r.status !== 200).every((r) => r.status === 403));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM account_sessions WHERE app_session_id = ?').get(c.id).n, 1);
});

test('a failed transaction creates no account, keeps the code usable and writes no audit event', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'atomic@example.com');
  const before = { accounts: count('accounts'), sessions: count('account_sessions'), audits: count('audit_events') };
  for (const [name, table] of [['fail_sessions', 'account_sessions'], ['fail_audit', 'audit_events']]) {
    db.exec(`CREATE TEMP TRIGGER ${name} BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'simulated failure'); END`);
    try {
      const failed = await signup(client, 'atomic@example.com', code);
      assert.equal(failed.status, 500);
      assert.deepEqual(failed.body, { error: 'internal_server_error' });
      assert.equal(failed.setCookies.length, 0, 'no cookie for a sign-in that was rolled back');
    } finally {
      db.exec(`DROP TRIGGER ${name}`);
    }
    assert.deepEqual({ accounts: count('accounts'), sessions: count('account_sessions'), audits: count('audit_events') }, before, table);
    assert.equal(latestCode(client.id).consumed_at, null, 'the code was not consumed by the failed attempt');
    assert.equal(latestCode(client.id).attempts, 0);
  }
  assert.equal((await signup(client, 'atomic@example.com', code)).status, 201);
});

test('login signs in an existing account with a valid code and never creates one', async () => {
  await newAccount('member@example.com');
  const device = await newClient();
  await withClock(61 * 1000, async () => {
    const code = await mailedCode(device, 'member@example.com');
    assert.equal((await login(device, 'member@example.com', wrongCode(code))).status, 403);
    const ok = await login(device, 'Member@Example.com', code);
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { authenticated: true, created: false, emailMasked: 'me***@e***.com' });
  });
  assert.deepEqual(await whoami(device), { authenticated: true, emailMasked: 'me***@e***.com' });

  const accounts = count('accounts');
  const nobody = await newClient();
  const code = await mailedCode(nobody, 'no-account@example.com');
  const missing = await login(nobody, 'no-account@example.com', code);
  assert.equal(missing.status, 404, 'only someone holding the right code learns there is no account');
  assert.deepEqual(missing.body, { error: 'account_not_found' });
  assert.equal(missing.setCookies.length, 0);
  assert.equal(count('accounts'), accounts);
  assert.notEqual(latestCode(nobody.id).consumed_at, null, 'the code is spent either way');
  assert.equal((await signup(nobody, 'no-account@example.com', code)).status, 403);
});

test('public responses do not reveal whether an address has an account', async () => {
  await newAccount('exists@example.com');
  await withClock(61 * 1000, async () => {
    const withAccount = await api(await newClient(), 'POST', '/api/email-verification/request', { email: 'exists@example.com' });
    const without = await api(await newClient(), 'POST', '/api/email-verification/request', { email: 'absent@example.com' });
    assert.deepEqual([withAccount.status, withAccount.body], [without.status, without.body]);
  });
  for (const route of [login, signup]) {
    const a = await route(await newClient(), 'exists@example.com', '12345678');
    const b = await route(await newClient(), 'absent@example.com', '12345678');
    assert.deepEqual([a.status, a.body], [b.status, b.body]);
    assert.deepEqual(a.body, { error: 'verification_failed' });
  }
});

test('the client cannot choose or change the account', async () => {
  const victim = await newAccount('victim@example.com');
  const victimId = accountIdOf(victim);
  const attacker = await newClient();
  const code = await mailedCode(attacker, 'attacker@example.com');
  const response = await signup(attacker, 'attacker@example.com', code,
    { accountId: victimId, account_id: victimId, id: victimId, status: 'active', created: false });
  assert.equal(response.status, 201);
  assert.notEqual(accountIdOf(attacker), victimId);
  assert.deepEqual(await whoami(attacker), { authenticated: true, emailMasked: 'at***@e***.com' });

  for (const pathname of ['/api/account', '/api/account/logout', '/api/account/login']) {
    const tampered = await api(attacker, 'POST', pathname, { accountId: victimId, email: 'victim@example.com', code: '12345678' });
    assert.notEqual(tampered.body && tampered.body.emailMasked, 'vi***@e***.com', pathname);
  }
  assert.deepEqual(await whoami(victim), { authenticated: true, emailMasked: 'vi***@e***.com' }, 'the victim is untouched');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM accounts WHERE id = ? AND status = ?').get(victimId, 'active').n, 1);
});

test('sign-in tokens resist fixation, theft into another browser, forgery, replay after logout and expiry', async () => {
  const user = await newClient();
  // A token planted before authentication is never adopted: sign-in issues a fresh one.
  const planted = `product_labels_account=${'A'.repeat(43)}`;
  user.account = planted;
  assert.deepEqual(await whoami(user), { authenticated: false });
  assert.equal(user.account, '', 'an unknown token is cleared');
  user.account = planted;
  const code = await mailedCode(user, 'fixation@example.com');
  assert.equal((await signup(user, 'fixation@example.com', code)).status, 201);
  assert.notEqual(user.account, planted);
  const firstToken = user.account;

  // Copying the account cookie into another browser (another anonymous session) does not carry the sign-in.
  const thief = await newClient();
  thief.account = firstToken;
  assert.deepEqual(await whoami(thief), { authenticated: false });
  // Neither do a forged token, a bit-flipped token or a malformed one.
  for (const forged of [`product_labels_account=${'b'.repeat(43)}`, `${firstToken.slice(0, -1)}${firstToken.endsWith('A') ? 'B' : 'A'}`,
    'product_labels_account=%E0%A4%A', 'product_labels_account=short']) {
    assert.deepEqual(await whoami({ ...user, account: forged }), { authenticated: false }, forged);
  }

  // Signing in again rotates the token and revokes the previous one.
  await withClock(61 * 1000, async () => {
    assert.equal((await login(user, 'fixation@example.com', await mailedCode(user, 'fixation@example.com'))).status, 200);
  });
  assert.notEqual(user.account, firstToken);
  assert.deepEqual(await whoami({ ...user, account: firstToken }), { authenticated: false });
  assert.deepEqual(await whoami(user), { authenticated: true, emailMasked: 'fi***@e***.com' });

  // A second browser of the same account is not affected by this browser's logout.
  const other = await newClient();
  await withClock(122 * 1000, async () => {
    assert.equal((await login(other, 'fixation@example.com', await mailedCode(other, 'fixation@example.com'))).status, 200);
  });
  const beforeLogout = user.account;
  const out = await api(user, 'POST', '/api/account/logout', {});
  assert.deepEqual([out.status, out.body], [200, { authenticated: false }]);
  assert.match(out.setCookies[0], /^product_labels_account=; Path=\/; HttpOnly; SameSite=Lax; Max-Age=0$/);
  assert.deepEqual(await whoami({ ...user, account: beforeLogout }), { authenticated: false }, 'a logged-out token is dead');
  assert.deepEqual(await whoami(other), { authenticated: true, emailMasked: 'fi***@e***.com' });
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'logout' AND outcome = 'ok' AND account_id = ?")
    .get(accountIdOf(other)).n, 1);
  // Logging out from another origin is refused.
  assert.equal((await api(other, 'POST', '/api/account/logout', {}, { Origin: 'https://evil.example' })).status, 403);
  assert.deepEqual(await whoami(other), { authenticated: true, emailMasked: 'fi***@e***.com' });

  // The sign-in has an absolute lifetime enforced with the server clock.
  await withClock(30 * 24 * 60 * 60 * 1000 - 120 * 1000, async () => {
    assert.equal((await whoami({ ...other })).authenticated, true);
  });
  await withClock(30 * 24 * 60 * 60 * 1000 + 123 * 1000, async () => {
    assert.deepEqual(await whoami({ ...other }), { authenticated: false });
  });
});

test('a suspended account cannot sign in and its open sign-ins stop working', async () => {
  const client = await newAccount('suspended@example.com');
  const accountId = accountIdOf(client);
  db.prepare("UPDATE accounts SET status = 'suspended' WHERE id = ?").run(accountId);
  try {
    assert.deepEqual(await whoami({ ...client }), { authenticated: false });
    const device = await newClient();
    await withClock(61 * 1000, async () => {
      const response = await login(device, 'suspended@example.com', await mailedCode(device, 'suspended@example.com'));
      assert.deepEqual([response.status, response.body], [403, { error: 'account_unavailable' }]);
      assert.equal(response.setCookies.length, 0);
    });
  } finally {
    db.prepare("UPDATE accounts SET status = 'active' WHERE id = ?").run(accountId);
  }
});

test('signing up or in grants no license, trial, device, certificate or purchase', async () => {
  const tables = ['devices', 'trials', 'license_certificates', 'stripe_purchases', 'license_transfers'];
  const before = Object.fromEntries(tables.map((table) => [table, count(table)]));
  const client = await newAccount('free@example.com');
  assert.deepEqual(Object.fromEntries(tables.map((table) => [table, count(table)])), before);
  const session = await api(client, 'GET', '/api/session');
  assert.deepEqual(session.body, { printedCount: 0, freeLimit: 20, unlocked: false });
  assert.equal((await api(client, 'GET', '/api/license')).body.licensed, false);
  assert.deepEqual({ ...db.prepare('SELECT unlocked, account_id, device_id FROM app_sessions WHERE id = ?').get(client.id) },
    { unlocked: 0, account_id: null, device_id: null });
  // The free label limit is unchanged by having an account.
  assert.equal((await api(client, 'POST', '/api/labels/reserve', { count: 21 })).status, 402);
});

test('a legacy buyer who signs up keeps the legacy license, its terms and its transfer', async () => {
  const email = 'legacy@example.com';
  const buyer = await newClient();
  const payload = JSON.stringify({
    id: 'evt_test_legacy_account',
    object: 'event',
    created: Math.floor(realNow() / 1000),
    data: {
      object: {
        id: 'cs_test_legacy_account', object: 'checkout.session', livemode: false, mode: 'payment', status: 'complete',
        payment_status: 'paid', amount_total: 500, currency: 'usd', client_reference_id: buyer.id,
        metadata: { app_session_id: buyer.id }, payment_intent: 'pi_test_legacy_account', customer_details: { email }
      }
    },
    livemode: false,
    pending_webhooks: 1,
    type: 'checkout.session.completed'
  });
  const webhook = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': stripe.webhooks.generateTestHeaderString({ payload, secret: webhookSecret }) },
    body: payload
  });
  assert.equal(webhook.status, 200);
  await waitForMail(email, 1);
  const purchase = () => ({ ...db.prepare(`SELECT app_session_id, status, account_id, license_policy, transfers_used, transfer_limit
    FROM stripe_purchases WHERE payment_intent_id = 'pi_test_legacy_account'`).get() });
  const original = purchase();
  assert.deepEqual(original, { app_session_id: buyer.id, status: 'active', account_id: null, license_policy: 'legacy', transfers_used: 0, transfer_limit: 1 });

  assert.equal((await signup(buyer, email, await mailedCode(buyer, email))).status, 201);
  assert.deepEqual(purchase(), original, 'the purchase is not claimed, moved or re-termed by signing up');
  assert.equal((await api(buyer, 'GET', '/api/session')).body.unlocked, true, 'the legacy license still works in this browser');

  const newDevice = await newClient();
  assert.equal((await api(newDevice, 'POST', '/api/license/transfer/request', { email })).status, 202);
  const transferCode = (await waitForMail(email, 3)).text.match(/verification code is: (\d{8})/)[1];
  issuedCodes.push(transferCode);
  assert.equal((await api(newDevice, 'POST', '/api/license/transfer/confirm', { code: transferCode })).status, 200);
  assert.deepEqual(purchase(), { ...original, app_session_id: newDevice.id, transfers_used: 1 });
  assert.equal((await whoami(buyer)).authenticated, true, 'the account sign-in is separate from the license');
});

test('TOTP enrollment adds a second sign-in factor, protects recovery codes, and supports one-time recovery', async () => {
  const owner = await newAccount('totp@example.com');
  const setup = await api(owner, 'POST', '/api/account/totp/setup', {});
  assert.equal(setup.status, 200);
  assert.match(setup.body.secret, /^[A-Z2-7]{32}$/);
  const storedSecret = db.prepare('SELECT secret_sealed FROM account_totp WHERE account_id = ?').get(accountIdOf(owner)).secret_sealed;
  assert.ok(!storedSecret.includes(setup.body.secret), 'the TOTP seed is encrypted at rest');
  assert.equal((await api(owner, 'GET', '/api/account/totp')).body.enabled, false);
  assert.equal((await api(owner, 'POST', '/api/account/totp/enable', { code: '000000' })).status, 403);

  const enabled = await api(owner, 'POST', '/api/account/totp/enable', { code: totp(setup.body.secret) });
  assert.equal(enabled.status, 200);
  assert.equal(enabled.body.enabled, true);
  assert.equal(enabled.body.recoveryCodes.length, 10);
  assert.ok(enabled.body.recoveryCodes.every((code) => /^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$/.test(code)));
  const recoveryRows = db.prepare('SELECT code_hash FROM account_recovery_codes WHERE account_id = ?').all(accountIdOf(owner));
  assert.equal(recoveryRows.length, 10);
  assert.ok(recoveryRows.every((row) => !enabled.body.recoveryCodes.some((code) => row.code_hash.includes(code.replace(/-/g, '')))));

  const other = await newClient();
  const code = await withClock(61_000, () => mailedCode(other, 'totp@example.com'));
  const pending = await login(other, 'totp@example.com', code);
  assert.deepEqual([pending.status, pending.body.mfaRequired], [202, true]);
  assert.match(pending.body.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(pending.setCookies.length, 0, 'email verification alone does not create a session');
  assert.deepEqual(await whoami(other), { authenticated: false });

  const wrong = String((Number(totp(setup.body.secret)) + 1) % 1_000_000).padStart(6, '0');
  assert.deepEqual((await api(other, 'POST', '/api/account/mfa/verify', { challenge: pending.body.challenge, code: wrong })).body,
    { error: 'mfa_failed' });
  const completed = await api(other, 'POST', '/api/account/mfa/verify', { challenge: pending.body.challenge, code: totp(setup.body.secret) });
  assert.equal(completed.status, 200);
  assert.equal((await whoami(other)).authenticated, true);
  assert.equal((await api(other, 'POST', '/api/account/mfa/verify', { challenge: pending.body.challenge, code: totp(setup.body.secret) })).status, 403,
    'a completed challenge cannot be replayed');

  await api(other, 'POST', '/api/account/logout', {});
  await withClock(122_000, async () => {
    const recoveryLogin = await login(other, 'totp@example.com', await mailedCode(other, 'totp@example.com'));
    assert.equal(recoveryLogin.status, 202);
    assert.equal((await api(other, 'POST', '/api/account/mfa/verify', {
      challenge: recoveryLogin.body.challenge, code: enabled.body.recoveryCodes[0]
    })).status, 200);
    assert.equal((await api(other, 'GET', '/api/account/totp')).body.recoveryCodesRemaining, 9);
    assert.equal((await api(other, 'POST', '/api/account/totp/disable', { code: enabled.body.recoveryCodes[0] })).status, 403,
      'a recovery code is single use');
    assert.equal((await api(other, 'POST', '/api/account/totp/disable', { code: enabled.body.recoveryCodes[1] })).status, 200);
    assert.deepEqual(await api(other, 'GET', '/api/account/totp').then((r) => r.body), { enabled: false, recoveryCodesRemaining: 0 });
  });
});

test('logs never contain codes, tokens or addresses, and no real SMTP transport was created', () => {
  assert.ok(issuedCodes.length >= 15);
  assert.ok(issuedTokens.length >= 10);
  const joined = logs.join('\n');
  for (const secret of [...issuedCodes, ...issuedTokens]) assert.ok(!joined.includes(secret), 'secret leaked to logs');
  for (const email of new Set(sent.map((message) => message.to))) assert.ok(!joined.toLowerCase().includes(email), 'email leaked to logs');
  assert.doesNotMatch(joined, /sk_test_|whsec_|test-secret-with/);
  assert.equal(transportsCreated, 0);
});
