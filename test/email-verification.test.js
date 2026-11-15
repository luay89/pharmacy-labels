'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-email-verify-'));
const webhookSecret = 'whsec_test_secret';
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31881';
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
const { isDisposableEmail, templates } = require('../mail');
const origin = process.env.PUBLIC_APP_URL;
const sent = [];
let mailFailure = null;
let deliveryGate = null;
mailer.configured = true;
mailer.send = async (message) => {
  if (deliveryGate) await deliveryGate;
  if (mailFailure) throw mailFailure;
  sent.push(message);
};
const realNow = clock.now;
const issuedCodes = [];
let server;
let ipCounter = 0;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31881, '127.0.0.1', () => resolve(listener));
  });
});

after(async () => {
  Object.assign(console, originalConsole);
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function newClient() {
  const ip = `198.51.100.${++ipCounter}`;
  const response = await fetch(`${origin}/api/session`, { headers: { 'X-Forwarded-For': ip } });
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { ip, cookie, id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

async function api(client, pathname, body, extraHeaders = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: client.cookie,
      Origin: origin,
      'X-Forwarded-For': client.ip,
      ...extraHeaders
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

const requestCode = (client, email, extra = {}) => api(client, '/api/email-verification/request', { email, ...extra });
const verify = (client, email, code) => api(client, '/api/email-verification/verify', { email, code });

async function waitForMail(to, count) {
  for (let i = 0; i < 200; i++) {
    await processOutbox();
    const matching = sent.filter((message) => message.to === to);
    if (matching.length >= count) return matching[count - 1];
    await sleep(10);
  }
  throw new Error(`Expected ${count} email(s) to ${to}`);
}

function codeFrom(message) {
  const code = message.text.match(/verification code is: (\d{8})/)[1];
  issuedCodes.push(code);
  return code;
}

// Requests a code and returns it as the mailbox owner would read it.
async function mailedCode(client, email) {
  const before = sent.filter((message) => message.to === email).length;
  const response = await requestCode(client, email);
  assert.equal(response.status, 202);
  return codeFrom(await waitForMail(email, before + 1));
}

const wrongCode = (code) => (code === '00000000' ? '11111111' : '00000000');
const latestCodeRow = (sessionId) => db.prepare(
  'SELECT * FROM account_codes WHERE app_session_id = ? ORDER BY id DESC LIMIT 1'
).get(sessionId);
const count = (table) => db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;

function withClock(offsetMs, fn) {
  clock.now = () => realNow() + offsetMs;
  return Promise.resolve().then(fn).finally(() => { clock.now = realNow; });
}

test('a valid request queues one sealed code bound to the session, and verification succeeds once', async () => {
  const client = await newClient();
  const before = realNow();
  let release;
  deliveryGate = new Promise((resolve) => { release = resolve; });
  const response = await requestCode(client, '  Valid.User@Example.COM ');
  assert.equal(response.status, 202);
  assert.deepEqual(response.body, { status: 'queued', expiresInMinutes: 10 });

  const row = latestCodeRow(client.id);
  assert.match(row.email_hash, /^[0-9a-f]{64}$/);
  assert.match(row.code_hash, /^[0-9a-f]{64}$/);
  assert.ok(row.expires_at - row.created_at === 10 * 60 * 1000 && row.created_at >= before);
  assert.equal(row.attempts, 0);
  assert.equal(row.consumed_at, null);
  const queued = db.prepare("SELECT * FROM email_outbox WHERE dedupe_key = ?").get(`email_verification_code:${row.id}`);
  assert.equal(queued.kind, 'email_verification_code');
  assert.equal(queued.status, 'pending');
  assert.equal(queued.to_address, 'valid.user@example.com', 'address is normalized');
  assert.equal(queued.payment_intent_id, null);
  assert.deepEqual(Object.keys(JSON.parse(queued.payload)), ['codeId', 'sealedCode']);

  deliveryGate = null;
  release();
  const message = await waitForMail('valid.user@example.com', 1);
  const code = codeFrom(message);
  assert.match(message.subject, /verification code/);
  assert.match(message.html, new RegExp(code));
  // Neither the stored hash nor the queued payload can give the code back.
  assert.ok(!row.code_hash.includes(code));
  assert.ok(!queued.payload.includes(code));
  const delivered = db.prepare('SELECT status, to_address, payload FROM email_outbox WHERE id = ?').get(queued.id);
  assert.deepEqual(delivered, { status: 'sent', to_address: null, payload: '{}' });

  const ok = await verify(client, 'VALID.user@example.com', `${code.slice(0, 4)}-${code.slice(4)}`);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { verified: true, emailMasked: 'va***@e***.com' });
  assert.notEqual(latestCodeRow(client.id).consumed_at, null);

  const replay = await verify(client, 'valid.user@example.com', code);
  assert.equal(replay.status, 403);
  assert.deepEqual(replay.body, { error: 'verification_failed' });
});

test('invalid, oversized, disposable and malformed input is rejected before anything is stored', async () => {
  const client = await newClient();
  const rows = count('account_codes');
  for (const email of [undefined, null, 42, '', 'no-at-sign', 'a@b', 'a b@example.com', '"q"@example.com',
    'x@example.com\r\nBcc: y@example.com', `${'a'.repeat(250)}@example.com`, ['a@example.com']]) {
    const response = await api(client, '/api/email-verification/request', { email });
    assert.equal(response.status, 400, String(email));
    assert.deepEqual(response.body, { error: 'invalid_email' });
  }
  for (const email of ['x@mailinator.com', 'x@MAILINATOR.com', 'x@inbox.mailinator.com', 'x@yopmail.com']) {
    const response = await requestCode(client, email);
    assert.equal(response.status, 400, email);
    assert.deepEqual(response.body, { error: 'email_not_allowed' });
  }
  for (const email of ['a@gmail.com', 'a@outlook.com', 'a@notmailinator.com', 'a@mailinator.com.example.org',
    'a@company.co.uk', 'a@yahoo.com', 'a@icloud.com', 'a@proton.me']) {
    assert.equal(isDisposableEmail(email), false, email);
  }
  assert.equal((await api(client, '/api/email-verification/request', '{"email":')).status, 400);
  assert.equal((await api(client, '/api/email-verification/request', '"a@example.com"')).status, 400);
  const big = await api(client, '/api/email-verification/request', { email: 'a@example.com', pad: 'x'.repeat(9000) });
  assert.equal(big.status, 413);
  assert.deepEqual(big.body, { error: 'payload_too_large' });
  const foreign = await api(client, '/api/email-verification/request', { email: 'a@example.com' },
    { Origin: 'https://evil.example' });
  assert.equal(foreign.status, 403);

  for (const code of [undefined, 12345678, '', '1234567', '123456789', 'abcdefgh', '1234 567x']) {
    const response = await api(client, '/api/email-verification/verify', { email: 'a@example.com', code });
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'invalid_code' });
  }
  assert.deepEqual((await verify(client, 'not-an-email', '12345678')).body, { error: 'invalid_email' });
  assert.equal(count('account_codes'), rows);
});

test('client-supplied expiry, time or purpose fields are ignored', async () => {
  const client = await newClient();
  const before = realNow();
  const response = await requestCode(client, 'ttl@example.com',
    { expiresAt: before + 365 * 24 * 3600 * 1000, ttl: 999999999, now: 0, purpose: 'transfer' });
  assert.equal(response.status, 202);
  const row = latestCodeRow(client.id);
  assert.equal(row.expires_at - row.created_at, 10 * 60 * 1000);
  assert.ok(row.created_at >= before && row.created_at <= realNow());
});

test('a wrong code is refused and counts as an attempt; a different email or session cannot use the code', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'wrong@example.com');
  const wrong = await verify(client, 'wrong@example.com', wrongCode(code));
  assert.equal(wrong.status, 403);
  assert.deepEqual(wrong.body, { error: 'verification_failed' });
  assert.equal(latestCodeRow(client.id).attempts, 1);

  assert.equal((await verify(client, 'other@example.com', code)).status, 403, 'code is bound to the email');
  assert.equal(latestCodeRow(client.id).attempts, 1, 'another address never reaches this code');
  const stranger = await newClient();
  assert.equal((await verify(stranger, 'wrong@example.com', code)).status, 403, 'code is bound to the session');
  assert.equal((await verify(client, 'wrong@example.com', code)).status, 200);
});

test('an expired code is refused, closed and never comes back', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'expired@example.com');
  await withClock(10 * 60 * 1000, async () => {
    const expired = await verify(client, 'expired@example.com', code);
    assert.equal(expired.status, 403);
    assert.deepEqual(expired.body, { error: 'verification_failed' });
  });
  assert.notEqual(latestCodeRow(client.id).consumed_at, null);
  assert.equal((await verify(client, 'expired@example.com', code)).status, 403);
});

test('a code locks after five wrong guesses, even for the right code later', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'guess@example.com');
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await verify(client, 'guess@example.com', wrongCode(code))).status, 403);
  }
  const row = latestCodeRow(client.id);
  assert.equal(row.attempts, 5);
  assert.notEqual(row.consumed_at, null);
  assert.equal((await verify(client, 'guess@example.com', code)).status, 403);
  assert.equal(latestCodeRow(client.id).attempts, 5, 'a locked code takes no further attempts');
});

test('a new request replaces the open code of the session', async () => {
  const client = await newClient();
  const first = await mailedCode(client, 'replace@example.com');
  const firstRow = latestCodeRow(client.id);
  await withClock(61 * 1000, async () => {
    const second = await mailedCode(client, 'replace@example.com');
    assert.notEqual(db.prepare('SELECT consumed_at FROM account_codes WHERE id = ?').get(firstRow.id).consumed_at, null);
    assert.equal((await verify(client, 'replace@example.com', first)).status, first === second ? 200 : 403);
    if (first !== second) assert.equal((await verify(client, 'replace@example.com', second)).status, 200);
  });
});

test('code requests are rate limited per address (with a resend cooldown), session and IP in SQLite', async () => {
  const email = 'limited@example.com';
  assert.equal((await requestCode(await newClient(), email)).status, 202);
  const tooSoon = await requestCode(await newClient(), email);
  assert.equal(tooSoon.status, 429);
  assert.deepEqual(tooSoon.body, { error: 'rate_limited' });
  await withClock(61 * 1000, async () => assert.equal((await requestCode(await newClient(), email)).status, 202));
  await withClock(122 * 1000, async () => assert.equal((await requestCode(await newClient(), email)).status, 202));
  await withClock(183 * 1000, async () => assert.equal((await requestCode(await newClient(), email)).status, 429));

  const session = await newClient();
  for (let i = 0; i < 5; i++) assert.equal((await requestCode(session, `s${i}@example.com`)).status, 202);
  assert.equal((await requestCode(session, 's5@example.com')).status, 429);

  const ip = await newClient();
  for (let i = 0; i < 10; i++) {
    const fresh = await fetch(`${origin}/api/session`, { headers: { 'X-Forwarded-For': ip.ip } });
    const cookie = fresh.headers.get('set-cookie').split(';')[0];
    assert.equal((await requestCode({ ip: ip.ip, cookie }, `ip${i}@example.com`)).status, 202);
  }
  assert.equal((await requestCode(ip, 'ip10@example.com')).status, 429);

  const keys = db.prepare("SELECT key FROM rate_limits WHERE key LIKE 'email-code-%'").all().map((row) => row.key);
  assert.ok(keys.some((key) => key.startsWith('email-code-request:resend:')));
  assert.ok(keys.every((key) => !/@|198\.51\.100/.test(key)), 'limit keys hold no address or IP');
});

test('concurrent requests cannot exceed the session limit', async () => {
  const client = await newClient();
  const results = await Promise.all(Array.from({ length: 12 },
    (_value, i) => requestCode(client, `burst${i}@example.com`)));
  assert.equal(results.filter((r) => r.status === 202).length, 5);
  assert.equal(results.filter((r) => r.status === 429).length, 7);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM account_codes WHERE app_session_id = ?').get(client.id).n, 5);
});

test('code checks are rate limited per session and IP', async () => {
  const guesser = await newClient();
  for (let i = 0; i < 10; i++) {
    assert.equal((await verify(guesser, 'nobody@example.com', '12345678')).status, 403);
  }
  assert.equal((await verify(guesser, 'nobody@example.com', '12345678')).status, 429);
});

test('two concurrent verifications with the same code succeed only once', async () => {
  const client = await newClient();
  const code = await mailedCode(client, 'race@example.com');
  const results = await Promise.all(Array.from({ length: 6 }, () => verify(client, 'race@example.com', code)));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  assert.ok(results.filter((r) => r.status !== 200).every((r) => r.status === 403));
});

test('responses do not reveal whether an account exists for the address', async () => {
  const known = await newClient();
  assert.equal((await requestCode(known, 'member@example.com')).status, 202);
  db.prepare("INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acct_test_member', ?, 'me***@e***.com', ?)")
    .run(latestCodeRow(known.id).email_hash, realNow());

  await withClock(61 * 1000, async () => {
    const forAccount = await requestCode(await newClient(), 'member@example.com');
    const forNobody = await requestCode(await newClient(), 'stranger@example.com');
    assert.equal(forAccount.status, forNobody.status);
    assert.deepEqual(forAccount.body, forNobody.body);
    const a = await verify(await newClient(), 'member@example.com', '12345678');
    const b = await verify(await newClient(), 'stranger@example.com', '12345678');
    assert.deepEqual([a.status, a.body], [b.status, b.body]);
  });
});

test('verification alone creates no account, device, trial, certificate, purchase or license', async () => {
  const tables = ['accounts', 'devices', 'trials', 'license_certificates', 'stripe_purchases', 'license_transfers', 'audit_events'];
  const before = Object.fromEntries(tables.map((table) => [table, count(table)]));
  const client = await newClient();
  const code = await mailedCode(client, 'nothing@example.com');
  assert.equal((await verify(client, 'nothing@example.com', code)).status, 200);
  assert.deepEqual(Object.fromEntries(tables.map((table) => [table, count(table)])), before);
  const session = db.prepare('SELECT unlocked, account_id, device_id FROM app_sessions WHERE id = ?').get(client.id);
  assert.deepEqual({ ...session }, { unlocked: 0, account_id: null, device_id: null });
  const license = await fetch(`${origin}/api/license`, { headers: { Cookie: client.cookie, 'X-Forwarded-For': client.ip } });
  assert.equal((await license.json()).licensed, false);
});

test('email verification codes and license transfer codes cannot stand in for each other', async () => {
  const email = 'purpose@example.com';
  const owner = await newClient();
  const payload = JSON.stringify({
    id: 'evt_test_purpose',
    object: 'event',
    created: Math.floor(realNow() / 1000),
    data: {
      object: {
        id: 'cs_test_purpose', object: 'checkout.session', livemode: false, mode: 'payment', status: 'complete',
        payment_status: 'paid', amount_total: 500, currency: 'usd', client_reference_id: owner.id,
        metadata: { app_session_id: owner.id }, payment_intent: 'pi_test_purpose', customer_details: { email }
      }
    },
    livemode: false,
    pending_webhooks: 1,
    type: 'checkout.session.completed'
  });
  const webhook = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'stripe-signature': stripe.webhooks.generateTestHeaderString({ payload, secret: webhookSecret })
    },
    body: payload
  });
  assert.equal(webhook.status, 200);
  await waitForMail(email, 1);

  const device = await newClient();
  assert.equal((await api(device, '/api/license/transfer/request', { email })).status, 202);
  const transferCode = (await waitForMail(email, 2)).text.match(/verification code is: (\d{8})/)[1];
  issuedCodes.push(transferCode);
  const emailCode = await mailedCode(device, email);

  if (emailCode !== transferCode) {
    assert.equal((await verify(device, email, transferCode)).status, 403, 'transfer code cannot verify an email');
    assert.equal((await api(device, '/api/license/transfer/confirm', { code: emailCode })).status, 403,
      'email code cannot confirm a transfer');
  }
  assert.equal(db.prepare("SELECT transfers_used FROM stripe_purchases WHERE payment_intent_id = 'pi_test_purpose'").get()
    .transfers_used, 0);
  assert.equal((await verify(device, email, emailCode)).status, 200);
  // Verifying the email does not move or unlock the license; only the transfer code does.
  assert.equal(db.prepare('SELECT unlocked FROM app_sessions WHERE id = ?').get(device.id).unlocked, 0);
  assert.equal((await api(device, '/api/license/transfer/confirm', { code: transferCode })).status, 200);
});

test('delivery failures retry briefly, never log the code, and a stale code is never sent', async () => {
  const client = await newClient();
  mailFailure = Object.assign(new Error('Email delivery failed.'), { code: 'EENVELOPE', smtpStatus: 550 });
  try {
    const response = await requestCode(client, 'bounce@example.com');
    assert.equal(response.status, 202, 'the request does not wait for, or reveal, delivery');
    await processOutbox();
  } finally {
    mailFailure = null;
  }
  const row = latestCodeRow(client.id);
  const outbox = () => db.prepare('SELECT status, attempts, last_error, next_attempt_at, to_address, payload FROM email_outbox WHERE dedupe_key = ?')
    .get(`email_verification_code:${row.id}`);
  const failed = outbox();
  assert.equal(failed.status, 'pending');
  assert.equal(failed.attempts, 1);
  assert.equal(failed.last_error, 'EENVELOPE');
  assert.ok(failed.next_attempt_at - realNow() <= 30_000, 'code emails use the short retry schedule');

  await withClock(9.5 * 60 * 1000, async () => {
    await processOutbox();
    assert.equal(sent.filter((message) => message.to === 'bounce@example.com').length, 0);
    assert.deepEqual({ ...outbox(), next_attempt_at: 0 },
      { status: 'failed', attempts: 2, last_error: 'code_unavailable', next_attempt_at: 0, to_address: null, payload: '{}' });
  });

  const outage = await newClient();
  mailFailure = Object.assign(new Error('Email delivery failed.'), { code: 'ECONNECTION' });
  try {
    assert.equal((await requestCode(outage, 'outage@example.com')).status, 202);
    await processOutbox();
  } finally {
    mailFailure = null;
  }
  const deferred = db.prepare('SELECT status, attempts, last_error FROM email_outbox WHERE dedupe_key = ?')
    .get(`email_verification_code:${latestCodeRow(outage.id).id}`);
  assert.deepEqual({ ...deferred }, { status: 'pending', attempts: 0, last_error: 'ECONNECTION' });
  await withClock(61 * 1000, async () => {
    const code = codeFrom(await waitForMail('outage@example.com', 1));
    assert.equal((await verify(outage, 'outage@example.com', code)).status, 200);
  });
});

test('mail service off or storage failures answer generically and leave nothing half-written', async () => {
  const client = await newClient();
  mailer.configured = false;
  try {
    const off = await requestCode(client, 'off@example.com');
    assert.equal(off.status, 503);
    assert.deepEqual(off.body, { error: 'email_unavailable' });
  } finally {
    mailer.configured = true;
  }

  const codes = count('account_codes');
  const queued = count('email_outbox');
  db.exec("CREATE TEMP TRIGGER fail_outbox BEFORE INSERT ON email_outbox BEGIN SELECT RAISE(ABORT, 'simulated outbox failure'); END");
  try {
    const failed = await requestCode(client, 'queuefail@example.com');
    assert.equal(failed.status, 500);
    assert.deepEqual(failed.body, { error: 'internal_server_error' });
  } finally {
    db.exec('DROP TRIGGER fail_outbox');
  }
  assert.equal(count('account_codes'), codes, 'the code row rolls back with its email');
  assert.equal(count('email_outbox'), queued);

  db.exec("CREATE TEMP TRIGGER fail_codes BEFORE INSERT ON account_codes BEGIN SELECT RAISE(ABORT, 'simulated database failure'); END");
  try {
    const failed = await requestCode(await newClient(), 'dbfail@example.com');
    assert.equal(failed.status, 500);
    assert.deepEqual(failed.body, { error: 'internal_server_error' });
  } finally {
    db.exec('DROP TRIGGER fail_codes');
  }
  assert.equal(count('email_outbox'), queued);

  const verifier = await newClient();
  const code = await mailedCode(verifier, 'verifyfail@example.com');
  db.exec("CREATE TEMP TRIGGER fail_consume BEFORE UPDATE ON account_codes BEGIN SELECT RAISE(ABORT, 'simulated database failure'); END");
  try {
    const failed = await verify(verifier, 'verifyfail@example.com', code);
    assert.equal(failed.status, 500);
    assert.deepEqual(failed.body, { error: 'internal_server_error' });
  } finally {
    db.exec('DROP TRIGGER fail_consume');
  }
  assert.equal(latestCodeRow(verifier.id).consumed_at, null, 'a failed consume is rolled back, not half-applied');
  assert.equal((await verify(verifier, 'verifyfail@example.com', code)).status, 200);
});

test('the verification email template carries the code and expiry only', () => {
  const message = templates.emailVerificationCode({ code: '12345678', minutes: 9, supportEmail: 'help@example.com' });
  assert.match(message.text, /12345678/);
  assert.match(message.text, /9 minutes/);
  assert.match(message.text, /help@example\.com/);
  assert.doesNotMatch(message.subject, /12345678/);
});

test('logs never contain codes or addresses, and no real SMTP transport was created', () => {
  assert.ok(issuedCodes.length >= 10);
  const joined = logs.join('\n');
  for (const code of issuedCodes) assert.ok(!joined.includes(code), 'code leaked to logs');
  for (const email of new Set(sent.map((message) => message.to))) {
    assert.ok(!joined.toLowerCase().includes(email), 'email leaked to logs');
  }
  assert.doesNotMatch(joined, /sk_test_|whsec_|test-secret-with/);
  assert.equal(transportsCreated, 0);
});
