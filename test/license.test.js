'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const Database = require('better-sqlite3');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-license-'));
const webhookSecret = 'whsec_test_secret';
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31880';
process.env.DATA_DIR = dataDir;
process.env.STRIPE_SECRET_KEY = 'sk_test_123456789';
process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
process.env.TRUST_PROXY = '1';
delete process.env.SMTP_HOST;

const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const logs = [];
const originalConsole = { log: console.log, warn: console.warn, error: console.error };
for (const level of Object.keys(originalConsole)) {
  console[level] = (...args) => logs.push(args.map(String).join(' '));
}

const { app, db, stripe: serverStripe, mailer, clock, processOutbox } = require('../server');
const origin = process.env.PUBLIC_APP_URL;
const sent = [];
let mailFailure = null;
mailer.configured = true;
mailer.send = async (message) => {
  if (mailFailure) throw mailFailure;
  sent.push(message);
};
const realNow = clock.now;
const issuedCodes = [];
const usedEmails = [];
let server;
let ipCounter = 0;
let eventCounter = 0;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31880, '127.0.0.1', () => resolve(listener));
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
  const ip = `203.0.113.${++ipCounter}`;
  const response = await fetch(`${origin}/api/session`, { headers: { 'X-Forwarded-For': ip } });
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { ip, cookie, id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

async function api(client, method, pathname, body, extraHeaders = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Cookie: client.cookie,
      Origin: origin,
      'X-Forwarded-For': client.ip,
      ...extraHeaders
    },
    body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body))
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function sendStripeEvent(type, object, { id = `evt_test_${++eventCounter}`, created } = {}) {
  const payload = JSON.stringify({
    id,
    object: 'event',
    created: created || Math.floor(realNow() / 1000),
    data: { object },
    livemode: false,
    pending_webhooks: 1,
    type
  });
  const signature = stripe.webhooks.generateTestHeaderString({ payload, secret: webhookSecret });
  const response = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': signature },
    body: payload
  });
  assert.equal(response.status, 200);
  return id;
}

function checkoutFor(client, email, intentId, overrides = {}) {
  usedEmails.push(email);
  return {
    id: `cs_test_${intentId.replace(/[^A-Za-z0-9]/g, '')}`,
    object: 'checkout.session',
    livemode: false,
    mode: 'payment',
    status: 'complete',
    payment_status: 'paid',
    amount_total: 500,
    currency: 'usd',
    client_reference_id: client.id,
    metadata: { app_session_id: client.id },
    payment_intent: intentId,
    customer_details: { email },
    ...overrides
  };
}

async function buy(client, email, intentId) {
  const checkout = checkoutFor(client, email, intentId);
  await sendStripeEvent('checkout.session.completed', checkout);
  await processOutbox();
  return checkout;
}

async function license(client) {
  return (await api(client, 'GET', '/api/license')).body;
}

async function unlocked(client) {
  return (await api(client, 'GET', '/api/session')).body.unlocked;
}

async function waitForMail(to, count) {
  for (let i = 0; i < 200; i++) {
    const matching = sent.filter((message) => message.to === to);
    if (matching.length >= count) return matching[count - 1];
    await sleep(10);
  }
  throw new Error(`Expected ${count} email(s) to ${to}`);
}

function codeFrom(message) {
  const match = message.text.match(/verification code is: (\d{8})/);
  assert.ok(match, 'transfer code email contains a code');
  issuedCodes.push(match[1]);
  return match[1];
}

async function requestCode(client, email, mailIndex) {
  const response = await api(client, 'POST', '/api/license/transfer/request', { email });
  assert.equal(response.status, 202);
  return codeFrom(await waitForMail(email.trim().toLowerCase(), mailIndex));
}

const purchaseRow = (intentId) => db.prepare(
  'SELECT app_session_id, status, transfers_used, transfer_limit FROM stripe_purchases WHERE payment_intent_id = ?'
).get(intentId);

test('confirmation email is sent once, only after a verified payment', async () => {
  const buyer = await newClient();
  const email = 'Buyer.One@Example.com';
  const normalized = email.toLowerCase();

  await sendStripeEvent('checkout.session.completed',
    checkoutFor(buyer, email, 'pi_test_one', { payment_status: 'unpaid' }));
  await sendStripeEvent('checkout.session.async_payment_failed',
    checkoutFor(buyer, email, 'pi_test_one', { payment_status: 'unpaid' }));
  await processOutbox();
  assert.equal(sent.filter((m) => m.to === normalized).length, 0);
  assert.equal(await unlocked(buyer), false);
  assert.equal(purchaseRow('pi_test_one'), undefined);

  const checkout = checkoutFor(buyer, email, 'pi_test_one');
  const eventId = await sendStripeEvent('checkout.session.completed', checkout);
  await sendStripeEvent('checkout.session.completed', checkout, { id: eventId });
  await sendStripeEvent('checkout.session.completed', checkout, { id: eventId });
  await sendStripeEvent('checkout.session.async_payment_succeeded', checkout);
  const originalRetrieve = serverStripe.checkout.sessions.retrieve;
  serverStripe.checkout.sessions.retrieve = async () => checkout;
  try {
    const completed = await api(buyer, 'POST', '/api/checkout/complete', { sessionId: checkout.id });
    assert.equal(completed.status, 200);
  } finally {
    serverStripe.checkout.sessions.retrieve = originalRetrieve;
  }
  await processOutbox();

  const confirmations = sent.filter((m) => m.to === normalized);
  assert.equal(confirmations.length, 1);
  assert.match(confirmations[0].subject, /purchase confirmed \(PL-[A-HJ-NP-Z2-9]{10}\)/);
  assert.match(confirmations[0].text, /5\.00 USD/);
  assert.match(confirmations[0].text, /one device at a time/);
  assert.doesNotMatch(confirmations[0].text, /pi_test|cs_test|sk_test/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM email_outbox WHERE payment_intent_id = 'pi_test_one'").get().n, 1);
  assert.equal(db.prepare("SELECT to_address FROM email_outbox WHERE payment_intent_id = 'pi_test_one'").get().to_address, null);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM stripe_purchases WHERE payment_intent_id = 'pi_test_one'").get().n, 1);

  assert.equal(await unlocked(buyer), true);
  const summary = await license(buyer);
  assert.equal(summary.licensed, true);
  assert.equal(summary.emailMasked, 'bu***@e***.com');
  assert.match(summary.orderRef, /^PL-[A-HJ-NP-Z2-9]{10}$/);
  assert.equal(summary.transferLimit, 1);
  assert.equal(summary.transfersRemaining, 1);
  assert.doesNotMatch(JSON.stringify(summary), /pi_test|buyer\.one/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM stripe_purchases WHERE email_hash LIKE '%buyer%'").get().n, 0);
});

test('unpaid sessions and foreign emails cannot obtain or bypass a transfer', async () => {
  const owner = await newClient();
  await buy(owner, 'owner.two@example.com', 'pi_test_two');
  const stranger = await newClient();

  const known = await api(stranger, 'POST', '/api/license/transfer/request', { email: 'owner.two@example.com' });
  const unknown = await api(stranger, 'POST', '/api/license/transfer/request', { email: 'nobody@example.com' });
  assert.equal(known.status, 202);
  assert.deepEqual(unknown, known);
  await waitForMail('owner.two@example.com', 2);
  await sleep(50);
  assert.equal(sent.filter((m) => m.to === 'nobody@example.com').length, 0);

  const guess = await api(stranger, 'POST', '/api/license/transfer/confirm', { code: '12345678' });
  assert.equal(guess.status, 403);
  assert.equal(guess.body.error, 'verification_failed');
  assert.equal(await unlocked(stranger), false);
  assert.equal(purchaseRow('pi_test_two').app_session_id, owner.id);

  const unpaid = await newClient();
  const noPurchase = await api(unpaid, 'POST', '/api/license/transfer/confirm', { code: '00000000' });
  assert.equal(noPurchase.status, 403);
  assert.equal((await license(unpaid)).licensed, false);

  const self = await api(owner, 'POST', '/api/license/transfer/request', { email: 'owner.two@example.com' });
  assert.equal(self.status, 409);
  assert.equal(self.body.error, 'already_licensed');
});

test('a verified transfer moves the license once and the old device loses it', async () => {
  const oldDevice = await newClient();
  const checkout = await buy(oldDevice, 'mover@example.com', 'pi_test_move');
  const newDevice = await newClient();

  const code = await requestCode(newDevice, '  MOVER@example.com ', 2);
  const moved = await api(newDevice, 'POST', '/api/license/transfer/confirm', { code: `${code.slice(0, 4)}-${code.slice(4)}` });
  assert.equal(moved.status, 200);
  assert.deepEqual(moved.body, { licensed: true, transfersRemaining: 0 });

  assert.equal(await unlocked(newDevice), true);
  assert.equal(await unlocked(oldDevice), false);
  assert.deepEqual(await license(oldDevice), { licensed: false, movedToAnotherDevice: true, transferService: true, supportEmail: null });
  const newSummary = await license(newDevice);
  assert.equal(newSummary.transfersUsed, 1);
  assert.equal(newSummary.transfersRemaining, 0);
  const row = purchaseRow('pi_test_move');
  assert.equal(row.app_session_id, newDevice.id);
  assert.equal(row.transfers_used, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM license_transfers WHERE payment_intent_id = 'pi_test_move'").get().n, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM stripe_purchases WHERE app_session_id = ?').get(oldDevice.id).n, 0);

  const reuse = await api(newDevice, 'POST', '/api/license/transfer/confirm', { code });
  assert.equal(reuse.status, 409);
  const replayOtherSession = await api(await newClient(), 'POST', '/api/license/transfer/confirm', { code });
  assert.equal(replayOtherSession.status, 403);

  const oldReserve = await api(oldDevice, 'POST', '/api/labels/reserve', { count: 21 });
  assert.equal(oldReserve.status, 402);

  const originalRetrieve = serverStripe.checkout.sessions.retrieve;
  serverStripe.checkout.sessions.retrieve = async () => checkout;
  try {
    const replay = await api(oldDevice, 'POST', '/api/checkout/complete', { sessionId: checkout.id });
    assert.equal(replay.status, 200);
    assert.equal(replay.body.unlocked, false);
  } finally {
    serverStripe.checkout.sessions.retrieve = originalRetrieve;
  }
  assert.equal(await unlocked(oldDevice), false);
  assert.equal(purchaseRow('pi_test_move').app_session_id, newDevice.id);

  for (const device of [await newClient(), oldDevice]) {
    const again = await api(device, 'POST', '/api/license/transfer/request', { email: 'mover@example.com' });
    assert.equal(again.status, 202);
  }
  const notice = await waitForMail('mover@example.com', 4);
  assert.match(notice.subject, /not available/);
  assert.match(notice.text, /already been used/);
  assert.doesNotMatch(notice.text, /verification code/);
  assert.equal(sent.filter((m) => m.to === 'mover@example.com' && /verification code/.test(m.text)).length, 1);
  assert.equal(purchaseRow('pi_test_move').transfers_used, 1);
});

test('codes expire, are single use and lock after repeated wrong attempts', async () => {
  const owner = await newClient();
  await buy(owner, 'codes@example.com', 'pi_test_codes');
  const device = await newClient();

  const expiring = await requestCode(device, 'codes@example.com', 2);
  clock.now = () => realNow() + 11 * 60 * 1000;
  try {
    const expired = await api(device, 'POST', '/api/license/transfer/confirm', { code: expiring });
    assert.equal(expired.status, 403);
  } finally {
    clock.now = realNow;
  }

  const locked = await requestCode(device, 'codes@example.com', 3);
  const wrong = locked === '00000000' ? '11111111' : '00000000';
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await api(device, 'POST', '/api/license/transfer/confirm', { code: wrong })).status, 403);
  }
  assert.equal((await api(device, 'POST', '/api/license/transfer/confirm', { code: locked })).status, 403);
  assert.equal(await unlocked(device), false);
  assert.equal(purchaseRow('pi_test_codes').transfers_used, 0);

  const fresh = await requestCode(device, 'codes@example.com', 4);
  const ok = await api(device, 'POST', '/api/license/transfer/confirm', { code: fresh });
  assert.equal(ok.status, 200);
  assert.equal(db.prepare(
    "SELECT COUNT(*) AS n FROM email_verifications WHERE payment_intent_id = 'pi_test_codes' AND consumed_at IS NULL"
  ).get().n, 0);
});

test('transfer requests and code checks are rate limited in SQLite', async () => {
  const owner = await newClient();
  await buy(owner, 'limited@example.com', 'pi_test_limited');
  const device = await newClient();
  for (let i = 0; i < 3; i++) {
    assert.equal((await api(device, 'POST', '/api/license/transfer/request', { email: 'limited@example.com' })).status, 202);
  }
  const blocked = await api(device, 'POST', '/api/license/transfer/request', { email: 'limited@example.com' });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error, 'rate_limited');
  const fromElsewhere = await api(await newClient(), 'POST', '/api/license/transfer/request', { email: 'limited@example.com' });
  assert.equal(fromElsewhere.status, 429);

  // The blocked request still counted against the session (4 of 5), so one more address is allowed.
  assert.equal((await api(device, 'POST', '/api/license/transfer/request', { email: 'other1@example.com' })).status, 202);
  assert.equal((await api(device, 'POST', '/api/license/transfer/request', { email: 'other2@example.com' })).status, 429);

  const guesser = await newClient();
  for (let i = 0; i < 10; i++) {
    assert.equal((await api(guesser, 'POST', '/api/license/transfer/confirm', { code: '12345678' })).status, 403);
  }
  assert.equal((await api(guesser, 'POST', '/api/license/transfer/confirm', { code: '12345678' })).status, 429);

  const reader = new Database(path.join(dataDir, 'product-labels.sqlite'), { readonly: true });
  try {
    const keys = reader.prepare('SELECT key, count FROM rate_limits').all();
    assert.ok(keys.some((row) => row.key.startsWith('transfer-request:email:') && row.count === 3));
    assert.ok(keys.some((row) => row.key === `transfer-confirm:session:${guesser.id}` && row.count === 10));
    assert.ok(keys.every((row) => !/@|203\.0\.113/.test(row.key)));
  } finally {
    reader.close();
  }
});

test('concurrent confirmations consume the single transfer only once', async () => {
  const owner = await newClient();
  await buy(owner, 'race@example.com', 'pi_test_race');
  const first = await newClient();
  const second = await newClient();
  const firstCode = await requestCode(first, 'race@example.com', 2);
  const secondCode = await requestCode(second, 'race@example.com', 3);

  const results = await Promise.all([
    api(first, 'POST', '/api/license/transfer/confirm', { code: firstCode }),
    api(second, 'POST', '/api/license/transfer/confirm', { code: secondCode })
  ]);
  const winners = results.filter((r) => r.status === 200);
  const losers = results.filter((r) => r.status !== 200);
  assert.equal(winners.length, 1);
  assert.equal(losers.length, 1);
  // The winner closes every open code for the purchase, so the loser fails verification or the transfer guard.
  assert.ok([403, 409].includes(losers[0].status));
  assert.ok(['verification_failed', 'transfer_used'].includes(losers[0].body.error));
  assert.equal(purchaseRow('pi_test_race').transfers_used, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM license_transfers WHERE payment_intent_id = 'pi_test_race'").get().n, 1);
  const states = [await unlocked(owner), await unlocked(first), await unlocked(second)];
  assert.equal(states.filter(Boolean).length, 1);
  assert.equal(states[0], false);
});

test('refunds and disputes follow trusted Stripe state without resetting transfers', async () => {
  const buyer = await newClient();
  await buy(buyer, 'refund@example.com', 'pi_test_refund');
  const pendingDevice = await newClient();
  const code = await requestCode(pendingDevice, 'refund@example.com', 2);
  await sendStripeEvent('charge.refunded', { id: 'ch_refund', object: 'charge', payment_intent: 'pi_test_refund', refunded: true });
  assert.equal(await unlocked(buyer), false);
  const afterRefund = await api(pendingDevice, 'POST', '/api/license/transfer/confirm', { code });
  assert.equal(afterRefund.status, 409);
  assert.equal(afterRefund.body.error, 'license_unavailable');
  assert.equal(purchaseRow('pi_test_refund').transfers_used, 0);
  assert.equal((await api(await newClient(), 'POST', '/api/license/transfer/request', { email: 'refund@example.com' })).status, 202);
  assert.match((await waitForMail('refund@example.com', 3)).text, /not active/);

  const original = await newClient();
  const checkout = await buy(original, 'dispute@example.com', 'pi_test_dispute');
  const current = await newClient();
  const moveCode = await requestCode(current, 'dispute@example.com', 2);
  assert.equal((await api(current, 'POST', '/api/license/transfer/confirm', { code: moveCode })).status, 200);

  const t0 = Math.floor(realNow() / 1000);
  const dispute = { id: 'dp_test', object: 'dispute', payment_intent: 'pi_test_dispute' };
  await sendStripeEvent('charge.dispute.created', dispute, { created: t0 + 10 });
  assert.equal(await unlocked(current), false);
  await sendStripeEvent('charge.dispute.closed', { ...dispute, status: 'warning_closed' }, { created: t0 + 15 });
  assert.equal(await unlocked(current), false);
  await sendStripeEvent('charge.dispute.closed', { ...dispute, status: 'won' }, { created: t0 + 20 });
  assert.equal(await unlocked(current), true);
  await sendStripeEvent('charge.dispute.created', dispute, { created: t0 + 10 });
  assert.equal(await unlocked(current), true);

  await sendStripeEvent('charge.refunded', { id: 'ch_dispute', object: 'charge', payment_intent: 'pi_test_dispute', refunded: true });
  await sendStripeEvent('charge.dispute.closed', { ...dispute, status: 'won' }, { created: t0 + 30 });
  await sendStripeEvent('checkout.session.completed', checkout);
  await sendStripeEvent('checkout.session.async_payment_succeeded', checkout);
  assert.equal(await unlocked(current), false);
  assert.equal(await unlocked(original), false);
  const row = purchaseRow('pi_test_dispute');
  assert.equal(row.status, 'refunded');
  assert.equal(row.transfers_used, 1);
  assert.equal(row.app_session_id, current.id);
});

test('email failures keep payments correct and never leak secrets', async () => {
  mailFailure = Object.assign(new Error('535 login failed for smtp-user password=SuperSecretPass'), { code: 'EAUTH' });
  try {
    const buyer = await newClient();
    await buy(buyer, 'mailfail@example.com', 'pi_test_mailfail');
    assert.equal(await unlocked(buyer), true);
    const outbox = db.prepare("SELECT status, attempts, last_error, to_address FROM email_outbox WHERE payment_intent_id = 'pi_test_mailfail'").get();
    // A rejected SMTP login is an outage, not a bad message: postponed without using up an attempt.
    assert.deepEqual(outbox, { status: 'pending', attempts: 0, last_error: 'EAUTH', to_address: 'mailfail@example.com' });

    const unpaid = await newClient();
    await sendStripeEvent('checkout.session.completed',
      checkoutFor(unpaid, 'unpaid@example.com', 'pi_test_unpaid', { payment_status: 'unpaid' }));
    await processOutbox();
    assert.equal(await unlocked(unpaid), false);

    const device = await newClient();
    const transfer = await api(device, 'POST', '/api/license/transfer/request', { email: 'mailfail@example.com' });
    assert.equal(transfer.status, 202);
    assert.doesNotMatch(JSON.stringify(transfer.body), /EAUTH|Secret|smtp/i);
    await sleep(50);
  } finally {
    mailFailure = null;
  }

  clock.now = () => realNow() + 6 * 60 * 1000;
  try {
    await processOutbox();
  } finally {
    clock.now = realNow;
  }
  const delivered = db.prepare("SELECT kind, status, to_address FROM email_outbox WHERE payment_intent_id = 'pi_test_mailfail' ORDER BY id").all();
  assert.deepEqual(delivered, [
    { kind: 'purchase_confirmation', status: 'sent', to_address: null },
    { kind: 'transfer_code', status: 'sent', to_address: null }
  ]);
  const retried = sent.filter((m) => m.to === 'mailfail@example.com');
  assert.equal(retried.length, 2);
  // The code email went out six minutes late, so it states the time actually left.
  assert.match(retried[1].text, /expires in 4 minutes/);
  codeFrom(retried[1]);
  assert.ok(logs.some((line) => /not delivered: EAUTH/.test(line)));

  mailer.configured = false;
  try {
    const offline = await api(await newClient(), 'POST', '/api/license/transfer/request', { email: 'mailfail@example.com' });
    assert.equal(offline.status, 503);
    assert.equal(offline.body.error, 'email_unavailable');
  } finally {
    mailer.configured = true;
  }
});

test('a long SMTP outage never drops queued confirmations or hammers the server', async () => {
  const outage = Object.assign(new Error('525 5.7.1 Unauthorized IP address'), { code: 'EAUTH', responseCode: 525 });
  const calls = [];
  const originalSend = mailer.send;
  mailer.send = async (message) => {
    calls.push(message.to);
    if (mailFailure) throw mailFailure;
    sent.push(message);
  };
  const buyers = [];
  mailFailure = Object.assign(new Error('Email delivery failed.'), { code: 'EAUTH', smtpStatus: outage.responseCode });
  try {
    for (const n of [1, 2, 3]) {
      const buyer = await newClient();
      await buy(buyer, `outage${n}@example.com`, `pi_test_outage${n}`);
      assert.equal(await unlocked(buyer), true, 'payment stays effective while email is down');
      buyers.push(buyer);
    }
    calls.length = 0;
    // Six hours of runs every minute: well past the 5-attempt budget for message errors.
    for (let minute = 1; minute <= 360; minute++) {
      await at(minute * 60 * 1000, () => processOutbox());
    }
  } finally {
    mailFailure = null;
  }
  const rows = () => db.prepare(`SELECT status, attempts, last_error, to_address FROM email_outbox
    WHERE payment_intent_id LIKE 'pi_test_outage%' ORDER BY payment_intent_id`).all();
  for (const [index, row] of rows().entries()) {
    assert.deepEqual(row, { status: 'pending', attempts: 0, last_error: 'EAUTH', to_address: `outage${index + 1}@example.com` });
  }
  // One login attempt per retry window, not one per queued message per minute.
  assert.ok(calls.length <= 360 / 5 + 1, `${calls.length} SMTP attempts during the outage`);
  assert.ok(calls.length >= 360 / 5 - 1, 'delivery keeps being retried during the outage');
  assert.ok(logs.some((line) => /not delivered: EAUTH \(SMTP 525\)\./.test(line)));

  // Once SMTP works again, the queue drains on the first run after the retry window.
  await at(366 * 60 * 1000, () => processOutbox());
  mailer.send = originalSend;
  assert.deepEqual(rows().map((row) => row.status), ['sent', 'sent', 'sent']);
  for (const n of [1, 2, 3]) assert.equal(sent.filter((m) => m.to === `outage${n}@example.com`).length, 1);
});

test('queued transfer codes are encrypted and never sent once replaced or expired', async () => {
  const owner = await newClient();
  await buy(owner, 'queued@example.com', 'pi_test_queued');
  const device = await newClient();
  const outbox = () => db.prepare(`SELECT id, status, attempts, last_error, to_address, payload FROM email_outbox
    WHERE payment_intent_id = 'pi_test_queued' AND kind = 'transfer_code' ORDER BY id`).all();
  const before = sent.length;

  mailFailure = Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });
  try {
    assert.equal((await api(device, 'POST', '/api/license/transfer/request', { email: 'queued@example.com' })).status, 202);
    await processOutbox();
    assert.equal((await api(device, 'POST', '/api/license/transfer/request', { email: 'queued@example.com' })).status, 202);
    await processOutbox();
  } finally {
    mailFailure = null;
  }
  const [first, second] = outbox();
  for (const row of [first, second]) {
    assert.equal(row.status, 'pending');
    assert.equal(row.last_error, 'ETIMEDOUT');
    assert.equal(row.to_address, 'queued@example.com');
    const payload = JSON.parse(row.payload);
    assert.deepEqual(Object.keys(payload).sort(), ['orderRef', 'sealedCode', 'verificationId']);
    assert.doesNotMatch(row.payload, /"code"|\b\d{8}\b/);
  }
  assert.equal(sent.length, before);

  clock.now = () => realNow() + 60 * 1000;
  try {
    await processOutbox();
  } finally {
    clock.now = realNow;
  }
  const [replaced, current] = outbox();
  assert.deepEqual({ status: replaced.status, error: replaced.last_error, to: replaced.to_address, payload: replaced.payload },
    { status: 'failed', error: 'code_unavailable', to: null, payload: '{}' }, 'the replaced code is dropped');
  assert.deepEqual({ status: current.status, to: current.to_address, payload: current.payload },
    { status: 'sent', to: null, payload: '{}' });
  const delivered = sent.slice(before);
  assert.equal(delivered.length, 1);
  const code = codeFrom(delivered[0]);
  assert.match(delivered[0].text, /expires in 9 minutes/);

  // A code whose email could not go out before expiry is never sent late.
  const late = await newClient();
  mailFailure = Object.assign(new Error('down'), { code: 'ECONNREFUSED' });
  try {
    assert.equal((await api(late, 'POST', '/api/license/transfer/request', { email: 'queued@example.com' })).status, 202);
    await processOutbox();
  } finally {
    mailFailure = null;
  }
  clock.now = () => realNow() + 9.5 * 60 * 1000;
  try {
    await processOutbox();
  } finally {
    clock.now = realNow;
  }
  const expired = outbox().at(-1);
  assert.deepEqual({ status: expired.status, error: expired.last_error, payload: expired.payload },
    { status: 'failed', error: 'code_unavailable', payload: '{}' });
  assert.equal(sent.length, before + 1);

  // Queueing changed nothing about ownership: the delivered code still moves the license exactly once.
  const moved = await api(device, 'POST', '/api/license/transfer/confirm', { code });
  assert.equal(moved.status, 200);
  assert.deepEqual(purchaseRow('pi_test_queued'), { app_session_id: device.id, status: 'active', transfers_used: 1, transfer_limit: 1 });
  assert.equal(await unlocked(owner), false);
});

const DAY = 24 * 60 * 60 * 1000;
const COOKIE_ATTRIBUTES = 'Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000';

async function sessionCookieHeader(client) {
  const response = await fetch(`${origin}/api/session`, { headers: { Cookie: client.cookie, 'X-Forwarded-For': client.ip } });
  assert.equal(response.status, 200);
  return { header: response.headers.get('set-cookie'), body: await response.json() };
}

function at(offset, fn) {
  const frozen = realNow() + offset;
  clock.now = () => frozen;
  return Promise.resolve().then(() => fn(frozen)).finally(() => { clock.now = realNow; });
}

const lastSeen = (id) => db.prepare('SELECT last_seen_at FROM app_sessions WHERE id = ?').get(id).last_seen_at;

test('an active session is renewed with the same id, signature and cookie attributes', async () => {
  const owner = await newClient();
  await buy(owner, 'renew@example.com', 'pi_test_renew');
  const before = purchaseRow('pi_test_renew');
  const sessions = db.prepare('SELECT COUNT(*) AS n FROM app_sessions').get().n;

  // Used every 300 days: well past one year since creation, the same device keeps its license.
  for (const offset of [300 * DAY, 600 * DAY]) {
    await at(offset, async (now) => {
      const { header, body } = await sessionCookieHeader(owner);
      assert.equal(header, `${owner.cookie}; ${COOKIE_ATTRIBUTES}`);
      assert.equal(body.unlocked, true);
      assert.equal(lastSeen(owner.id), now);
    });
  }
  assert.deepEqual(purchaseRow('pi_test_renew'), before);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM app_sessions').get().n, sessions, 'renewal never creates a session');

  // Only /api/session renews; other routes accept the session without extending it.
  const renewedAt = lastSeen(owner.id);
  await at(601 * DAY, async () => {
    const response = await fetch(`${origin}/api/license`, { headers: { Cookie: owner.cookie, 'X-Forwarded-For': owner.ip } });
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal((await response.json()).licensed, true);
    assert.equal(lastSeen(owner.id), renewedAt);
  });
  // A clock that goes backwards never shortens the recorded activity.
  await sessionCookieHeader(owner);
  assert.equal(lastSeen(owner.id), renewedAt);
});

test('expired, forged and unknown sessions are replaced, never renewed, and keep no license', async () => {
  const owner = await newClient();
  await buy(owner, 'expired@example.com', 'pi_test_expired');
  const before = purchaseRow('pi_test_expired');

  await at(366 * DAY, async () => {
    // A replayed cookie whose lifetime ran out is treated like no cookie at all.
    const { header, body } = await sessionCookieHeader(owner);
    assert.match(header, new RegExp(`; ${COOKIE_ATTRIBUTES}$`));
    assert.notEqual(header.split(';')[0], owner.cookie);
    assert.equal(body.unlocked, false);
    const replay = await api(owner, 'GET', '/api/license');
    assert.equal(replay.body.licensed, false);
    assert.equal((await api(owner, 'POST', '/api/labels/reserve', { count: 21 })).status, 402);
  });
  // Expiry moves nothing: the license stays bound to the old session and no transfer is counted.
  assert.deepEqual(purchaseRow('pi_test_expired'), before);
  assert.equal(before.app_session_id, owner.id);

  const crypto = require('node:crypto');
  const sign = (id) => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(id).digest('base64url');
  const [id, signature] = decodeURIComponent(owner.cookie.split('=')[1]).split('.');
  const forged = [
    `${id}.${signature.slice(0, -1)}${signature.endsWith('A') ? 'B' : 'A'}`, // tampered signature
    `${id}.${sign(`${id}x`)}`, // signature of another id
    `${id}.${signature}.extra`,
    `unknown-session-id.${sign('unknown-session-id')}` // validly signed but never issued
  ];
  for (const value of forged) {
    const client = { ip: `198.51.100.${forged.indexOf(value) + 1}`, cookie: `product_labels_session=${encodeURIComponent(value)}` };
    const { header, body } = await sessionCookieHeader(client);
    const issued = decodeURIComponent(header.split(';')[0].split('=')[1]);
    assert.notEqual(issued, value);
    assert.notEqual(issued.split('.')[0], id);
    assert.equal(body.unlocked, false);
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM app_sessions WHERE id = 'unknown-session-id'").get().n, 0);
  assert.deepEqual(purchaseRow('pi_test_expired'), before);
});

test('sessions created before renewal existed use created_at as their last activity', async () => {
  const recent = await newClient();
  const stale = await newClient();
  const setLegacy = db.prepare("UPDATE app_sessions SET last_seen_at = NULL, created_at = datetime('now', ?) WHERE id = ?");
  setLegacy.run('-10 days', recent.id);
  setLegacy.run('-400 days', stale.id);

  const renewed = await sessionCookieHeader(recent);
  assert.equal(renewed.header.split(';')[0], recent.cookie);
  assert.ok(lastSeen(recent.id) >= realNow() - 1000);

  const replaced = await sessionCookieHeader(stale);
  assert.notEqual(replaced.header.split(';')[0], stale.cookie);
  assert.equal(lastSeen(stale.id), null);
});

test('a test-mode server ignores live Stripe objects', async () => {
  const client = await newClient();
  const liveCheckout = checkoutFor(client, 'livebuyer@example.com', 'pi_test_livemix', { livemode: true, id: 'cs_live_mix' });
  const payload = JSON.stringify({ id: 'evt_live_on_test', object: 'event', created: Math.floor(realNow() / 1000), livemode: true,
    pending_webhooks: 1, type: 'checkout.session.completed', data: { object: liveCheckout } });
  const response = await fetch(`${origin}/api/stripe/webhook`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': stripe.webhooks.generateTestHeaderString({ payload, secret: webhookSecret }) },
    body: payload });
  assert.equal(response.status, 200);
  // A test envelope carrying a live checkout is rejected too.
  await sendStripeEvent('checkout.session.completed', liveCheckout);
  assert.equal(await unlocked(client), false);
  assert.equal(purchaseRow('pi_test_livemix'), undefined);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM stripe_events WHERE id = 'evt_live_on_test'").get().n, 0);

  const complete = await api(client, 'POST', '/api/checkout/complete', { sessionId: 'cs_live_a1B2c3' });
  assert.deepEqual(complete, { status: 400, body: { error: 'invalid_checkout_session' } });
});

test('license routes keep origin, input and body size protections', async () => {
  const client = await newClient();
  const forged = await api(client, 'POST', '/api/license/transfer/request', { email: 'x@example.com' },
    { Origin: 'https://attacker.example' });
  assert.equal(forged.status, 403);
  const forgedConfirm = await api(client, 'POST', '/api/license/transfer/confirm', { code: '12345678' },
    { Origin: 'https://attacker.example' });
  assert.equal(forgedConfirm.status, 403);
  assert.deepEqual((await api(client, 'POST', '/api/license/transfer/request', '{bad')).body, { error: 'invalid_json' });
  assert.equal((await api(client, 'POST', '/api/license/transfer/request',
    JSON.stringify({ email: `${'a'.repeat(9000)}@example.com` }))).status, 413);
  for (const email of ['', 'no-at-sign', 'a"b"@example.com', 'x@example.com>,evil@example.com', ['x@example.com'], 7]) {
    const response = await api(client, 'POST', '/api/license/transfer/request', { email });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_email');
  }
  for (const code of ['1234567', 'abcdefgh', '123456789', 12345678, null]) {
    const response = await api(client, 'POST', '/api/license/transfer/confirm', { code });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_code');
  }
  const paidClaim = await api(client, 'POST', '/api/license', { licensed: true, transfersUsed: 0 });
  assert.equal(paidClaim.status, 404);
  assert.equal(await unlocked(client), false);
});

test('server logs never contain codes, customer emails or Stripe secrets', () => {
  assert.ok(issuedCodes.length >= 8);
  const joined = logs.join('\n');
  for (const code of issuedCodes) assert.ok(!joined.includes(code), 'transfer code leaked to logs');
  for (const email of new Set([...usedEmails, ...sent.map((m) => m.to)])) {
    assert.ok(!joined.toLowerCase().includes(email.toLowerCase()), 'email leaked to logs');
  }
  assert.doesNotMatch(joined, /sk_test_|whsec_|SuperSecretPass|smtp-user/);
});
