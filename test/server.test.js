'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-test-'));
const webhookSecret = 'whsec_test_secret';
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31877';
process.env.DATA_DIR = dataDir;
process.env.STRIPE_SECRET_KEY = 'sk_test_123456789';
process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const { app, db, mailer, stripe: serverStripe } = require('../server');
let server;
const origin = process.env.PUBLIC_APP_URL;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31877, '127.0.0.1', () => resolve(listener));
  });
});

async function newSession() {
  const response = await fetch(`${origin}/api/session`);
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { cookie, id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

function addAccountAndDevice(session) {
  const accountId = crypto.randomBytes(16).toString('base64url');
  const accountToken = crypto.randomBytes(32).toString('base64url');
  const accountKey = Buffer.from(crypto.hkdfSync('sha256', process.env.SESSION_SECRET, Buffer.alloc(0), 'product-labels/license-v1', 32));
  const tokenHash = crypto.createHmac('sha256', accountKey).update(`account-session:${accountToken}`).digest('hex');
  const now = Date.now();
  db.prepare('INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES (?, ?, ?, ?)')
    .run(accountId, crypto.randomBytes(32).toString('hex'), 'te***@e***.com', now);
  db.prepare('INSERT INTO account_sessions (token_hash, account_id, app_session_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(tokenHash, accountId, session.id, now, now + 30 * 24 * 60 * 60 * 1000);
  db.prepare(`INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at, last_validated_at)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(crypto.randomBytes(16).toString('base64url'), accountId, crypto.randomBytes(32).toString('base64url'),
      JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) }), now, now);
  return { id: session.id, accountId, cookie: `${session.cookie}; product_labels_account=${accountToken}` };
}

function post(pathname, body, cookie, requestOrigin = origin) {
  return fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: requestOrigin },
    body: JSON.stringify(body)
  });
}

async function sendStripeEvent(id, type, object, secret = webhookSecret) {
  const payload = JSON.stringify({
    id,
    object: 'event',
    created: Math.floor(Date.now() / 1000),
    data: { object },
    livemode: false,
    pending_webhooks: 1,
    type
  });
  const signature = stripe.webhooks.generateTestHeaderString({ payload, secret });
  return fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': signature },
    body: payload
  });
}

function paidCheckout(appSessionId, overrides = {}) {
  return {
    id: `cs_test_${appSessionId.replace(/[^A-Za-z0-9]/g, '')}`,
    object: 'checkout.session',
    livemode: false,
    mode: 'payment',
    status: 'complete',
    payment_status: 'paid',
    amount_total: 500,
    currency: 'usd',
    client_reference_id: appSessionId,
    metadata: { app_session_id: appSessionId },
    payment_intent: `pi_test_${appSessionId.slice(0, 12).replace(/[^A-Za-z0-9]/g, '')}`,
    ...overrides
  };
}

async function isUnlocked(cookie) {
  const response = await fetch(`${origin}/api/session`, { headers: { Cookie: cookie } });
  return (await response.json()).unlocked;
}

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('server enforces trial limits and processes signed Stripe entitlement events', async () => {
  const health = await fetch(`${origin}/api/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { ok: true });

  const sessionResponse = await fetch(`${origin}/api/session`);
  assert.equal(sessionResponse.status, 200);
  const cookie = sessionResponse.headers.get('set-cookie').split(';')[0];
  assert.match(sessionResponse.headers.get('set-cookie'), /HttpOnly/);
  assert.match(sessionResponse.headers.get('set-cookie'), /SameSite=Lax/);
  assert.deepEqual(await sessionResponse.json(), { printedCount: 0, freeLimit: 20, unlocked: false });

  const tamperedCookie = `${cookie.slice(0, -1)}${cookie.endsWith('a') ? 'b' : 'a'}`;
  const tamperedSession = await fetch(`${origin}/api/session`, {
    headers: { Cookie: tamperedCookie }
  });
  assert.equal(tamperedSession.status, 200);
  assert.equal((await tamperedSession.json()).unlocked, false);

  const malformedSession = await fetch(`${origin}/api/session`, {
    headers: { Cookie: 'product_labels_session=%E0%A4%A' }
  });
  assert.equal(malformedSession.status, 200);
  assert.match(malformedSession.headers.get('set-cookie'), /^product_labels_session=/);
  assert.equal((await malformedSession.json()).unlocked, false);
  const freshCookie = malformedSession.headers.get('set-cookie').split(';')[0];
  const freshSession = await fetch(`${origin}/api/session`, { headers: { Cookie: freshCookie } });
  assert.equal(freshSession.status, 200);
  // A valid session is renewed with the same cookie value instead of being replaced.
  assert.equal(freshSession.headers.get('set-cookie').split(';')[0], freshCookie);
  assert.deepEqual(await freshSession.json(), { printedCount: 0, freeLimit: 20, unlocked: false });

  const reserve = (count, sessionCookie = cookie, requestOrigin = origin) => fetch(
    `${origin}/api/labels/reserve`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: sessionCookie,
        Origin: requestOrigin
      },
      body: JSON.stringify({ count })
    }
  );
  const firstTwenty = await reserve(20);
  assert.equal(firstTwenty.status, 200);
  assert.deepEqual(await firstTwenty.json(), { printedCount: 20, unlocked: false });

  const twentyFirst = await reserve(1);
  assert.equal(twentyFirst.status, 402);
  assert.equal((await twentyFirst.json()).error, 'free_limit_reached');

  const forgedOrigin = await reserve(1, cookie, 'https://attacker.example');
  assert.equal(forgedOrigin.status, 403);

  const purchaseSession = await fetch(`${origin}/api/session`);
  const purchaseCookie = purchaseSession.headers.get('set-cookie').split(';')[0];
  const appSessionId = decodeURIComponent(purchaseCookie.split('=')[1]).split('.')[0];
  const sendStripeEvent = async (id, type, object) => {
    const payload = JSON.stringify({
      id,
      object: 'event',
      created: Math.floor(Date.now() / 1000),
      data: { object },
      livemode: false,
      pending_webhooks: 1,
      type
    });
    const signature = stripe.webhooks.generateTestHeaderString({
      payload,
      secret: webhookSecret
    });
    return fetch(`${origin}/api/stripe/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': signature },
      body: payload
    });
  };
  const checkoutSession = {
    id: 'cs_test_paid',
    object: 'checkout.session',
    livemode: false,
    mode: 'payment',
    payment_status: 'paid',
    amount_total: 500,
    currency: 'usd',
    client_reference_id: appSessionId,
    metadata: { app_session_id: appSessionId },
    payment_intent: 'pi_test_labels'
  };
  const paidEvent = await sendStripeEvent(
    'evt_test_checkout_completed',
    'checkout.session.completed',
    checkoutSession
  );
  assert.equal(paidEvent.status, 200);
  const paidSession = await fetch(`${origin}/api/session`, { headers: { Cookie: purchaseCookie } });
  assert.equal((await paidSession.json()).unlocked, true);

  const refundEvent = await sendStripeEvent('evt_test_charge_refunded', 'charge.refunded', {
    id: 'ch_test_refund',
    object: 'charge',
    payment_intent: 'pi_test_labels',
    refunded: true
  });
  assert.equal(refundEvent.status, 200);
  const refundedSession = await fetch(`${origin}/api/session`, { headers: { Cookie: purchaseCookie } });
  assert.equal((await refundedSession.json()).unlocked, false);

  const openedDispute = await sendStripeEvent('evt_test_dispute_created', 'charge.dispute.created', {
    id: 'dp_test_refund',
    object: 'dispute',
    payment_intent: 'pi_test_labels'
  });
  assert.equal(openedDispute.status, 200);
  const wonDispute = await sendStripeEvent('evt_test_dispute_won', 'charge.dispute.closed', {
    id: 'dp_test_refund',
    object: 'dispute',
    payment_intent: 'pi_test_labels',
    status: 'won'
  });
  assert.equal(wonDispute.status, 200);
  const stillRefunded = await fetch(`${origin}/api/session`, { headers: { Cookie: purchaseCookie } });
  assert.equal((await stillRefunded.json()).unlocked, false);

  const invalidSignature = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': 'invalid' },
    body: JSON.stringify({ id: 'evt_invalid', type: 'checkout.session.completed' })
  });
  assert.equal(invalidSignature.status, 400);

  const source = await fetch(`${origin}/server.js`);
  assert.equal(source.status, 404);
});

test('checkout uses the server price and rejects unauthorized requests', async () => {
  const session = await newSession();
  const { cookie, id, accountId } = addAccountAndDevice(session);
  const originalCreate = serverStripe.checkout.sessions.create;
  let createParams;
  serverStripe.checkout.sessions.create = async (params) => {
    createParams = params;
    return { url: 'https://checkout.stripe.com/c/pay/cs_test_fake' };
  };
  try {
    const forged = await post('/api/checkout', {}, cookie, 'https://attacker.example');
    assert.equal(forged.status, 403);
    assert.equal(createParams, undefined);

    const response = await post('/api/checkout', {
      price: 1, amount: 1, unit_amount: 1, currency: 'jpy', unlocked: true
    }, cookie);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).url, 'https://checkout.stripe.com/c/pay/cs_test_fake');
    assert.equal(createParams.mode, 'payment');
    assert.equal(createParams.client_reference_id, id);
    assert.equal(createParams.metadata.app_session_id, id);
    assert.equal(createParams.metadata.account_id, accountId);
    assert.equal(createParams.metadata.license_policy, 'single_device');
    assert.deepEqual(createParams.line_items.map((item) => [
      item.price_data.unit_amount, item.price_data.currency, item.quantity
    ]), [[500, 'usd', 1]]);
    assert.equal(await isUnlocked(cookie), false);
  } finally {
    serverStripe.checkout.sessions.create = originalCreate;
  }
});

test('checkout completion only unlocks a verified paid session owned by the caller', async () => {
  const owner = await newSession();
  const other = await newSession();
  const originalRetrieve = serverStripe.checkout.sessions.retrieve;
  let stripeSession;
  serverStripe.checkout.sessions.retrieve = async () => stripeSession;
  const complete = (cookie) => post('/api/checkout/complete', { sessionId: 'cs_test_abc123' }, cookie);
  try {
    const badId = await post('/api/checkout/complete', { sessionId: 'pi_123' }, owner.cookie);
    assert.equal(badId.status, 400);

    stripeSession = paidCheckout(owner.id);
    const stolen = await complete(other.cookie);
    assert.equal(stolen.status, 403);
    assert.equal(await isUnlocked(other.cookie), false);

    stripeSession = paidCheckout(owner.id, { amount_total: 100 });
    assert.equal((await complete(owner.cookie)).status, 403);
    stripeSession = paidCheckout(owner.id, { amount_total: 300 });
    assert.equal((await complete(owner.cookie)).status, 403);
    stripeSession = paidCheckout(owner.id, { currency: 'eur' });
    assert.equal((await complete(owner.cookie)).status, 403);

    stripeSession = paidCheckout(owner.id, { payment_status: 'unpaid' });
    const pending = await complete(owner.cookie);
    assert.equal(pending.status, 409);
    assert.equal((await pending.json()).error, 'payment_pending');
    assert.equal(await isUnlocked(owner.cookie), false);

    serverStripe.checkout.sessions.retrieve = async () => {
      const error = new Error('No such checkout.session');
      error.type = 'StripeInvalidRequestError';
      throw error;
    };
    assert.equal((await complete(owner.cookie)).status, 403);

    stripeSession = paidCheckout(owner.id);
    serverStripe.checkout.sessions.retrieve = async () => stripeSession;
    const verified = await complete(owner.cookie);
    assert.equal(verified.status, 200);
    assert.equal((await verified.json()).unlocked, true);
    assert.equal(await isUnlocked(owner.cookie), true);
  } finally {
    serverStripe.checkout.sessions.retrieve = originalRetrieve;
  }
});

test('new checkout completion binds the purchase to the account and one-device policy', async () => {
  const session = await newSession();
  const buyer = addAccountAndDevice(session);
  const otherSession = await newSession();
  const other = addAccountAndDevice(otherSession);
  const originalRetrieve = serverStripe.checkout.sessions.retrieve;
  const mailWasConfigured = mailer.configured;
  mailer.configured = true;
  const checkout = paidCheckout(buyer.id, {
    metadata: { app_session_id: buyer.id, account_id: buyer.accountId, license_policy: 'single_device' },
    payment_intent: 'pi_account_bound_purchase'
  });
  serverStripe.checkout.sessions.retrieve = async () => checkout;
  try {
    const withoutAccount = await post('/api/checkout/complete', { sessionId: checkout.id }, session.cookie);
    assert.equal(withoutAccount.status, 403);
    const wrongAccount = await post('/api/checkout/complete', { sessionId: checkout.id }, other.cookie);
    assert.equal(wrongAccount.status, 403);
    const verified = await post('/api/checkout/complete', { sessionId: checkout.id }, buyer.cookie);
    assert.equal(verified.status, 200);
    const purchase = db.prepare(`SELECT account_id, license_policy, transfers_used, transfer_limit
      FROM stripe_purchases WHERE payment_intent_id = ?`).get('pi_account_bound_purchase');
    assert.deepEqual(purchase, { account_id: buyer.accountId, license_policy: 'single_device', transfers_used: 0, transfer_limit: 1 });
    assert.equal((await post('/api/license/transfer/request', { email: 'buyer@example.com' }, other.cookie)).status, 202,
      'transfer endpoints keep a generic response for non-legacy purchases');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM email_outbox WHERE kind = \'transfer_code\'').get().n, 0);
  } finally {
    serverStripe.checkout.sessions.retrieve = originalRetrieve;
    mailer.configured = mailWasConfigured;
  }
});

test('webhook rejects bad signatures, ignores unpaid or mismatched sessions and is idempotent', async () => {
  const { cookie, id } = await newSession();

  const wrongSecret = await sendStripeEvent(
    'evt_wrong_secret', 'checkout.session.completed', paidCheckout(id), 'whsec_attacker_secret'
  );
  assert.equal(wrongSecret.status, 400);
  const noSignature = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 'evt_unsigned', type: 'checkout.session.completed' })
  });
  assert.equal(noSignature.status, 400);
  assert.equal(await isUnlocked(cookie), false);

  const pending = await sendStripeEvent('evt_pending', 'checkout.session.completed',
    paidCheckout(id, { payment_status: 'unpaid' }));
  assert.equal(pending.status, 200);
  assert.equal(await isUnlocked(cookie), false);

  const failed = await sendStripeEvent('evt_failed', 'checkout.session.async_payment_failed',
    paidCheckout(id, { payment_status: 'unpaid' }));
  assert.equal(failed.status, 200);
  const expired = await sendStripeEvent('evt_expired', 'checkout.session.expired',
    paidCheckout(id, { status: 'expired', payment_status: 'unpaid' }));
  assert.equal(expired.status, 200);
  assert.equal(await isUnlocked(cookie), false);

  const cheap = await sendStripeEvent('evt_cheap', 'checkout.session.completed',
    paidCheckout(id, { amount_total: 1 }));
  assert.equal(cheap.status, 200);
  const unknownSession = await sendStripeEvent('evt_unknown', 'checkout.session.completed',
    paidCheckout('unknown-session-id'));
  assert.equal(unknownSession.status, 200);
  assert.equal(await isUnlocked(cookie), false);

  const checkout = paidCheckout(id, { payment_intent: 'pi_test_async_paid' });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const delivered = await sendStripeEvent('evt_async_paid', 'checkout.session.async_payment_succeeded', checkout);
    assert.equal(delivered.status, 200);
  }
  assert.equal(await isUnlocked(cookie), true);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM stripe_events WHERE id = 'evt_async_paid'").get().n, 1);
  assert.equal(db.prepare(
    "SELECT COUNT(*) AS n FROM stripe_purchases WHERE payment_intent_id = 'pi_test_async_paid'"
  ).get().n, 1);

  const refund = await sendStripeEvent('evt_async_refund', 'charge.refunded', {
    id: 'ch_test_async', object: 'charge', payment_intent: 'pi_test_async_paid', refunded: true
  });
  assert.equal(refund.status, 200);
  const replay = await sendStripeEvent('evt_async_paid', 'checkout.session.async_payment_succeeded', checkout);
  assert.equal(replay.status, 200);
  const newEventSamePayment = await sendStripeEvent('evt_async_paid_again', 'checkout.session.completed', checkout);
  assert.equal(newEventSamePayment.status, 200);
  assert.equal(await isUnlocked(cookie), false);
});

test('malformed and oversized request bodies return client errors without details', async () => {
  const { cookie } = await newSession();
  const send = (body, pathname = '/api/labels/reserve') => fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: origin },
    body
  });

  const malformed = await send('{bad');
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: 'invalid_json' });

  const oversized = await send(JSON.stringify({ count: 1, pad: 'x'.repeat(9000) }));
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), { error: 'payload_too_large' });

  const oversizedCheckout = await send(JSON.stringify({ sessionId: 'x'.repeat(9000) }), '/api/checkout/complete');
  assert.equal(oversizedCheckout.status, 413);

  const oversizedWebhook = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': 't=1,v1=fake' },
    body: JSON.stringify({ pad: 'x'.repeat(70 * 1024) })
  });
  assert.equal(oversizedWebhook.status, 413);

  const stillWorks = await send(JSON.stringify({ count: 1 }));
  assert.equal(stillWorks.status, 200);
});

test('responses carry security headers and no HSTS over plain HTTP', async () => {
  const response = await fetch(`${origin}/`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(response.headers.get('content-security-policy'), /object-src 'none'/);
  assert.match(response.headers.get('content-security-policy'), /script-src 'self' 'sha256-[A-Za-z0-9+/]+=*'/);
  assert.doesNotMatch(response.headers.get('content-security-policy'), /unsafe-inline|unsafe-eval/);
  assert.equal(response.headers.get('strict-transport-security'), null);
  assert.equal(response.headers.get('x-powered-by'), null);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});
