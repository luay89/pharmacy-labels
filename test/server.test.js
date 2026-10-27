'use strict';

const assert = require('node:assert/strict');
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
const { app, db } = require('../server');
let server;
const origin = process.env.PUBLIC_APP_URL;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31877, '127.0.0.1', () => resolve(listener));
  });
});

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
    mode: 'payment',
    payment_status: 'paid',
    amount_total: 300,
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
