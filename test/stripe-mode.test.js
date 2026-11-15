'use strict';

// A server configured with a (fake) live key must ignore everything from Stripe test mode.
// No request reaches Stripe: webhooks are verified locally and test session ids are rejected before any lookup.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-live-'));
const webhookSecret = 'whsec_fake_live_mode_tests';
process.env.SESSION_SECRET = 'live-mode-test-secret-with-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31910';
process.env.DATA_DIR = dataDir;
process.env.STRIPE_SECRET_KEY = 'sk_live_fake_key_for_tests_only';
process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
delete process.env.SMTP_HOST;

const logs = [];
const originalWarn = console.warn;
console.warn = (...args) => logs.push(args.join(' '));

const Stripe = require('stripe');
const signer = new Stripe('sk_test_signer_only');
const { app, db } = require('../server');
const origin = process.env.PUBLIC_APP_URL;
let server;
let counter = 0;

before(async () => {
  server = await new Promise((resolve) => { const l = app.listen(31910, '127.0.0.1', () => resolve(l)); });
});

after(async () => {
  console.warn = originalWarn;
  await new Promise((resolve) => server.close(resolve));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function newSession() {
  const response = await fetch(`${origin}/api/session`);
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { cookie, id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

const unlocked = async (client) => (await (await fetch(`${origin}/api/session`, { headers: { Cookie: client.cookie } })).json()).unlocked;

function checkout(client, { livemode, intent }) {
  return {
    id: `cs_${livemode ? 'live' : 'test'}_${++counter}`, object: 'checkout.session', livemode, mode: 'payment',
    status: 'complete', payment_status: 'paid', amount_total: 500, currency: 'usd', client_reference_id: client.id,
    metadata: { app_session_id: client.id }, payment_intent: intent, customer_details: { email: `buyer${counter}@example.com` }
  };
}

async function webhook(type, object, livemode) {
  const payload = JSON.stringify({ id: `evt_mode_${++counter}`, object: 'event', created: Math.floor(Date.now() / 1000),
    livemode, pending_webhooks: 1, type, data: { object } });
  const response = await fetch(`${origin}/api/stripe/webhook`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': signer.webhooks.generateTestHeaderString({ payload, secret: webhookSecret }) },
    body: payload });
  assert.equal(response.status, 200);
}

const purchase = (intent) => db.prepare('SELECT app_session_id, status, stripe_mode FROM stripe_purchases WHERE payment_intent_id = ?').get(intent);

test('test-mode events never unlock, refund or restore on a live server', async () => {
  const tester = await newSession();
  await webhook('checkout.session.completed', checkout(tester, { livemode: false, intent: 'pi_mode_test' }), false);
  assert.equal(await unlocked(tester), false);
  assert.equal(purchase('pi_mode_test'), undefined);
  assert.ok(logs.some((line) => /ignored: test event on a live server/.test(line)));

  // A live envelope cannot smuggle in a test-mode checkout either.
  const smuggler = await newSession();
  await webhook('checkout.session.completed', checkout(smuggler, { livemode: false, intent: 'pi_mode_mixed' }), true);
  assert.equal(await unlocked(smuggler), false);
  assert.equal(purchase('pi_mode_mixed'), undefined);

  // Positive control: a genuine live purchase still unlocks.
  const buyer = await newSession();
  await webhook('checkout.session.completed', checkout(buyer, { livemode: true, intent: 'pi_mode_live' }), true);
  assert.equal(await unlocked(buyer), true);

  // A test-mode refund or dispute for the live purchase changes nothing.
  await webhook('charge.refunded', { object: 'charge', livemode: false, refunded: true, payment_intent: 'pi_mode_live' }, false);
  await webhook('charge.dispute.created', { object: 'dispute', livemode: false, payment_intent: 'pi_mode_live' }, false);
  assert.deepEqual(purchase('pi_mode_live'), { app_session_id: buyer.id, status: 'active', stripe_mode: 'live' });
  assert.equal(await unlocked(buyer), true);

  // The real refund still applies.
  await webhook('charge.refunded', { object: 'charge', livemode: true, refunded: true, payment_intent: 'pi_mode_live' }, true);
  assert.equal(purchase('pi_mode_live').status, 'refunded');
  assert.equal(await unlocked(buyer), false);
});

test('a live server rejects test checkout session ids before asking Stripe', async () => {
  const client = await newSession();
  const response = await fetch(`${origin}/api/checkout/complete`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: client.cookie, Origin: origin },
    body: JSON.stringify({ sessionId: 'cs_test_a1B2c3' }) });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'invalid_checkout_session' });
  assert.equal(await unlocked(client), false);
});

function launchProductionServer(dataDir, port) {
  const child = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, NODE_ENV: 'production', PORT: String(port), DATA_DIR: dataDir,
      SESSION_SECRET: process.env.SESSION_SECRET, PUBLIC_APP_URL: 'https://labels.example.test',
      STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET: webhookSecret } });
  let output = '';
  let settled = false;
  return new Promise((resolve) => {
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ ...result, child, output });
    };
    const onData = (chunk) => {
      output += chunk;
      if (output.includes('listening')) finish({ started: true });
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code, signal) => finish({ started: false, code, signal }));
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      finish({ started: false, timedOut: true });
    }, 5000);
  });
}

async function stopProductionServer(child) {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  await exited;
}

function seedPurchase(dataDir, { intent, sessionId, checkoutSessionId, stripeMode }) {
  const { db: copy } = require('../db').openDatabase(dataDir);
  copy.prepare('INSERT INTO app_sessions (id, unlocked) VALUES (?, 1)').run(sessionId);
  copy.prepare(`
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, checkout_session_id, stripe_mode)
    VALUES (?, ?, 'active', ?, ?)
  `).run(intent, sessionId, checkoutSessionId, stripeMode);
  copy.close();
}

test('production refuses active legacy purchases with a missing Checkout ID and unknown mode', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-live-start-'));
  try {
    seedPurchase(dir, { intent: 'pi_unknown', sessionId: 'legacy-session', checkoutSessionId: null, stripeMode: null });
    const result = await launchProductionServer(dir, 31911);
    assert.equal(result.started, false);
    assert.notEqual(result.code, 0);
    assert.match(result.output, /Production startup blocked: 1 active or disputed purchase\(s\) with unknown Stripe mode/);
    assert.doesNotMatch(result.output, /sk_live_|whsec_/);

    const { db: copy } = require('../db').openDatabase(dir);
    assert.deepEqual(copy.prepare(`
      SELECT p.status, p.stripe_mode, s.unlocked
      FROM stripe_purchases p JOIN app_sessions s ON s.id = p.app_session_id
      WHERE p.payment_intent_id = 'pi_unknown'
    `).get(), { status: 'active', stripe_mode: null, unlocked: 1 });
    copy.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('production refuses active test-mode purchases when Stripe Live is configured', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-live-start-'));
  try {
    seedPurchase(dir, { intent: 'pi_test', sessionId: 'test-session', checkoutSessionId: 'cs_test_verified', stripeMode: 'test' });
    const result = await launchProductionServer(dir, 31911);
    assert.equal(result.started, false);
    assert.notEqual(result.code, 0);
    assert.match(result.output, /Production startup blocked: 1 active or disputed test-mode purchase/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('production starts with a classified live purchase and preserves its entitlement', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-live-start-'));
  try {
    seedPurchase(dir, { intent: 'pi_live', sessionId: 'live-session', checkoutSessionId: 'cs_live_verified', stripeMode: 'live' });
    const result = await launchProductionServer(dir, 31911);
    assert.equal(result.started, true, result.output);
    assert.equal(result.output.includes('Production startup blocked'), false);
    await stopProductionServer(result.child);

    const { db: copy } = require('../db').openDatabase(dir);
    assert.deepEqual(copy.prepare(`
      SELECT p.status, p.stripe_mode, s.unlocked
      FROM stripe_purchases p JOIN app_sessions s ON s.id = p.app_session_id
      WHERE p.payment_intent_id = 'pi_live'
    `).get(), { status: 'active', stripe_mode: 'live', unlocked: 1 });
    copy.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
