'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-test-'));
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31878';
process.env.DATA_DIR = dataDir;
delete process.env.STRIPE_SECRET_KEY;
delete process.env.STRIPE_WEBHOOK_SECRET;

const { app, db, stripe } = require('../server');
let server;
const origin = process.env.PUBLIC_APP_URL;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31878, '127.0.0.1', () => resolve(listener));
  });
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('payment routes fail closed when Stripe keys are missing', async () => {
  assert.equal(stripe, null);
  const sessionResponse = await fetch(`${origin}/api/session`);
  const cookie = sessionResponse.headers.get('set-cookie').split(';')[0];
  assert.equal((await sessionResponse.json()).unlocked, false);
  const post = (pathname, body) => fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: origin },
    body: JSON.stringify(body)
  });

  const checkout = await post('/api/checkout', {});
  assert.equal(checkout.status, 503);
  assert.equal((await checkout.json()).error, 'stripe_not_configured');

  const complete = await post('/api/checkout/complete', { sessionId: 'cs_test_abc123' });
  assert.equal(complete.status, 503);

  const webhook = await fetch(`${origin}/api/stripe/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': 't=1,v1=fake' },
    body: JSON.stringify({ id: 'evt_x', type: 'checkout.session.completed' })
  });
  assert.equal(webhook.status, 503);

  const after = await fetch(`${origin}/api/session`, { headers: { Cookie: cookie } });
  assert.equal((await after.json()).unlocked, false);
});
