'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-test-'));
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'https://labels.example.test';
process.env.DATA_DIR = dataDir;
delete process.env.STRIPE_SECRET_KEY;
delete process.env.STRIPE_WEBHOOK_SECRET;

const { app, db } = require('../server');
let server;
const local = 'http://127.0.0.1:31879';

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31879, '127.0.0.1', () => resolve(listener));
  });
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('HTTPS deployments send HSTS and Secure session cookies', async () => {
  const response = await fetch(`${local}/api/session`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('strict-transport-security'), 'max-age=15552000');
  assert.match(response.headers.get('set-cookie'), /; Secure$/);
  assert.equal((await response.json()).unlocked, false);

  const wrongOrigin = await fetch(`${local}/api/labels/reserve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: local },
    body: JSON.stringify({ count: 1 })
  });
  assert.equal(wrongOrigin.status, 403);
});
