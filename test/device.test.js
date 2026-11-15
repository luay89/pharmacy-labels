'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-device-'));
const webhookSecret = 'whsec_test_secret';
process.env.SESSION_SECRET = 'test-secret-with-at-least-32-characters';
process.env.PUBLIC_APP_URL = 'http://127.0.0.1:31883';
process.env.DATA_DIR = dataDir;
process.env.STRIPE_SECRET_KEY = 'sk_test_123456789';
process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
process.env.TRUST_PROXY = '1';
delete process.env.SMTP_HOST;
const signingKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
process.env.LICENSE_SIGNING_KEY = signingKey.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
process.env.LICENSE_SIGNING_KID = 'test-license-key';

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
const { createDeviceKeys, PROOF_PREFIX } = require('../device-key');
const { verifyCertificate, TRIAL_MS } = require('../license-cert');
const { subtle } = globalThis.crypto;
const origin = process.env.PUBLIC_APP_URL;
const sent = [];
mailer.configured = true;
mailer.send = async (message) => { sent.push(message); };
const realNow = clock.now;
const secrets = [];
const requestBodies = [];
let server;
let ipCounter = 0;
let emailCounter = 0;

before(async () => {
  server = await new Promise((resolve) => {
    const listener = app.listen(31883, '127.0.0.1', () => resolve(listener));
  });
});

after(async () => {
  Object.assign(console, originalConsole);
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Just enough of IndexedDB for device-key.js: one store, get and add, with add refusing an existing key.
function fakeIndexedDB() {
  const databases = new Map();
  const tick = (fn) => setTimeout(fn, 0);
  return {
    open(name) {
      const request = {};
      tick(() => {
        let stores = databases.get(name);
        const isNew = !stores;
        if (isNew) databases.set(name, stores = new Map());
        request.result = {
          createObjectStore: (storeName) => stores.set(storeName, new Map()),
          close() {},
          transaction(storeName, mode) {
            const tx = {};
            const store = stores.get(storeName);
            const operation = (run) => {
              const op = {};
              tick(() => {
                try {
                  op.result = run();
                  op.onsuccess();
                  tick(() => tx.oncomplete());
                } catch (error) {
                  op.error = tx.error = error;
                  op.onerror();
                  tick(() => tx.onabort());
                }
              });
              return op;
            };
            tx.objectStore = () => ({
              get: (key) => operation(() => store.get(key)),
              add: (value, key) => operation(() => {
                if (mode !== 'readwrite') throw new Error('ReadOnlyError');
                if (store.has(key)) throw Object.assign(new Error('Key already exists.'), { name: 'ConstraintError' });
                store.set(key, value);
                return key;
              }),
              put: (value, key) => operation(() => { if (mode !== 'readwrite') throw new Error('ReadOnlyError'); store.set(key, value); return key; })
            });
            return tx;
          }
        };
        if (isNew) request.onupgradeneeded();
        request.onsuccess();
      });
      return request;
    }
  };
}

async function newClient() {
  const ip = `198.18.0.${++ipCounter}`;
  const response = await fetch(`${origin}/api/session`, { headers: { 'X-Forwarded-For': ip } });
  const cookie = response.headers.get('set-cookie').split(';')[0];
  return { ip, cookie, account: '', id: decodeURIComponent(cookie.split('=')[1]).split('.')[0] };
}

// A fetch that behaves like this client's browser: same cookies, same origin, same address.
function browserFetch(client) {
  return async (pathname, init = {}) => {
    if (init.body) requestBodies.push(init.body);
    const response = await fetch(`${origin}${pathname}`, {
      ...init,
      headers: {
        ...init.headers,
        Cookie: [client.cookie, client.account].filter(Boolean).join('; '),
        Origin: origin,
        'X-Forwarded-For': client.ip
      }
    });
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';');
      if (pair.startsWith('product_labels_account=')) {
        client.account = /Max-Age=0/.test(header) ? '' : pair;
        if (client.account) secrets.push(pair.split('=')[1]);
      }
    }
    return response;
  };
}

async function api(client, method, pathname, body) {
  const response = await browserFetch(client)(pathname, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
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

async function signIn(client, email) {
  const before = sent.filter((message) => message.to === email).length;
  assert.equal((await api(client, 'POST', '/api/email-verification/request', { email })).status, 202);
  const code = (await waitForMail(email, before + 1)).text.match(/verification code is: (\d{8})/)[1];
  secrets.push(code);
  const response = await api(client, 'POST', '/api/account/signup', { email, code });
  assert.ok([200, 201].includes(response.status), JSON.stringify(response.body));
  return client;
}

async function signedInClient(email = `user${++emailCounter}@example.com`) {
  const client = await signIn(await newClient(), email);
  client.email = email;
  client.keys = createDeviceKeys({ subtle, indexedDB: fakeIndexedDB(), fetch: browserFetch(client) });
  return client;
}

// A key the test controls directly, to sign whatever it wants (as an attacker would).
async function rawKey() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey);
  return { pair, jwk: { kty, crv, x, y } };
}

async function signWith(privateKey, message) {
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(message));
  return Buffer.from(signature).toString('base64url');
}

const challengeFor = (client, purpose, publicKey) => api(client, 'POST', '/api/devices/challenge', { purpose, publicKey });
const submit = (client, pathname, publicKey, challenge, signature) => api(client, 'POST', pathname, { publicKey, challenge, signature });

async function manualRegister(client, key) {
  const issued = await challengeFor(client, 'register', key.jwk);
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  return { challenge: issued.body.challenge, signature: await signWith(key.pair.privateKey, PROOF_PREFIX + issued.body.challenge) };
}

function withClock(offsetMs, fn) {
  clock.now = () => realNow() + offsetMs;
  return Promise.resolve().then(fn).finally(() => { clock.now = realNow; });
}

const count = (table) => db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
const accountOf = (client) => db.prepare(
  'SELECT account_id FROM account_sessions WHERE app_session_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1'
).get(client.id).account_id;
const devicesOf = (accountId) => db.prepare('SELECT * FROM devices WHERE account_id = ? ORDER BY registered_at').all(accountId);
const decodeChallenge = (challenge) => JSON.parse(Buffer.from(challenge.split('.')[0], 'base64url').toString('utf8'));

test('a signed-in browser registers a non-extractable key; only the public key and a signature are sent', async () => {
  const client = await signedInClient();
  const response = await client.keys.register();
  assert.equal(response.status, 201, JSON.stringify(response.body));
  const thumbprint = await client.keys.thumbprint();
  assert.equal(response.body.registered, true);
  assert.equal(response.body.keyThumbprint, thumbprint, 'server and browser compute the same RFC 7638 thumbprint');

  const [device] = devicesOf(accountOf(client));
  assert.equal(device.key_thumbprint, thumbprint);
  assert.deepEqual(JSON.parse(device.public_key_jwk), await client.keys.publicJwk());
  assert.deepEqual(Object.keys(JSON.parse(device.public_key_jwk)).sort(), ['crv', 'kty', 'x', 'y']);
  assert.equal(device.revoked_at, null);
  assert.equal(device.last_validated_at, device.registered_at, 'registration itself is a proof of possession');
  assert.deepEqual((await api(client, 'GET', '/api/devices')).body,
    { device: { keyThumbprint: thumbprint, registeredAt: device.registered_at, lastValidatedAt: device.registered_at } });

  const { privateKey } = await client.keys.keyPair();
  assert.equal(privateKey.extractable, false);
  await assert.rejects(subtle.exportKey('jwk', privateKey));
  await assert.rejects(subtle.exportKey('pkcs8', privateKey));
  for (const body of requestBodies) {
    const parsed = JSON.parse(body);
    assert.ok(!parsed.publicKey || !Object.hasOwn(parsed.publicKey, 'd'), 'no private key component is ever sent');
    assert.ok(Object.keys(parsed).every((field) => ['email', 'code', 'purpose', 'publicKey', 'challenge', 'signature'].includes(field)));
  }
  const audit = db.prepare("SELECT outcome, device_id, ip_hash FROM audit_events WHERE event = 'device_register' AND account_id = ?").all(accountOf(client));
  assert.deepEqual(audit.map((row) => [row.outcome, row.device_id]), [['ok', device.id]]);
});

test('the key persists: the same store gives the same key, and two racing creators agree on one', async () => {
  const indexedDB = fakeIndexedDB();
  const peek = createDeviceKeys({ subtle, indexedDB, fetch: () => assert.fail('no network') });
  assert.equal(await peek.storedThumbprint(), null, 'looking does not create a key');
  assert.equal(await peek.storedThumbprint(), null);
  const first = createDeviceKeys({ subtle, indexedDB, fetch: () => assert.fail('no network') });
  const second = createDeviceKeys({ subtle, indexedDB, fetch: () => assert.fail('no network') });
  const [a, b] = await Promise.all([first.thumbprint(), second.thumbprint()]);
  assert.equal(a, b, 'the losing creator adopts the stored key instead of replacing it');
  const later = createDeviceKeys({ subtle, indexedDB, fetch: () => assert.fail('no network') });
  assert.equal(await later.storedThumbprint(), a);
  assert.equal(await later.thumbprint(), a);
  const licenseState = { certificate: 'signed-certificate', type: 'trial', lastObservedAt: 123 };
  await later.saveLicenseState(licenseState);
  assert.deepEqual(await createDeviceKeys({ subtle, indexedDB, fetch: () => assert.fail('no network') }).readLicenseState(), licenseState);
  assert.notEqual(await createDeviceKeys({ subtle, indexedDB: fakeIndexedDB() }).thumbprint(), a, 'another profile, another key');
});

test('a registered device proves possession again with a fresh challenge', async () => {
  const client = await signedInClient();
  assert.equal((await client.keys.register()).status, 201);
  const registeredAt = devicesOf(accountOf(client))[0].last_validated_at;
  await withClock(5000, async () => {
    const proof = await client.keys.verify();
    assert.equal(proof.status, 200, JSON.stringify(proof.body));
    assert.deepEqual(proof.body, { verified: true, keyThumbprint: await client.keys.thumbprint(), lastValidatedAt: proof.body.lastValidatedAt });
  });
  assert.ok(devicesOf(accountOf(client))[0].last_validated_at > registeredAt);
  const again = await client.keys.register();
  assert.deepEqual([again.status, again.body], [409, { error: 'already_registered' }]);
});

test('every device route requires a signed-in account; the anonymous cookie is not enough', async () => {
  const anonymous = await newClient();
  const key = await rawKey();
  const devices = await count('devices');
  assert.deepEqual((await api(anonymous, 'GET', '/api/devices')).body, { error: 'not_authenticated' });
  for (const [pathname, body] of [['/api/devices/challenge', { purpose: 'register', publicKey: key.jwk }],
    ['/api/devices/register', { publicKey: key.jwk, challenge: 'x.y', signature: 'z' }],
    ['/api/devices/verify', { publicKey: key.jwk, challenge: 'x.y', signature: 'z' }]]) {
    const response = await api(anonymous, 'POST', pathname, body);
    assert.deepEqual([response.status, response.body], [401, { error: 'not_authenticated' }], pathname);
  }
  // A challenge obtained while signed in is useless after logout.
  const client = await signedInClient();
  const { challenge, signature } = await manualRegister(client, key);
  await api(client, 'POST', '/api/account/logout', {});
  assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 401);
  assert.equal(await count('devices'), devices);
});

test('wrong, tampered or misdirected signatures create no device', async () => {
  const client = await signedInClient();
  const key = await rawKey();
  const other = await rawKey();
  const devices = await count('devices');
  const { challenge, signature } = await manualRegister(client, key);
  const flipped = Buffer.from(signature, 'base64url');
  flipped[10] ^= 1;
  const cases = {
    'signed by another key': await signWith(other.pair.privateKey, PROOF_PREFIX + challenge),
    'tampered signature': flipped.toString('base64url'),
    'signature without the domain prefix': await signWith(key.pair.privateKey, challenge),
    'signature over another message': await signWith(key.pair.privateKey, `${PROOF_PREFIX}${challenge}x`),
    'DER instead of raw': Buffer.concat([Buffer.from([0x30, 0x44]), Buffer.from(signature, 'base64url')]).toString('base64url'),
    'truncated': signature.slice(0, 80),
    'empty': '',
    'not a string': 12345
  };
  for (const [name, bad] of Object.entries(cases)) {
    const response = await submit(client, '/api/devices/register', key.jwk, challenge, bad);
    assert.deepEqual([response.status, response.body], [403, { error: 'proof_failed' }], name);
  }
  // Swapping in the other public key with the right signature fails too: the challenge names the key.
  assert.equal((await submit(client, '/api/devices/register', other.jwk, challenge, signature)).status, 403);
  // And a key cannot ride on a challenge issued for another key, even when it signs it itself.
  assert.equal((await submit(client, '/api/devices/register', other.jwk, challenge,
    await signWith(other.pair.privateKey, PROOF_PREFIX + challenge))).status, 403, 'challenge issued for another key');
  assert.equal(await count('devices'), devices);
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'device_register' AND outcome = 'proof_failed' AND account_id = ?")
    .get(accountOf(client)).n >= Object.keys(cases).length);
  assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 201, 'the genuine proof still works');
});

test('challenges are bound to the server key, purpose, account, browser and device', async () => {
  const alice = await signedInClient();
  const mallory = await signedInClient();
  const key = await rawKey();
  const devices = await count('devices');
  const { challenge } = await manualRegister(mallory, key);
  const sign = (text) => signWith(key.pair.privateKey, PROOF_PREFIX + text);

  // Forged claims: re-encoding the payload breaks the server's MAC.
  const claims = decodeChallenge(challenge);
  const forged = `${Buffer.from(JSON.stringify({ ...claims, acc: accountOf(alice) })).toString('base64url')}.${challenge.split('.')[1]}`;
  assert.equal((await submit(alice, '/api/devices/register', key.jwk, forged, await sign(forged))).status, 403, 'forged account');
  for (const broken of ['', 'abc', `${challenge}.extra`, challenge.replace('.', ''), 'x'.repeat(2000)]) {
    assert.equal((await submit(mallory, '/api/devices/register', key.jwk, broken, await sign(broken))).status, 403, broken.slice(0, 20));
  }
  // Claims copied from a genuine challenge with only the expiry stretched: the MAC no longer matches.
  const stale = (await challengeFor(alice, 'register', key.jwk)).body.challenge;
  await withClock(3 * 60 * 1000, async () => {
    const stretched = `${Buffer.from(JSON.stringify({ ...decodeChallenge(stale), exp: realNow() + 3600 * 1000 }))
      .toString('base64url')}.${stale.split('.')[1]}`;
    assert.equal((await submit(alice, '/api/devices/register', key.jwk, stretched, await sign(stretched))).status, 403, 'stretched expiry');
  });
  // Mallory's genuine challenge, signed by the right key, used from Alice's account.
  assert.equal((await submit(alice, '/api/devices/register', key.jwk, challenge, await sign(challenge))).status, 403, 'other account');
  // The same account signed in from a second browser cannot use a challenge issued to the first.
  // (One minute later, past the code resend cooldown and still inside the challenge lifetime.)
  await withClock(61 * 1000, async () => {
    const secondBrowser = await signIn(await newClient(), mallory.email);
    assert.equal(accountOf(secondBrowser), accountOf(mallory));
    assert.equal((await submit(secondBrowser, '/api/devices/register', key.jwk, challenge, await sign(challenge))).status, 403, 'other browser');
  });
  // A register challenge cannot be used to prove an existing device, and the reverse.
  assert.equal((await submit(mallory, '/api/devices/verify', key.jwk, challenge, await sign(challenge))).status, 403, 'wrong purpose');
  assert.equal(await count('devices'), devices);

  assert.equal((await submit(mallory, '/api/devices/register', key.jwk, challenge, await sign(challenge))).status, 201);
  const prove = await withClock(1000, () => challengeFor(mallory, 'prove', key.jwk));
  assert.equal(prove.status, 200);
  const proveChallenge = prove.body.challenge;
  assert.equal(decodeChallenge(proveChallenge).dev, devicesOf(accountOf(mallory))[0].id);
  assert.match(decodeChallenge(proveChallenge).ses, /^[0-9a-f]{32}$/, 'the session id itself never appears');
  assert.ok(!proveChallenge.includes(mallory.id));
  await withClock(1000, async () => {
    assert.equal((await submit(mallory, '/api/devices/register', key.jwk, proveChallenge, await sign(proveChallenge))).status, 403);
    assert.equal((await submit(alice, '/api/devices/verify', key.jwk, proveChallenge, await sign(proveChallenge))).status, 403, 'other account');
  });
});

test('a challenge issued to one account is refused after another account signs in on the same browser', async () => {
  const shared = await signedInClient();
  const key = await rawKey();
  const { challenge, signature } = await manualRegister(shared, key);
  const firstAccount = accountOf(shared);
  await api(shared, 'POST', '/api/account/logout', {});
  await signIn(shared, `second-${shared.email}`);
  assert.notEqual(accountOf(shared), firstAccount);
  assert.deepEqual((await submit(shared, '/api/devices/register', key.jwk, challenge, signature)).body, { error: 'proof_failed' });
  assert.equal(devicesOf(accountOf(shared)).length + devicesOf(firstAccount).length, 0);
});

test('expired challenges are refused and leave no device', async () => {
  const client = await signedInClient();
  const key = await rawKey();
  const { challenge, signature } = await manualRegister(client, key);
  await withClock(2 * 60 * 1000, async () => {
    assert.deepEqual((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).body, { error: 'proof_failed' });
  });
  assert.equal(devicesOf(accountOf(client)).length, 0);
  // A challenge stamped in the future (server clock moved back) is refused as well.
  await withClock(-60 * 1000, async () => {
    assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 403);
  });
});

test('challenges are single use: replays and older challenges fail after a successful proof', async () => {
  const client = await signedInClient();
  const key = await rawKey();
  const registration = await manualRegister(client, key);
  assert.equal((await submit(client, '/api/devices/register', key.jwk, registration.challenge, registration.signature)).status, 201);
  const replayed = await submit(client, '/api/devices/register', key.jwk, registration.challenge, registration.signature);
  assert.equal(replayed.status, 409, 'the key is registered once, ever, so the register challenge cannot succeed again');
  assert.equal(devicesOf(accountOf(client)).length, 1);

  const older = await withClock(1000, () => challengeFor(client, 'prove', key.jwk));
  const newer = await withClock(2000, () => challengeFor(client, 'prove', key.jwk));
  const sign = (text) => signWith(key.pair.privateKey, PROOF_PREFIX + text);
  await withClock(3000, async () => {
    assert.equal((await submit(client, '/api/devices/verify', key.jwk, newer.body.challenge, await sign(newer.body.challenge))).status, 200);
    assert.equal((await submit(client, '/api/devices/verify', key.jwk, newer.body.challenge, await sign(newer.body.challenge))).status, 403, 'replay');
    assert.equal((await submit(client, '/api/devices/verify', key.jwk, older.body.challenge, await sign(older.body.challenge))).status, 403, 'older');
  });
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'device_verify' AND outcome = 'challenge_used'").get().n >= 2);

  // Concurrent uses of one fresh challenge: exactly one succeeds.
  const fresh = await withClock(4000, () => challengeFor(client, 'prove', key.jwk));
  const signature = await sign(fresh.body.challenge);
  const results = await withClock(5000, () => Promise.all(Array.from({ length: 6 },
    () => submit(client, '/api/devices/verify', key.jwk, fresh.body.challenge, signature))));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  assert.ok(results.filter((r) => r.status !== 200).every((r) => r.status === 403));
});

test('one active device per account, also under concurrent registrations', async () => {
  const client = await signedInClient();
  const first = await rawKey();
  const second = await rawKey();
  const proofs = [await manualRegister(client, first), await manualRegister(client, second)];
  const results = await Promise.all([
    submit(client, '/api/devices/register', first.jwk, proofs[0].challenge, proofs[0].signature),
    submit(client, '/api/devices/register', second.jwk, proofs[1].challenge, proofs[1].signature)
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [201, 409]);
  assert.deepEqual(results.find((r) => r.status === 409).body, { error: 'device_limit_reached' });
  assert.equal(devicesOf(accountOf(client)).filter((d) => d.revoked_at === null).length, 1);

  const third = await rawKey();
  const refused = await challengeFor(client, 'register', third.jwk);
  assert.deepEqual([refused.status, refused.body], [409, { error: 'device_limit_reached' }]);
  // The database refuses a second active device even if application checks were bypassed.
  assert.throws(() => db.prepare('INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at) VALUES (?, ?, ?, ?, ?)')
    .run('bypass', accountOf(client), 'bypass-thumbprint', '{}', realNow()), /UNIQUE constraint failed: devices.account_id/);
  // No reset or recovery route exists.
  for (const pathname of ['/api/devices/reset', '/api/devices/recover', '/api/devices/revoke']) {
    assert.equal((await api(client, 'POST', pathname, {})).status, 404, pathname);
  }
});

test('a key cannot be registered to a second account, nor proved from it', async () => {
  const owner = await signedInClient();
  assert.equal((await owner.keys.register()).status, 201);
  const other = await signedInClient();
  const sharedKeys = { ...owner.keys };
  const publicKey = await sharedKeys.publicJwk();
  assert.deepEqual((await challengeFor(other, 'register', publicKey)).body, { error: 'key_unavailable' });
  assert.deepEqual((await challengeFor(other, 'prove', publicKey)).body, { error: 'device_not_registered' });
});

test('a failed transaction creates no device and records nothing', async () => {
  const client = await signedInClient();
  const key = await rawKey();
  const before = { devices: await count('devices'), audits: await count('audit_events') };
  for (const table of ['devices', 'audit_events']) {
    const { challenge, signature } = await manualRegister(client, key);
    db.exec(`CREATE TEMP TRIGGER fail_${table} BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'simulated failure'); END`);
    try {
      const failed = await submit(client, '/api/devices/register', key.jwk, challenge, signature);
      assert.deepEqual([failed.status, failed.body], [500, { error: 'internal_server_error' }]);
    } finally {
      db.exec(`DROP TRIGGER fail_${table}`);
    }
    assert.deepEqual({ devices: await count('devices'), audits: await count('audit_events') }, before, table);
  }
  const { challenge, signature } = await manualRegister(client, key);
  assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 201);
});

test('malformed public keys and purposes are rejected', async () => {
  const client = await signedInClient();
  const { jwk } = await rawKey();
  const p384 = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  const p384Jwk = await subtle.exportKey('jwk', p384.publicKey);
  const withPrivate = await subtle.exportKey('jwk', (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])).privateKey);
  for (const [name, publicKey] of Object.entries({
    missing: undefined, array: [jwk], string: JSON.stringify(jwk), 'with private d': withPrivate, 'P-384': p384Jwk,
    'RSA type': { ...jwk, kty: 'RSA' }, 'short x': { ...jwk, x: jwk.x.slice(1) }, 'padded y': { ...jwk, y: `${jwk.y}=` },
    'off curve': { ...jwk, y: jwk.x }
  })) {
    const response = await challengeFor(client, 'register', publicKey);
    assert.deepEqual([response.status, response.body], [400, { error: 'invalid_public_key' }], name);
  }
  for (const purpose of [undefined, 'Register', 'license', 'transfer']) {
    assert.deepEqual((await challengeFor(client, purpose, jwk)).body, { error: 'invalid_purpose' }, String(purpose));
  }
  assert.equal(devicesOf(accountOf(client)).length, 0);
});

test('suspended accounts and revoked devices cannot register or prove', async () => {
  const client = await signedInClient();
  const key = await rawKey();
  const { challenge, signature } = await manualRegister(client, key);
  const accountId = accountOf(client);
  db.prepare("UPDATE accounts SET status = 'suspended' WHERE id = ?").run(accountId);
  try {
    assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 401);
  } finally {
    db.prepare("UPDATE accounts SET status = 'active' WHERE id = ?").run(accountId);
  }
  assert.equal((await submit(client, '/api/devices/register', key.jwk, challenge, signature)).status, 201);
  const prove = await withClock(1000, () => challengeFor(client, 'prove', key.jwk));
  db.prepare("UPDATE devices SET revoked_at = ?, revoke_reason = 'test' WHERE account_id = ?").run(realNow(), accountId);
  await withClock(2000, async () => {
    const proof = await submit(client, '/api/devices/verify', key.jwk, prove.body.challenge,
      await signWith(key.pair.privateKey, PROOF_PREFIX + prove.body.challenge));
    assert.equal(proof.status, 403);
    assert.deepEqual((await challengeFor(client, 'prove', key.jwk)).body, { error: 'device_not_registered' });
    assert.deepEqual((await challengeFor(client, 'register', key.jwk)).body, { error: 'key_unavailable' }, 'a revoked key is never reused');
  });
});

test('device registration grants no license, trial or certificate and leaves legacy purchases alone', async () => {
  const email = 'legacy-device@example.com';
  const buyer = await newClient();
  const payload = JSON.stringify({
    id: 'evt_test_legacy_device',
    object: 'event',
    created: Math.floor(realNow() / 1000),
    data: {
      object: {
        id: 'cs_test_legacy_device', object: 'checkout.session', livemode: false, mode: 'payment', status: 'complete',
        payment_status: 'paid', amount_total: 500, currency: 'usd', client_reference_id: buyer.id,
        metadata: { app_session_id: buyer.id }, payment_intent: 'pi_test_legacy_device', customer_details: { email }
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
    FROM stripe_purchases WHERE payment_intent_id = 'pi_test_legacy_device'`).get() });
  const original = purchase();
  const tables = ['trials', 'license_certificates', 'stripe_purchases', 'license_transfers'];
  const before = Object.fromEntries(tables.map((table) => [table, count(table)]));

  await signIn(buyer, email);
  buyer.keys = createDeviceKeys({ subtle, indexedDB: fakeIndexedDB(), fetch: browserFetch(buyer) });
  assert.equal((await buyer.keys.register()).status, 201);
  await withClock(1000, async () => assert.equal((await buyer.keys.verify()).status, 200));

  assert.deepEqual(purchase(), original);
  assert.equal(original.license_policy, 'legacy');
  assert.deepEqual(Object.fromEntries(tables.map((table) => [table, count(table)])), before);
  assert.equal((await api(buyer, 'GET', '/api/session')).body.unlocked, true, 'the legacy cookie license still works');
  assert.deepEqual({ ...db.prepare('SELECT unlocked, account_id, device_id FROM app_sessions WHERE id = ?').get(buyer.id) },
    { unlocked: 1, account_id: null, device_id: null });

  const fresh = await signedInClient();
  assert.equal((await fresh.keys.register()).status, 201);
  assert.deepEqual((await api(fresh, 'GET', '/api/session')).body, { printedCount: 0, freeLimit: 20, unlocked: false });
  assert.equal((await api(fresh, 'GET', '/api/license')).body.licensed, false);
});

test('fresh device proof issues a signed 48-hour trial without extending it on renewal', async () => {
  const client = await signedInClient();
  assert.equal((await client.keys.register()).status, 201);
  const thumbprint = await client.keys.thumbprint();
  const first = await client.keys.certificate();
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.type, 'trial');
  const trial = db.prepare('SELECT * FROM trials WHERE account_id = ?').get(accountOf(client));
  assert.equal(trial.device_thumbprint, thumbprint);
  assert.equal(trial.expires_at - trial.started_at, TRIAL_MS);
  const publicJwk = crypto.createPublicKey(signingKey.privateKey).export({ format: 'jwk' });
  const checked = verifyCertificate(first.body.certificate, {
    keys: { 'test-license-key': publicJwk }, now: realNow(), expectedType: 'trial', expectedDevice: thumbprint
  });
  assert.equal(checked.state, 'active');
  assert.equal(checked.claims.exp, trial.expires_at);

  const renewal = await withClock(1000, () => client.keys.certificate());
  assert.equal(renewal.status, 200, JSON.stringify(renewal.body));
  assert.equal(verifyCertificate(renewal.body.certificate, {
    keys: { 'test-license-key': publicJwk }, now: realNow(), expectedType: 'trial', expectedDevice: thumbprint
  }).claims.exp, trial.expires_at, 'renewal never moves the original trial deadline');
  assert.equal(count('trials'), 1);
  assert.equal(count('license_certificates'), 2);
  const keys = await fetch(`${origin}/api/license/keys`, { headers: { Cookie: [client.cookie, client.account].join('; ') } });
  assert.deepEqual(await keys.json(), { keys: { 'test-license-key': publicJwk } });
});

test('the browser script is served and logs never contain codes, tokens, challenges or signatures', async () => {
  const script = await fetch(`${origin}/device-key.js`);
  assert.equal(script.status, 200);
  assert.match(script.headers.get('content-type'), /javascript/);
  assert.match(await script.text(), /createDeviceKeys/);

  for (const body of requestBodies) {
    const parsed = JSON.parse(body);
    if (parsed.challenge) secrets.push(parsed.challenge);
    if (typeof parsed.signature === 'string' && parsed.signature.length > 40) secrets.push(parsed.signature);
  }
  assert.ok(secrets.length >= 20);
  const joined = logs.join('\n');
  for (const secret of secrets) assert.ok(!joined.includes(secret), 'secret leaked to logs');
  assert.doesNotMatch(joined, /sk_test_|whsec_|test-secret-with|"d":/);
  assert.equal(transportsCreated, 0);
});
