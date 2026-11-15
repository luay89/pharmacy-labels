'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const {
  createSigner, verifyCertificate, readSigningConfig, jwkThumbprint,
  TRIAL_MS, REVALIDATE_MS, GRACE_MS, DEFAULT_CLOCK_SKEW_MS
} = require('../license-cert');

// Throwaway keys generated per run; nothing here is a real signing key.
function p256Pem() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
}
function deviceThumbprint() {
  return jwkThumbprint(crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }));
}

const NOW = Date.UTC(2026, 9, 30, 12, 0, 0);
const ACCOUNT = 'acc_0123456789abcdef';
const pem = p256Pem();
const signer = createSigner({ privateKeyPem: pem, kid: 'k2026a' });
const keys = { k2026a: signer.publicJwk };
const DEVICE = deviceThumbprint();
const OTHER_DEVICE = deviceThumbprint();

function verify(token, overrides = {}) {
  return verifyCertificate(token, { keys, now: NOW, expectedType: 'trial', expectedDevice: DEVICE, ...overrides });
}
function trial(overrides = {}) {
  return signer.issueTrial({ accountId: ACCOUNT, deviceThumbprint: DEVICE, now: NOW, trialExpiresAt: NOW + TRIAL_MS, ...overrides });
}
function paid() {
  return signer.issuePaid({ accountId: ACCOUNT, deviceThumbprint: DEVICE, now: NOW });
}
// Signs arbitrary payload text with the test key, to reach the checks that run after the signature.
function signRaw(text, key = pem) {
  const payload = Buffer.from(text);
  const signature = crypto.sign('sha256', payload, { key, dsaEncoding: 'ieee-p1363' });
  return `${payload.toString('base64url')}.${signature.toString('base64url')}`;
}
function decode(token) {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

test('a trial certificate verifies, carries only the minimum claims and ends exactly at exp', () => {
  const { token, claims } = trial();
  assert.deepEqual(Object.keys(decode(token)), ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'exp']);
  assert.deepEqual(decode(token), { ...claims });
  assert.equal(claims.v, 1);
  assert.equal(claims.exp - claims.iat, TRIAL_MS);
  assert.match(claims.jti, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(trial().claims.jti, claims.jti, 'every certificate has its own id');

  assert.deepEqual(verify(token), { ok: true, state: 'active', usable: true, claims: { ...claims } });
  assert.equal(verify(token, { now: claims.exp - 1 }).state, 'active');
  assert.deepEqual(verify(token, { now: claims.exp }), { ok: true, state: 'expired', usable: false, claims: { ...claims } },
    'expiry is exclusive and an expired certificate stays authentic for read-only use');
  assert.equal(verify(token, { now: claims.exp + 365 * 24 * 3600_000 }).state, 'expired');

  // A re-issued trial certificate keeps the stored end time instead of granting a fresh 48 hours.
  const later = trial({ now: NOW + TRIAL_MS / 2 });
  assert.equal(later.claims.exp, NOW + TRIAL_MS);
});

test('a paid certificate is active for 30 days, then in grace for exactly 14 days, then expired', () => {
  const { token, claims } = paid();
  assert.deepEqual(Object.keys(decode(token)), ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'rva', 'grc']);
  assert.equal(claims.rva, NOW + REVALIDATE_MS);
  assert.equal(claims.grc, claims.rva + GRACE_MS);
  assert.equal(REVALIDATE_MS, 30 * 24 * 3600_000);
  assert.equal(GRACE_MS, 14 * 24 * 3600_000);

  const at = (now) => verify(token, { now, expectedType: 'paid' });
  assert.deepEqual([at(NOW).state, at(claims.rva - 1).state], ['active', 'active']);
  assert.deepEqual([at(claims.rva).state, at(claims.rva).usable], ['grace', true]);
  assert.equal(at(claims.grc - 1).state, 'grace');
  assert.deepEqual([at(claims.grc).ok, at(claims.grc).state, at(claims.grc).usable], [true, 'expired', false]);
});

test('signature tampering, payload tampering and the wrong public key are rejected', () => {
  const { token } = trial();
  const [payload, signature] = token.split('.');
  const sig = Buffer.from(signature, 'base64url');

  for (let i = 0; i < sig.length; i += 9) {
    const flipped = Buffer.from(sig);
    flipped[i] ^= 0x01;
    assert.equal(verify(`${payload}.${flipped.toString('base64url')}`).error, 'bad_signature', `byte ${i}`);
  }
  assert.equal(verify(`${payload}.${sig.subarray(0, 63).toString('base64url')}`).error, 'bad_signature');
  assert.equal(verify(`${payload}.${Buffer.concat([sig, Buffer.alloc(1)]).toString('base64url')}`).error, 'bad_signature');

  const claims = decode(token);
  for (const change of [{ dev: OTHER_DEVICE }, { exp: claims.exp + 1 }, { acc: 'acc_attacker_00000000' }, { typ: 'paid' }]) {
    const forged = Buffer.from(JSON.stringify({ ...claims, ...change })).toString('base64url');
    assert.equal(verify(`${forged}.${signature}`).error, 'bad_signature', JSON.stringify(change));
  }

  const stranger = createSigner({ privateKeyPem: p256Pem(), kid: 'k2026a' });
  assert.equal(verify(token, { keys: { k2026a: stranger.publicJwk } }).error, 'bad_signature');
  assert.equal(verify(stranger.issueTrial({ accountId: ACCOUNT, deviceThumbprint: DEVICE, now: NOW, trialExpiresAt: NOW + 1000 }).token)
    .error, 'bad_signature', 'a certificate from another key with a reused kid is not accepted');
});

test('the certificate is bound to the expected device and type', () => {
  assert.deepEqual(verify(trial().token, { expectedDevice: OTHER_DEVICE }), { ok: false, error: 'wrong_device' });
  assert.deepEqual(verify(trial().token, { expectedType: 'paid' }), { ok: false, error: 'wrong_type' });
  assert.deepEqual(verify(paid().token), { ok: false, error: 'wrong_type' });
});

test('certificates issued in the future are not yet valid beyond the allowed clock skew', () => {
  const { token, claims } = trial();
  assert.equal(verify(token, { now: claims.iat - DEFAULT_CLOCK_SKEW_MS }).state, 'active');
  assert.deepEqual(verify(token, { now: claims.iat - DEFAULT_CLOCK_SKEW_MS - 1 }), { ok: false, error: 'not_yet_valid' });
  assert.deepEqual(verify(token, { now: claims.iat - 1, clockSkewMs: 0 }), { ok: false, error: 'not_yet_valid' });
});

test('malformed tokens are rejected without throwing', () => {
  const { token } = trial();
  const [payload, signature] = token.split('.');
  for (const bad of [
    undefined, null, 42, {}, '', '.', token + '.x', payload, `${payload}.`, `.${signature}`,
    `${payload}=.${signature}`, `${payload}.${signature}=`, `${payload}+.${signature}`, `${payload} .${signature}`,
    'a'.repeat(3000) + '.' + signature
  ]) {
    assert.deepEqual(verify(bad), { ok: false, error: 'malformed' }, String(bad).slice(0, 40));
  }
  // Non-canonical base64url (unused trailing bits set) decodes leniently in Node, so it is refused explicitly.
  const lenient = payload.slice(0, -1) + String.fromCharCode(payload.charCodeAt(payload.length - 1) + 1);
  if (Buffer.from(lenient, 'base64url').toString('base64url') !== lenient) {
    assert.equal(verify(`${lenient}.${signature}`).error, 'malformed');
  }
  for (const text of ['not json', '[1,2]', 'null', '"text"', '{"v":1']) {
    assert.deepEqual(verify(signRaw(text)), { ok: false, error: 'malformed' }, text);
  }
});

test('unsupported versions are rejected before any key is used', () => {
  const claims = decode(trial().token);
  assert.deepEqual(verify(signRaw(JSON.stringify({ ...claims, v: 2 }))), { ok: false, error: 'unsupported_version' });
  assert.deepEqual(verify(signRaw(JSON.stringify({ ...claims, v: '1' }))), { ok: false, error: 'unsupported_version' });
  const { v, ...noVersion } = claims;
  assert.equal(v, 1);
  assert.deepEqual(verify(signRaw(JSON.stringify(noVersion))), { ok: false, error: 'unsupported_version' });
});

test('signed but invalid claims are rejected: types, time ranges, extra or missing claims, non-canonical text', () => {
  const t = decode(trial().token);
  const p = decode(paid().token);
  const reorder = (o, names) => JSON.stringify(Object.fromEntries(names.map((n) => [n, o[n]])));
  const cases = {
    'seconds instead of ms': JSON.stringify({ ...t, iat: Math.floor(t.iat / 1000), exp: Math.floor(t.exp / 1000) }),
    'exp equal to iat': JSON.stringify({ ...t, exp: t.iat }),
    'exp before iat': JSON.stringify({ ...t, exp: t.iat - 1 }),
    'trial longer than 48h': JSON.stringify({ ...t, exp: t.iat + TRIAL_MS + 1 }),
    'fractional time': JSON.stringify({ ...t, exp: t.exp + 0.5 }),
    'time as string': JSON.stringify({ ...t, iat: String(t.iat) }),
    'far future': JSON.stringify({ ...t, iat: Date.UTC(2200, 0, 1), exp: Date.UTC(2200, 0, 2) }),
    'paid revalidation stretched': JSON.stringify({ ...p, rva: p.rva + 1, grc: p.grc + 1 }),
    'paid grace stretched': JSON.stringify({ ...p, grc: p.grc + 1 }),
    'paid without grace': JSON.stringify((({ grc, ...rest }) => rest)(p)),
    'trial with paid claims': JSON.stringify({ ...t, rva: p.rva }),
    'extra claim': JSON.stringify({ ...t, admin: true }),
    'unknown type': JSON.stringify({ ...t, typ: 'lifetime' }),
    'device not a thumbprint': JSON.stringify({ ...t, dev: 'short' }),
    'account with symbols': JSON.stringify({ ...t, acc: 'acc/../../etc/passwd!!' }),
    'bad jti': JSON.stringify({ ...t, jti: 'x' }),
    'claims out of order': reorder(t, ['typ', 'v', 'kid', 'jti', 'acc', 'dev', 'iat', 'exp']),
    'whitespace': JSON.stringify(t, null, 1),
    'duplicate claim': JSON.stringify(t).replace('"exp":', `"exp":${t.exp + TRIAL_MS},"exp":`)
  };
  for (const [name, text] of Object.entries(cases)) {
    const result = verify(signRaw(text), { expectedType: name.startsWith('paid') ? 'paid' : 'trial' });
    assert.deepEqual(result, { ok: false, error: 'invalid_claims' }, name);
  }
});

test('key rotation: every listed kid verifies, unknown or retired kids do not, private JWKs are refused', () => {
  const next = createSigner({ privateKeyPem: p256Pem(), kid: 'k2027a' });
  const oldToken = trial().token;
  const newToken = next.issueTrial({ accountId: ACCOUNT, deviceThumbprint: DEVICE, now: NOW, trialExpiresAt: NOW + TRIAL_MS }).token;
  const both = { k2026a: signer.publicJwk, k2027a: next.publicJwk };
  assert.equal(verify(oldToken, { keys: both }).state, 'active');
  assert.equal(verify(newToken, { keys: both }).state, 'active');
  assert.deepEqual(verify(oldToken, { keys: { k2027a: next.publicJwk } }), { ok: false, error: 'unknown_key' });
  assert.deepEqual(verify(newToken), { ok: false, error: 'unknown_key' });
  assert.deepEqual(verify(oldToken, { keys: Object.create({ k2026a: signer.publicJwk }) }), { ok: false, error: 'unknown_key' },
    'inherited properties are not keys');
  const privateJwk = crypto.createPrivateKey(pem).export({ format: 'jwk' });
  assert.deepEqual(verify(oldToken, { keys: { k2026a: privateJwk } }), { ok: false, error: 'unknown_key' });
  assert.deepEqual(verify(oldToken, { keys: { k2026a: { kty: 'EC', crv: 'P-384', x: 'a', y: 'b' } } }), { ok: false, error: 'unknown_key' });
});

test('private key material never leaves the signer', () => {
  const privateJwk = crypto.createPrivateKey(pem).export({ format: 'jwk' });
  const body = pem.split('\n').filter((l) => l && !l.startsWith('-----')).join('');
  const { token, claims } = paid();
  const result = verify(token, { expectedType: 'paid' });
  const surfaces = {
    signer: JSON.stringify(signer),
    signerKeys: Object.keys(signer).join(','),
    publicJwk: JSON.stringify(signer.publicJwk),
    token,
    payload: Buffer.from(token.split('.')[0], 'base64url').toString('utf8'),
    claims: JSON.stringify(claims),
    result: JSON.stringify(result)
  };
  for (const [name, text] of Object.entries(surfaces)) {
    assert.ok(!text.includes(privateJwk.d), `${name} contains the private scalar`);
    assert.ok(!text.includes(body.slice(0, 40)) && !text.includes('PRIVATE KEY'), `${name} contains the PEM`);
    assert.ok(!/"d"\s*:/.test(text), `${name} has a private JWK member`);
  }
  assert.deepEqual(Object.keys(signer.publicJwk).sort(), ['crv', 'kty', 'x', 'y']);
  assert.ok(Object.isFrozen(signer) && Object.isFrozen(signer.publicJwk));
});

test('issuing validates its inputs and the signing key; errors never echo key material', () => {
  assert.throws(() => trial({ trialExpiresAt: NOW }), RangeError);
  assert.throws(() => trial({ trialExpiresAt: NOW - 1 }), RangeError);
  assert.throws(() => trial({ trialExpiresAt: NOW + TRIAL_MS + 1 }), RangeError);
  assert.throws(() => trial({ now: Math.floor(NOW / 1000) }), /server clock/);
  assert.throws(() => trial({ accountId: 'short' }), /accountId/);
  assert.throws(() => trial({ deviceThumbprint: 'x' }), /deviceThumbprint/);

  assert.throws(() => createSigner({ privateKeyPem: pem, kid: 'has space' }), /kid is invalid/);
  assert.throws(() => createSigner({ privateKeyPem: pem }), /kid is invalid/);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => createSigner({ privateKeyPem: rsa, kid: 'k1' }), /EC P-256/);
  assert.throws(() => createSigner({ privateKeyPem: p384, kid: 'k1' }), /EC P-256/);
  const publicPem = crypto.createPublicKey(pem).export({ type: 'spki', format: 'pem' });
  assert.throws(() => createSigner({ privateKeyPem: publicPem, kid: 'k1' }), /readable PEM private key/);
  assert.throws(() => createSigner({ privateKeyPem: pem.slice(0, 80) + 'garbage', kid: 'k1' }), (error) => {
    assert.equal(error.message, 'License signing key is not a readable PEM private key.');
    return true;
  });
});

test('verification requires the expected type, device and an explicit clock', () => {
  const { token } = trial();
  assert.throws(() => verifyCertificate(token, { keys, now: NOW, expectedDevice: DEVICE }), /expectedType/);
  assert.throws(() => verifyCertificate(token, { keys, now: NOW, expectedType: 'trial' }), /expectedDevice/);
  assert.throws(() => verifyCertificate(token, { keys, expectedType: 'trial', expectedDevice: DEVICE }), /now/);
  assert.throws(() => verifyCertificate(token, { now: NOW, expectedType: 'trial', expectedDevice: DEVICE }), /keys/);
});

test('signing configuration comes from its own variables and is never SESSION_SECRET', () => {
  assert.deepEqual(readSigningConfig({}), { configured: false });
  assert.throws(() => readSigningConfig({ LICENSE_SIGNING_KEY_FILE: '/x', LICENSE_SIGNING_KEY: pem, LICENSE_SIGNING_KID: 'k1' }), /not both/);
  assert.throws(() => readSigningConfig({ LICENSE_SIGNING_KEY: 'same-secret', SESSION_SECRET: 'same-secret', LICENSE_SIGNING_KID: 'k1' }),
    /separate from SESSION_SECRET/);
  assert.throws(() => readSigningConfig({ LICENSE_SIGNING_KEY_FILE: path.join(os.tmpdir(), 'missing-key-file.pem'), LICENSE_SIGNING_KID: 'k1' }),
    (error) => error.message === 'LICENSE_SIGNING_KEY_FILE cannot be read.');

  const inline = readSigningConfig({ LICENSE_SIGNING_KEY: pem.replace(/\n/g, '\\n'), LICENSE_SIGNING_KID: 'k1', SESSION_SECRET: 'other' });
  assert.equal(inline.configured, true);
  assert.deepEqual(inline.signer.publicJwk, signer.publicJwk);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-cert-'));
  try {
    const file = path.join(dir, 'signing.pem');
    fs.writeFileSync(file, pem, { mode: 0o600 });
    const fromFile = readSigningConfig({ LICENSE_SIGNING_KEY_FILE: file, LICENSE_SIGNING_KID: 'k1' });
    assert.equal(fromFile.signer.kid, 'k1');
    assert.equal(verifyCertificate(fromFile.signer.issuePaid({ accountId: ACCOUNT, deviceThumbprint: DEVICE, now: NOW }).token,
      { keys: { k1: fromFile.signer.publicJwk }, now: NOW, expectedType: 'paid', expectedDevice: DEVICE }).state, 'active');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('device thumbprints follow RFC 7638: stable, order-independent and limited to public members', () => {
  const jwk = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
  const tp = jwkThumbprint(jwk);
  assert.match(tp, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(jwkThumbprint({ y: jwk.y, x: jwk.x, crv: 'P-256', kty: 'EC', ext: true, key_ops: ['verify'] }), tp);
  assert.equal(tp, crypto.createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`).digest('base64url'));
  assert.throws(() => jwkThumbprint({ kty: 'RSA', n: 'x', e: 'AQAB' }), TypeError);
});
