'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { test } = require('node:test');
const { createSigner, TRIAL_MS, REVALIDATE_MS, GRACE_MS } = require('../license-cert');
const { verifyCertificate } = require('../license-client');

const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const signer = createSigner({
  privateKeyPem: keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), kid: 'browser-test'
});
const keys = { 'browser-test': signer.publicJwk };
const now = Date.UTC(2026, 10, 2, 12);
const accountId = 'account_browser_test_1';
const device = crypto.randomBytes(32).toString('base64url');

const trial = () => signer.issueTrial({ accountId, deviceThumbprint: device, now, trialExpiresAt: now + TRIAL_MS });
const paid = () => signer.issuePaid({ accountId, deviceThumbprint: device, now });
const check = (token, extra = {}) => verifyCertificate(token, {
  keys, now, expectedType: 'trial', expectedDevice: device, subtle: crypto.webcrypto.subtle, ...extra
});

test('browser WebCrypto verifies a Node trial certificate and exact expiry', async () => {
  const certificate = trial();
  const verified = await check(certificate.token);
  assert.equal(verified.ok, true);
  assert.equal(verified.state, 'active');
  assert.equal(verified.claims.exp, now + TRIAL_MS);
  assert.equal((await check(certificate.token, { now: now + TRIAL_MS })).state, 'expired');
});

test('browser verifier enforces signature, key, type, device and time bounds', async () => {
  const certificate = trial();
  const [payload, signature] = certificate.token.split('.');
  const changedSignature = Buffer.from(signature, 'base64url');
  changedSignature[0] ^= 1;
  const tampered = `${payload}.${changedSignature.toString('base64url')}`;
  assert.equal((await check(tampered)).error, 'bad_signature');
  assert.equal((await check(certificate.token, { expectedType: 'paid' })).error, 'wrong_type');
  assert.equal((await check(certificate.token, { expectedDevice: crypto.randomBytes(32).toString('base64url') })).error, 'wrong_device');
  assert.equal((await check(certificate.token, { keys: {} })).error, 'unknown_key');
  assert.equal((await check(certificate.token, { now: now - 6 * 60 * 1000 })).error, 'not_yet_valid');
  assert.equal((await check(`${payload}!.${signature}`)).error, 'malformed');
});

test('browser verifier applies the paid revalidation and grace intervals', async () => {
  const certificate = paid();
  const verifyPaid = (at) => verifyCertificate(certificate.token, {
    keys, now: at, expectedType: 'paid', expectedDevice: device, subtle: crypto.webcrypto.subtle
  });
  assert.equal((await verifyPaid(now + REVALIDATE_MS - 1)).state, 'active');
  assert.equal((await verifyPaid(now + REVALIDATE_MS)).state, 'grace');
  assert.equal((await verifyPaid(now + REVALIDATE_MS + GRACE_MS - 1)).usable, true);
  assert.equal((await verifyPaid(now + REVALIDATE_MS + GRACE_MS)).usable, false);
});
