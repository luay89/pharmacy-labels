'use strict';

// Offline license certificates: ECDSA P-256 / SHA-256 signatures that a browser can check with
// WebCrypto (raw 64-byte r||s, the IEEE P1363 form WebCrypto expects).
//
// Format: base64url(payload JSON) "." base64url(signature). The signature covers the exact payload
// bytes, and verification also requires those bytes to be the canonical serialization of the claims,
// so there is a single valid encoding for every certificate.
//
// Limits a caller must not paper over:
// - `now` on a device is the device's clock. Offline, nothing proves real-world time, so a rolled-back
//   or frozen clock can stretch a certificate; the client can only detect rollback against times it
//   has already seen. Server-side checks must use the server's own clock.
// - A certificate cannot be recalled while the device stays offline. A refund, dispute or revocation
//   is learned at the next successful revalidation, so a paid certificate can outlive one by up to
//   REVALIDATE_MS + GRACE_MS from its issue time.

const crypto = require('node:crypto');
const fs = require('node:fs');

const CERT_VERSION = 1;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const TRIAL_MS = 48 * HOUR_MS;
const REVALIDATE_MS = 30 * DAY_MS;
const GRACE_MS = 14 * DAY_MS;
const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_TOKEN_LENGTH = 2048;
// Millisecond timestamps between 2024-01-01 and 2100-01-01; catches seconds passed as milliseconds.
const MIN_TIME = Date.UTC(2024, 0, 1);
const MAX_TIME = Date.UTC(2100, 0, 1);

const KID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const ACCOUNT_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/; // base64url SHA-256
const JTI_PATTERN = /^[A-Za-z0-9_-]{22}$/; // base64url of 16 random bytes
const B64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

// Claim order is part of the format: it fixes the canonical serialization.
const CLAIMS = {
  trial: ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'exp'],
  paid: ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'rva', 'grc']
};

function isTime(value) {
  return Number.isSafeInteger(value) && value >= MIN_TIME && value < MAX_TIME;
}

function decodeB64url(text) {
  if (!B64URL_PATTERN.test(text)) return null;
  const bytes = Buffer.from(text, 'base64url');
  return bytes.toString('base64url') === text ? bytes : null;
}

function canonicalPayload(claims) {
  return JSON.stringify(Object.fromEntries(CLAIMS[claims.typ].map((name) => [name, claims[name]])));
}

// RFC 7638 thumbprint of an EC P-256 public JWK; used for device keys and for key ids.
function jwkThumbprint(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new TypeError('Expected an EC P-256 public JWK.');
  }
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function privateKeyFromPem(pem) {
  let key;
  try {
    key = crypto.createPrivateKey({ key: pem, format: 'pem' });
  } catch {
    // Never echo the input: it may be a real private key.
    throw new Error('License signing key is not a readable PEM private key.');
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1') {
    throw new Error('License signing key must be an EC P-256 private key.');
  }
  return key;
}

// The private key lives only in this closure: the returned object exposes the kid and the public JWK,
// so logging or serializing a signer cannot leak it.
function createSigner({ privateKeyPem, kid }) {
  if (typeof kid !== 'string' || !KID_PATTERN.test(kid)) throw new Error('License signing kid is invalid.');
  const privateKey = privateKeyFromPem(privateKeyPem);
  const { kty, crv, x, y } = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  const publicJwk = Object.freeze({ kty, crv, x, y });

  function sign(claims) {
    const payload = Buffer.from(canonicalPayload(claims));
    const signature = crypto.sign('sha256', payload, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return { token: `${payload.toString('base64url')}.${signature.toString('base64url')}`, claims: Object.freeze(claims) };
  }

  function baseClaims(typ, { accountId, deviceThumbprint, now }) {
    if (typeof accountId !== 'string' || !ACCOUNT_PATTERN.test(accountId)) throw new TypeError('accountId is invalid.');
    if (typeof deviceThumbprint !== 'string' || !THUMBPRINT_PATTERN.test(deviceThumbprint)) {
      throw new TypeError('deviceThumbprint is invalid.');
    }
    if (!isTime(now)) throw new TypeError('now must be a millisecond timestamp from the server clock.');
    return { v: CERT_VERSION, typ, kid, jti: crypto.randomBytes(16).toString('base64url'), acc: accountId, dev: deviceThumbprint, iat: now };
  }

  return Object.freeze({
    kid,
    publicJwk,
    // `trialExpiresAt` comes from the stored trial, so a re-issued certificate never extends it.
    issueTrial({ accountId, deviceThumbprint, now, trialExpiresAt }) {
      const claims = baseClaims('trial', { accountId, deviceThumbprint, now });
      if (!isTime(trialExpiresAt) || trialExpiresAt <= now || trialExpiresAt - now > TRIAL_MS) {
        throw new RangeError('trialExpiresAt must be in the future and at most 48 hours away.');
      }
      return sign({ ...claims, exp: trialExpiresAt });
    },
    issuePaid({ accountId, deviceThumbprint, now }) {
      const claims = baseClaims('paid', { accountId, deviceThumbprint, now });
      return sign({ ...claims, rva: now + REVALIDATE_MS, grc: now + REVALIDATE_MS + GRACE_MS });
    },
    toJSON() {
      return { kid, publicJwk };
    }
  });
}

function validClaims(claims) {
  const names = CLAIMS[claims.typ];
  if (!names || Object.keys(claims).length !== names.length || !names.every((n) => Object.hasOwn(claims, n))) return false;
  if (typeof claims.kid !== 'string' || !KID_PATTERN.test(claims.kid)) return false;
  if (typeof claims.jti !== 'string' || !JTI_PATTERN.test(claims.jti)) return false;
  if (typeof claims.acc !== 'string' || !ACCOUNT_PATTERN.test(claims.acc)) return false;
  if (typeof claims.dev !== 'string' || !THUMBPRINT_PATTERN.test(claims.dev)) return false;
  if (!isTime(claims.iat)) return false;
  if (claims.typ === 'trial') {
    return isTime(claims.exp) && claims.exp > claims.iat && claims.exp - claims.iat <= TRIAL_MS;
  }
  return isTime(claims.rva) && isTime(claims.grc) &&
    claims.rva - claims.iat === REVALIDATE_MS && claims.grc - claims.rva === GRACE_MS;
}

function verificationKey(jwk) {
  // A key set is shipped to clients; refuse one that carries private material.
  if (!jwk || Object.hasOwn(jwk, 'd') || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null;
  try {
    return crypto.createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
  } catch {
    return null;
  }
}

/**
 * Checks authenticity first, then binding, then time. Never throws for a bad certificate.
 *
 * Returns { ok: false, error } when the certificate must be ignored, or
 * { ok: true, state, usable, claims } where state is:
 *   trial: 'active' while now < exp, then 'expired'
 *   paid:  'active' while now < rva, 'grace' while now < grc, then 'expired'
 * 'grace' only means the deadline passed; whether grace applies (server unreachable, not a refusal)
 * is the caller's decision. An expired but authentic certificate stays ok so read-only mode can use it.
 */
function verifyCertificate(token, { keys, now, expectedType, expectedDevice, clockSkewMs = DEFAULT_CLOCK_SKEW_MS } = {}) {
  if (!keys || typeof keys !== 'object') throw new TypeError('keys must map kid to a public JWK.');
  if (!Number.isSafeInteger(now)) throw new TypeError('now must be a millisecond timestamp.');
  if (!Object.hasOwn(CLAIMS, expectedType)) throw new TypeError('expectedType must be trial or paid.');
  if (typeof expectedDevice !== 'string' || !expectedDevice) throw new TypeError('expectedDevice is required.');

  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return { ok: false, error: 'malformed' };
  const parts = token.split('.');
  if (parts.length !== 2) return { ok: false, error: 'malformed' };
  const payload = decodeB64url(parts[0]);
  const signature = decodeB64url(parts[1]);
  if (!payload || !signature) return { ok: false, error: 'malformed' };

  let claims;
  try {
    claims = JSON.parse(payload.toString('utf8'));
  } catch {
    return { ok: false, error: 'malformed' };
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return { ok: false, error: 'malformed' };
  if (claims.v !== CERT_VERSION) return { ok: false, error: 'unsupported_version' };

  const key = typeof claims.kid === 'string' && Object.hasOwn(keys, claims.kid) ? verificationKey(keys[claims.kid]) : null;
  if (!key) return { ok: false, error: 'unknown_key' };
  if (signature.length !== 64 ||
      !crypto.verify('sha256', payload, { key, dsaEncoding: 'ieee-p1363' }, signature)) {
    return { ok: false, error: 'bad_signature' };
  }

  if (!validClaims(claims) || canonicalPayload(claims) !== payload.toString('utf8')) {
    return { ok: false, error: 'invalid_claims' };
  }
  if (claims.typ !== expectedType) return { ok: false, error: 'wrong_type' };
  if (claims.dev !== expectedDevice) return { ok: false, error: 'wrong_device' };
  if (now < claims.iat - clockSkewMs) return { ok: false, error: 'not_yet_valid' };

  let state;
  if (claims.typ === 'trial') state = now < claims.exp ? 'active' : 'expired';
  else state = now < claims.rva ? 'active' : now < claims.grc ? 'grace' : 'expired';
  return { ok: true, state, usable: state !== 'expired', claims: Object.freeze({ ...claims }) };
}

// Reads the signing key from LICENSE_SIGNING_KEY_FILE (preferred) or LICENSE_SIGNING_KEY, never both.
// It must not be SESSION_SECRET: certificates must survive a session-secret rotation and vice versa.
function readSigningConfig(env) {
  const file = env.LICENSE_SIGNING_KEY_FILE || '';
  const inline = env.LICENSE_SIGNING_KEY || '';
  if (!file && !inline) return { configured: false };
  if (file && inline) throw new Error('Set LICENSE_SIGNING_KEY_FILE or LICENSE_SIGNING_KEY, not both.');
  let pem = inline.replace(/\\n/g, '\n');
  if (file) {
    try {
      pem = fs.readFileSync(file, 'utf8');
    } catch {
      throw new Error('LICENSE_SIGNING_KEY_FILE cannot be read.');
    }
  }
  if (env.SESSION_SECRET && (pem.trim() === env.SESSION_SECRET.trim() || inline === env.SESSION_SECRET)) {
    throw new Error('The license signing key must be separate from SESSION_SECRET.');
  }
  return { configured: true, signer: createSigner({ privateKeyPem: pem, kid: env.LICENSE_SIGNING_KID }) };
}

module.exports = {
  createSigner,
  verifyCertificate,
  readSigningConfig,
  jwkThumbprint,
  CERT_VERSION,
  TRIAL_MS,
  REVALIDATE_MS,
  GRACE_MS,
  DEFAULT_CLOCK_SKEW_MS
};
