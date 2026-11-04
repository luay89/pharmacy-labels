'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ProductLabelsLicense = factory();
})(typeof self !== 'undefined' ? self : this, () => {
  const TRIAL_MS = 48 * 60 * 60 * 1000;
  const REVALIDATE_MS = 30 * 24 * 60 * 60 * 1000;
  const GRACE_MS = 14 * 24 * 60 * 60 * 1000;
  const MIN_TIME = Date.UTC(2024, 0, 1);
  const MAX_TIME = Date.UTC(2100, 0, 1);
  const CLAIMS = {
    trial: ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'exp'],
    paid: ['v', 'typ', 'kid', 'jti', 'acc', 'dev', 'iat', 'rva', 'grc']
  };

  function decodeB64url(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
    try {
      const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4));
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      let encoded = '';
      for (const byte of bytes) encoded += String.fromCharCode(byte);
      encoded = btoa(encoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      return encoded === text ? bytes : null;
    } catch {
      return null;
    }
  }

  function isTime(value) {
    return Number.isSafeInteger(value) && value >= MIN_TIME && value < MAX_TIME;
  }

  function validClaims(claims, payloadText) {
    const names = CLAIMS[claims.typ];
    if (!names || Object.keys(claims).length !== names.length || !names.every((name, i) => Object.keys(claims)[i] === name)) return false;
    if (claims.v !== 1 || typeof claims.kid !== 'string' || !/^[A-Za-z0-9_-]{1,32}$/.test(claims.kid) ||
        typeof claims.jti !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(claims.jti) ||
        typeof claims.acc !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(claims.acc) ||
        typeof claims.dev !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(claims.dev) || !isTime(claims.iat)) return false;
    if (claims.typ === 'trial') {
      if (!isTime(claims.exp) || claims.exp <= claims.iat || claims.exp - claims.iat > TRIAL_MS) return false;
    } else if (!isTime(claims.rva) || !isTime(claims.grc) ||
        claims.rva - claims.iat !== REVALIDATE_MS || claims.grc - claims.rva !== GRACE_MS) return false;
    return JSON.stringify(claims) === payloadText;
  }

  async function verifyCertificate(token, { keys, now = Date.now(), expectedType, expectedDevice, subtle = globalThis.crypto && globalThis.crypto.subtle } = {}) {
    if (!Number.isSafeInteger(now)) return { ok: false, error: 'invalid_clock' };
    if (!keys || typeof keys !== 'object' || !['trial', 'paid'].includes(expectedType) || typeof expectedDevice !== 'string') {
      return { ok: false, error: 'invalid_options' };
    }
    if (typeof token !== 'string' || token.length > 2048) return { ok: false, error: 'malformed' };
    const parts = token.split('.');
    if (parts.length !== 2) return { ok: false, error: 'malformed' };
    const payload = decodeB64url(parts[0]);
    const signature = decodeB64url(parts[1]);
    if (!payload || !signature || signature.length !== 64) return { ok: false, error: 'malformed' };
    let claims;
    const payloadText = new TextDecoder().decode(payload);
    try { claims = JSON.parse(payloadText); } catch { return { ok: false, error: 'malformed' }; }
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return { ok: false, error: 'malformed' };
    if (claims.v !== 1) return { ok: false, error: 'unsupported_version' };
    const publicJwk = Object.hasOwn(keys, claims.kid) ? keys[claims.kid] : null;
    if (!publicJwk || Object.hasOwn(publicJwk, 'd') || publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-256') {
      return { ok: false, error: 'unknown_key' };
    }
    if (!subtle) return { ok: false, error: 'crypto_unavailable' };
    let key;
    try { key = await subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']); }
    catch { return { ok: false, error: 'unknown_key' }; }
    let verified = false;
    try { verified = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, payload); }
    catch { return { ok: false, error: 'bad_signature' }; }
    if (!verified) return { ok: false, error: 'bad_signature' };
    if (!validClaims(claims, payloadText)) return { ok: false, error: 'invalid_claims' };
    if (claims.typ !== expectedType) return { ok: false, error: 'wrong_type' };
    if (claims.dev !== expectedDevice) return { ok: false, error: 'wrong_device' };
    if (now < claims.iat - 5 * 60 * 1000) return { ok: false, error: 'not_yet_valid' };
    const state = claims.typ === 'trial'
      ? (now < claims.exp ? 'active' : 'expired')
      : (now < claims.rva ? 'active' : now < claims.grc ? 'grace' : 'expired');
    return { ok: true, usable: state !== 'expired', state, claims: Object.freeze({ ...claims }) };
  }

  return { verifyCertificate, TRIAL_MS, REVALIDATE_MS, GRACE_MS };
});
