'use strict';

// Device key for Product Labels. Each browser profile gets one ECDSA P-256 key pair, generated with
// WebCrypto as non-extractable and kept in IndexedDB: the private key cannot be exported, read or sent,
// only used to sign the server's one-time device challenges. Nothing here logs keys or signatures.
// Loaded on demand by the account panel for registration, proof and certificate renewal.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ProductLabelsDevice = factory();
})(typeof self !== 'undefined' ? self : this, () => {
  const DB_NAME = 'product-labels-device';
  const STORE = 'keys';
  const RECORD = 'device-key-v1';
  const LICENSE_STATE_RECORD = 'license-state-v1';
  // Must match DEVICE_PROOF_PREFIX in server.js.
  const PROOF_PREFIX = 'product-labels-device-proof:v1:';
  const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
  const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };

  function settle(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function inStore(indexedDB, mode, action) {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    const db = await settle(open);
    try {
      const tx = db.transaction(STORE, mode);
      const done = new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
      // Awaited together so a failed request (and the aborted transaction it causes) is one rejection.
      const [result] = await Promise.all([settle(action(tx.objectStore(STORE))), done]);
      return result;
    } finally {
      db.close();
    }
  }

  function base64url(buffer) {
    let binary = '';
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function createDeviceKeys(options = {}) {
    const subtle = options.subtle || globalThis.crypto.subtle;
    const indexedDB = options.indexedDB || globalThis.indexedDB;
    const send = options.fetch || ((...args) => globalThis.fetch(...args));
    const base = options.base || '';
    let pending = null;

    // Reuses the stored pair; otherwise makes one. `add` (not `put`) means two tabs racing to create a key
    // cannot overwrite each other: the loser reads back the winner's pair.
    function keyPair() {
      pending = pending || (async () => {
        const stored = await inStore(indexedDB, 'readonly', (store) => store.get(RECORD));
        if (stored) return stored;
        const generated = await subtle.generateKey(KEY_ALGORITHM, false, ['sign', 'verify']);
        const pair = { privateKey: generated.privateKey, publicKey: generated.publicKey };
        try {
          await inStore(indexedDB, 'readwrite', (store) => store.add(pair, RECORD));
          return pair;
        } catch (error) {
          const winner = await inStore(indexedDB, 'readonly', (store) => store.get(RECORD));
          if (winner) return winner;
          throw error;
        }
      })().catch((error) => {
        pending = null;
        throw error;
      });
      return pending;
    }

    async function jwkOf(publicKey) {
      const { kty, crv, x, y } = await subtle.exportKey('jwk', publicKey);
      return { kty, crv, x, y };
    }

    // RFC 7638, the same value the server stores as key_thumbprint.
    async function thumbprintOf(publicKey) {
      const { crv, kty, x, y } = await jwkOf(publicKey);
      const canonical = new TextEncoder().encode(JSON.stringify({ crv, kty, x, y }));
      return base64url(await subtle.digest('SHA-256', canonical));
    }

    const publicJwk = async () => jwkOf((await keyPair()).publicKey);
    const thumbprint = async () => thumbprintOf((await keyPair()).publicKey);

    // Looks at the stored key only: null when this browser has none, and never creates one.
    async function storedThumbprint() {
      const stored = await inStore(indexedDB, 'readonly', (store) => store.get(RECORD));
      return stored ? thumbprintOf(stored.publicKey) : null;
    }

    function saveLicenseState(state) {
      return inStore(indexedDB, 'readwrite', (store) => store.put(state, LICENSE_STATE_RECORD));
    }

    function readLicenseState() {
      return inStore(indexedDB, 'readonly', (store) => store.get(LICENSE_STATE_RECORD));
    }

    async function sign(challenge) {
      const message = new TextEncoder().encode(PROOF_PREFIX + challenge);
      return base64url(await subtle.sign(SIGN_ALGORITHM, (await keyPair()).privateKey, message));
    }

    async function post(pathname, body) {
      const response = await send(base + pathname, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      return { status: response.status, body: await response.json().catch(() => null) };
    }

    // Asks for a fresh challenge, signs it locally and sends back only the public key and the signature.
    async function prove(purpose, pathname) {
      const publicKey = await publicJwk();
      const issued = await post('/api/devices/challenge', { purpose, publicKey });
      if (issued.status !== 200) return issued;
      const signature = await sign(issued.body.challenge);
      return post(pathname, { publicKey, challenge: issued.body.challenge, signature });
    }

    return {
      keyPair,
      publicJwk,
      thumbprint,
      storedThumbprint,
      saveLicenseState,
      readLicenseState,
      register: () => prove('register', '/api/devices/register'),
      verify: () => prove('prove', '/api/devices/verify'),
      certificate: () => prove('certificate', '/api/license/certificate')
    };
  }

  return { createDeviceKeys, PROOF_PREFIX };
});
