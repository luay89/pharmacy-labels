'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { openDatabase } = require('../db');
const { recoverDevice, YEAR_MS } = require('../recover-device');

function fixture() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-recovery-'));
  const { db } = openDatabase(dataDir);
  const accountId = 'account_recovery_test_1';
  const appSessionId = 'a'.repeat(43);
  const deviceId = 'd'.repeat(22);
  const now = Date.now();
  db.prepare('INSERT INTO app_sessions (id, last_seen_at) VALUES (?, ?)').run(appSessionId, now);
  db.prepare('INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES (?, ?, ?, ?)')
    .run(accountId, 'a'.repeat(64), 'te***@e***.com', now);
  db.prepare(`INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, account_id, license_policy, order_ref)
    VALUES (?, ?, 'active', ?, ?, ?)`)
    .run('pi_recovery_test', appSessionId, accountId, 'single_device', 'PL-ABCDEFGHJK');
  db.prepare(`INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at, last_validated_at)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(deviceId, accountId, 't'.repeat(43), JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }), now, now);
  db.prepare(`INSERT INTO account_sessions (token_hash, account_id, app_session_id, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)`)
    .run('s'.repeat(64), accountId, appSessionId, now, now + YEAR_MS);
  return { db, dataDir, accountId, appSessionId, deviceId, now };
}

test('support recovery revokes the old device and account sessions and records its ticket and reason', () => {
  const f = fixture();
  try {
    assert.deepEqual(recoverDevice(f.db, {
      orderRef: 'PL-ABCDEFGHJK', ticket: 'SUP-12345', reason: 'Customer lost access to registered browser.', now: f.now + 1000
    }), { recovered: true });
    assert.deepEqual({ ...f.db.prepare('SELECT revoked_at, revoke_reason FROM devices WHERE id = ?').get(f.deviceId) },
      { revoked_at: f.now + 1000, revoke_reason: 'support_recovery' });
    assert.equal(f.db.prepare('SELECT revoked_at FROM account_sessions').get().revoked_at, f.now + 1000);
    assert.deepEqual({ ...f.db.prepare('SELECT ticket, reason FROM device_recoveries').get() }, {
      ticket: 'SUP-12345', reason: 'Customer lost access to registered browser.'
    });
    assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = 'device_recovery' AND outcome = 'approved'").get().n, 1);
    assert.deepEqual(recoverDevice(f.db, {
      orderRef: 'PL-ABCDEFGHJK', ticket: 'SUP-67890', reason: 'Second support request is refused.', now: f.now + 2000
    }), { error: 'recovery_limit' });
  } finally {
    f.db.close();
    fs.rmSync(f.dataDir, { recursive: true, force: true });
  }
});

test('recovery refuses malformed inputs and purchases that are not active single-device licenses', () => {
  const f = fixture();
  try {
    assert.deepEqual(recoverDevice(f.db, { orderRef: 'bad', ticket: 'SUP-123', reason: 'Enough detail here', now: f.now }),
      { error: 'invalid_input' });
    f.db.prepare("UPDATE stripe_purchases SET license_policy = 'legacy' WHERE payment_intent_id = 'pi_recovery_test'").run();
    assert.deepEqual(recoverDevice(f.db, {
      orderRef: 'PL-ABCDEFGHJK', ticket: 'SUP-123', reason: 'Legacy license recovery attempt.', now: f.now
    }), { error: 'purchase_unavailable' });
    assert.equal(f.db.prepare('SELECT revoked_at FROM devices WHERE id = ?').get(f.deviceId).revoked_at, null);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM device_recoveries').get().n, 0);
  } finally {
    f.db.close();
    fs.rmSync(f.dataDir, { recursive: true, force: true });
  }
});
