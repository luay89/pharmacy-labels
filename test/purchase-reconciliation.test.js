'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { openDatabase } = require('../db');

const root = path.join(__dirname, '..');

function createUnknownPurchase(dataDir) {
  const { db } = openDatabase(dataDir);
  db.exec(`
    INSERT INTO app_sessions (id, unlocked) VALUES ('reconcile-session', 1);
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status)
    VALUES ('pi_legacyunknown', 'reconcile-session', 'active');
  `);
  db.close();
}

function readPurchase(dataDir) {
  const { db } = openDatabase(dataDir);
  const result = db.prepare(`
    SELECT p.status, p.stripe_mode, p.stripe_mode_review_reference, p.stripe_mode_reviewed_at,
      p.excluded_from_entitlements, s.unlocked
    FROM stripe_purchases p JOIN app_sessions s ON s.id = p.app_session_id
    WHERE p.payment_intent_id = 'pi_legacyunknown'
  `).get();
  db.close();
  return result;
}

test('purchase reconciliation requires explicit review and changes classification only', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-reconcile-'));
  try {
    createUnknownPurchase(dataDir);
    const env = { PATH: process.env.PATH, DATA_DIR: dataDir };
    const script = path.join(root, 'reconcile-purchase.js');

    assert.throws(() => execFileSync(process.execPath, [
      script, 'pi_legacyunknown', 'live', 'CASE-123'
    ], { cwd: root, env, stdio: 'pipe' }));
    assert.throws(() => execFileSync(process.execPath, [
      script, 'pi_legacyunknown', 'live', 'AB', '--operator-reviewed'
    ], { cwd: root, env, stdio: 'pipe' }));
    assert.deepEqual(readPurchase(dataDir), {
      status: 'active', stripe_mode: null, stripe_mode_review_reference: null, stripe_mode_reviewed_at: null,
      excluded_from_entitlements: 0, unlocked: 1
    });

    const output = execFileSync(process.execPath, [
      script, 'pi_legacyunknown', 'live', 'CASE-123', '--operator-reviewed'
    ], { cwd: root, env, encoding: 'utf8' });
    assert.match(output, /purchase status and entitlements were not changed/);
    const reviewed = readPurchase(dataDir);
    assert.deepEqual({
      status: reviewed.status,
      stripe_mode: reviewed.stripe_mode,
      stripe_mode_review_reference: reviewed.stripe_mode_review_reference,
      excluded_from_entitlements: reviewed.excluded_from_entitlements,
      unlocked: reviewed.unlocked
    }, {
      status: 'active',
      stripe_mode: 'live',
      stripe_mode_review_reference: 'CASE-123',
      excluded_from_entitlements: 0,
      unlocked: 1
    });
    assert.ok(Number.isInteger(reviewed.stripe_mode_reviewed_at));

    assert.throws(() => execFileSync(process.execPath, [
      script, 'pi_legacyunknown', 'test', 'CASE-456', '--operator-reviewed'
    ], { cwd: root, env, stdio: 'pipe' }));
    assert.equal(readPurchase(dataDir).stripe_mode, 'live', 'an operator review cannot silently overwrite a classification');
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('excluding a reviewed test purchase is explicit and preserves other live purchases', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-reconcile-'));
  try {
    const { db } = openDatabase(dataDir);
    db.exec(`
      INSERT INTO app_sessions (id, unlocked)
        VALUES ('test-only-session', 1), ('shared-session', 1), ('locked-session', 0);
      INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, checkout_session_id, stripe_mode)
        VALUES ('pi_testonly', 'test-only-session', 'active', 'cs_test_only', 'test'),
               ('pi_testshared', 'shared-session', 'active', 'cs_test_shared', 'test'),
               ('pi_liveshared', 'shared-session', 'active', 'cs_live_shared', 'live'),
               ('pi_testlocked', 'locked-session', 'active', 'cs_test_locked', 'test'),
               ('pi_livelocked', 'locked-session', 'active', 'cs_live_locked', 'live');
    `);
    db.close();

    const env = { PATH: process.env.PATH, DATA_DIR: dataDir };
    const script = path.join(root, 'reconcile-purchase.js');
    assert.throws(() => execFileSync(process.execPath, [
      script, 'pi_testonly', 'test', 'CASE-TEST'
    ], { cwd: root, env, stdio: 'pipe' }));

    execFileSync(process.execPath, [
      script, 'pi_testonly', 'test', 'CASE-TEST', '--operator-reviewed', '--exclude-from-entitlements'
    ], { cwd: root, env, stdio: 'pipe' });
    execFileSync(process.execPath, [
      script, 'pi_testshared', 'test', 'CASE-TEST', '--operator-reviewed', '--exclude-from-entitlements'
    ], { cwd: root, env, stdio: 'pipe' });
    execFileSync(process.execPath, [
      script, 'pi_testlocked', 'test', 'CASE-TEST', '--operator-reviewed', '--exclude-from-entitlements'
    ], { cwd: root, env, stdio: 'pipe' });

    const { db: verified } = openDatabase(dataDir);
    assert.deepEqual(verified.prepare(`
      SELECT payment_intent_id, status, excluded_from_entitlements
      FROM stripe_purchases ORDER BY payment_intent_id
    `).all(), [
      { payment_intent_id: 'pi_livelocked', status: 'active', excluded_from_entitlements: 0 },
      { payment_intent_id: 'pi_liveshared', status: 'active', excluded_from_entitlements: 0 },
      { payment_intent_id: 'pi_testlocked', status: 'active', excluded_from_entitlements: 1 },
      { payment_intent_id: 'pi_testonly', status: 'active', excluded_from_entitlements: 1 },
      { payment_intent_id: 'pi_testshared', status: 'active', excluded_from_entitlements: 1 }
    ]);
    assert.deepEqual(verified.prepare('SELECT id, unlocked FROM app_sessions ORDER BY id').all(), [
      { id: 'locked-session', unlocked: 0 },
      { id: 'shared-session', unlocked: 1 },
      { id: 'test-only-session', unlocked: 0 }
    ]);
    verified.close();
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
