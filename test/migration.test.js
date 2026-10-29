'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const Database = require('better-sqlite3');
const { openDatabase, SCHEMA_VERSION, DB_FILE } = require('../db');

function legacyDatabase() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  const legacy = new Database(path.join(dir, DB_FILE));
  legacy.pragma('journal_mode = WAL');
  legacy.exec(`
    CREATE TABLE app_sessions (
      id TEXT PRIMARY KEY,
      labels_printed INTEGER NOT NULL DEFAULT 0 CHECK (labels_printed >= 0),
      unlocked INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE stripe_events (id TEXT PRIMARY KEY, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE stripe_purchases (
      payment_intent_id TEXT PRIMARY KEY,
      app_session_id TEXT REFERENCES app_sessions(id),
      status TEXT NOT NULL CHECK (status IN ('active', 'refunded', 'disputed')),
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO app_sessions (id, labels_printed, unlocked) VALUES ('paid-session', 7, 1), ('refunded-session', 20, 0);
    INSERT INTO stripe_events (id) VALUES ('evt_legacy');
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status) VALUES
      ('pi_legacy_paid', 'paid-session', 'active'),
      ('pi_legacy_refunded', 'refunded-session', 'refunded'),
      ('pi_legacy_orphan', NULL, 'disputed');
  `);
  legacy.close();
  return dir;
}

function snapshot(db) {
  return {
    sessions: db.prepare('SELECT id, labels_printed, unlocked FROM app_sessions ORDER BY id').all(),
    events: db.prepare('SELECT id FROM stripe_events ORDER BY id').all(),
    purchases: db.prepare(`
      SELECT payment_intent_id, app_session_id, status, transfers_used, transfer_limit, email_hash
      FROM stripe_purchases ORDER BY payment_intent_id
    `).all()
  };
}

test('migration keeps legacy purchases, backs up first and is safe to re-run', () => {
  const dir = legacyDatabase();
  try {
    const first = openDatabase(dir);
    assert.equal(first.migration.from, 0);
    assert.equal(first.migration.to, SCHEMA_VERSION);
    assert.ok(first.migration.backupPath.startsWith(path.join(dir, 'backups')));
    assert.equal(fs.statSync(first.migration.backupPath).mode & 0o777, 0o600);
    assert.equal(first.db.pragma('user_version', { simple: true }), SCHEMA_VERSION);
    const migrated = snapshot(first.db);
    assert.deepEqual(migrated.sessions, [
      { id: 'paid-session', labels_printed: 7, unlocked: 1 },
      { id: 'refunded-session', labels_printed: 20, unlocked: 0 }
    ]);
    assert.deepEqual(migrated.events, [{ id: 'evt_legacy' }]);
    assert.deepEqual(migrated.purchases, [
      { payment_intent_id: 'pi_legacy_orphan', app_session_id: null, status: 'disputed', transfers_used: 0, transfer_limit: 1, email_hash: null },
      { payment_intent_id: 'pi_legacy_paid', app_session_id: 'paid-session', status: 'active', transfers_used: 0, transfer_limit: 1, email_hash: null },
      { payment_intent_id: 'pi_legacy_refunded', app_session_id: 'refunded-session', status: 'refunded', transfers_used: 0, transfer_limit: 1, email_hash: null }
    ]);
    assert.deepEqual(first.db.prepare('SELECT id, last_seen_at FROM app_sessions ORDER BY id').all(), [
      { id: 'paid-session', last_seen_at: null },
      { id: 'refunded-session', last_seen_at: null }
    ], 'existing sessions keep NULL and fall back to created_at');
    for (const table of ['license_transfers', 'email_verifications', 'rate_limits', 'email_outbox']) {
      assert.equal(first.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0);
    }
    first.db.close();

    const backup = new Database(first.migration.backupPath, { readonly: true });
    assert.equal(backup.pragma('user_version', { simple: true }), 0);
    assert.equal(backup.prepare('SELECT COUNT(*) AS n FROM stripe_purchases').get().n, 3);
    assert.ok(!backup.prepare('PRAGMA table_info(stripe_purchases)').all().some((c) => c.name === 'transfers_used'));
    backup.close();

    const second = openDatabase(dir);
    assert.deepEqual(second.migration, { from: SCHEMA_VERSION, to: SCHEMA_VERSION, backupPath: null });
    assert.deepEqual(snapshot(second.db), migrated);
    second.db.close();
    assert.equal(fs.readdirSync(path.join(dir, 'backups')).length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a v2 database upgrades to the current schema, keeping sessions and purchases', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  try {
    // Build a real v2 file: current schema minus what later versions added.
    const { db: seed } = openDatabase(dir);
    seed.exec(`
      ALTER TABLE app_sessions DROP COLUMN last_seen_at;
      INSERT INTO app_sessions (id, unlocked) VALUES ('v2-buyer', 1);
      INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, transfers_used, checkout_session_id)
        VALUES ('pi_v2', 'v2-buyer', 'active', 1, 'cs_test_v2');
      INSERT INTO stripe_events (id) VALUES ('evt_v2');
    `);
    seed.pragma('user_version = 2');
    seed.close();

    const { db, migration } = openDatabase(dir);
    assert.equal(migration.from, 2);
    assert.equal(migration.to, SCHEMA_VERSION);
    assert.ok(migration.backupPath);
    assert.deepEqual(db.prepare('SELECT id, unlocked, last_seen_at FROM app_sessions').get(), { id: 'v2-buyer', unlocked: 1, last_seen_at: null });
    assert.deepEqual(db.prepare('SELECT app_session_id, status, transfers_used FROM stripe_purchases').get(),
      { app_session_id: 'v2-buyer', status: 'active', transfers_used: 1 });
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM stripe_events').get().n, 1);
    db.close();
    assert.equal(fs.statSync(path.join(dir, DB_FILE)).mode & 0o777, 0o600, 'database file is owner-only');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('fresh databases are created at the current schema without a backup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  try {
    const { db, migration } = openDatabase(dir);
    assert.deepEqual(migration, { from: 0, to: SCHEMA_VERSION, backupPath: null });
    assert.ok(db.prepare('PRAGMA table_info(stripe_purchases)').all().some((c) => c.name === 'transfer_limit'));
    db.close();
    assert.equal(fs.existsSync(path.join(dir, 'backups')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a database from a newer server version is refused instead of modified', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  try {
    const future = new Database(path.join(dir, DB_FILE));
    future.pragma(`user_version = ${SCHEMA_VERSION + 1}`);
    future.close();
    assert.throws(() => openDatabase(dir), /newer than this server/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
