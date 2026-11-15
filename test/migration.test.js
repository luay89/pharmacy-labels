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

// The schema exactly as the v3 server created it (dumped from sqlite_master at commit 90c90fb).
// v2 is the same minus app_sessions.last_seen_at. Fixed text, so later migrations cannot leak into these files.
const V3_SCHEMA = `
  CREATE TABLE app_sessions (
    id TEXT PRIMARY KEY,
    labels_printed INTEGER NOT NULL DEFAULT 0 CHECK (labels_printed >= 0),
    unlocked INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  , last_seen_at INTEGER);
  CREATE TABLE stripe_events (id TEXT PRIMARY KEY, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE stripe_purchases (
    payment_intent_id TEXT PRIMARY KEY,
    app_session_id TEXT REFERENCES app_sessions(id),
    status TEXT NOT NULL CHECK (status IN ('active', 'refunded', 'disputed')),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  , checkout_session_id TEXT, email_hash TEXT, email_masked TEXT, order_ref TEXT, amount_total INTEGER, currency TEXT,
    transfers_used INTEGER NOT NULL DEFAULT 0 CHECK (transfers_used >= 0),
    transfer_limit INTEGER NOT NULL DEFAULT 1 CHECK (transfer_limit >= 0), last_transfer_at TEXT, status_event_created INTEGER);
  CREATE INDEX stripe_purchases_email_hash ON stripe_purchases(email_hash);
  CREATE INDEX stripe_purchases_app_session ON stripe_purchases(app_session_id);
  CREATE TABLE license_transfers (
    id INTEGER PRIMARY KEY,
    payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
    from_app_session_id TEXT,
    to_app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
    transferred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX license_transfers_from ON license_transfers(from_app_session_id);
  CREATE TABLE email_verifications (
    id INTEGER PRIMARY KEY,
    payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
    app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX email_verifications_session ON email_verifications(app_session_id, consumed_at);
  CREATE TABLE rate_limits (key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL CHECK (count >= 0));
  CREATE TABLE email_outbox (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    payment_intent_id TEXT REFERENCES stripe_purchases(payment_intent_id),
    to_address TEXT,
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    sent_at INTEGER
  );
  CREATE INDEX email_outbox_due ON email_outbox(status, next_attempt_at);
`;
const V2_SCHEMA = V3_SCHEMA.replace('  , last_seen_at INTEGER);', ');');
const V4_TABLES = ['accounts', 'account_codes', 'devices', 'trials', 'license_certificates', 'audit_events'];
// Dumped from the v4 schema (db.js before migration v5) on a fresh database.
const V4_SCHEMA = `
  CREATE TABLE app_sessions (
    id TEXT PRIMARY KEY,
    labels_printed INTEGER NOT NULL DEFAULT 0 CHECK (labels_printed >= 0),
    unlocked INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  , last_seen_at INTEGER, account_id TEXT REFERENCES accounts(id), device_id TEXT REFERENCES devices(id));
  CREATE TABLE stripe_events (
    id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE stripe_purchases (
    payment_intent_id TEXT PRIMARY KEY,
    app_session_id TEXT REFERENCES app_sessions(id),
    status TEXT NOT NULL CHECK (status IN ('active', 'refunded', 'disputed')),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  , checkout_session_id TEXT, email_hash TEXT, email_masked TEXT, order_ref TEXT, amount_total INTEGER, currency TEXT, transfers_used INTEGER NOT NULL DEFAULT 0 CHECK (transfers_used >= 0), transfer_limit INTEGER NOT NULL DEFAULT 1 CHECK (transfer_limit >= 0), last_transfer_at TEXT, status_event_created INTEGER, account_id TEXT REFERENCES accounts(id), license_policy TEXT NOT NULL DEFAULT 'legacy' CHECK (license_policy IN ('legacy', 'single_device')));
  CREATE INDEX stripe_purchases_email_hash ON stripe_purchases(email_hash);
  CREATE INDEX stripe_purchases_app_session ON stripe_purchases(app_session_id);
  CREATE TABLE license_transfers (
    id INTEGER PRIMARY KEY,
    payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
    from_app_session_id TEXT,
    to_app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
    transferred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX license_transfers_from ON license_transfers(from_app_session_id);
  CREATE TABLE email_verifications (
    id INTEGER PRIMARY KEY,
    payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
    app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX email_verifications_session ON email_verifications(app_session_id, consumed_at);
  CREATE TABLE rate_limits (
    key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 0)
  );
  CREATE TABLE email_outbox (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    payment_intent_id TEXT REFERENCES stripe_purchases(payment_intent_id),
    to_address TEXT,
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    sent_at INTEGER
  );
  CREATE INDEX email_outbox_due ON email_outbox(status, next_attempt_at);
  CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    email_hash TEXT NOT NULL UNIQUE,
    email_masked TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at INTEGER NOT NULL
  );
  CREATE TABLE account_codes (
    id INTEGER PRIMARY KEY,
    email_hash TEXT NOT NULL,
    app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX account_codes_session ON account_codes(app_session_id, consumed_at);
  CREATE INDEX account_codes_email ON account_codes(email_hash, created_at);
  CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    key_thumbprint TEXT NOT NULL UNIQUE,
    public_key_jwk TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    last_validated_at INTEGER,
    revoked_at INTEGER,
    revoke_reason TEXT,
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
  );
  CREATE UNIQUE INDEX devices_one_active ON devices(account_id) WHERE revoked_at IS NULL;
  CREATE TABLE trials (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    device_thumbprint TEXT NOT NULL UNIQUE,
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > started_at)
  );
  CREATE TABLE license_certificates (
    jti TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    kind TEXT NOT NULL CHECK (kind IN ('trial', 'paid')),
    kid TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER,
    revalidate_at INTEGER,
    grace_until INTEGER
  );
  CREATE INDEX license_certificates_device ON license_certificates(device_id, issued_at);
  CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    account_id TEXT,
    device_id TEXT,
    ip_hash TEXT
  );
  CREATE INDEX audit_events_account ON audit_events(account_id, at);
  CREATE INDEX audit_events_event ON audit_events(event, at);
  CREATE INDEX stripe_purchases_account ON stripe_purchases(account_id);
`;

function databaseAt(version, schema, seed = '') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  const file = new Database(path.join(dir, DB_FILE));
  file.pragma('journal_mode = WAL');
  file.exec(schema + seed);
  file.pragma(`user_version = ${version}`);
  file.close();
  return dir;
}

function schemaObjects(db) {
  return db.prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").all();
}

function columns(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map(({ name, type, notnull, dflt_value, pk }) =>
    ({ name, type, notnull, dflt_value, pk }));
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
    for (const table of ['license_transfers', 'email_verifications', 'rate_limits', 'email_outbox', ...V4_TABLES]) {
      assert.equal(first.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0);
    }
    assert.deepEqual(first.db.prepare(
      'SELECT payment_intent_id, license_policy, account_id FROM stripe_purchases ORDER BY payment_intent_id'
    ).all(), [
      { payment_intent_id: 'pi_legacy_orphan', license_policy: 'legacy', account_id: null },
      { payment_intent_id: 'pi_legacy_paid', license_policy: 'legacy', account_id: null },
      { payment_intent_id: 'pi_legacy_refunded', license_policy: 'legacy', account_id: null }
    ], 'purchases made before accounts keep the terms they were sold under');
    assert.deepEqual(first.db.prepare(
      'SELECT payment_intent_id, stripe_mode, stripe_mode_review_reference, stripe_mode_reviewed_at FROM stripe_purchases ORDER BY payment_intent_id'
    ).all(), [
      { payment_intent_id: 'pi_legacy_orphan', stripe_mode: null, stripe_mode_review_reference: null, stripe_mode_reviewed_at: null },
      { payment_intent_id: 'pi_legacy_paid', stripe_mode: null, stripe_mode_review_reference: null, stripe_mode_reviewed_at: null },
      { payment_intent_id: 'pi_legacy_refunded', stripe_mode: null, stripe_mode_review_reference: null, stripe_mode_reviewed_at: null }
    ], 'legacy purchases without a verifiable Checkout ID remain unclassified');
    assert.deepEqual(first.db.prepare('SELECT DISTINCT account_id, device_id FROM app_sessions').all(),
      [{ account_id: null, device_id: null }]);
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
  const dir = databaseAt(2, V2_SCHEMA, `
    INSERT INTO app_sessions (id, unlocked) VALUES ('v2-buyer', 1);
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, transfers_used, checkout_session_id)
      VALUES ('pi_v2', 'v2-buyer', 'active', 1, 'cs_test_v2');
    INSERT INTO stripe_events (id) VALUES ('evt_v2');
  `);
  try {
    const { db, migration } = openDatabase(dir);
    assert.equal(migration.from, 2);
    assert.equal(migration.to, SCHEMA_VERSION);
    assert.ok(migration.backupPath);
    assert.deepEqual(db.prepare('SELECT id, unlocked, last_seen_at FROM app_sessions').get(), { id: 'v2-buyer', unlocked: 1, last_seen_at: null });
    assert.deepEqual(db.prepare('SELECT app_session_id, status, transfers_used, license_policy FROM stripe_purchases').get(),
      { app_session_id: 'v2-buyer', status: 'active', transfers_used: 1, license_policy: 'legacy' });
    assert.equal(db.prepare('SELECT stripe_mode FROM stripe_purchases').get().stripe_mode, 'test');
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

test('a v3 database upgrades additively through v4: rows, columns and indexes stay, legacy terms are kept', () => {
  const dir = databaseAt(3, V3_SCHEMA, `
    INSERT INTO app_sessions (id, labels_printed, unlocked, last_seen_at) VALUES ('v3-buyer', 3, 1, 1700000000000),
      ('v3-new-device', 0, 0, NULL), ('v3-free', 12, 0, NULL);
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, email_hash, order_ref, transfers_used, transfer_limit)
      VALUES ('pi_v3_active', 'v3-buyer', 'active', 'hash-a', 'PL-AAAAAAAAAA', 0, 1),
             ('pi_v3_moved', 'v3-new-device', 'active', 'hash-b', 'PL-BBBBBBBBBB', 1, 1),
             ('pi_v3_refunded', NULL, 'refunded', NULL, NULL, 0, 1);
    INSERT INTO license_transfers (payment_intent_id, from_app_session_id, to_app_session_id) VALUES ('pi_v3_moved', 'old', 'v3-new-device');
    INSERT INTO email_outbox (kind, dedupe_key, payment_intent_id, to_address, payload, status, next_attempt_at, created_at)
      VALUES ('purchase_confirmation', 'purchase_confirmation:pi_v3_active', 'pi_v3_active', 'buyer@example.com', '{}', 'pending', 1, 1);
    INSERT INTO rate_limits (key, window_start, count) VALUES ('transfer-request:email:hash-a', 1, 2);
    INSERT INTO stripe_events (id) VALUES ('evt_v3');
  `);
  try {
    const before = new Database(path.join(dir, DB_FILE), { readonly: true });
    const v3Objects = schemaObjects(before);
    const v3Columns = Object.fromEntries(['app_sessions', 'stripe_purchases'].map((t) => [t, columns(before, t)]));
    const v3Rows = Object.fromEntries(['app_sessions', 'stripe_purchases', 'license_transfers', 'email_outbox', 'rate_limits', 'stripe_events']
      .map((t) => [t, before.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()]));
    before.close();

    const { db, migration } = openDatabase(dir);
    assert.equal(migration.from, 3);
    assert.equal(migration.to, SCHEMA_VERSION);

    // Nothing that existed is dropped or redefined; old columns keep their order, types and defaults.
    const after = schemaObjects(db);
    for (const object of v3Objects) assert.ok(after.some((o) => o.name === object.name && o.type === object.type), object.name);
    for (const [table, cols] of Object.entries(v3Columns)) assert.deepEqual(columns(db, table).slice(0, cols.length), cols, table);
    for (const [table, rows] of Object.entries(v3Rows)) {
      const keys = Object.keys(rows[0]);
      assert.deepEqual(db.prepare(`SELECT ${keys.join(', ')} FROM ${table} ORDER BY rowid`).all(), rows, table);
    }

    assert.deepEqual(columns(db, 'stripe_purchases').slice(-6), [
      { name: 'account_id', type: 'TEXT', notnull: 0, dflt_value: null, pk: 0 },
      { name: 'license_policy', type: 'TEXT', notnull: 1, dflt_value: "'legacy'", pk: 0 },
      { name: 'stripe_mode', type: 'TEXT', notnull: 0, dflt_value: null, pk: 0 },
      { name: 'stripe_mode_review_reference', type: 'TEXT', notnull: 0, dflt_value: null, pk: 0 },
      { name: 'stripe_mode_reviewed_at', type: 'INTEGER', notnull: 0, dflt_value: null, pk: 0 },
      { name: 'excluded_from_entitlements', type: 'INTEGER', notnull: 1, dflt_value: '0', pk: 0 }
    ]);
    assert.deepEqual(columns(db, 'app_sessions').slice(-2).map((c) => [c.name, c.notnull, c.dflt_value]),
      [['account_id', 0, null], ['device_id', 0, null]]);
    assert.deepEqual(db.prepare('SELECT DISTINCT license_policy, account_id FROM stripe_purchases').all(),
      [{ license_policy: 'legacy', account_id: null }]);
    for (const table of V4_TABLES) assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0, table);
    assert.equal(db.pragma('foreign_key_check').length, 0);
    assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');

    // The legacy transfer still works on migrated rows (same statement shape as server.js transferPurchase).
    const moved = db.prepare(`
      UPDATE stripe_purchases SET app_session_id = ?, transfers_used = transfers_used + 1
      WHERE payment_intent_id = ? AND status = 'active' AND transfers_used < transfer_limit AND app_session_id IS ?
    `).run('v3-free', 'pi_v3_active', 'v3-buyer');
    assert.equal(moved.changes, 1);
    db.close();

    const backup = new Database(migration.backupPath, { readonly: true });
    assert.match(path.basename(migration.backupPath), /^product-labels-v3-/);
    assert.equal(backup.pragma('user_version', { simple: true }), 3);
    assert.deepEqual(schemaObjects(backup), v3Objects, 'the backup is the untouched v3 database');
    backup.close();

    const again = openDatabase(dir);
    assert.deepEqual(again.migration, { from: SCHEMA_VERSION, to: SCHEMA_VERSION, backupPath: null });
    again.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a failing v4 step rolls back completely and leaves the v3 database usable', () => {
  // An unexpected object with the same name makes the v4 index creation fail mid-step.
  const dir = databaseAt(3, V3_SCHEMA, `
    CREATE TABLE license_certificates (jti TEXT PRIMARY KEY);
    INSERT INTO stripe_purchases (payment_intent_id, status) VALUES ('pi_keep', 'active');
  `);
  try {
    assert.throws(() => openDatabase(dir), /no such column: device_id/);
    const db = new Database(path.join(dir, DB_FILE), { readonly: true });
    assert.equal(db.pragma('user_version', { simple: true }), 3);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
    for (const table of V4_TABLES.filter((t) => t !== 'license_certificates')) assert.ok(!tables.includes(table), table);
    assert.ok(!columns(db, 'stripe_purchases').some((c) => c.name === 'license_policy'));
    assert.ok(!columns(db, 'app_sessions').some((c) => c.name === 'account_id'));
    assert.deepEqual(db.prepare('SELECT payment_intent_id, status FROM stripe_purchases').all(), [{ payment_intent_id: 'pi_keep', status: 'active' }]);
    db.close();
    assert.equal(fs.readdirSync(path.join(dir, 'backups')).length, 1, 'the pre-migration backup was still taken');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('v4 constraints: one active device per account, one trial per account and device, valid policies only', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  try {
    const { db } = openDatabase(dir);
    db.exec(`
      INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acc-1', 'h1', 'a***@e***.com', 1), ('acc-2', 'h2', 'b***@e***.com', 1);
      INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at) VALUES ('dev-1', 'acc-1', 'tp-1', '{}', 1);
    `);
    const addDevice = db.prepare('INSERT INTO devices (id, account_id, key_thumbprint, public_key_jwk, registered_at) VALUES (?, ?, ?, ?, 1)');
    assert.throws(() => addDevice.run('dev-2', 'acc-1', 'tp-2', '{}'), /UNIQUE constraint failed: devices.account_id/);
    assert.throws(() => addDevice.run('dev-3', 'acc-2', 'tp-1', '{}'), /UNIQUE constraint failed: devices.key_thumbprint/);
    assert.throws(() => addDevice.run('dev-4', 'acc-missing', 'tp-4', '{}'), /FOREIGN KEY constraint failed/);
    assert.throws(() => db.prepare("UPDATE devices SET revoked_at = 5 WHERE id = 'dev-1'").run(), /CHECK constraint failed/,
      'a revoked device must record why');
    db.prepare("UPDATE devices SET revoked_at = 5, revoke_reason = 'support_recovery' WHERE id = 'dev-1'").run();
    addDevice.run('dev-2', 'acc-1', 'tp-2', '{}');
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM devices WHERE account_id = 'acc-1'").get().n, 2, 'revoked devices stay as history');

    const addTrial = db.prepare('INSERT INTO trials (account_id, device_thumbprint, started_at, expires_at) VALUES (?, ?, ?, ?)');
    addTrial.run('acc-1', 'tp-1', 0, 48 * 60 * 60 * 1000);
    assert.throws(() => addTrial.run('acc-1', 'tp-9', 0, 1), /UNIQUE constraint failed: trials.account_id/);
    assert.throws(() => addTrial.run('acc-2', 'tp-1', 0, 1), /UNIQUE constraint failed: trials.device_thumbprint/);
    assert.throws(() => addTrial.run('acc-2', 'tp-5', 10, 10), /CHECK constraint failed/);

    assert.throws(() => db.prepare("INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acc-3', 'h1', 'x', 1)").run(),
      /UNIQUE constraint failed: accounts.email_hash/);
    assert.throws(() => db.prepare("INSERT INTO accounts (id, email_hash, email_masked, status, created_at) VALUES ('acc-4', 'h4', 'x', 'deleted', 1)").run(),
      /CHECK constraint failed/);
    assert.throws(() => db.prepare("INSERT INTO license_certificates (jti, device_id, kind, kid, issued_at) VALUES ('j1', 'dev-2', 'free', 'k1', 1)").run(),
      /CHECK constraint failed/);

    // Purchases written the way server.js writes them today still default to the legacy terms.
    db.prepare("INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status) VALUES ('pi_today', NULL, 'active')").run();
    assert.equal(db.prepare("SELECT license_policy FROM stripe_purchases WHERE payment_intent_id = 'pi_today'").get().license_policy, 'legacy');
    assert.throws(() => db.prepare("UPDATE stripe_purchases SET license_policy = 'transferable' WHERE payment_intent_id = 'pi_today'").run(),
      /CHECK constraint failed/);
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a v4 database upgrades additively through current schema: legacy terms stay untouched', () => {
  const dir = databaseAt(4, V4_SCHEMA, `
    INSERT INTO app_sessions (id, labels_printed, unlocked, last_seen_at) VALUES ('v4-buyer', 2, 1, 1700000000000), ('v4-free', 7, 0, NULL);
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, email_hash, order_ref, transfers_used, transfer_limit)
      VALUES ('pi_v4_legacy', 'v4-buyer', 'active', 'hash-a', 'PL-CCCCCCCCCC', 0, 1);
    INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acc-v4', 'hash-b', 'b***@e***.com', 1);
    INSERT INTO account_codes (email_hash, app_session_id, code_hash, expires_at, created_at) VALUES ('hash-b', 'v4-free', 'h', 2, 1);
    INSERT INTO audit_events (at, event, outcome, account_id) VALUES (1, 'account_created', 'ok', 'acc-v4');
  `);
  try {
    const before = new Database(path.join(dir, DB_FILE), { readonly: true });
    const v4Objects = schemaObjects(before);
    const tables = ['app_sessions', 'stripe_purchases', 'accounts', 'account_codes', 'audit_events'];
    const v4Columns = Object.fromEntries(tables.map((t) => [t, columns(before, t)]));
    const v4Rows = Object.fromEntries(tables.map((t) => [t, before.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()]));
    before.close();

    const { db, migration } = openDatabase(dir);
    assert.equal(SCHEMA_VERSION, 8);
    assert.equal(migration.from, 4);
    assert.equal(migration.to, 8);
    const after = schemaObjects(db);
    assert.deepEqual(after.filter((o) => !v4Objects.some((v) => v.name === o.name)).map((o) => o.name).sort(), [
      'account_mfa_challenges', 'account_mfa_challenges_session', 'account_recovery_codes',
      'account_recovery_codes_unused', 'account_sessions', 'account_sessions_account',
      'account_sessions_app_session', 'account_totp', 'device_recoveries', 'device_recoveries_account_time'
    ]);
    for (const object of v4Objects) assert.ok(after.some((o) => o.name === object.name && o.type === object.type), object.name);
    for (const table of tables) {
      const expectedColumns = table === 'stripe_purchases'
        ? [...v4Columns[table],
          { name: 'stripe_mode', type: 'TEXT', notnull: 0, dflt_value: null, pk: 0 },
          { name: 'stripe_mode_review_reference', type: 'TEXT', notnull: 0, dflt_value: null, pk: 0 },
          { name: 'stripe_mode_reviewed_at', type: 'INTEGER', notnull: 0, dflt_value: null, pk: 0 },
          { name: 'excluded_from_entitlements', type: 'INTEGER', notnull: 1, dflt_value: '0', pk: 0 }]
        : v4Columns[table];
      assert.deepEqual(columns(db, table), expectedColumns, table);
      const oldColumns = v4Columns[table].map((column) => `"${column.name}"`).join(', ');
      assert.deepEqual(db.prepare(`SELECT ${oldColumns} FROM ${table} ORDER BY rowid`).all(), v4Rows[table], table);
    }
    assert.deepEqual(columns(db, 'account_sessions').map((c) => [c.name, c.notnull]), [
      ['token_hash', 1], ['account_id', 1], ['app_session_id', 1], ['created_at', 1], ['expires_at', 1], ['revoked_at', 0]
    ]);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM account_sessions').get().n, 0);
    assert.deepEqual(db.prepare('SELECT license_policy, account_id FROM stripe_purchases').all(), [{ license_policy: 'legacy', account_id: null }]);
    assert.equal(db.pragma('foreign_key_check').length, 0);
    assert.equal(db.pragma('integrity_check', { simple: true }), 'ok');
    db.close();

    const backup = new Database(migration.backupPath, { readonly: true });
    assert.match(path.basename(migration.backupPath), /^product-labels-v4-/);
    assert.deepEqual(schemaObjects(backup), v4Objects, 'the backup is the untouched v4 database');
    backup.close();
    const again = openDatabase(dir);
    assert.deepEqual(again.migration, { from: 8, to: 8, backupPath: null });
    again.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('v4 purchase modes are backfilled only from valid Stripe Checkout ID prefixes', () => {
  const dir = databaseAt(4, V4_SCHEMA, `
    INSERT INTO app_sessions (id, unlocked) VALUES
      ('mode-test-session', 1), ('mode-live-session', 1), ('mode-unknown-session', 1);
    INSERT INTO stripe_purchases (payment_intent_id, app_session_id, status, checkout_session_id)
      VALUES ('pi_mode_test', 'mode-test-session', 'active', 'cs_test_valid123'),
             ('pi_mode_live', 'mode-live-session', 'active', 'cs_live_valid456'),
             ('pi_mode_unknown', 'mode-unknown-session', 'active', NULL);
  `);
  try {
    const { db, migration } = openDatabase(dir);
    assert.equal(migration.from, 4);
    assert.equal(migration.to, SCHEMA_VERSION);
    assert.deepEqual(db.prepare(`
      SELECT payment_intent_id, stripe_mode, stripe_mode_review_reference, stripe_mode_reviewed_at, status
      FROM stripe_purchases ORDER BY payment_intent_id
    `).all(), [
      { payment_intent_id: 'pi_mode_live', stripe_mode: 'live', stripe_mode_review_reference: null, stripe_mode_reviewed_at: null, status: 'active' },
      { payment_intent_id: 'pi_mode_test', stripe_mode: 'test', stripe_mode_review_reference: null, stripe_mode_reviewed_at: null, status: 'active' },
      { payment_intent_id: 'pi_mode_unknown', stripe_mode: null, stripe_mode_review_reference: null, stripe_mode_reviewed_at: null, status: 'active' }
    ]);
    assert.deepEqual(db.prepare('SELECT id, unlocked FROM app_sessions ORDER BY id').all(), [
      { id: 'mode-live-session', unlocked: 1 },
      { id: 'mode-test-session', unlocked: 1 },
      { id: 'mode-unknown-session', unlocked: 1 }
    ], 'classification never grants or revokes an existing entitlement');
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a failing v5 step rolls back completely and leaves the v4 database usable', () => {
  const dir = databaseAt(4, V4_SCHEMA, `
    CREATE TABLE account_sessions (token_hash TEXT PRIMARY KEY);
    INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acc-keep', 'h', 'x', 1);
  `);
  try {
    assert.throws(() => openDatabase(dir), /no such column: account_id/);
    const db = new Database(path.join(dir, DB_FILE), { readonly: true });
    assert.equal(db.pragma('user_version', { simple: true }), 4);
    assert.deepEqual(columns(db, 'account_sessions').map((c) => c.name), ['token_hash']);
    assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'account_sessions_%'").all().length, 0);
    assert.deepEqual(db.prepare('SELECT id FROM accounts').all(), [{ id: 'acc-keep' }]);
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('v5 constraints: account sessions need a real account and app session and a positive lifetime', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-migration-'));
  try {
    const { db } = openDatabase(dir);
    db.exec(`
      INSERT INTO app_sessions (id) VALUES ('app-1');
      INSERT INTO accounts (id, email_hash, email_masked, created_at) VALUES ('acc-1', 'h1', 'a***@e***.com', 1);
    `);
    const add = db.prepare('INSERT INTO account_sessions (token_hash, account_id, app_session_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)');
    add.run('t1', 'acc-1', 'app-1', 1, 2);
    assert.throws(() => add.run('t1', 'acc-1', 'app-1', 1, 2), /UNIQUE constraint failed: account_sessions.token_hash/);
    assert.throws(() => add.run('t2', 'acc-missing', 'app-1', 1, 2), /FOREIGN KEY constraint failed/);
    assert.throws(() => add.run('t3', 'acc-1', 'app-missing', 1, 2), /FOREIGN KEY constraint failed/);
    assert.throws(() => add.run('t4', 'acc-1', 'app-1', 5, 5), /CHECK constraint failed/);
    assert.throws(() => add.run(null, 'acc-1', 'app-1', 1, 2), /NOT NULL constraint failed: account_sessions.token_hash/);
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
