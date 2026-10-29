'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const DB_FILE = 'product-labels.sqlite';

function columnNames(db, table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name));
}

function addColumns(db, table, definitions) {
  const existing = columnNames(db, table);
  for (const [name, definition] of definitions) {
    if (!existing.has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
  }
}

// Each entry upgrades the schema by one version. Steps must be additive and safe to re-run.
const MIGRATIONS = [
  function baseSchema(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS app_sessions (
        id TEXT PRIMARY KEY,
        labels_printed INTEGER NOT NULL DEFAULT 0 CHECK (labels_printed >= 0),
        unlocked INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS stripe_events (
        id TEXT PRIMARY KEY,
        received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS stripe_purchases (
        payment_intent_id TEXT PRIMARY KEY,
        app_session_id TEXT REFERENCES app_sessions(id),
        status TEXT NOT NULL CHECK (status IN ('active', 'refunded', 'disputed')),
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
  },
  function singleDeviceLicenses(db) {
    addColumns(db, 'stripe_purchases', [
      ['checkout_session_id', 'TEXT'],
      ['email_hash', 'TEXT'],
      ['email_masked', 'TEXT'],
      ['order_ref', 'TEXT'],
      ['amount_total', 'INTEGER'],
      ['currency', 'TEXT'],
      ['transfers_used', 'INTEGER NOT NULL DEFAULT 0 CHECK (transfers_used >= 0)'],
      ['transfer_limit', 'INTEGER NOT NULL DEFAULT 1 CHECK (transfer_limit >= 0)'],
      ['last_transfer_at', 'TEXT'],
      ['status_event_created', 'INTEGER']
    ]);
    db.exec(`
      CREATE INDEX IF NOT EXISTS stripe_purchases_email_hash ON stripe_purchases(email_hash);
      CREATE INDEX IF NOT EXISTS stripe_purchases_app_session ON stripe_purchases(app_session_id);
      CREATE TABLE IF NOT EXISTS license_transfers (
        id INTEGER PRIMARY KEY,
        payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
        from_app_session_id TEXT,
        to_app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
        transferred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS license_transfers_from ON license_transfers(from_app_session_id);
      CREATE TABLE IF NOT EXISTS email_verifications (
        id INTEGER PRIMARY KEY,
        payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
        app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS email_verifications_session ON email_verifications(app_session_id, consumed_at);
      CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        count INTEGER NOT NULL CHECK (count >= 0)
      );
      CREATE TABLE IF NOT EXISTS email_outbox (
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
      CREATE INDEX IF NOT EXISTS email_outbox_due ON email_outbox(status, next_attempt_at);
    `);
  },
  function sessionActivity(db) {
    // Last cookie renewal (ms). NULL for older sessions, which fall back to created_at.
    addColumns(db, 'app_sessions', [['last_seen_at', 'INTEGER']]);
  }
];

const SCHEMA_VERSION = MIGRATIONS.length;

function hasUserTables(db) {
  return Boolean(db.prepare(
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
  ).get());
}

function backupDatabase(db, dataDir, version, label = '') {
  const backupDir = path.join(dataDir, 'backups');
  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const target = path.join(backupDir, `product-labels-v${version}${label}-${stamp}.sqlite`);
  db.prepare('VACUUM INTO ?').run(target);
  fs.chmodSync(target, 0o600);
  return target;
}

function migrate(db, { dataDir } = {}) {
  const current = db.pragma('user_version', { simple: true });
  if (current > SCHEMA_VERSION) {
    throw new Error(`Database schema v${current} is newer than this server (v${SCHEMA_VERSION}).`);
  }
  let backupPath = null;
  if (current < SCHEMA_VERSION && dataDir && hasUserTables(db)) {
    backupPath = backupDatabase(db, dataDir, current);
  }
  for (let version = current; version < SCHEMA_VERSION; version += 1) {
    db.transaction(() => {
      MIGRATIONS[version](db);
      db.pragma(`user_version = ${version + 1}`);
    }).immediate();
  }
  return { from: current, to: SCHEMA_VERSION, backupPath };
}

function openDatabase(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(dataDir, DB_FILE);
  const db = new Database(file);
  // Owner-only; SQLite creates the -wal/-shm files with the same mode as the database.
  fs.chmodSync(file, 0o600);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  const result = migrate(db, { dataDir });
  return { db, migration: result };
}

// Consistent snapshot of a live database (safe while the server runs, thanks to WAL); never migrates.
function backupNow(dataDir) {
  const db = new Database(path.join(dataDir, DB_FILE), { readonly: true, fileMustExist: true });
  let target;
  try {
    target = backupDatabase(db, dataDir, db.pragma('user_version', { simple: true }), '-manual');
  } finally {
    db.close();
  }
  const copy = new Database(target, { readonly: true });
  try {
    const result = copy.pragma('quick_check', { simple: true });
    if (result !== 'ok') throw new Error(`backup failed its integrity check (${result})`);
  } finally {
    copy.close();
  }
  return target;
}

module.exports = { openDatabase, migrate, backupNow, SCHEMA_VERSION, DB_FILE };
