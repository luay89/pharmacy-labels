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
  },
  function accountsAndDevices(db) {
    // accounts, account_codes and audit_events are in use; devices, trials and certificates not yet. Accounts are created only after an email
    // code is verified; times are server milliseconds; email_hash uses the same keyed hash as purchases.
    db.exec(`
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email_hash TEXT NOT NULL UNIQUE,
        email_masked TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS account_codes (
        id INTEGER PRIMARY KEY,
        email_hash TEXT NOT NULL,
        app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS account_codes_session ON account_codes(app_session_id, consumed_at);
      CREATE INDEX IF NOT EXISTS account_codes_email ON account_codes(email_hash, created_at);
      CREATE TABLE IF NOT EXISTS devices (
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
      -- One active device per account; revoked rows stay as history (support recoveries are counted from them).
      CREATE UNIQUE INDEX IF NOT EXISTS devices_one_active ON devices(account_id) WHERE revoked_at IS NULL;
      -- One trial per account and per device key, ever. Rows are never deleted.
      CREATE TABLE IF NOT EXISTS trials (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id),
        device_thumbprint TEXT NOT NULL UNIQUE,
        started_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK (expires_at > started_at)
      );
      CREATE TABLE IF NOT EXISTS license_certificates (
        jti TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id),
        kind TEXT NOT NULL CHECK (kind IN ('trial', 'paid')),
        kid TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        revalidate_at INTEGER,
        grace_until INTEGER
      );
      CREATE INDEX IF NOT EXISTS license_certificates_device ON license_certificates(device_id, issued_at);
      -- No foreign keys on purpose: the audit trail must outlive whatever it describes.
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL,
        event TEXT NOT NULL,
        outcome TEXT NOT NULL,
        account_id TEXT,
        device_id TEXT,
        ip_hash TEXT
      );
      CREATE INDEX IF NOT EXISTS audit_events_account ON audit_events(account_id, at);
      CREATE INDEX IF NOT EXISTS audit_events_event ON audit_events(event, at);
    `);
    // Every purchase made so far keeps the terms it was sold under, including its transfer allowance.
    addColumns(db, 'stripe_purchases', [
      ['account_id', 'TEXT REFERENCES accounts(id)'],
      ['license_policy', "TEXT NOT NULL DEFAULT 'legacy' CHECK (license_policy IN ('legacy', 'single_device'))"]
    ]);
    addColumns(db, 'app_sessions', [
      ['account_id', 'TEXT REFERENCES accounts(id)'],
      ['device_id', 'TEXT REFERENCES devices(id)']
    ]);
    db.exec('CREATE INDEX IF NOT EXISTS stripe_purchases_account ON stripe_purchases(account_id)');
  },
  function accountSessions(db) {
    // Sign-ins live beside the anonymous app session, never in place of it: legacy licenses stay bound to
    // app_sessions.id, so that id must not change. Only a keyed hash of the cookie token is stored; a
    // session is usable only from the app session that signed in, and revoked rows stay as history.
    db.exec(`
      CREATE TABLE IF NOT EXISTS account_sessions (
        token_hash TEXT NOT NULL PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
        revoked_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS account_sessions_account ON account_sessions(account_id, revoked_at);
      CREATE INDEX IF NOT EXISTS account_sessions_app_session ON account_sessions(app_session_id, revoked_at);
    `);
  },
  function accountTwoFactor(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS account_totp (
        account_id TEXT NOT NULL PRIMARY KEY REFERENCES accounts(id),
        secret_sealed TEXT NOT NULL,
        enabled_at INTEGER,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS account_mfa_challenges (
        token_hash TEXT NOT NULL PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        app_session_id TEXT NOT NULL REFERENCES app_sessions(id),
        intent TEXT NOT NULL CHECK (intent IN ('signup', 'login')),
        replaced_token_hash TEXT,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
        consumed_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS account_mfa_challenges_session ON account_mfa_challenges(app_session_id, expires_at);
      CREATE TABLE IF NOT EXISTS account_recovery_codes (
        id INTEGER PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        UNIQUE(account_id, code_hash)
      );
      CREATE INDEX IF NOT EXISTS account_recovery_codes_unused ON account_recovery_codes(account_id, used_at);
    `);
  },
  function deviceRecoveryAudit(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS device_recoveries (
        id INTEGER PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        payment_intent_id TEXT NOT NULL REFERENCES stripe_purchases(payment_intent_id),
        previous_device_id TEXT NOT NULL,
        recovered_at INTEGER NOT NULL,
        ticket TEXT NOT NULL CHECK (length(ticket) BETWEEN 3 AND 64),
        reason TEXT NOT NULL CHECK (length(reason) BETWEEN 8 AND 500)
      );
      CREATE INDEX IF NOT EXISTS device_recoveries_account_time ON device_recoveries(account_id, recovered_at);
    `);
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
