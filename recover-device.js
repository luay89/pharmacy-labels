'use strict';

const path = require('node:path');
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

function recoverDevice(db, { orderRef, ticket, reason, now = Date.now() }) {
  if (!/^PL-[A-Z0-9]{10}$/.test(orderRef || '') || !/^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/.test(ticket || '') ||
      typeof reason !== 'string' || reason.trim().length < 8 || reason.trim().length > 500 ||
      /[\r\n\0]/.test(reason)) {
    return { error: 'invalid_input' };
  }

  return db.transaction(() => {
    const purchase = db.prepare(`SELECT payment_intent_id, account_id, status, license_policy
      FROM stripe_purchases WHERE order_ref = ?`).get(orderRef);
    if (!purchase || !purchase.account_id || purchase.status !== 'active' || purchase.license_policy !== 'single_device') {
      return { error: 'purchase_unavailable' };
    }
    const account = db.prepare('SELECT status FROM accounts WHERE id = ?').get(purchase.account_id);
    if (!account || account.status !== 'active') return { error: 'account_unavailable' };
    if (db.prepare('SELECT 1 FROM device_recoveries WHERE account_id = ? AND recovered_at > ? LIMIT 1')
      .get(purchase.account_id, now - YEAR_MS)) return { error: 'recovery_limit' };
    const device = db.prepare('SELECT id FROM devices WHERE account_id = ? AND revoked_at IS NULL').get(purchase.account_id);
    if (!device) return { error: 'device_not_found' };
    const revoked = db.prepare(`UPDATE devices SET revoked_at = ?, revoke_reason = 'support_recovery'
      WHERE id = ? AND account_id = ? AND revoked_at IS NULL`).run(now, device.id, purchase.account_id);
    if (revoked.changes !== 1) return { error: 'device_changed' };
    db.prepare(`INSERT INTO device_recoveries
      (account_id, payment_intent_id, previous_device_id, recovered_at, ticket, reason)
      VALUES (?, ?, ?, ?, ?, ?)`).run(purchase.account_id, purchase.payment_intent_id, device.id, now, ticket, reason.trim());
    db.prepare('UPDATE account_sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL')
      .run(now, purchase.account_id);
    db.prepare(`INSERT INTO audit_events (at, event, outcome, account_id, device_id)
      VALUES (?, 'device_recovery', 'approved', ?, ?)`).run(now, purchase.account_id, device.id);
    return { recovered: true };
  }).immediate();
}

function readArgs(args) {
  const values = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--apply') values.apply = true;
    else if (['--order-ref', '--ticket', '--reason'].includes(arg) && args[i + 1]) values[arg.slice(2)] = args[++i];
    else if (arg === '--help') values.help = true;
    else throw new Error('Invalid command arguments.');
  }
  return values;
}

function main() {
  const args = readArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write('Usage: DATA_DIR=/secure/path node recover-device.js --order-ref PL-XXXXXXXXXX --ticket TICKET --reason "support case" --apply\n');
    return;
  }
  if (!args.apply || !args['order-ref'] || !args.ticket || !args.reason) {
    throw new Error('Recovery requires --order-ref, --ticket, --reason, and explicit --apply.');
  }
  const dataDir = process.env.DATA_DIR;
  if (!dataDir || path.resolve(dataDir) === path.join(__dirname, 'data')) {
    throw new Error('Set DATA_DIR to the production database directory explicitly.');
  }
  const { openDatabase, SCHEMA_VERSION, DB_FILE } = require('./db');
  const Database = require('better-sqlite3');
  const databasePath = path.join(path.resolve(dataDir), DB_FILE);
  const inspection = new Database(databasePath, { readonly: true, fileMustExist: true });
  const currentVersion = inspection.pragma('user_version', { simple: true });
  inspection.close();
  if (currentVersion !== SCHEMA_VERSION) throw new Error('Database schema is not current; migrate and review it separately first.');
  const { db } = openDatabase(path.resolve(dataDir));
  try {
    const result = recoverDevice(db, { orderRef: args['order-ref'], ticket: args.ticket, reason: args.reason });
    if (result.error) throw new Error(`Recovery refused (${result.error}).`);
    process.stdout.write('Device recovery recorded. The customer can sign in and register a replacement device.\n');
  } finally {
    db.close();
  }
}

if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { recoverDevice, YEAR_MS };
