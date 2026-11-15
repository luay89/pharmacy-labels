'use strict';

// Runs the real server process: live backup, then a clean SIGTERM shutdown like a redeploy.
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const Database = require('better-sqlite3');

const root = path.join(__dirname, '..');
const PORT = 31895;

test('a live backup is consistent and SIGTERM closes the database cleanly', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-ops-'));
  const env = {
    PATH: process.env.PATH, PORT: String(PORT), DATA_DIR: dataDir,
    SESSION_SECRET: 'ops-test-secret-with-at-least-32-characters', PUBLIC_APP_URL: `http://127.0.0.1:${PORT}`
  };
  const child = spawn(process.execPath, ['server.js'], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  try {
    for (let i = 0; i < 100 && !output.includes('listening'); i++) await new Promise((r) => setTimeout(r, 50));
    assert.match(output, /listening/);
    const cookie = (await fetch(`http://127.0.0.1:${PORT}/api/session`)).headers.get('set-cookie');
    assert.ok(cookie);

    const log = execFileSync(process.execPath, ['backup.js'], { cwd: root, env, encoding: 'utf8' });
    assert.match(log, /Backup written: backups[\\/]product-labels-v\d+-manual-.+\.sqlite \(inside DATA_DIR\)/);
    assert.ok(!log.includes(dataDir), 'the backup log does not print server paths');
    const [file] = fs.readdirSync(path.join(dataDir, 'backups'));
    const backupPath = path.join(dataDir, 'backups', file);
    assert.equal(fs.statSync(backupPath).mode & 0o777, 0o600);
    const backup = new Database(backupPath, { readonly: true });
    assert.equal(backup.prepare('SELECT COUNT(*) AS n FROM app_sessions').get().n, 1);
    backup.close();

    child.kill('SIGTERM');
    assert.deepEqual(await exited, { code: 0, signal: null });
    assert.match(output, /SIGTERM received, shutting down\./);
    assert.equal(fs.existsSync(path.join(dataDir, 'product-labels.sqlite-wal')), false, 'WAL checkpointed on close');
  } finally {
    if (child.exitCode === null) child.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  }

  const missing = fs.mkdtempSync(path.join(os.tmpdir(), 'product-labels-ops-'));
  try {
    assert.throws(() => execFileSync(process.execPath, ['backup.js'], { cwd: root, env: { PATH: process.env.PATH, DATA_DIR: missing }, stdio: 'pipe' }));
    assert.equal(fs.existsSync(path.join(missing, 'product-labels.sqlite')), false, 'backup never creates an empty database');
  } finally {
    fs.rmSync(missing, { recursive: true, force: true });
  }
});
