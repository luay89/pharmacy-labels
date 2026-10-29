'use strict';

// npm run backup: writes DATA_DIR/backups/product-labels-v<schema>-manual-<time>.sqlite (mode 0600).
const path = require('node:path');
const { backupNow } = require('./db');

const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
try {
  console.log(`Backup written: ${path.relative(dataDir, backupNow(dataDir))} (inside DATA_DIR)`);
} catch (error) {
  console.error(`Backup failed: ${error.message}`);
  process.exitCode = 1;
}
