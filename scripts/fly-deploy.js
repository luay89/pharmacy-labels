'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const PROJECT_ROOT = path.join(__dirname, '..');
const FLY_CONFIG_PATH = path.join(PROJECT_ROOT, 'fly.toml');
const EXPECTED = {
  region: 'fra',
  dataDir: '/data',
  volumeName: 'labels_data',
  port: 3000,
  healthPath: '/api/health'
};

function tomlValue(text, section, key) {
  let currentSection = '';
  const keyPattern = new RegExp(
    `^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(?:"([^"]*)"|(\\d+)|(true|false))\\s*(?:#.*)?$`
  );

  for (const line of text.split(/\r?\n/)) {
    const header = line.match(/^\s*\[{1,2}([^\]]+)\]{1,2}\s*(?:#.*)?$/);
    if (header) {
      currentSection = header[1].trim();
      continue;
    }

    if (currentSection !== section) continue;
    const match = line.match(keyPattern);
    if (!match) continue;
    if (match[1] !== undefined) return match[1];
    if (match[2] !== undefined) return Number(match[2]);
    return match[3] === 'true';
  }

  return undefined;
}

function requireValue(text, section, key, expected) {
  const actual = tomlValue(text, section, key);
  if (actual !== expected) {
    const location = section ? `[${section}].${key}` : key;
    throw new Error(`fly.toml must set ${location} to ${JSON.stringify(expected)}.`);
  }
}

function validateFlyConfig(text) {
  requireValue(text, '', 'app', 'product-labels-luay');
  requireValue(text, '', 'primary_region', EXPECTED.region);
  requireValue(text, '', 'kill_signal', 'SIGTERM');
  requireValue(text, '', 'kill_timeout', '15s');
  requireValue(text, 'env', 'NODE_ENV', 'production');
  requireValue(text, 'env', 'DATA_DIR', EXPECTED.dataDir);
  requireValue(text, 'env', 'PORT', String(EXPECTED.port));
  requireValue(text, 'env', 'TRUST_PROXY', '1');
  requireValue(text, 'env', 'PUBLIC_APP_URL', 'https://product-labels-luay.fly.dev');
  requireValue(text, 'mounts', 'source', EXPECTED.volumeName);
  requireValue(text, 'mounts', 'destination', EXPECTED.dataDir);
  requireValue(text, 'http_service', 'internal_port', EXPECTED.port);
  requireValue(text, 'http_service', 'force_https', true);
  requireValue(text, 'http_service', 'auto_stop_machines', 'off');
  requireValue(text, 'http_service', 'auto_start_machines', true);
  requireValue(text, 'http_service.checks', 'path', EXPECTED.healthPath);
  requireValue(text, 'http_service.checks', 'port', EXPECTED.port);
  requireValue(text, 'deploy', 'strategy', 'rolling');
  requireValue(text, 'deploy', 'max_unavailable', 1);
  if (tomlValue(text, 'http_service', 'min_machines_running') !== undefined) {
    throw new Error('Remove http_service.min_machines_running; it is not a Machine-count cap.');
  }
  return tomlValue(text, '', 'app');
}

function parseJsonArray(output, description) {
  let value;
  try {
    value = JSON.parse(output);
  } catch (error) {
    throw new Error(`Fly CLI returned invalid JSON for ${description}: ${error.message}`);
  }
  if (!Array.isArray(value)) {
    throw new Error(`Fly CLI returned an unexpected ${description} response; expected a JSON array.`);
  }
  return value;
}

function validateFlyInventory(machines, volumes) {
  if (!Array.isArray(machines) || !Array.isArray(volumes)) {
    throw new Error('Fly inventory is incomplete; refusing deployment.');
  }
  if (machines.length > 1) {
    throw new Error(`Found ${machines.length} Fly Machines; SQLite deployment requires exactly one. Refusing deployment.`);
  }

  const attachedVolumes = volumes.filter((volume) =>
    volume && volume.state !== 'destroyed' && volume.attached_machine_id
  );
  const dataVolumes = volumes.filter((volume) =>
    volume && volume.name === EXPECTED.volumeName && volume.state !== 'destroyed'
  );
  if (dataVolumes.length !== 1) {
    throw new Error(`Expected exactly one non-destroyed ${EXPECTED.volumeName} volume; found ${dataVolumes.length}. Refusing deployment.`);
  }

  const [volume] = dataVolumes;
  if (volume.region !== EXPECTED.region || volume.state !== 'created') {
    throw new Error(`${EXPECTED.volumeName} must be a created volume in ${EXPECTED.region}. Refusing deployment.`);
  }

  if (machines.length === 0) {
    if (attachedVolumes.length > 0) {
      throw new Error(`${EXPECTED.volumeName} is reported attached to a Machine missing from the Machine list. Refusing deployment.`);
    }
    return { mode: 'bootstrap', volume };
  }

  const [machine] = machines;
  if (!machine || typeof machine.id !== 'string' || machine.region !== EXPECTED.region || machine.state !== 'started') {
    throw new Error(`The sole Fly Machine must be started in ${EXPECTED.region}. Refusing deployment.`);
  }
  if (volume.attached_machine_id !== machine.id) {
    throw new Error(`${EXPECTED.volumeName} is not attached to the sole Fly Machine. Refusing deployment.`);
  }
  if (attachedVolumes.length !== 1 || attachedVolumes[0].id !== volume.id) {
    throw new Error('Unexpected attached Fly volumes were found. Refusing deployment.');
  }

  const mounts = machine.config && machine.config.mounts;
  if (!Array.isArray(mounts) || mounts.length !== 1 ||
      mounts[0].path !== EXPECTED.dataDir || mounts[0].volume !== volume.id) {
    throw new Error(`The sole Fly Machine must mount ${EXPECTED.volumeName} at ${EXPECTED.dataDir}. Refusing deployment.`);
  }

  return { mode: 'existing', machine, volume };
}

function runFly(args, inherit = false) {
  const result = spawnSync('fly', args, {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    stdio: inherit ? 'inherit' : 'pipe'
  });
  if (result.error) {
    throw new Error(`Could not run Fly CLI: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = result.stderr && result.stderr.trim();
    throw new Error(
      `Fly CLI command failed (exit ${result.status}): fly ${args.join(' ')}${detail ? `\n${detail}` : ''}`
    );
  }
  return result;
}

function readInventory(run, app) {
  const machinesOutput = run(['machine', 'list', '--app', app, '--json']);
  const volumesOutput = run(['volumes', 'list', '--app', app, '--json']);
  return {
    machines: parseJsonArray(machinesOutput.stdout, 'Machine list'),
    volumes: parseJsonArray(volumesOutput.stdout, 'volume list')
  };
}

function preflight({ run = runFly, configText = fs.readFileSync(FLY_CONFIG_PATH, 'utf8') } = {}) {
  const app = validateFlyConfig(configText);
  const inventory = readInventory(run, app);
  const state = validateFlyInventory(inventory.machines, inventory.volumes);
  return { app, ...state };
}

function deploySafely({ run = runFly, configText = fs.readFileSync(FLY_CONFIG_PATH, 'utf8') } = {}) {
  const { app, mode } = preflight({ run, configText });
  const deployResult = run(['deploy', '--app', app, '--ha=false', '--strategy', 'rolling'], true);
  if (deployResult.status !== 0) {
    throw new Error(`Fly deployment failed (exit ${deployResult.status}).`);
  }

  const inventory = readInventory(run, app);
  validateFlyInventory(inventory.machines, inventory.volumes);
  return { app, mode };
}

function main(command) {
  if (command !== 'check' && command !== 'deploy') {
    throw new Error('Usage: node scripts/fly-deploy.js <check|deploy>');
  }
  if (command === 'check') {
    const { app, mode } = preflight();
    console.log(`Fly pre-deployment check passed for ${app} (${mode}).`);
    return;
  }

  const { app, mode } = deploySafely();
  console.log(`Fly deployment completed and single-Machine state verified for ${app} (${mode}).`);
}

if (require.main === module) {
  try {
    main(process.argv[2]);
  } catch (error) {
    console.error(`Fly deployment blocked: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = {
  deploySafely,
  parseJsonArray,
  preflight,
  tomlValue,
  validateFlyConfig,
  validateFlyInventory
};
