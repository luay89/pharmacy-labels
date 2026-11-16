'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const {
  deploySafely,
  validateFlyConfig,
  validateFlyInventory
} = require('../scripts/fly-deploy');

const root = path.join(__dirname, '..');
const config = fs.readFileSync(path.join(root, 'fly.toml'), 'utf8');

function oneMachineInventory() {
  const machine = {
    id: 'machine-1',
    region: 'fra',
    state: 'started',
    config: { mounts: [{ volume: 'vol-1', path: '/data' }] }
  };
  const volume = {
    id: 'vol-1',
    name: 'labels_data',
    region: 'fra',
    state: 'created',
    attached_machine_id: machine.id
  };
  return { machines: [machine], volumes: [volume] };
}

test('Fly config keeps the production volume, health check, region, and graceful shutdown aligned', () => {
  assert.equal(validateFlyConfig(config), 'product-labels-luay');
  assert.throws(() => validateFlyConfig(config.replace('DATA_DIR = "/data"', 'DATA_DIR = "/wrong"')), /DATA_DIR/);
  assert.throws(() => validateFlyConfig(config.replace('primary_region = "fra"', 'primary_region = "ams"')), /primary_region/);
  assert.throws(
    () => validateFlyConfig(config.replace('auto_start_machines = true', 'auto_start_machines = false')),
    /auto_start_machines/
  );
  assert.throws(
    () => validateFlyConfig(config.replace('auto_start_machines = true', 'auto_start_machines = true\n  min_machines_running = 1')),
    /not a Machine-count cap/
  );
});

test('preflight accepts only one started Machine attached to the sole data volume', () => {
  const inventory = oneMachineInventory();
  assert.equal(validateFlyInventory(inventory.machines, inventory.volumes).mode, 'existing');
  assert.throws(
    () => validateFlyInventory([...inventory.machines, { ...inventory.machines[0], id: 'machine-2' }], inventory.volumes),
    /requires exactly one/
  );
  assert.throws(
    () => validateFlyInventory(inventory.machines, [{ ...inventory.volumes[0], attached_machine_id: 'machine-2' }]),
    /not attached/
  );
  assert.throws(
    () => validateFlyInventory(inventory.machines, [{ ...inventory.volumes[0], id: 'other-volume' }]),
    /mount/
  );
  assert.throws(
    () => validateFlyInventory(inventory.machines, [...inventory.volumes, { ...inventory.volumes[0], id: 'vol-2' }]),
    /exactly one non-destroyed/
  );
});

test('initial deployment is allowed only with one unattached data volume and no Machines', () => {
  const inventory = oneMachineInventory();
  assert.equal(
    validateFlyInventory([], [{ ...inventory.volumes[0], attached_machine_id: null }]).mode,
    'bootstrap'
  );
  assert.throws(() => validateFlyInventory([], []), /Expected exactly one/);
  assert.throws(
    () => validateFlyInventory([], [{ ...inventory.volumes[0], attached_machine_id: 'orphan-machine' }]),
    /missing from the Machine list/
  );
});

test('deployment never invokes Fly deploy when preflight finds multiple Machines', () => {
  const inventory = oneMachineInventory();
  const calls = [];
  const run = (args, inherit = false) => {
    calls.push({ args, inherit });
    if (args[0] === 'machine') {
      return { status: 0, stdout: JSON.stringify([inventory.machines[0], { ...inventory.machines[0], id: 'machine-2' }]) };
    }
    if (args[0] === 'volumes') return { status: 0, stdout: JSON.stringify(inventory.volumes) };
    return { status: 0, stdout: '' };
  };

  assert.throws(() => deploySafely({ run, configText: config }), /requires exactly one/);
  assert.equal(calls.some(({ args }) => args[0] === 'deploy'), false);
});

test('deployment disables Fly HA and verifies the resulting single-Machine inventory', () => {
  const before = oneMachineInventory();
  const after = oneMachineInventory();
  let deployed = false;
  const calls = [];
  const run = (args, inherit = false) => {
    calls.push({ args, inherit });
    if (args[0] === 'machine') {
      return { status: 0, stdout: JSON.stringify(deployed ? after.machines : before.machines) };
    }
    if (args[0] === 'volumes') {
      return { status: 0, stdout: JSON.stringify(deployed ? after.volumes : before.volumes) };
    }
    if (args[0] === 'deploy') {
      deployed = true;
      return { status: 0, stdout: '' };
    }
    throw new Error(`Unexpected command: ${args[0]}`);
  };

  assert.equal(deploySafely({ run, configText: config }).mode, 'existing');
  const deployCall = calls.find(({ args }) => args[0] === 'deploy');
  assert.deepEqual(deployCall.args, ['deploy', '--app', 'product-labels-luay', '--ha=false', '--strategy', 'rolling']);
  assert.equal(deployCall.inherit, true);
});

test('deployment reports a post-deploy scale violation instead of claiming success', () => {
  const before = oneMachineInventory();
  const calls = [];
  let deployed = false;
  const run = (args, inherit = false) => {
    calls.push(args);
    if (args[0] === 'machine') {
      const machines = deployed
        ? [before.machines[0], { ...before.machines[0], id: 'machine-2' }]
        : before.machines;
      return { status: 0, stdout: JSON.stringify(machines) };
    }
    if (args[0] === 'volumes') return { status: 0, stdout: JSON.stringify(before.volumes) };
    if (args[0] === 'deploy') {
      deployed = true;
      return { status: 0, stdout: '' };
    }
    throw new Error(`Unexpected command: ${args[0]}`);
  };

  assert.throws(() => deploySafely({ run, configText: config }), /requires exactly one/);
  assert.equal(calls.some((args) => args[0] === 'deploy'), true);
});
