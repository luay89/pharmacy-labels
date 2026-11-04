'use strict';

// Runs the real sw.js in a sandbox with in-memory Cache Storage and a controllable network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'sw.js'), 'utf8');
const SCOPE = 'https://labels.example/app/';
const FILES = {
  'https://labels.example/app/': ['<!doctype html><title>Product Labels</title>', 'text/html'],
  'https://labels.example/app/index.html': ['<!doctype html><title>Product Labels</title>', 'text/html'],
  'https://labels.example/app/manifest.webmanifest': ['{"name":"Product Labels"}', 'application/manifest+json'],
  'https://labels.example/app/web-icon-192.svg': ['<svg/>', 'image/svg+xml'],
  'https://labels.example/app/web-icon-512.svg': ['<svg/>', 'image/svg+xml'],
  'https://labels.example/app/device-key.js': ['function createDeviceKeys() {}', 'text/javascript'],
  'https://labels.example/app/license-client.js': ['function verifyCertificate() {}', 'text/javascript'],
  'https://labels.example/app/api/session': ['{"unlocked":false}', 'application/json']
};

function createCaches(initial = {}) {
  const stores = new Map(Object.entries(initial).map(([name, entries]) => [name, new Map(entries)]));
  const keyOf = (request) => new URL(typeof request === 'string' ? request : request.url, SCOPE).href;
  const open = async (name) => {
    if (!stores.has(name)) stores.set(name, new Map());
    const store = stores.get(name);
    return {
      async addAll(requests) {
        const responses = await Promise.all(requests.map(async (request) => {
          const response = await world.fetch({ url: keyOf(request), method: 'GET', mode: 'cors' });
          if (!response.ok) throw new TypeError(`addAll failed for ${request}`);
          return [keyOf(request), response];
        }));
        for (const [key, response] of responses) store.set(key, response);
      },
      async put(request, response) { store.set(keyOf(request), response); }
    };
  };
  const world = {
    stores,
    caches: {
      open,
      keys: async () => [...stores.keys()],
      delete: async (name) => stores.delete(name),
      async match(request) {
        for (const store of stores.values()) {
          const hit = store.get(keyOf(request));
          if (hit) return hit.clone();
        }
        return undefined;
      }
    },
    online: true,
    fetches: [],
    async fetch(request) {
      world.fetches.push(request.url);
      if (!world.online) throw new TypeError('Failed to fetch');
      const file = FILES[request.url];
      return file
        ? new Response(file[0], { status: 200, headers: { 'Content-Type': file[1] } })
        : new Response('Not found.', { status: 404, headers: { 'Content-Type': 'text/plain' } });
    }
  };
  return world;
}

function loadWorker(initialCaches) {
  const world = createCaches(initialCaches);
  const listeners = {};
  const calls = { skipWaiting: 0, claim: 0 };
  const sandbox = {
    self: {
      addEventListener: (type, listener) => { listeners[type] = listener; },
      skipWaiting: async () => { calls.skipWaiting += 1; },
      clients: { claim: async () => { calls.claim += 1; } }
    },
    caches: world.caches,
    fetch: (request) => world.fetch(request),
    Response,
    URL,
    Promise
  };
  vm.runInNewContext(SOURCE, sandbox, { filename: 'sw.js' });
  const exported = vm.runInNewContext('({ CACHE_NAME, ASSETS })', sandbox);
  return { world, listeners, calls, CACHE_NAME: exported.CACHE_NAME, ASSETS: [...exported.ASSETS] };
}

async function dispatch(listener, extra = {}) {
  const event = {
    ...extra,
    waited: null,
    responded: null,
    waitUntil(promise) { this.waited = promise; },
    respondWith(promise) { this.responded = promise; }
  };
  listener(event);
  if (event.waited) await event.waited;
  return event;
}

const request = (pathname, { method = 'GET', mode = 'cors' } = {}) => ({ url: new URL(pathname, SCOPE).href, method, mode });

async function installed(initialCaches) {
  const worker = loadWorker(initialCaches);
  await dispatch(worker.listeners.install);
  await dispatch(worker.listeners.activate);
  worker.world.fetches.length = 0;
  return worker;
}

test('install precaches the device and license scripts in the v11 cache', async () => {
  const worker = loadWorker();
  assert.equal(worker.CACHE_NAME, 'product-labels-v11');
  assert.ok(worker.ASSETS.includes('./device-key.js'));
  assert.ok(worker.ASSETS.includes('./license-client.js'));
  assert.deepEqual(worker.ASSETS, ['./', './index.html', './manifest.webmanifest', './web-icon-192.svg', './web-icon-512.svg', './device-key.js', './license-client.js']);
  await dispatch(worker.listeners.install);
  const cached = worker.world.stores.get('product-labels-v11');
  assert.deepEqual([...cached.keys()].sort(), worker.ASSETS.map((asset) => new URL(asset, SCOPE).href).sort());
  assert.equal(await cached.get(`${SCOPE}device-key.js`).clone().text(), 'function createDeviceKeys() {}');
  assert.equal(await cached.get(`${SCOPE}license-client.js`).clone().text(), 'function verifyCertificate() {}');
  assert.equal(worker.calls.skipWaiting, 1);
  assert.ok(!worker.world.fetches.some((url) => url.includes('/api/')), 'nothing under /api/ is precached');
});

test('a failed precache leaves no partial v11 cache behind and keeps the old one', async () => {
  const worker = loadWorker({ 'product-labels-v6': [[`${SCOPE}index.html`, new Response('old')]] });
  const original = FILES[`${SCOPE}device-key.js`];
  delete FILES[`${SCOPE}device-key.js`];
  try {
    await assert.rejects(dispatch(worker.listeners.install));
  } finally {
    FILES[`${SCOPE}device-key.js`] = original;
  }
  assert.equal(worker.world.stores.get('product-labels-v11').size, 0);
  assert.ok(worker.world.stores.has('product-labels-v6'));
  assert.equal(worker.calls.skipWaiting, 0, 'the old worker stays in charge');
});

test('activation removes older product-labels caches only and claims open pages', async () => {
  const worker = loadWorker({
    'product-labels-v5': [[`${SCOPE}index.html`, new Response('v5')]],
    'product-labels-v6': [[`${SCOPE}index.html`, new Response('v6')]],
    'product-labels-v7': [[`${SCOPE}device-key.js`, new Response('old device script')]],
    'another-app-cache': [[`${SCOPE}other`, new Response('keep')]]
  });
  await dispatch(worker.listeners.install);
  await dispatch(worker.listeners.activate);
  assert.deepEqual([...worker.world.stores.keys()].sort(), ['another-app-cache', 'product-labels-v11']);
  assert.equal(worker.calls.claim, 1);
});

test('API requests always go to the network and are never cached, online or offline', async () => {
  const worker = await installed();
  const sizes = () => [...worker.world.stores.values()].map((store) => store.size);
  const before = sizes();
  const online = await dispatch(worker.listeners.fetch, { request: request('api/session') });
  assert.equal(await (await online.responded).text(), '{"unlocked":false}');
  assert.deepEqual(worker.world.fetches, [`${SCOPE}api/session`]);
  assert.deepEqual(sizes(), before, 'the API response was not stored');

  worker.world.online = false;
  const offline = await dispatch(worker.listeners.fetch, { request: request('api/devices/challenge') });
  await assert.rejects(offline.responded, /Failed to fetch/, 'no cached page stands in for an API answer');

  for (const method of ['POST', 'PUT', 'DELETE']) {
    const event = await dispatch(worker.listeners.fetch, { request: request('api/devices/register', { method }) });
    assert.equal(event.responded, null, `${method} is not intercepted`);
  }
});

test('offline, device-key.js comes from the cache as JavaScript', async () => {
  const worker = await installed();
  worker.world.online = false;
  const event = await dispatch(worker.listeners.fetch, { request: request('device-key.js', { mode: 'no-cors' }) });
  const response = await event.responded;
  assert.match(response.headers.get('content-type'), /javascript/);
  assert.equal(await response.text(), 'function createDeviceKeys() {}');
  assert.deepEqual(worker.world.fetches, [], 'served without touching the network');
});

test('a script that is neither cached nor reachable fails as a network error, never as index.html', async () => {
  const worker = await installed();
  worker.world.online = false;
  for (const pathname of ['missing.js', 'device-key.js?v=2', 'manifest.json']) {
    const event = await dispatch(worker.listeners.fetch, { request: request(pathname, { mode: 'no-cors' }) });
    const response = await event.responded;
    assert.equal(response.type, 'error', pathname);
    assert.equal(response.status, 0, pathname);
    assert.doesNotMatch(await response.text(), /<!doctype html>/i, pathname);
  }
  // Even with device-key.js missing from the cache (e.g. evicted), its request does not turn into HTML.
  worker.world.stores.get('product-labels-v11').delete(`${SCOPE}device-key.js`);
  const evicted = await (await dispatch(worker.listeners.fetch, { request: request('device-key.js', { mode: 'no-cors' }) })).responded;
  assert.equal(evicted.type, 'error');
});

test('navigations keep their network-first behaviour with the cached page as the offline fallback', async () => {
  const worker = await installed();
  const online = await (await dispatch(worker.listeners.fetch, { request: request('./', { mode: 'navigate' }) })).responded;
  assert.equal(online.status, 200);
  worker.world.online = false;
  const offline = await (await dispatch(worker.listeners.fetch, { request: request('./', { mode: 'navigate' }) })).responded;
  assert.match(await offline.text(), /<!doctype html>/);
});

test('reachable static files are still cached at runtime as before', async () => {
  const worker = await installed();
  worker.world.stores.get('product-labels-v11').delete(`${SCOPE}web-icon-192.svg`);
  const response = await (await dispatch(worker.listeners.fetch, { request: request('web-icon-192.svg', { mode: 'no-cors' }) })).responded;
  assert.equal(response.status, 200);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.ok(worker.world.stores.get('product-labels-v11').has(`${SCOPE}web-icon-192.svg`));
  const missing = await (await dispatch(worker.listeners.fetch, { request: request('nope.svg', { mode: 'no-cors' }) })).responded;
  assert.equal(missing.status, 404, 'a reachable 404 is passed through, not replaced');
  assert.ok(!worker.world.stores.get('product-labels-v11').has(`${SCOPE}nope.svg`));
});
